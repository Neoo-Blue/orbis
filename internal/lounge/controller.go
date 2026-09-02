package lounge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options are the live settings a controller reads on every decision, so a
// change in the UI takes effect without reconnecting.
type Options struct {
	SkipAds       bool
	MuteAds       bool
	Categories    []string
	MinSkipLength float64
	Offset        float64 // seconds added when seeking past a segment
}

// AdRecord is one ad as the UI's history sees it: what it was, how long it
// should have run, how long it actually ran, and why it ended. The history is
// the evidence for whether the engine is working on a given television.
type AdRecord struct {
	At             time.Time `json:"at"`
	AdVideoID      string    `json:"ad_video_id"`
	ContentVideoID string    `json:"content_video_id"`
	Duration       float64   `json:"duration"`
	Watched        float64   `json:"watched"`
	Skippable      bool      `json:"skippable"`
	Bumper         bool      `json:"bumper"`
	Muted          bool      `json:"muted"`
	Attempts       int       `json:"attempts"`
	// Outcome is one of "skipped" (the player ended it before its length),
	// "played" (ran to its end; unskippable), "abandoned" (the screen went
	// away or the viewer changed video), or "lost" (the player never said it
	// ended and its length was unknown). Reason is what closed it.
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// Stats is the observable state of one device session.
type Stats struct {
	ScreenID  string `json:"screen_id"`
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
	// Online is whether the screen itself is present in the lounge. A session
	// can be connected to YouTube's servers while the television is off.
	Online   bool    `json:"online"`
	VideoID  string  `json:"video_id"`
	Position float64 `json:"position"`
	AdActive bool    `json:"ad_active"`
	// AdsHandled counts ads seen; AdsSkipped counts the ones that ended early
	// because Orbis cut them short; AdsLost counts the ones whose end was
	// never reported. The gaps between them are the honest measure of how
	// well this is working, and they are the numbers the UI shows.
	AdsHandled      int        `json:"ads_handled"`
	AdsSkipped      int        `json:"ads_skipped"`
	AdsLost         int        `json:"ads_lost"`
	SegmentsSkipped int        `json:"segments_skipped"`
	SegmentsMuted   int        `json:"segments_muted"`
	SegmentsLoaded  int        `json:"segments_loaded"`
	SecondsSaved    float64    `json:"seconds_saved"`
	LastError       string     `json:"last_error,omitempty"`
	LastEvent       string     `json:"last_event,omitempty"`
	LastEventAt     time.Time  `json:"last_event_at"`
	Recent          []AdRecord `json:"recent"`
}

// commandSender is the one thing a controller needs from a session: the
// ability to send a command. Tests substitute a recorder for the real one.
type commandSender interface {
	sendCommand(ctx context.Context, command string, args map[string]string) error
}

// Controller owns one screen: it keeps a live Lounge session, tracks playback,
// and acts on ads and sponsor segments.
type Controller struct {
	screenID string
	name     string
	sess     *Session
	send     commandSender
	sb       *SponsorBlock
	opts     func() Options
	log      func(string, ...any)
	now      func() time.Time

	ctx context.Context

	mu        sync.Mutex
	connected bool
	online    bool
	videoID   string
	segments  []Segment
	lastTime  float64
	lastWall  time.Time
	playing   bool

	// Ad state. One ad at a time; a pod of several ads arrives as a sequence
	// of adPlaying events with distinct ids and no end event between them, so
	// a new id closes the previous ad and opens the next.
	adActive    bool
	adID        string
	adContent   string
	adBegan     time.Time // wall time the ad started; for the record
	adStart     time.Time // shifted forward by pauses; for the deadline
	adPausedAt  time.Time
	adDur       float64
	adSkippable bool
	adBumper    bool
	adSkipOK    bool
	adTries     int
	nextTry     time.Time

	// Volume state. mutedByUs records that Orbis, not the viewer, set the
	// volume to zero, so a session that drops mid-ad can put it back instead
	// of leaving the television silent until somebody picks up the remote.
	lastVol   int
	mutedByUs bool
	muteSeg   *Segment

	stats Stats
	seen  map[string]bool
	cmds  chan queuedCmd
}

// queuedCmd is one player command awaiting its turn on the single command
// sender. Serialising sends keeps the browser-channel offset strictly ordered.
type queuedCmd struct {
	name string
	args map[string]string
}

const (
	// maxRecent bounds the per-screen ad history kept in memory for the UI.
	maxRecent = 40
	// adEndGrace is how long past an ad's own duration Orbis keeps believing
	// the ad is still on screen without the player saying so. Beyond it the
	// ad is closed as lost: better a rare early un-mute than a television
	// that stays silent, and a skip command sent every second, until someone
	// notices.
	adEndGrace = 6 * time.Second
	// adUnknownLimit bounds an ad whose duration was never reported.
	adUnknownLimit = 90 * time.Second
	// adPausedLimit bounds an ad the viewer has paused; a paused ad does not
	// advance, but a pause that lasts this long is a walked-away television.
	adPausedLimit = 10 * time.Minute
)

// NewController wires a controller for one screen. deviceID must be stable for
// the life of the process so the TV recognises reconnections as the same remote.
func NewController(screenID, name, deviceID string, hc *http.Client, sb *SponsorBlock, opts func() Options, log func(string, ...any)) *Controller {
	if log == nil {
		log = func(string, ...any) {}
	}
	if opts == nil {
		opts = func() Options { return Options{} }
	}
	c := &Controller{
		screenID: screenID,
		name:     name,
		sb:       sb,
		opts:     opts,
		log:      log,
		now:      time.Now,
		lastVol:  100,
		seen:     map[string]bool{},
		cmds:     make(chan queuedCmd, 64),
		stats:    Stats{ScreenID: screenID, Name: name, Recent: []AdRecord{}},
	}
	c.sess = newSession(screenID, deviceID, "Orbis", hc)
	c.sess.onEvent = c.handleEvent
	c.send = c.sess
	return c
}

// Run maintains the session until ctx is cancelled, reconnecting with backoff.
func (c *Controller) Run(ctx context.Context) {
	c.ctx = ctx
	go c.sendLoop(ctx)
	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.sess.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.setError(err.Error())
			sleep(ctx, backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		c.setConnected(true)
		c.log("lounge: connected to %s (%s)", c.name, short(c.screenID))

		// Ask what is on screen rather than waiting for the next event. A TV
		// that has been playing for ten minutes sends nothing until something
		// changes, and without this the first ad after a reconnect is missed.
		c.command("getNowPlaying", nil)

		tctx, cancelTick := context.WithCancel(ctx)
		go c.tickLoop(tctx)

		for ctx.Err() == nil {
			err := c.sess.poll(ctx)
			if err == errSessionExpired {
				break // re-bind
			}
			if err != nil {
				if ctx.Err() == nil {
					c.setError(err.Error())
				}
				break
			}
		}
		cancelTick()
		if ctx.Err() != nil {
			// Going away: the send loop is gone with the context, so a
			// queued restore would never leave. Send it directly, on a
			// context of its own, before the session is dropped.
			c.restoreVolumeNow()
		}
		c.setConnected(false)
		sleep(ctx, backoff)
	}
}

// restoreVolumeNow is the shutdown path of restoreVolumeIfMuted: it sends
// the command itself, synchronously, on a fresh context, because the queue
// and its sender are bound to the context that has just been cancelled.
func (c *Controller) restoreVolumeNow() {
	c.mu.Lock()
	if !c.mutedByUs {
		c.mu.Unlock()
		return
	}
	c.mutedByUs = false
	vol := c.lastVol
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.send.sendCommand(ctx, "setVolume", map[string]string{"volume": strconv.Itoa(vol), "delta": "0"}); err != nil {
		c.log("lounge[%s]: volume restore on shutdown FAILED: %v", c.name, err)
	} else {
		c.log("lounge[%s]: volume restored to %d on shutdown", c.name, vol)
	}
}

// adInfo is what an ad-start event tells us about the ad.
type adInfo struct {
	id       string
	content  string
	duration float64
	// skippable is YouTube saying the ad has a skip button; skipArmed is it
	// saying the button is live right now. They arrive on different events.
	skippable bool
	skipArmed bool
	bumper    bool
}

// onNowPlayingDuringAd decides what a nowPlaying event means while an ad is
// on screen. On a television it is not the end of the ad by itself: the
// player reports nowPlaying about two seconds into an unskippable ad, and
// treating that as the end un-muted every unskippable ad and recorded it as
// skipped. So it ends the ad only when it carries evidence: a different
// content video (the viewer moved on), or a position past the ad's own
// length. A genuine skip is confirmed by adState=0, and an ad that quietly
// ends is closed by its deadline.
func (c *Controller) onNowPlayingDuringAd(vid string) {
	c.mu.Lock()
	if !c.adActive {
		c.mu.Unlock()
		return
	}
	adID, content := c.adID, c.adContent
	elapsed := c.now().Sub(c.adStart).Seconds()
	dur := c.adDur
	c.mu.Unlock()

	switch {
	case vid != "" && vid == adID:
		// The ad itself being reported as the current video.
	case vid != "" && content != "" && vid != content:
		c.clearAd("nowPlaying: different video")
	case dur > 0 && elapsed >= dur-1.5:
		c.clearAd("nowPlaying at the ad's end")
	default:
		c.log("lounge[%s]: nowPlaying %.1fs into a %.0fs ad; keeping the ad open", c.name, elapsed, dur)
	}
}

func (c *Controller) handleEvent(ev event) {
	c.mu.Lock()
	c.stats.LastEvent = ev.typ
	c.stats.LastEventAt = c.now()
	first := !c.seen[ev.typ]
	c.seen[ev.typ] = true
	c.mu.Unlock()

	// Log the first time each event type is seen, every ad-related event in
	// full, and every playback event that arrives while an ad is on screen,
	// so a session that is connected but not skipping can be diagnosed from
	// the log rather than guessed at.
	c.mu.Lock()
	duringAd := c.adActive
	c.mu.Unlock()
	if first || duringAd || strings.Contains(strings.ToLower(ev.typ), "ad") {
		c.log("lounge[%s]: event %q %s", c.name, ev.typ, rawArgs(ev))
	}

	switch ev.typ {
	case "nowPlaying", "onStateChange":
		obj := ev.object()
		state := asString(obj["state"])
		vid := asString(obj["videoId"])
		if ev.typ == "nowPlaying" {
			c.onNowPlayingDuringAd(vid)
		}
		if t, ok := asFloat(obj["currentTime"]); ok {
			c.updatePosition(t, state == "1")
		}
		c.notePlayerState(state)
		if vid != "" {
			c.onVideo(vid)
		}
	case "onAdStateChange":
		obj := ev.object()
		adState := asString(obj["adState"])
		var info adInfo
		if d, ok := asFloat(obj["adDuration"]); ok {
			info.duration = normaliseDuration(d)
		}
		info.skippable = truthy(obj["isSkippable"])
		info.skipArmed = truthy(obj["isSkipEnabled"])
		if adState == "" || adState == "0" || adState == "-1" {
			c.clearAd("adState=" + adState)
		} else {
			c.onAd(info)
		}
	case "adPlaying", "onAdStart":
		obj := ev.object()
		info := adInfo{
			id:        asString(obj["adVideoId"]),
			content:   asString(obj["contentVideoId"]),
			skippable: truthy(obj["isSkippable"]),
			skipArmed: truthy(obj["isSkipEnabled"]),
			bumper:    truthy(obj["isBumper"]),
		}
		if d, ok := asFloat(obj["duration"]); ok {
			info.duration = normaliseDuration(d)
		} else if d, ok := asFloat(obj["adDuration"]); ok {
			info.duration = normaliseDuration(d)
		}
		c.onAd(info)
	case "onAdCancel", "onAdEnd", "onAdSkip":
		c.clearAd(ev.typ)
	case "onVolumeChanged":
		obj := ev.object()
		if v, ok := asFloat(obj["volume"]); ok {
			c.mu.Lock()
			// Only trust a volume report that is not our own doing, or the
			// restore level would be overwritten with the zero we just set.
			if !c.mutedByUs && v > 0 {
				c.lastVol = int(v)
			}
			c.mu.Unlock()
		}
	case "loungeScreenDisconnected":
		// The television left: app closed, input changed, or power off. An
		// ad that was on screen is not on screen any more, and nothing will
		// ever say so.
		c.mu.Lock()
		c.online = false
		c.stats.Online = false
		c.playing = false
		c.mu.Unlock()
		c.clearAd("screen disconnected")
	case "loungeStatus":
		online := screenPresent(ev)
		c.mu.Lock()
		c.online = online
		c.stats.Online = online
		wasMuted := c.mutedByUs && !c.adActive && c.muteSeg == nil
		c.mu.Unlock()
		// The screen coming back is the first chance to undo a mute that was
		// left behind when it went away.
		if online && wasMuted {
			c.restoreVolumeIfMuted()
		}
	}
}

// screenPresent reads a loungeStatus payload, whose "devices" field is a JSON
// string (not an array) listing everything attached to the lounge, and
// reports whether any of them is a screen rather than a remote.
func screenPresent(ev event) bool {
	obj := ev.object()
	raw := asString(obj["devices"])
	if raw == "" {
		return false
	}
	var devs []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(raw), &devs) != nil {
		return false
	}
	for _, d := range devs {
		if strings.EqualFold(d.Type, "LOUNGE_SCREEN") {
			return true
		}
	}
	return false
}

// normaliseDuration accepts seconds or milliseconds; clients differ.
func normaliseDuration(d float64) float64 {
	if d <= 0 {
		return 0
	}
	if d > 600 {
		d /= 1000
	}
	return d
}

// notePlayerState tracks pauses during an ad. A paused ad does not advance,
// so its deadline is pushed forward by however long it sat.
func (c *Controller) notePlayerState(state string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.adActive {
		return
	}
	switch state {
	case "2": // paused
		if c.adPausedAt.IsZero() {
			c.adPausedAt = c.now()
		}
	case "1": // playing
		if !c.adPausedAt.IsZero() {
			c.adStart = c.adStart.Add(c.now().Sub(c.adPausedAt))
			c.adPausedAt = time.Time{}
		}
	}
}

// onVideo loads sponsor segments for a newly-playing video.
func (c *Controller) onVideo(videoID string) {
	c.mu.Lock()
	same := videoID == c.videoID
	c.videoID = videoID
	c.stats.VideoID = videoID
	if !same {
		c.segments = nil
		c.stats.SegmentsLoaded = 0
		c.muteSeg = nil
	}
	c.mu.Unlock()
	if same || c.sb == nil {
		return
	}

	opts := c.opts()
	if len(opts.Categories) == 0 {
		return
	}
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		segs, err := c.sb.Segments(ctx, videoID, opts.Categories)
		if err != nil {
			c.log("lounge: sponsorblock lookup failed for %s: %v", videoID, err)
			return
		}
		// Drop segments shorter than the minimum: not worth a jarring seek.
		// A mute segment has no seek to be jarring, so the floor is only
		// applied to the ones that move the playhead.
		if opts.MinSkipLength > 0 {
			filtered := segs[:0]
			for _, s := range segs {
				if s.Action == ActionMute || s.End-s.Start >= opts.MinSkipLength {
					filtered = append(filtered, s)
				}
			}
			segs = filtered
		}
		c.mu.Lock()
		if c.videoID == videoID {
			c.segments = segs
			c.stats.SegmentsLoaded = len(segs)
		}
		c.mu.Unlock()
	}()
}

// adRetryDelay spaces out repeated skip attempts. YouTube arms the skip button
// a few seconds into an ad and ignores anything sent before then, so the first
// stretch is probed once a second; after that the ad is very likely one of the
// unskippable kind and a slow retry is enough to catch the moment it ends.
func adRetryDelay(attempt int) time.Duration {
	switch {
	case attempt < 12:
		return time.Second
	case attempt < 24:
		return 3 * time.Second
	default:
		return 6 * time.Second
	}
}

// maxAdTries bounds the retries for one ad. Beyond this the ad is unskippable
// by any means available here, and continuing to ask only adds requests.
const maxAdTries = 40

// onAd records an ad start (or a state change within one) and acts on it.
func (c *Controller) onAd(info adInfo) {
	c.mu.Lock()
	// A different ad id while one is active is the next ad in a pod. Close
	// the current one first so each ad gets its own record and its own
	// skip budget.
	if c.adActive && info.id != "" && c.adID != "" && info.id != c.adID {
		c.mu.Unlock()
		// Keep the mute across the boundary: un-muting for the half second
		// between two ads is a burst of sound, not a restore.
		c.closeAd("next ad in pod", false)
		c.mu.Lock()
	}
	firstSeen := !c.adActive
	c.adActive = true
	c.stats.AdActive = true
	if firstSeen {
		c.stats.AdsHandled++
		c.adStart = c.now()
		c.adBegan = c.adStart
		c.adPausedAt = time.Time{}
		c.adID = info.id
		c.adContent = info.content
		c.adDur = 0
		c.adSkippable = false
		c.adBumper = info.bumper
		c.adSkipOK = false
		c.adTries = 0
		c.nextTry = time.Time{}
	}
	if info.id != "" && c.adID == "" {
		c.adID = info.id
	}
	if info.content != "" {
		c.adContent = info.content
	}
	if info.duration > 0 {
		c.adDur = info.duration
	}
	if info.bumper {
		c.adBumper = true
	}
	if info.skippable {
		c.adSkippable = true
	}
	// Either signal is worth a skip attempt; the retry schedule covers the
	// gap between "has a button" and "button is live".
	skipJustEnabled := (info.skippable || info.skipArmed) && !c.adSkipOK
	if skipJustEnabled {
		c.adSkipOK = true
	}
	elapsed := c.now().Sub(c.adStart).Seconds()
	dur := c.adDur
	o := c.opts()
	needMute := firstSeen && o.MuteAds && !c.mutedByUs
	if needMute {
		c.mutedByUs = true
	}
	c.mu.Unlock()

	if firstSeen {
		c.log("lounge[%s]: AD %s detected (skippable=%v, bumper=%v, duration=%.0fs) -> mute=%v skip=%v",
			c.name, orUnknown(info.id), info.skippable, info.bumper, dur, o.MuteAds, o.SkipAds)
	} else if skipJustEnabled {
		c.log("lounge[%s]: skip button ENABLED after %.1fs", c.name, elapsed)
	}
	if needMute {
		c.command("setVolume", map[string]string{"volume": "0", "delta": "0"})
	}
	if o.SkipAds && (firstSeen || skipJustEnabled) {
		// skipAd is a no-op server-side until the ad is skippable, so sending
		// it on the way in costs nothing and catches an already-skippable ad
		// without waiting a whole tick.
		c.trySkip()
	}
}

// trySkip queues one skip attempt and schedules the next.
func (c *Controller) trySkip() {
	c.mu.Lock()
	if !c.adActive || c.adTries >= maxAdTries {
		c.mu.Unlock()
		return
	}
	c.adTries++
	c.nextTry = c.now().Add(adRetryDelay(c.adTries))
	c.mu.Unlock()
	c.command("skipAd", nil)
}

// clearAd closes the current ad, if any, with the given reason, records it,
// and restores the volume if Orbis took it away.
func (c *Controller) clearAd(reason string) { c.closeAd(reason, true) }

// closeAd is clearAd with control over the volume: a pod boundary keeps the
// mute in place for the ad that follows.
func (c *Controller) closeAd(reason string, restore bool) {
	c.mu.Lock()
	wasAd := c.adActive
	if !wasAd {
		c.mu.Unlock()
		return
	}
	c.adActive = false
	c.stats.AdActive = false
	elapsed := c.now().Sub(c.adStart).Seconds()
	if !c.adPausedAt.IsZero() {
		elapsed -= c.now().Sub(c.adPausedAt).Seconds()
		c.adPausedAt = time.Time{}
	}
	if elapsed < 0 {
		elapsed = 0
	}
	dur := c.adDur
	outcome := adOutcome(reason, dur, elapsed)
	switch outcome {
	case "lost":
		c.stats.AdsLost++
	case "skipped":
		c.stats.AdsSkipped++
		c.stats.SecondsSaved += dur - elapsed
	}
	rec := AdRecord{
		At:             c.adBegan,
		AdVideoID:      c.adID,
		ContentVideoID: c.adContent,
		Duration:       dur,
		Watched:        round1(elapsed),
		Skippable:      c.adSkippable,
		Bumper:         c.adBumper,
		Muted:          c.mutedByUs,
		Attempts:       c.adTries,
		Outcome:        outcome,
		Reason:         reason,
	}
	c.stats.Recent = append([]AdRecord{rec}, c.stats.Recent...)
	if len(c.stats.Recent) > maxRecent {
		c.stats.Recent = c.stats.Recent[:maxRecent]
	}
	attempts := c.adTries
	c.adTries = 0
	c.adDur = 0
	c.adID = ""
	c.mu.Unlock()

	c.log("lounge[%s]: ad cleared via %s after %.1fs of %.0fs (%d skip attempt(s)) -> %s",
		c.name, reason, elapsed, dur, attempts, strings.ToUpper(outcome))
	c.mu.Lock()
	inMuteSeg := c.muteSeg != nil
	c.mu.Unlock()
	// Inside a SponsorBlock mute segment the sound stays off; applySegments
	// puts it back when the playhead leaves the segment.
	if restore && !inMuteSeg {
		c.restoreVolumeIfMuted()
	}
}

// adOutcome classifies how an ad ended. "skipped" is only claimed when the
// player itself reported the end and it came before the ad's own length;
// a screen that went away or a viewer who changed video is "abandoned",
// and an ad closed by its deadline is "played" if it ran its length and
// "lost" if nobody knows.
func adOutcome(reason string, dur, elapsed float64) string {
	ranFull := dur > 0 && elapsed >= dur-1
	switch {
	case strings.HasPrefix(reason, "no end event"):
		if ranFull {
			return "played"
		}
		return "lost"
	case reason == "screen disconnected", reason == "onAdCancel",
		strings.HasPrefix(reason, "nowPlaying: different"):
		if ranFull {
			return "played"
		}
		return "abandoned"
	default:
		if dur > 0 && elapsed < dur-1 {
			return "skipped"
		}
		return "played"
	}
}

// restoreVolumeIfMuted puts the volume back if Orbis is the one that took it
// away. Safe to call at any time; it does nothing if the viewer muted the TV.
func (c *Controller) restoreVolumeIfMuted() {
	c.mu.Lock()
	if !c.mutedByUs {
		c.mu.Unlock()
		return
	}
	c.mutedByUs = false
	vol := c.lastVol
	c.mu.Unlock()
	c.command("setVolume", map[string]string{"volume": strconv.Itoa(vol), "delta": "0"})
}

func (c *Controller) updatePosition(t float64, playing bool) {
	c.mu.Lock()
	c.lastTime = t
	c.lastWall = c.now()
	c.playing = playing
	c.stats.Position = t
	c.mu.Unlock()
}

func (c *Controller) currentPos() (pos float64, playing, adActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.playing && !c.lastWall.IsZero() {
		return c.lastTime + c.now().Sub(c.lastWall).Seconds(), c.playing, c.adActive
	}
	return c.lastTime, c.playing, c.adActive
}

// tickLoop interpolates position between events and acts every second.
func (c *Controller) tickLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.tick()
	}
}

// tick is one decision cycle: it closes an ad the player forgot to end,
// retries the skip while an ad is on screen, seeks past sponsor segments and
// mutes the ones marked mute rather than skip.
func (c *Controller) tick() {
	pos, playing, adActive := c.currentPos()
	opts := c.opts()

	if adActive {
		if reason := c.adOverdue(); reason != "" {
			c.clearAd(reason)
			return
		}
		if opts.SkipAds {
			c.mu.Lock()
			due := c.nextTry.IsZero() || !c.now().Before(c.nextTry)
			c.mu.Unlock()
			if due {
				c.trySkip()
			}
		}
		return
	}
	if !playing {
		return
	}
	c.applySegments(pos, opts)
}

// adOverdue reports a non-empty reason when the current ad has run past any
// point at which it could still be on screen.
func (c *Controller) adOverdue() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.adActive {
		return ""
	}
	now := c.now()
	if !c.adPausedAt.IsZero() {
		if now.Sub(c.adPausedAt) > adPausedLimit {
			return fmt.Sprintf("no end event, paused for %s", adPausedLimit)
		}
		return ""
	}
	elapsed := now.Sub(c.adStart)
	limit := adUnknownLimit
	if c.adDur > 0 {
		limit = time.Duration(c.adDur*float64(time.Second)) + adEndGrace
	}
	if elapsed > limit {
		return fmt.Sprintf("no end event after %.0fs", elapsed.Seconds())
	}
	return ""
}

// applySegments acts on whichever sponsor segment covers the playhead.
func (c *Controller) applySegments(pos float64, opts Options) {
	c.mu.Lock()
	seg := SegmentAt(c.segments, pos)
	inMute := c.muteSeg
	c.mu.Unlock()

	// Leaving a mute segment: put the sound back before anything else.
	if inMute != nil && (seg == nil || seg.Action != ActionMute || seg.Start != inMute.Start) {
		c.mu.Lock()
		c.muteSeg = nil
		c.mu.Unlock()
		c.restoreVolumeIfMuted()
	}
	if seg == nil {
		return
	}

	if seg.Action == ActionMute {
		c.mu.Lock()
		already := c.muteSeg != nil || c.mutedByUs
		if !already {
			c.muteSeg = seg
			c.mutedByUs = true
			c.stats.SegmentsMuted++
			c.stats.SecondsSaved += seg.End - pos
		}
		c.mu.Unlock()
		if !already {
			c.command("setVolume", map[string]string{"volume": "0", "delta": "0"})
			c.log("lounge: %s muted %s segment [%.0f-%.0f]", c.name, seg.Category, seg.Start, seg.End)
		}
		return
	}

	target := seg.End + opts.Offset
	c.command("seekTo", map[string]string{"newTime": strconv.FormatFloat(target, 'f', 3, 64)})
	c.mu.Lock()
	c.lastTime = target
	c.lastWall = c.now()
	c.stats.SegmentsSkipped++
	if d := seg.End - pos; d > 0 {
		c.stats.SecondsSaved += d
	}
	c.mu.Unlock()
	c.log("lounge: %s skipped %s segment [%.0f-%.0f]", c.name, seg.Category, seg.Start, seg.End)
}

// command queues a player command. It never blocks the caller: the poll
// goroutine (via handleEvent) and the tick goroutine both enqueue here, and a
// single sender drains the queue so commands reach YouTube strictly in order.
// Concurrent sends would interleave the browser-channel offset and desync the
// session, the failure that left ads unskipped and the stream silent.
func (c *Controller) command(name string, args map[string]string) {
	select {
	case c.cmds <- queuedCmd{name: name, args: args}:
	default:
		c.log("lounge[%s]: command %s dropped (queue full)", c.name, name)
	}
}

// sendLoop is the sole caller of sendCommand, so offsets stay ordered.
func (c *Controller) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cm := <-c.cmds:
			if !c.waitConnected(ctx, 5*time.Second) {
				// A skip is worthless once the moment has passed, and a
				// volume restore is re-issued on reconnect, so dropping a
				// command that has nowhere to go is the right answer.
				c.log("lounge[%s]: command %s dropped (not connected)", c.name, cm.name)
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := c.send.sendCommand(sctx, cm.name, cm.args)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					c.log("lounge[%s]: command %s FAILED: %v", c.name, cm.name, err)
				}
			}
		}
	}
}

// waitConnected gives a command a short grace period to catch a reconnect
// that is already in flight, rather than throwing it away on a one-second gap.
func (c *Controller) waitConnected(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		c.mu.Lock()
		ok := c.connected
		c.mu.Unlock()
		if ok {
			return true
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return false
		}
		sleep(ctx, 200*time.Millisecond)
	}
}

func (c *Controller) setConnected(v bool) {
	c.mu.Lock()
	c.connected = v
	c.stats.Connected = v
	if v {
		c.stats.LastError = ""
	} else {
		c.online = false
		c.stats.Online = false
	}
	wasMuted := c.mutedByUs && !c.adActive && c.muteSeg == nil
	c.mu.Unlock()
	// A session that dropped mid-ad left the television silent. Reconnecting
	// is the first chance to undo that.
	if v && wasMuted {
		c.restoreVolumeIfMuted()
	}
}

func (c *Controller) setError(msg string) {
	c.mu.Lock()
	c.stats.LastError = msg
	c.mu.Unlock()
}

// Stats returns a copy of the current session state for the API.
func (c *Controller) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Recent = append([]AdRecord(nil), c.stats.Recent...)
	if c.playing && !c.lastWall.IsZero() && !c.adActive {
		s.Position = c.lastTime + c.now().Sub(c.lastWall).Seconds()
	}
	return s
}

// rawArgs renders an event's payload for logging.
func rawArgs(ev event) string {
	parts := make([]string, 0, len(ev.args))
	for _, a := range ev.args {
		parts = append(parts, string(a))
	}
	return strings.Join(parts, " ")
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x != 0
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
