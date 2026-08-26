package lounge

import (
	"context"
	"net/http"
	"strconv"
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

// Stats is the observable state of one device session.
type Stats struct {
	ScreenID        string  `json:"screen_id"`
	Name            string  `json:"name"`
	Connected       bool    `json:"connected"`
	VideoID         string  `json:"video_id"`
	Position        float64 `json:"position"`
	AdActive        bool    `json:"ad_active"`
	AdsHandled      int     `json:"ads_handled"`
	SegmentsSkipped int     `json:"segments_skipped"`
	SegmentsLoaded  int     `json:"segments_loaded"`
	LastError       string  `json:"last_error,omitempty"`
	LastEvent       string  `json:"last_event,omitempty"`
}

// Controller owns one screen: it keeps a live Lounge session, tracks playback,
// and acts on ads and sponsor segments.
type Controller struct {
	screenID string
	name     string
	sess     *Session
	sb       *SponsorBlock
	opts     func() Options
	log      func(string, ...any)

	ctx context.Context

	mu        sync.Mutex
	connected bool
	videoID   string
	segments  []Segment
	lastTime  float64
	lastWall  time.Time
	playing   bool
	adActive  bool
	lastVol   int
	stats     Stats
}

// NewController wires a controller for one screen. deviceID must be stable for
// the life of the process so the TV recognises reconnections as the same remote.
func NewController(screenID, name, deviceID string, hc *http.Client, sb *SponsorBlock, opts func() Options, log func(string, ...any)) *Controller {
	if log == nil {
		log = func(string, ...any) {}
	}
	c := &Controller{
		screenID: screenID,
		name:     name,
		sb:       sb,
		opts:     opts,
		log:      log,
		lastVol:  100,
		stats:    Stats{ScreenID: screenID, Name: name},
	}
	c.sess = newSession(screenID, deviceID, "Orbis", hc)
	c.sess.onEvent = c.handleEvent
	return c
}

// Run maintains the session until ctx is cancelled, reconnecting with backoff.
func (c *Controller) Run(ctx context.Context) {
	c.ctx = ctx
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
		c.setConnected(false)
		sleep(ctx, backoff)
	}
}

func (c *Controller) handleEvent(ev event) {
	c.mu.Lock()
	c.stats.LastEvent = ev.typ
	c.mu.Unlock()

	switch ev.typ {
	case "nowPlaying":
		obj := ev.object()
		vid := asString(obj["videoId"])
		// A new video always means no ad is on screen.
		c.clearAd()
		if t, ok := asFloat(obj["currentTime"]); ok {
			c.updatePosition(t, asString(obj["state"]) == "1")
		}
		if vid != "" {
			c.onVideo(vid)
		}
	case "onStateChange":
		obj := ev.object()
		state := asString(obj["state"])
		if t, ok := asFloat(obj["currentTime"]); ok {
			c.updatePosition(t, state == "1")
		}
	case "onAdStateChange":
		obj := ev.object()
		adState := asString(obj["adState"])
		if adState == "" || adState == "0" || adState == "-1" {
			c.clearAd()
		} else {
			c.onAd(truthy(obj["isSkipEnabled"]) || truthy(obj["isSkippable"]))
		}
	case "adPlaying":
		obj := ev.object()
		c.onAd(truthy(obj["isSkippable"]) || truthy(obj["isSkipEnabled"]))
	case "onAdCancel", "onAdEnd":
		c.clearAd()
	case "onVolumeChanged":
		obj := ev.object()
		if v, ok := asFloat(obj["volume"]); ok {
			c.mu.Lock()
			if !c.adActive {
				c.lastVol = int(v)
			}
			c.mu.Unlock()
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
	}
	c.mu.Unlock()
	if same {
		return
	}

	opts := c.opts()
	if len(opts.Categories) == 0 {
		return
	}
	go func() {
		segs, err := c.sb.Segments(c.ctx, videoID, opts.Categories)
		if err != nil {
			c.log("lounge: sponsorblock lookup failed for %s: %v", videoID, err)
			return
		}
		// Drop segments shorter than the minimum: not worth a jarring seek.
		if opts.MinSkipLength > 0 {
			filtered := segs[:0]
			for _, s := range segs {
				if s.End-s.Start >= opts.MinSkipLength {
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

func (c *Controller) onAd(skippable bool) {
	c.mu.Lock()
	firstSeen := !c.adActive
	c.adActive = true
	c.stats.AdActive = true
	if firstSeen {
		c.stats.AdsHandled++
	}
	mute := c.opts().MuteAds
	c.mu.Unlock()
	if firstSeen && mute {
		c.command("setVolume", map[string]string{"volume": "0", "delta": "0"})
	}
	if skippable && c.opts().SkipAds {
		c.command("skipAd", nil)
	}
}

func (c *Controller) clearAd() {
	c.mu.Lock()
	wasAd := c.adActive
	c.adActive = false
	c.stats.AdActive = false
	vol := c.lastVol
	mute := c.opts().MuteAds
	c.mu.Unlock()
	if wasAd && mute {
		c.command("setVolume", map[string]string{"volume": strconv.Itoa(vol), "delta": "0"})
	}
}

func (c *Controller) updatePosition(t float64, playing bool) {
	c.mu.Lock()
	c.lastTime = t
	c.lastWall = time.Now()
	c.playing = playing
	c.stats.Position = t
	c.mu.Unlock()
}

func (c *Controller) currentPos() (pos float64, playing, adActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.playing && !c.lastWall.IsZero() {
		return c.lastTime + time.Since(c.lastWall).Seconds(), c.playing, c.adActive
	}
	return c.lastTime, c.playing, c.adActive
}

// tickLoop interpolates position between events and acts every second: it seeks
// past sponsor segments and keeps hammering skipAd while an ad is on screen (an
// ad becomes skippable a few seconds in, and the server ignores an early skip).
func (c *Controller) tickLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		pos, playing, adActive := c.currentPos()
		opts := c.opts()

		if adActive {
			if opts.SkipAds {
				c.command("skipAd", nil)
			}
			continue
		}
		if !playing {
			continue
		}

		c.mu.Lock()
		seg := SegmentAt(c.segments, pos)
		c.mu.Unlock()
		if seg == nil {
			continue
		}
		target := seg.End + opts.Offset
		c.command("seekTo", map[string]string{"newTime": strconv.FormatFloat(target, 'f', 3, 64)})
		c.mu.Lock()
		c.lastTime = target
		c.lastWall = time.Now()
		c.stats.SegmentsSkipped++
		c.mu.Unlock()
		c.log("lounge: %s skipped %s segment [%.0f-%.0f]", c.name, seg.Category, seg.Start, seg.End)
	}
}

func (c *Controller) command(cmd string, args map[string]string) {
	c.mu.Lock()
	connected := c.connected
	c.mu.Unlock()
	if !connected {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, 8*time.Second)
	defer cancel()
	if err := c.sess.sendCommand(ctx, cmd, args); err != nil && c.ctx.Err() == nil {
		c.log("lounge: %s command %s failed: %v", c.name, cmd, err)
	}
}

func (c *Controller) setConnected(v bool) {
	c.mu.Lock()
	c.connected = v
	c.stats.Connected = v
	if v {
		c.stats.LastError = ""
	}
	c.mu.Unlock()
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
	if c.playing && !c.lastWall.IsZero() && !c.adActive {
		s.Position = c.lastTime + time.Since(c.lastWall).Seconds()
	}
	return s
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
