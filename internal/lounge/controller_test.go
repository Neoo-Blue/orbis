package lounge

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSender records every command the controller emits.
type fakeSender struct {
	mu   sync.Mutex
	cmds []queuedCmd
}

func (f *fakeSender) sendCommand(_ context.Context, name string, args map[string]string) error {
	f.mu.Lock()
	f.cmds = append(f.cmds, queuedCmd{name: name, args: args})
	f.mu.Unlock()
	return nil
}

func (f *fakeSender) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if c.name == name {
			n++
		}
	}
	return n
}

func (f *fakeSender) last(name string) (queuedCmd, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.cmds) - 1; i >= 0; i-- {
		if f.cmds[i].name == name {
			return f.cmds[i], true
		}
	}
	return queuedCmd{}, false
}

// waitFor polls until name has been sent at least n times or the deadline
// passes; the send loop is asynchronous by design.
func (f *fakeSender) waitFor(t *testing.T, name string, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.count(name) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("command %s sent %d time(s), wanted at least %d; all: %+v", name, f.count(name), n, f.cmds)
}

// settle waits for the command queue to drain so counts are stable.
func (c *Controller) settle() {
	for i := 0; i < 200 && len(c.cmds) > 0; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *clock) now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.t
}

func (k *clock) advance(d time.Duration) {
	k.mu.Lock()
	k.t = k.t.Add(d)
	k.mu.Unlock()
}

func newTestController(t *testing.T, opts Options) (*Controller, *fakeSender, *clock) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	k := &clock{t: time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)}
	fake := &fakeSender{}
	c := NewController("screen-1", "Living room TV", "dev-1", nil, nil,
		func() Options { return opts }, func(string, ...any) {})
	c.send = fake
	c.now = k.now
	c.ctx = ctx
	c.connected = true
	c.online = true
	go c.sendLoop(ctx)
	return c, fake, k
}

func ev(typ string, payload map[string]any) event {
	if payload == nil {
		return event{typ: typ}
	}
	raw, _ := json.Marshal(payload)
	return event{typ: typ, args: []json.RawMessage{raw}}
}

func adPlaying(id string, dur float64, skippable, bumper bool) event {
	return ev("adPlaying", map[string]any{
		"adVideoId": id, "contentVideoId": "content-1",
		"duration": dur, "isSkippable": skippable, "isBumper": bumper,
	})
}

func TestAdWithNoEndEventIsClosedByDeadline(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})

	c.handleEvent(adPlaying("ad-A", 30, true, false))
	fake.waitFor(t, "setVolume", 1)
	fake.waitFor(t, "skipAd", 1)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "0" {
		t.Fatalf("first setVolume should mute, got %+v", cmd)
	}

	// Well inside the ad's own duration: still active, retrying.
	k.advance(20 * time.Second)
	c.tick()
	if !c.Stats().AdActive {
		t.Fatal("ad should still be active at 20s of a 30s ad")
	}

	// Past duration + grace with no end event: closed as lost, volume back.
	k.advance(25 * time.Second)
	c.tick()
	st := c.Stats()
	if st.AdActive {
		t.Fatal("ad should have been closed by the deadline")
	}
	// It ran past its own length, so it played; nothing was saved.
	if st.AdsLost != 0 || st.AdsSkipped != 0 || st.SecondsSaved != 0 {
		t.Fatalf("expected 0 lost / 0 skipped / nothing saved, got %+v", st)
	}
	if len(st.Recent) != 1 || st.Recent[0].Outcome != "played" || !strings.HasPrefix(st.Recent[0].Reason, "no end event") {
		t.Fatalf("expected a played-by-deadline record, got %+v", st.Recent)
	}
	fake.waitFor(t, "setVolume", 2)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "100" {
		t.Fatalf("volume should be restored to 100, got %+v", cmd)
	}

	// And nothing keeps retrying afterwards.
	before := fake.count("skipAd")
	for i := 0; i < 5; i++ {
		k.advance(time.Second)
		c.tick()
	}
	c.settle()
	if fake.count("skipAd") != before {
		t.Fatalf("skipAd kept being sent after the ad was closed: %d -> %d", before, fake.count("skipAd"))
	}
}

func TestSkipRetriesAreBounded(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true})
	// An ad whose duration is never reported and never ends by itself.
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "1", "isSkipEnabled": "false"}))
	for i := 0; i < 80; i++ {
		k.advance(time.Second)
		c.tick()
	}
	c.settle()
	if n := fake.count("skipAd"); n > maxAdTries {
		t.Fatalf("skipAd sent %d times, cap is %d", n, maxAdTries)
	}
	// The unknown-duration limit eventually closes it, as lost: nobody knows
	// how long it was.
	k.advance(adUnknownLimit)
	c.tick()
	st := c.Stats()
	if st.AdActive || st.AdsLost != 1 || st.Recent[0].Outcome != "lost" {
		t.Fatalf("ad with unknown duration should have been closed as lost: %+v", st)
	}
}

func TestAdPodProducesOneRecordPerAd(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})

	c.handleEvent(adPlaying("ad-A", 6, false, true))
	k.advance(6 * time.Second)
	c.handleEvent(adPlaying("ad-B", 15, true, false))
	k.advance(2 * time.Second)
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	c.settle()

	st := c.Stats()
	if st.AdsHandled != 2 {
		t.Fatalf("pod of two ads should count 2, got %d", st.AdsHandled)
	}
	if len(st.Recent) != 2 {
		t.Fatalf("expected 2 records, got %+v", st.Recent)
	}
	// Newest first.
	if st.Recent[0].AdVideoID != "ad-B" || st.Recent[0].Outcome != "skipped" {
		t.Fatalf("second ad should be recorded as skipped: %+v", st.Recent[0])
	}
	if st.Recent[1].AdVideoID != "ad-A" || st.Recent[1].Reason != "next ad in pod" || !st.Recent[1].Bumper {
		t.Fatalf("first ad should be closed by the pod: %+v", st.Recent[1])
	}
	if st.AdsSkipped != 1 {
		t.Fatalf("only the second ad was cut short, got skipped=%d", st.AdsSkipped)
	}
	// Muted once on the way in, restored once on the way out: the pod does
	// not un-mute between ads.
	if n := fake.count("setVolume"); n != 2 {
		t.Fatalf("expected mute + restore (2 setVolume), got %d: %+v", n, fake.cmds)
	}
}

func TestScreenDisconnectClearsAdAndRestoresVolume(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})
	c.handleEvent(adPlaying("ad-A", 30, true, false))
	fake.waitFor(t, "setVolume", 1)
	k.advance(3 * time.Second)

	c.handleEvent(ev("loungeScreenDisconnected", nil))
	st := c.Stats()
	if st.AdActive || st.Online {
		t.Fatalf("disconnect should clear the ad and mark the screen offline: %+v", st)
	}
	fake.waitFor(t, "setVolume", 2)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "100" {
		t.Fatalf("volume should be restored on disconnect, got %+v", cmd)
	}
	if st.Recent[0].Reason != "screen disconnected" || st.Recent[0].Outcome != "abandoned" {
		t.Fatalf("a screen that went away is abandoned, not skipped: %+v", st.Recent[0])
	}
	if st.AdsSkipped != 0 || st.SecondsSaved != 0 {
		t.Fatalf("an abandoned ad must not be credited as saved time: %+v", st)
	}
}

func TestNowPlayingEarlyInAnAdDoesNotEndIt(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})
	c.handleEvent(adPlaying("ad-A", 15, false, false))
	fake.waitFor(t, "setVolume", 1)
	k.advance(2 * time.Second)
	// The television reports nowPlaying two seconds in, naming the content
	// video but saying an ad is playing (the live payload of 2026-09-01).
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "content-1", "adState": "1", "adVideoId": "ad-A", "duration": "15.041"}))
	if !c.Stats().AdActive {
		t.Fatal("nowPlaying 2s into a 15s unskippable ad must not end it (that un-muted every unskippable ad)")
	}
	// One that says nothing about ads does not end it either.
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "content-1", "state": "1", "currentTime": "40"}))
	if !c.Stats().AdActive {
		t.Fatal("a nowPlaying with no ad state is not evidence the ad ended")
	}
	// The ad itself reported as now playing is not the end either.
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "ad-A", "state": "1"}))
	if !c.Stats().AdActive {
		t.Fatal("nowPlaying for the ad's own id must not end it")
	}
	// Past the ad's length it is.
	k.advance(13 * time.Second)
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "content-1", "state": "1", "currentTime": "40"}))
	st := c.Stats()
	if st.AdActive || st.Recent[0].Outcome != "played" {
		t.Fatalf("nowPlaying at the ad's end should close it as played: %+v", st.Recent)
	}
}

func TestNowPlayingDifferentVideoAbandonsAd(t *testing.T) {
	c, _, k := newTestController(t, Options{SkipAds: true})
	c.handleEvent(adPlaying("ad-A", 30, true, false))
	k.advance(3 * time.Second)
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "content-2", "state": "1"}))
	st := c.Stats()
	if st.AdActive || st.Recent[0].Outcome != "abandoned" {
		t.Fatalf("viewer changing video mid-ad is abandoned: active=%v %+v", st.AdActive, st.Recent)
	}
}

func TestDeadlinePastFullLengthIsPlayedNotLost(t *testing.T) {
	c, _, k := newTestController(t, Options{SkipAds: true})
	c.handleEvent(adPlaying("ad-A", 15, false, true))
	k.advance(15*time.Second + adEndGrace + time.Second)
	c.tick()
	st := c.Stats()
	if st.AdActive || st.Recent[0].Outcome != "played" || st.AdsLost != 0 {
		t.Fatalf("an ad that ran its whole length and was closed by the deadline played: %+v", st.Recent)
	}
}

func TestShutdownRestoreSendsDirectly(t *testing.T) {
	c, fake, _ := newTestController(t, Options{MuteAds: true})
	c.handleEvent(adPlaying("ad-A", 30, false, false))
	fake.waitFor(t, "setVolume", 1)
	// Simulate the session going away: nothing is connected and the send
	// loop's context is gone. The restore must still reach the sender.
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	c.restoreVolumeNow()
	if cmd, ok := fake.last("setVolume"); !ok || cmd.args["volume"] != "100" {
		t.Fatalf("shutdown restore did not send: %+v", fake.cmds)
	}
	if c.Stats().AdActive {
		// The ad record is left as is; only the volume matters on the way out.
		return
	}
}

func TestAdInsideMuteSegmentKeepsSoundOff(t *testing.T) {
	c, fake, k := newTestController(t, Options{Categories: []string{"sponsor"}, MuteAds: true, SkipAds: true})
	c.mu.Lock()
	c.segments = []Segment{{Category: "sponsor", Action: ActionMute, Start: 10, End: 60}}
	c.mu.Unlock()
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "12"}))
	c.tick()
	fake.waitFor(t, "setVolume", 1) // muted for the segment
	// An ad starts and ends while still inside the segment.
	c.handleEvent(adPlaying("ad-A", 6, false, true))
	k.advance(2 * time.Second)
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	c.settle()
	if n := fake.count("setVolume"); n != 1 {
		t.Fatalf("sound must stay off inside the mute segment across an ad; got %d setVolume: %+v", n, fake.cmds)
	}
	if st := c.Stats(); st.SegmentsMuted != 1 {
		t.Fatalf("mute segment counted once, got %d", st.SegmentsMuted)
	}
}

func TestLoungeStatusReportsScreenPresence(t *testing.T) {
	c, _, _ := newTestController(t, Options{})
	devices := `[{"type":"REMOTE_CONTROL","name":"Orbis"},{"type":"LOUNGE_SCREEN","name":"YouTube on TV"}]`
	c.handleEvent(ev("loungeStatus", map[string]any{"devices": devices}))
	if !c.Stats().Online {
		t.Fatal("a LOUNGE_SCREEN in the device list means the screen is online")
	}
	c.handleEvent(ev("loungeStatus", map[string]any{"devices": `[{"type":"REMOTE_CONTROL"}]`}))
	if c.Stats().Online {
		t.Fatal("no screen in the device list means offline")
	}
}

func TestPausedAdExtendsDeadline(t *testing.T) {
	c, _, k := newTestController(t, Options{SkipAds: true})
	c.handleEvent(adPlaying("ad-A", 15, false, false))
	k.advance(5 * time.Second)
	// The pause report carries the ad's own duration: it is the ad that is paused.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "2", "currentTime": "5", "duration": "15.041"}))
	k.advance(60 * time.Second)
	c.tick()
	if !c.Stats().AdActive {
		t.Fatal("a paused ad must not expire on wall-clock time")
	}
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "5", "duration": "15.041"}))
	k.advance(5 * time.Second) // 10s of actual ad time
	c.tick()
	if !c.Stats().AdActive {
		t.Fatal("resumed ad at 10s of 15s should still be active")
	}
	k.advance(20 * time.Second) // 30s of ad time, past 15s + grace
	c.tick()
	if c.Stats().AdActive {
		t.Fatal("resumed ad should expire once its adjusted deadline passes")
	}
}

func TestSkippedAdCountsSecondsSaved(t *testing.T) {
	c, _, k := newTestController(t, Options{SkipAds: true})
	c.handleEvent(adPlaying("ad-A", 30, true, false))
	k.advance(2 * time.Second)
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	st := c.Stats()
	if st.AdsSkipped != 1 || st.SecondsSaved < 27 || st.SecondsSaved > 29 {
		t.Fatalf("expected ~28s saved from a 30s ad cut at 2s, got %+v", st)
	}
	if st.Recent[0].Watched != 2 {
		t.Fatalf("watched should be 2.0s, got %v", st.Recent[0].Watched)
	}
}

func TestMuteSegmentMutesThenRestores(t *testing.T) {
	c, fake, k := newTestController(t, Options{Categories: []string{"sponsor"}})
	c.mu.Lock()
	c.videoID = "vid"
	c.segments = []Segment{{Category: "sponsor", Action: ActionMute, Start: 10, End: 20}}
	c.mu.Unlock()

	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "9"}))
	k.advance(3 * time.Second) // position 12
	c.tick()
	fake.waitFor(t, "setVolume", 1)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "0" {
		t.Fatalf("should mute inside a mute segment, got %+v", cmd)
	}
	if n := fake.count("seekTo"); n != 0 {
		t.Fatalf("a mute segment must not seek, got %d seekTo", n)
	}
	k.advance(10 * time.Second) // position 22
	c.tick()
	fake.waitFor(t, "setVolume", 2)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "100" {
		t.Fatalf("should restore after the segment, got %+v", cmd)
	}
	if st := c.Stats(); st.SegmentsMuted != 1 {
		t.Fatalf("expected 1 muted segment, got %+v", st)
	}
}

func TestSkipSegmentSeeksPastIt(t *testing.T) {
	c, fake, k := newTestController(t, Options{Categories: []string{"sponsor"}, Offset: 0.5})
	c.mu.Lock()
	c.segments = []Segment{{Category: "sponsor", Action: ActionSkip, Start: 10, End: 20}}
	c.mu.Unlock()
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "9"}))
	k.advance(2 * time.Second)
	c.tick()
	fake.waitFor(t, "seekTo", 1)
	if cmd, _ := fake.last("seekTo"); cmd.args["newTime"] != "20.500" {
		t.Fatalf("seek target should be end + offset, got %+v", cmd)
	}
}

func TestViewerVolumeIsNotOverwrittenByOurMute(t *testing.T) {
	c, fake, _ := newTestController(t, Options{MuteAds: true})
	c.handleEvent(ev("onVolumeChanged", map[string]any{"volume": "35"}))
	c.handleEvent(adPlaying("ad-A", 10, false, false))
	// The TV echoes our own mute back; it must not become the restore level.
	c.handleEvent(ev("onVolumeChanged", map[string]any{"volume": "0"}))
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	fake.waitFor(t, "setVolume", 2)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "35" {
		t.Fatalf("restore should return to the viewer's 35, got %+v", cmd)
	}
}

// The sequence a television actually sends when a skip takes effect: no
// adState=0, no nowPlaying, just the content's own state reports. Taken from
// the live log of 2026-09-01 22:58:13.
func TestInstantSkipIsRecognisedFromContentStateChange(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})
	// Content had been playing: the engine knows its length.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "330", "duration": "626.721"}))
	c.handleEvent(adPlaying("ad-A", 45.061, true, false))
	fake.waitFor(t, "setVolume", 1)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1081", "currentTime": "0.01", "duration": "45.061"}))
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "1082", "isSkipEnabled": "false"}))
	k.advance(300 * time.Millisecond)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "3", "currentTime": "332.193", "duration": "626.721"}))
	st := c.Stats()
	if st.AdActive {
		t.Fatal("content buffering with the content's duration means the ad is gone")
	}
	if st.Recent[0].Outcome != "skipped" || st.SecondsSaved < 44 {
		t.Fatalf("an ad cut at 0.3s of 45s is skipped with ~45s saved: %+v saved=%v", st.Recent[0], st.SecondsSaved)
	}
	fake.waitFor(t, "setVolume", 2)
	if cmd, _ := fake.last("setVolume"); cmd.args["volume"] != "100" {
		t.Fatalf("volume must come back the moment content resumes, got %+v", cmd)
	}
}

// A pre-roll: the content has never played, so its length is unknown. The
// content starting is still recognisable because its duration is not the ad's.
func TestPreRollSkipIsRecognisedWithoutKnownContentDuration(t *testing.T) {
	c, _, k := newTestController(t, Options{SkipAds: true, MuteAds: true})
	c.handleEvent(adPlaying("ad-A", 15.041, true, false))
	k.advance(200 * time.Millisecond)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "-1", "currentTime": "0", "duration": "1945.101"}))
	if !c.Stats().AdActive {
		t.Fatal("an unstarted report alone is not the content playing (the next ad loads the same way)")
	}
	c.handleEvent(ev("onStateChange", map[string]any{"state": "3", "currentTime": "0.041", "duration": "1945.101"}))
	if c.Stats().AdActive {
		t.Fatal("content buffering with a non-ad duration should end the ad")
	}
}

// The next ad in a pod announces itself with onStateChange too, in the
// ad-playing state or unstarted, and must not be mistaken for content.
func TestNextAdLoadingDoesNotEndCurrentAd(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true})
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "10", "duration": "626.721"}))
	c.handleEvent(adPlaying("ad-A", 6.041, false, true))
	fake.waitFor(t, "setVolume", 1)
	k.advance(6 * time.Second)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1081", "currentTime": "0", "duration": "15", "seekableEndTime": "15.015"}))
	c.handleEvent(ev("onStateChange", map[string]any{"state": "-1", "currentTime": "0", "duration": "15.041"}))
	if !c.Stats().AdActive {
		t.Fatal("the next ad loading must not close the current one as content")
	}
	c.handleEvent(adPlaying("ad-B", 15.041, true, false))
	c.settle()
	if n := fake.count("setVolume"); n != 1 {
		t.Fatalf("no un-mute between ads in a pod; got %d setVolume: %+v", n, fake.cmds)
	}
	st := c.Stats()
	if st.AdsHandled != 2 || st.Recent[0].Reason != "next ad in pod" {
		t.Fatalf("pod handling: %+v", st)
	}
}

func TestVideoIdFromQualityEventLoadsSegments(t *testing.T) {
	c, _, _ := newTestController(t, Options{Categories: []string{"sponsor"}})
	c.handleEvent(ev("onVideoQualityChanged", map[string]any{"videoId": "PkHhHTwxN-0", "qualityLevel": "1080"}))
	if c.Stats().VideoID != "PkHhHTwxN-0" {
		t.Fatal("the quality event names the video and must be used")
	}
}

func TestNowPlayingWithAdStateStartsAMissedAd(t *testing.T) {
	c, fake, _ := newTestController(t, Options{SkipAds: true, MuteAds: true})
	// First thing heard after a reconnect: an ad is already on screen.
	c.handleEvent(ev("nowPlaying", map[string]any{
		"videoId": "content-1", "adState": "1", "adVideoId": "ad-Z", "duration": "30.061", "isSkippable": "true",
	}))
	st := c.Stats()
	if !st.AdActive || st.AdsHandled != 1 {
		t.Fatalf("an ad reported by nowPlaying must be handled: %+v", st)
	}
	fake.waitFor(t, "setVolume", 1)
	fake.waitFor(t, "skipAd", 1)
	// And a clear ad state ends it.
	c.handleEvent(ev("nowPlaying", map[string]any{"videoId": "content-1", "adState": "0"}))
	if c.Stats().AdActive {
		t.Fatal("nowPlaying with adState=0 ends the ad")
	}
}

func TestUnskippableMidRollIsReloadedPast(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true, ReloadUnskippable: true})
	// Content playing at 330s of a 626s video.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "330", "duration": "626.721"}))
	k.advance(2 * time.Second)
	// The ad-playing state arrives first, then the ad is named.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1081", "currentTime": "0", "duration": "30", "seekableEndTime": "30.061"}))
	if st := c.Stats(); !st.AdActive || st.AdsHandled != 1 {
		t.Fatalf("state 1081 should open the ad early: %+v", st)
	}
	c.handleEvent(adPlaying("ad-U", 30.061, false, false))
	fake.waitFor(t, "setPlaylist", 1)
	cmd, _ := fake.last("setPlaylist")
	if cmd.args["videoId"] != "content-1" || cmd.args["currentTime"] != "332.0" {
		t.Fatalf("reload should resume the content where it was: %+v", cmd.args)
	}
	// The player comes back with the content at that position.
	k.advance(2 * time.Second)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "3", "currentTime": "332.0", "duration": "626.721"}))
	st := c.Stats()
	if st.AdActive || st.Reloads != 1 || st.Recent[0].Outcome != "skipped" || !st.Recent[0].Reloaded {
		t.Fatalf("reloaded ad should be closed as skipped: active=%v %+v", st.AdActive, st.Recent[0])
	}
	if n := fake.count("setPlaylist"); n != 1 {
		t.Fatalf("exactly one reload per ad, got %d", n)
	}
}

func TestReloadIsNotTriedForPreRollsBumpersOrSkippable(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true, ReloadUnskippable: true})
	// Pre-roll: content has not started.
	c.handleEvent(adPlaying("ad-P", 30, false, false))
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	// Mid-roll bumper.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "100", "duration": "600"}))
	k.advance(time.Second)
	c.handleEvent(adPlaying("ad-B", 6, false, true))
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	// Mid-roll skippable: skipAd handles it.
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "200", "duration": "600"}))
	k.advance(time.Second)
	c.handleEvent(adPlaying("ad-S", 30, true, false))
	c.settle()
	if n := fake.count("setPlaylist"); n != 0 {
		t.Fatalf("no reload for pre-rolls, bumpers or skippable ads; got %d: %+v", n, fake.cmds)
	}
	if fake.count("skipAd") == 0 {
		t.Fatal("the skippable ad should still get skipAd")
	}
}

func TestVideoThatServesAdAfterReloadIsLeftAlone(t *testing.T) {
	c, fake, k := newTestController(t, Options{SkipAds: true, MuteAds: true, ReloadUnskippable: true})
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "100", "duration": "600"}))
	k.advance(time.Second)
	c.handleEvent(adPlaying("ad-U1", 30, false, false))
	fake.waitFor(t, "setPlaylist", 1)
	// The player reloads and serves an ad again straight away.
	k.advance(3 * time.Second)
	c.handleEvent(adPlaying("ad-U2", 30, false, false))
	c.settle()
	st := c.Stats()
	if st.ReloadsResisted != 1 {
		t.Fatalf("the second ad after a reload marks the video as resisting: %+v", st)
	}
	if st.Recent[0].Outcome == "skipped" {
		t.Fatalf("the reloaded ad was not skipped when another ad came back: %+v", st.Recent[0])
	}
	// A later mid-roll on the same video is not reloaded again.
	c.handleEvent(ev("onAdStateChange", map[string]any{"adState": "0"}))
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "300", "duration": "600"}))
	k.advance(40 * time.Second)
	c.handleEvent(adPlaying("ad-U3", 30, false, false))
	c.settle()
	if n := fake.count("setPlaylist"); n != 1 {
		t.Fatalf("a resisting video must not be reloaded again; got %d reloads", n)
	}
}

func TestAdPositionReportsDoNotMoveTheContentPosition(t *testing.T) {
	c, _, k := newTestController(t, Options{})
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1", "currentTime": "500", "duration": "1000"}))
	k.advance(time.Second)
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1081", "currentTime": "0", "duration": "15"}))
	c.handleEvent(ev("onStateChange", map[string]any{"state": "-1", "currentTime": "0", "duration": "15.041"}))
	c.handleEvent(adPlaying("ad-A", 15.041, false, false))
	c.handleEvent(ev("onStateChange", map[string]any{"state": "1081", "currentTime": "0.012", "duration": "15.041"}))
	c.mu.Lock()
	pos := c.contentPos
	last := c.lastTime
	c.mu.Unlock()
	if pos < 500.5 || pos > 502 || last < 500 {
		t.Fatalf("content position must survive the ad's own reports: contentPos=%v lastTime=%v", pos, last)
	}
}
