package lounge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/google/uuid"
)

// Manager owns the set of screen controllers, the discovery loop, and pairing.
// It is the single object the app and API talk to.
type Manager struct {
	cfg      *config.Config
	log      func(string, ...any)
	hc       *http.Client
	sb       *SponsorBlock
	deviceID string

	mu          sync.Mutex
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	running     bool
	discovering bool
	controllers map[string]*ctrlHandle
	discovered  []DiscoveredScreen
}

type ctrlHandle struct {
	ctrl   *Controller
	cancel context.CancelFunc
}

// New builds a manager. The HTTP client deliberately has no overall timeout:
// the event long-poll is a held-open request. Per-stage timeouts on the
// transport keep a dead connection from hanging forever.
func New(cfg *config.Config, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: time.Second,
			MaxIdleConns:          8,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	return &Manager{
		cfg:         cfg,
		log:         log,
		hc:          hc,
		sb:          NewSponsorBlock(cfg.Snapshot().YouTube.Lounge.SponsorBlockAPI),
		deviceID:    uuid.NewString(),
		controllers: map[string]*ctrlHandle{},
	}
}

// Start brings up controllers for every configured device and, if enabled,
// the periodic discovery loop.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.running = true
	m.mu.Unlock()

	// Apply starts controllers and (if enabled + auto-discover) the scan loop.
	m.Apply()
}

// Apply reconciles the running controllers with the current config: it starts
// controllers for newly-added or enabled devices and stops removed ones. Safe
// to call after any change.
func (m *Manager) Apply() {
	lc := m.cfg.Snapshot().YouTube.Lounge

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}

	if !lc.Enabled {
		for id, h := range m.controllers {
			h.cancel()
			delete(m.controllers, id)
		}
		return
	}

	want := map[string]config.LoungeDevice{}
	for _, d := range lc.Devices {
		if d.ScreenID != "" {
			want[d.ScreenID] = d
		}
	}
	// Stop controllers whose device is gone.
	for id, h := range m.controllers {
		if _, ok := want[id]; !ok {
			h.cancel()
			delete(m.controllers, id)
		}
	}
	// Start controllers for new devices.
	for id, d := range want {
		if _, ok := m.controllers[id]; ok {
			continue
		}
		m.startLocked(d)
	}

	// (Re)start the discovery loop if it should run and is not already.
	if lc.AutoDiscover && !m.discovering {
		m.discovering = true
		go func() {
			defer func() {
				m.mu.Lock()
				m.discovering = false
				m.mu.Unlock()
			}()
			m.discoverLoop(m.ctx)
		}()
	}
}

// startLocked launches a controller. Caller holds m.mu.
func (m *Manager) startLocked(d config.LoungeDevice) {
	offset := d.Offset
	opts := func() Options {
		lc := m.cfg.Snapshot().YouTube.Lounge
		return Options{
			SkipAds:           lc.SkipAds,
			MuteAds:           lc.MuteAds,
			ReloadUnskippable: lc.ReloadUnskippable,
			Categories:        lc.SkipCategories,
			MinSkipLength:     lc.MinSkipLength,
			Offset:            offset,
		}
	}
	ctrl := NewController(d.ScreenID, d.Name, m.deviceID, m.hc, m.sb, opts, m.log)
	cctx, ccancel := context.WithCancel(m.ctx)
	m.controllers[d.ScreenID] = &ctrlHandle{ctrl: ctrl, cancel: ccancel}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ctrl.Run(cctx)
	}()
}

// Stop tears down all controllers and waits, briefly, for them to finish.
// The wait is what lets a controller put a television's volume back on the
// way out; without it the process is gone before the command is sent.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.controllers = map[string]*ctrlHandle{}
	m.running = false
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// Discover runs an on-demand DIAL scan and caches the result.
func (m *Manager) Discover(ctx context.Context, window time.Duration) ([]DiscoveredScreen, error) {
	screens, err := Discover(ctx, window)
	if err != nil {
		return nil, err
	}
	sort.Slice(screens, func(i, j int) bool { return screens[i].Name < screens[j].Name })
	m.mu.Lock()
	m.discovered = screens
	m.mu.Unlock()
	return screens, nil
}

// discoverLoop periodically scans and auto-adopts screens that expose a screen
// id (the ones that need no manual code).
func (m *Manager) discoverLoop(ctx context.Context) {
	// A short initial delay lets the network settle after boot.
	sleep(ctx, 10*time.Second)
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		lc := m.cfg.Snapshot().YouTube.Lounge
		if !lc.Enabled || !lc.AutoDiscover {
			return // stop scanning once the feature or auto-discover is turned off
		}
		screens, err := m.Discover(ctx, 3*time.Second)
		if err == nil {
			for _, s := range screens {
				if s.AutoPairable() && !m.isConfigured(s.ScreenID) {
					if err := m.Adopt(s.ScreenID, s.Name, 0); err == nil {
						m.log("lounge: auto-adopted %s (%s)", s.Name, short(s.ScreenID))
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) isConfigured(screenID string) bool {
	for _, d := range m.cfg.Snapshot().YouTube.Lounge.Devices {
		if d.ScreenID == screenID {
			return true
		}
	}
	return false
}

// PairCode pairs via a "Link with TV code", persists the device, and starts it.
func (m *Manager) PairCode(ctx context.Context, code, name string) (config.LoungeDevice, error) {
	screenID, discovered, err := PairWithCode(ctx, m.hc, code)
	if err != nil {
		return config.LoungeDevice{}, err
	}
	if name == "" {
		name = discovered
	}
	if name == "" {
		name = "YouTube device"
	}
	dev := config.LoungeDevice{ScreenID: screenID, Name: name}
	if err := m.persistDevice(dev); err != nil {
		return config.LoungeDevice{}, err
	}
	m.Apply()
	return dev, nil
}

// Adopt persists an already-known screen id (from discovery) and starts it.
func (m *Manager) Adopt(screenID, name string, offset float64) error {
	if screenID == "" {
		return fmt.Errorf("empty screen id")
	}
	if name == "" {
		name = "YouTube device"
	}
	if err := m.persistDevice(config.LoungeDevice{ScreenID: screenID, Name: name, Offset: offset}); err != nil {
		return err
	}
	m.Apply()
	return nil
}

// Forget removes a device and stops its controller.
func (m *Manager) Forget(screenID string) error {
	err := m.cfg.Update(func(c *config.Config) {
		out := c.YouTube.Lounge.Devices[:0]
		for _, d := range c.YouTube.Lounge.Devices {
			if d.ScreenID != screenID {
				out = append(out, d)
			}
		}
		c.YouTube.Lounge.Devices = out
	})
	if err != nil {
		return err
	}
	m.Apply()
	return nil
}

// persistDevice adds or replaces a device in config (idempotent on screen id).
func (m *Manager) persistDevice(dev config.LoungeDevice) error {
	return m.cfg.Update(func(c *config.Config) {
		for i, d := range c.YouTube.Lounge.Devices {
			if d.ScreenID == dev.ScreenID {
				c.YouTube.Lounge.Devices[i] = dev
				return
			}
		}
		c.YouTube.Lounge.Devices = append(c.YouTube.Lounge.Devices, dev)
	})
}

// Segments answers the in-page engine's request for a video's sponsor
// segments. It uses the same categories and minimum length as the Lounge
// engine so a segment is treated the same way on a laptop and on a
// television, and it is the only path by which a browser gets segments: the
// browser asks Orbis, Orbis asks SponsorBlock, and the lookup is cached.
func (m *Manager) Segments(ctx context.Context, videoID string) (any, error) {
	lc := m.cfg.Snapshot().YouTube.Lounge
	segs, err := m.sb.Segments(ctx, videoID, lc.SkipCategories)
	if err != nil {
		return nil, err
	}
	out := make([]Segment, 0, len(segs))
	for _, s := range segs {
		if s.Action == ActionMute || lc.MinSkipLength <= 0 || s.End-s.Start >= lc.MinSkipLength {
			out = append(out, s)
		}
	}
	return map[string]any{"video_id": videoID, "segments": out}, nil
}

// Status is the full picture for the API/UI.
type Status struct {
	Enabled      bool `json:"enabled"`
	AutoDiscover bool `json:"auto_discover"`
	SkipAds      bool `json:"skip_ads"`
	MuteAds      bool `json:"mute_ads"`
	// ReloadUnskippable reloads the content past unskippable mid-rolls.
	ReloadUnskippable bool               `json:"reload_unskippable"`
	Categories        []string           `json:"categories"`
	Devices           []Stats            `json:"devices"`
	Discovered        []DiscoveredScreen `json:"discovered"`
	Coverage          []CoverageRow      `json:"coverage"`
}

// CoverageRow is one honest statement about a device class: which engine covers
// it and whether it needs anything on the client.
type CoverageRow struct {
	DeviceClass string `json:"device_class"`
	Engine      string `json:"engine"`
	NoCA        bool   `json:"no_ca"`
	Covered     bool   `json:"covered"`
	Note        string `json:"note"`
}

// coverageMatrix is fixed: it states plainly what each engine can and cannot do
// so the UI never implies a device is handled when it is not.
var coverageMatrix = []CoverageRow{
	{"Apple TV / smart TV / console / Chromecast", "Lounge remote", true, true,
		"No certificate, nothing installed on the TV. Orbis attaches as a remote, mutes the ad the moment it starts and skips it the moment YouTube allows. Auto-pairs over DIAL when the device allows same-network linking; otherwise a one-time TV code. Every ad is recorded below so you can see it working."},
	{"Desktop / laptop browser", "Response filter + in-page engine", false, true,
		"Needs the Orbis CA trusted on that machine, plus the QUIC block so YouTube falls back to interceptable TCP. Ad structures are removed before the page sees them, an in-page engine drives past anything that still starts, and SponsorBlock segments are skipped with no extension. uBlock Origin remains the simpler no-CA alternative on a laptop."},
	{"TV browser / mobile browser", "Response filter + in-page engine", false, true,
		"The same two layers, in any browser that will trust a CA: the browser on a Samsung or LG set, Safari on iOS, Chrome on Android. A content blocker in the browser is easier where one exists."},
	{"Mobile YouTube app", "none", true, false,
		"Cannot be filtered from the network: the app pins certificates and ignores user CAs, and is not a castable screen. Casting from the app to a TV puts the TV under the Lounge engine. Otherwise, a patched client (ReVanced/uYou)."},
	{"Server-side stitched ads", "none", true, false,
		"When YouTube muxes the ad into the same stream as the video, no filter anywhere can separate them. Orbis counts how often this happens so a silent filter and an unfilterable stream are not mistaken for each other."},
}

func (m *Manager) Status() Status {
	lc := m.cfg.Snapshot().YouTube.Lounge
	m.mu.Lock()
	devs := make([]Stats, 0, len(m.controllers))
	for _, h := range m.controllers {
		devs = append(devs, h.ctrl.Stats())
	}
	discovered := append([]DiscoveredScreen(nil), m.discovered...)
	m.mu.Unlock()

	// Devices configured but not yet started (manager stopped) still show up.
	seen := map[string]bool{}
	for _, d := range devs {
		seen[d.ScreenID] = true
	}
	for _, d := range lc.Devices {
		if !seen[d.ScreenID] {
			devs = append(devs, Stats{ScreenID: d.ScreenID, Name: d.Name})
		}
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })

	return Status{
		Enabled:           lc.Enabled,
		AutoDiscover:      lc.AutoDiscover,
		SkipAds:           lc.SkipAds,
		MuteAds:           lc.MuteAds,
		ReloadUnskippable: lc.ReloadUnskippable,
		Categories:        lc.SkipCategories,
		Devices:           devs,
		Discovered:        discovered,
		Coverage:          coverageMatrix,
	}
}
