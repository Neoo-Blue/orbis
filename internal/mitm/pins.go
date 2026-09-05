package mitm

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Pinned-app bypass.
//
// An app that pins its certificate, or a device that never trusted the CA,
// rejects the leaf the proxy presents: the handshake fails and the app gets
// nothing, over and over. Left alone that is strictly worse than not
// filtering, because the app is broken rather than merely showing ads. So
// the proxy learns. A client that rejects the certificate for a host twice
// in a short window is spliced straight through to that host for a while,
// and the same for a whole domain once several of its hosts have been
// rejected, which is what a video CDN with a different name per node needs.
// The bypass expires, so a device that later installs the certificate is
// picked up again without anyone touching anything.

const (
	pinWindow      = 5 * time.Minute
	pinHostFails   = 2
	pinDomainFails = 5
	// A bypass lasts a day and survives restarts (see SetStore). An hour
	// meant the pinned YouTube app on a phone broke for a few seconds every
	// hour while the tracker relearned what it already knew.
	pinBypassFor  = 24 * time.Hour
	pinMaxEntries = 4096
	pinPruneEvery = 200
	// pinHandshakeTimeout is how long a client that has already sent its
	// ClientHello gets to finish the handshake. A browser finishes in well
	// under a second on a LAN; a pinned app that goes silent after seeing
	// our certificate is recognised in this many seconds instead of hanging
	// for twenty and being written off as a network hiccup.
	pinHandshakeTimeout = 6 * time.Second
)

// pinTracker keeps rejection counts and active bypasses per (client, name).
type pinTracker struct {
	mu      sync.Mutex
	entries map[pinKey]*pinEntry
	ops     int
	// save persists a bypass when one trips, so a restart does not make a
	// pinned app fail again before the tracker relearns it. Optional.
	save func(client, name string, until time.Time)
}

// PinStore is what the tracker needs to remember bypasses across restarts.
type PinStore interface {
	PinBypasses() ([]Bypass, error)
	SavePinBypass(client, name string, until time.Time) error
}

// SetStore loads persisted bypasses and arranges for new ones to be saved.
func (t *pinTracker) SetStore(st PinStore, now time.Time) int {
	if st == nil {
		return 0
	}
	saved, err := st.PinBypasses()
	if err != nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = map[pinKey]*pinEntry{}
	}
	n := 0
	for _, b := range saved {
		addr, err := netip.ParseAddr(b.Client)
		if err != nil || !now.Before(b.Until) {
			continue
		}
		t.entries[pinKey{addr, strings.ToLower(b.Name)}] = &pinEntry{fails: b.Fails, first: now, until: b.Until}
		n++
	}
	t.save = func(client, name string, until time.Time) { _ = st.SavePinBypass(client, name, until) }
	return n
}

type pinKey struct {
	client netip.Addr
	name   string // a host, or a registrable domain prefixed with "."
}

type pinEntry struct {
	fails int
	first time.Time
	until time.Time // bypass expiry; zero when not bypassed
}

// Bypass is one active pinned-app bypass, for the API.
type Bypass struct {
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Until  time.Time `json:"until"`
	Fails  int       `json:"fails"`
}

// bypassed reports whether connections from client to host are currently
// spliced because the client keeps rejecting the certificate.
func (t *pinTracker) bypassed(client netip.Addr, host string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range pinKeys(client, host) {
		if e := t.entries[k]; e != nil && now.Before(e.until) {
			return true
		}
	}
	return false
}

// fail records one rejection and reports whether it just triggered a bypass,
// and for which name.
func (t *pinTracker) fail(client netip.Addr, host string, now time.Time) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = map[pinKey]*pinEntry{}
	}
	t.ops++
	if t.ops%pinPruneEvery == 0 || len(t.entries) >= pinMaxEntries {
		t.pruneLocked(now)
	}
	keys := pinKeys(client, host)
	limits := []int{pinHostFails, pinDomainFails}
	for i, k := range keys {
		e := t.entries[k]
		if e == nil || now.Sub(e.first) > pinWindow {
			e = &pinEntry{first: now}
			t.entries[k] = e
		}
		e.fails++
		if e.fails >= limits[i] && now.After(e.until) {
			e.until = now.Add(pinBypassFor)
			if t.save != nil {
				t.save(k.client.String(), k.name, e.until)
			}
			return k.name, true
		}
	}
	return "", false
}

// handshakeRejected is rejectedCertificate plus the silent case: a client
// that sent a ClientHello, received our certificate and then said nothing
// until the handshake deadline. Browsers and libraries that accept the
// certificate finish in milliseconds; only a client that decided not to
// continue leaves the handshake hanging.
func handshakeRejected(err error) bool {
	if rejectedCertificate(err) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

// pinKeys returns the exact-host key and, when the host has a parent
// domain, the domain key.
func pinKeys(client netip.Addr, host string) []pinKey {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	keys := []pinKey{{client, h}}
	if d := registrable(h); d != "" && d != h {
		keys = append(keys, pinKey{client, "." + d})
	}
	return keys
}

// registrable is a deliberately simple "last two labels": enough to group a
// CDN's per-node names, without a public-suffix list the binary does not
// otherwise need. It errs towards narrower groups: "a.b.co.uk" groups as
// "co.uk", which merely means such hosts need their own two rejections.
func registrable(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (t *pinTracker) pruneLocked(now time.Time) {
	for k, e := range t.entries {
		if now.After(e.until) && now.Sub(e.first) > pinWindow {
			delete(t.entries, k)
		}
	}
}

// active lists the bypasses in force, for the API.
func (t *pinTracker) active(now time.Time) []Bypass {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []Bypass{}
	for k, e := range t.entries {
		if now.Before(e.until) {
			out = append(out, Bypass{Client: k.client.String(), Name: k.name, Until: e.until, Fails: e.fails})
		}
	}
	return out
}

// rejectedCertificate reports whether a failed handshake looks like the
// client refusing our certificate, as opposed to a network hiccup. A client
// that validates and fails sends a certificate alert; a pinned app often
// just hangs up after the ServerHello, which arrives here as EOF or a reset.
// Both count. A timeout or a malformed hello does not.
func rejectedCertificate(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") {
		return true
	}
	if !strings.Contains(msg, "remote error") {
		return false
	}
	for _, s := range []string{
		"bad certificate", "unknown certificate authority", "certificate unknown",
		"unsupported certificate", "certificate revoked", "certificate expired",
		"unknown ca", "access denied", "handshake failure",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
