// Package unblock lets someone stopped by the block page ask for the site, and
// lets the owner say yes from wherever they are. An answer is a grant: for one
// device or everyone, for a while or for good. Grants live here and not in the
// blocklists, so they expire by themselves and undoing one touches nothing else.
package unblock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type State string

const (
	Pending  State = "pending"
	Approved State = "approved"
	Denied   State = "denied"
)

const (
	// maxPerDevice and maxPending keep one device, or a page looping through
	// blocked names, from burying the owner in requests.
	maxPerDevice = 5
	maxPending   = 50
	maxKept      = 200
	maxNote      = 280
	// requestLife is how long an unanswered request stays open.
	requestLife = 24 * time.Hour
)

var (
	ErrTooMany  = errors.New("too many requests are already waiting")
	ErrNotFound = errors.New("no such request")
)

// Request is one ask and, once answered, the grant it became.
type Request struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	ClientID string `json:"client_id"`
	ClientIP string `json:"client_ip"`
	Device   string `json:"device"`
	Note     string `json:"note,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Wants is how long they asked for, in minutes; zero means for good.
	Wants    int       `json:"wants"`
	Why      string    `json:"why,omitempty"`
	Category string    `json:"category,omitempty"`
	Risky    bool      `json:"risky,omitempty"`
	Asked    time.Time `json:"asked"`
	State    State     `json:"state"`
	Decided  time.Time `json:"decided,omitempty"`
	// Until is when a grant ends; zero means it stands until revoked.
	Until    time.Time `json:"until,omitempty"`
	Everyone bool      `json:"everyone,omitempty"`
	By       string    `json:"by,omitempty"`
}

func (r *Request) active(now time.Time) bool {
	return r.State == Approved && (r.Until.IsZero() || now.Before(r.Until))
}

type saved struct {
	Secret   string          `json:"secret"`
	Requests []*Request      `json:"requests"`
	Trusted  map[string]bool `json:"trusted"`
}

// Manager holds requests, grants and trusted devices, in a file next to the
// database so a grant outlives a restart.
type Manager struct {
	path    string
	mu      sync.Mutex
	secret  []byte
	reqs    []*Request // newest first
	trusted map[string]bool
	// grants is the number of approved requests, read on every DNS lookup so a
	// network with none pays nothing.
	grants atomic.Int64
}

func New(path string) (*Manager, error) {
	m := &Manager{path: path, trusted: map[string]bool{}}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var s saved
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		m.reqs = s.Requests
		if s.Trusted != nil {
			m.trusted = s.Trusted
		}
		if m.secret, err = hex.DecodeString(s.Secret); err != nil {
			m.secret = nil
		}
	}
	if len(m.secret) == 0 {
		m.secret = make([]byte, 32)
		if _, err := rand.Read(m.secret); err != nil {
			return nil, err
		}
	}
	m.recount()
	return m, nil
}

func (m *Manager) recount() {
	n := int64(0)
	for _, r := range m.reqs {
		if r.State == Approved {
			n++
		}
	}
	m.grants.Store(n)
}

func (m *Manager) save() error {
	raw, err := json.Marshal(saved{hex.EncodeToString(m.secret), m.reqs, m.trusted})
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func nameKey(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func covers(host, name string) bool {
	return name == host || strings.HasSuffix(name, "."+host)
}

// Ask records a request, or returns the one already open for this device and
// name. The bool reports a new request, the only kind worth telling anyone about.
func (m *Manager) Ask(r Request, now time.Time) (*Request, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Host = nameKey(r.Host)
	mine, open := 0, 0
	for _, x := range m.reqs {
		if x.State != Pending || now.Sub(x.Asked) >= requestLife {
			continue
		}
		open++
		if x.ClientID == r.ClientID {
			mine++
			if x.Host == r.Host {
				return x, false, nil
			}
		}
	}
	if mine >= maxPerDevice || open >= maxPending {
		return nil, false, ErrTooMany
	}
	id := make([]byte, 9)
	if _, err := rand.Read(id); err != nil {
		return nil, false, err
	}
	r.ID = hex.EncodeToString(id)
	if len(r.Note) > maxNote {
		r.Note = r.Note[:maxNote]
	}
	r.Asked, r.State = now, Pending
	m.reqs = append([]*Request{&r}, m.reqs...)
	m.trim(now)
	return &r, true, m.save()
}

// trim drops answered and lapsed requests beyond the limit, and never a live
// grant.
func (m *Manager) trim(now time.Time) {
	kept := m.reqs[:0]
	n := 0
	for _, r := range m.reqs {
		if n >= maxKept && !r.active(now) {
			continue
		}
		kept = append(kept, r)
		n++
	}
	m.reqs = kept
}

// Decide answers a request. A positive duration grants until then; zero grants
// until revoked. An answer stands: a request can be answered once.
func (m *Manager) Decide(id string, allow bool, d time.Duration, everyone bool, by string, now time.Time) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reqs {
		if r.ID != id {
			continue
		}
		if r.State != Pending {
			return r, nil
		}
		r.Decided, r.By = now, by
		r.State = Denied
		if allow {
			r.State, r.Everyone = Approved, everyone
			if d > 0 {
				r.Until = now.Add(d)
			}
		}
		m.recount()
		return r, m.save()
	}
	return nil, ErrNotFound
}

// Grant opens a name straight away, for a trusted device that need not ask.
func (m *Manager) Grant(r Request, d time.Duration, now time.Time) (*Request, error) {
	asked, _, err := m.Ask(r, now)
	if err != nil {
		return nil, err
	}
	return m.Decide(asked.ID, true, d, false, "trusted device", now)
}

// Revoke ends a grant early.
func (m *Manager) Revoke(id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reqs {
		if r.ID == id {
			r.Until = now
			r.State = Denied
			m.recount()
			return m.save()
		}
	}
	return ErrNotFound
}

// Granted reports whether a grant covers this device and name.
func (m *Manager) Granted(clientID, name string, now time.Time) bool {
	if m.grants.Load() == 0 {
		return false
	}
	name = nameKey(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reqs {
		if r.active(now) && (r.Everyone || r.ClientID == clientID) && covers(r.Host, name) {
			return true
		}
	}
	return false
}

// Status returns the latest request from this device for this name, if any.
func (m *Manager) Status(clientID, host string, now time.Time) *Request {
	host = nameKey(host)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reqs {
		if r.ClientID == clientID && r.Host == host && (r.State != Pending || now.Sub(r.Asked) < requestLife) {
			c := *r
			return &c
		}
	}
	return nil
}

// Get returns one request.
func (m *Manager) Get(id string) (*Request, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reqs {
		if r.ID == id {
			c := *r
			return &c, true
		}
	}
	return nil, false
}

// List sorts requests into what needs an answer, what is open now, and what
// has finished.
func (m *Manager) List(now time.Time) (pending, grants, past []Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, grants, past = []Request{}, []Request{}, []Request{}
	for _, r := range m.reqs {
		switch {
		case r.State == Pending && now.Sub(r.Asked) < requestLife:
			pending = append(pending, *r)
		case r.active(now):
			grants = append(grants, *r)
		default:
			past = append(past, *r)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].Asked.After(pending[j].Asked) })
	return pending, grants, past
}

// Trust marks a device whose block page may unblock without asking.
func (m *Manager) Trust(clientID string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on {
		m.trusted[clientID] = true
	} else {
		delete(m.trusted, clientID)
	}
	return m.save()
}

func (m *Manager) Trusted(clientID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.trusted[clientID]
}

func (m *Manager) TrustedDevices() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.trusted))
	for id := range m.trusted {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Token is what makes a link in a notification worth one answer to one request.
func (m *Manager) Token(id string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (m *Manager) ValidToken(id, token string) bool {
	return hmac.Equal([]byte(m.Token(id)), []byte(token))
}

// Any reports whether any grant exists, the cheap check for the DNS path.
func (m *Manager) Any() bool { return m.grants.Load() > 0 }
