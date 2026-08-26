// Package consent implements ask-on-first-connection: the Little Snitch model,
// applied to a whole network.
//
// Orbis has always been observe-then-block, which means a new destination is
// allowed by default and only stopped once someone notices it. This inverts
// that for devices the operator opts in: the first time a device reaches a
// destination it has never reached before, the connection is recorded as
// pending and the operator is asked. A verdict becomes a durable rule.
//
// It is per-device and opt-in because applying it to a whole household would
// produce hundreds of prompts on day one and be switched off within an hour.
// The value is in pointing it at one suspicious device, or at an IoT gadget
// that should only ever talk to two hosts.
package consent

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Decision is a durable verdict for a (client, destination) pair.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

// Request is one pending question.
type Request struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	ClientIP  string    `json:"client_ip"`
	Host      string    `json:"host"`
	DstIP     string    `json:"dst_ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	App       string    `json:"app,omitempty"`
	Country   string    `json:"country,omitempty"`
	ASOrg     string    `json:"as_org,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// Rule is a decided (client, host) pair.
type Rule struct {
	ClientID string    `json:"client_id"`
	Host     string    `json:"host"`
	Decision Decision  `json:"decision"`
	DecidedAt time.Time `json:"decided_at"`
	// Scope "device" applies to one client; "network" applies everywhere.
	Scope string `json:"scope"`
}

// Store keeps pending requests and decided rules. Persistence is the caller's
// job; this type is the in-memory index the hot path consults.
type Store struct {
	mu sync.RWMutex
	// enrolled clients are the only ones that generate prompts.
	enrolled map[string]bool
	pending  map[string]*Request // key: client|host
	rules    map[string]Rule     // key: client|host, or *|host for network scope
	// maxPending bounds the queue so an enrolled device that talks to a
	// thousand hosts cannot exhaust memory or make the UI useless.
	maxPending int

	onNew func(Request)
}

func NewStore(maxPending int) *Store {
	if maxPending <= 0 {
		maxPending = 500
	}
	return &Store{
		enrolled:   map[string]bool{},
		pending:    map[string]*Request{},
		rules:      map[string]Rule{},
		maxPending: maxPending,
	}
}

// SetOnNew registers a callback fired the first time a request appears, for
// pushing a live notification.
func (s *Store) SetOnNew(fn func(Request)) {
	s.mu.Lock()
	s.onNew = fn
	s.mu.Unlock()
}

// SetEnrolled replaces the set of clients under ask-first control.
func (s *Store) SetEnrolled(clientIDs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrolled = make(map[string]bool, len(clientIDs))
	for _, id := range clientIDs {
		if id != "" {
			s.enrolled[id] = true
		}
	}
	// Drop pending questions for devices no longer enrolled: answering them
	// would create rules for a device nobody is policing.
	for k, req := range s.pending {
		if !s.enrolled[req.ClientID] {
			delete(s.pending, k)
		}
	}
}

func (s *Store) Enrolled() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.enrolled))
	for id := range s.enrolled {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// IsEnrolled reports whether a client is under ask-first control.
func (s *Store) IsEnrolled(clientID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enrolled[clientID]
}

// LoadRules seeds decided rules, normally from the database at boot.
func (s *Store) LoadRules(rules []Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rules {
		s.rules[ruleKey(r.ClientID, r.Host, r.Scope)] = r
	}
}

// Lookup returns the standing decision for a connection, if any. A network
// scoped rule is consulted before the device-specific one so a global "deny
// this tracker everywhere" cannot be undone by a stale per-device allow.
func (s *Store) Lookup(clientID, host string) (Decision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.rules[ruleKey("", host, "network")]; ok {
		return r.Decision, true
	}
	if r, ok := s.rules[ruleKey(clientID, host, "device")]; ok {
		return r.Decision, true
	}
	return "", false
}

// Observe records a connection from an enrolled client. It returns the
// standing decision when one exists, and otherwise queues a question.
//
// The hot path calls this for every new flow, so it must stay cheap: two map
// lookups under a read lock in the common case where a decision already exists.
func (s *Store) Observe(req Request) (Decision, bool) {
	if req.Host == "" {
		// Without a hostname there is nothing durable to decide about: an
		// address alone changes under any CDN and a rule keyed on it would be
		// wrong within the hour.
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(req.Host, "."))
	req.Host = host

	s.mu.RLock()
	enrolled := s.enrolled[req.ClientID]
	if !enrolled {
		s.mu.RUnlock()
		return "", false
	}
	if r, ok := s.rules[ruleKey("", host, "network")]; ok {
		s.mu.RUnlock()
		return r.Decision, true
	}
	if r, ok := s.rules[ruleKey(req.ClientID, host, "device")]; ok {
		s.mu.RUnlock()
		return r.Decision, true
	}
	s.mu.RUnlock()

	key := req.ClientID + "|" + host
	s.mu.Lock()
	existing, ok := s.pending[key]
	if ok {
		existing.Count++
		existing.LastSeen = req.LastSeen
		s.mu.Unlock()
		return "", false
	}
	if len(s.pending) >= s.maxPending {
		s.mu.Unlock()
		return "", false
	}
	req.ID = key
	req.Count = 1
	if req.FirstSeen.IsZero() {
		req.FirstSeen = time.Now()
	}
	req.LastSeen = req.FirstSeen
	s.pending[key] = &req
	cb := s.onNew
	s.mu.Unlock()

	if cb != nil {
		cb(req)
	}
	return "", false
}

// Decide answers a pending request and records a durable rule.
func (s *Store) Decide(id string, decision Decision, scope string) (Rule, bool) {
	if scope != "network" {
		scope = "device"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.pending[id]
	if !ok {
		return Rule{}, false
	}
	delete(s.pending, id)

	client := req.ClientID
	if scope == "network" {
		client = ""
	}
	r := Rule{
		ClientID: client, Host: req.Host, Decision: decision,
		DecidedAt: time.Now(), Scope: scope,
	}
	s.rules[ruleKey(client, req.Host, scope)] = r

	// A network-scope decision answers every queued question for that host,
	// which is the point of choosing that scope.
	if scope == "network" {
		for k, p := range s.pending {
			if p.Host == req.Host {
				delete(s.pending, k)
			}
		}
	}
	return r, true
}

// Pending returns the queue, newest first.
func (s *Store) Pending() []Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Request, 0, len(s.pending))
	for _, r := range s.pending {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Rules returns every decided rule.
func (s *Store) Rules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out
}

// Forget removes a decided rule so the next connection asks again.
func (s *Store) Forget(clientID, host, scope string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := ruleKey(clientID, host, scope)
	if _, ok := s.rules[k]; !ok {
		return false
	}
	delete(s.rules, k)
	return true
}

// Clear drops the pending queue without deciding anything.
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.pending)
	s.pending = map[string]*Request{}
	return n
}

func ruleKey(clientID, host, scope string) string {
	if scope == "network" {
		return "*|" + host
	}
	return clientID + "|" + host
}
