package store

import (
	"sync"
	"time"
)

// memo caches the answers to the handful of aggregate queries that every
// open page polls: a full scan of a day of flows grouped by country costs
// seconds on a small board, and the answer does not change between two
// polls a few seconds apart. Keys include the query's window so different
// windows do not collide; entries live for their TTL and are then recomputed.
type memo struct {
	mu      sync.Mutex
	entries map[string]memoEntry
}

type memoEntry struct {
	at  time.Time
	val any
}

func (m *memo) get(key string, ttl time.Duration, compute func() (any, error)) (any, error) {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]memoEntry{}
	}
	if e, ok := m.entries[key]; ok && time.Since(e.at) < ttl {
		m.mu.Unlock()
		return e.val, nil
	}
	m.mu.Unlock()
	val, err := compute()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.entries[key] = memoEntry{at: time.Now(), val: val}
	if len(m.entries) > 64 {
		for k, e := range m.entries {
			if time.Since(e.at) > 10*time.Minute {
				delete(m.entries, k)
			}
		}
	}
	m.mu.Unlock()
	return val, nil
}

// bucket rounds a time down so that polls a few seconds apart share a key.
func bucket(t time.Time, d time.Duration) string {
	return t.Truncate(d).Format(time.RFC3339)
}
