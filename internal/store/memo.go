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
	mu         sync.Mutex
	entries    map[string]memoEntry
	refreshing map[string]bool
}

type memoEntry struct {
	at  time.Time
	val any
}

func (m *memo) get(key string, ttl time.Duration, compute func() (any, error)) (any, error) {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]memoEntry{}
		m.refreshing = map[string]bool{}
	}
	if e, ok := m.entries[key]; ok {
		if time.Since(e.at) < ttl {
			m.mu.Unlock()
			return e.val, nil
		}
		// Stale: answer now, recompute once in the background. A page that
		// polls a slow aggregate then never waits on it after the first call.
		if !m.refreshing[key] {
			m.refreshing[key] = true
			go func() {
				val, err := compute()
				m.mu.Lock()
				delete(m.refreshing, key)
				if err == nil {
					m.entries[key] = memoEntry{at: time.Now(), val: val}
				}
				m.mu.Unlock()
			}()
		}
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

// getAsync is get for answers too slow to wait for at all: a week-long report
// on a Raspberry Pi. With no entry yet it starts the computation in the
// background and reports not ready; the caller answers "building" and the
// page asks again. Once an entry exists it behaves like get.
func (m *memo) getAsync(key string, ttl time.Duration, compute func() (any, error)) (any, bool) {
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]memoEntry{}
		m.refreshing = map[string]bool{}
	}
	if _, ok := m.entries[key]; ok {
		m.mu.Unlock()
		v, err := m.get(key, ttl, compute)
		return v, err == nil
	}
	if !m.refreshing[key] {
		m.refreshing[key] = true
		go func() {
			val, err := compute()
			m.mu.Lock()
			delete(m.refreshing, key)
			if err == nil {
				m.entries[key] = memoEntry{at: time.Now(), val: val}
			}
			m.mu.Unlock()
		}()
	}
	m.mu.Unlock()
	return nil, false
}

// MemoAsync exposes getAsync for aggregates assembled outside the store.
func (s *Store) MemoAsync(key string, ttl time.Duration, compute func() (any, error)) (any, bool) {
	return s.aggregates.getAsync(key, ttl, compute)
}

// window names a query window by its length, not its start, so "the last
// 24 hours" keeps one cache key as the clock moves and the entry can be
// refreshed in place instead of recomputed under a new key every poll.
func window(since time.Time) string {
	return time.Since(since).Round(time.Minute).String()
}

// bucket rounds a time down so that polls a few seconds apart share a key.
func bucket(t time.Time, d time.Duration) string {
	return t.Truncate(d).Format(time.RFC3339)
}
