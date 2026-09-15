package app

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event is a live update fanned out to WebSocket subscribers.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
	TS   int64  `json:"ts"`
}

// Bus is a non-blocking fan-out. A slow subscriber drops messages rather than
// stalling the packet path — a browser tab that cannot keep up must never be
// able to apply backpressure to packet capture.
type Bus struct {
	mu       sync.RWMutex
	subs     map[int]chan Event
	next     int
	capacity int
	closed   bool

	published atomic.Int64
	dropped   atomic.Int64
}

func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 256
	}
	return &Bus{subs: map[int]chan Event{}, capacity: capacity}
}

// Subscribe returns a channel and an unsubscribe function.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, b.capacity)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		close(ch)
		return ch, func() {}
	}
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			if c, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(c)
			}
			b.mu.Unlock()
		})
	}
}

func (b *Bus) Publish(e Event) {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	b.published.Add(1)
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			b.dropped.Add(1)
		}
	}
}

func (b *Bus) Stats() map[string]any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return map[string]any{
		"subscribers": len(b.subs),
		"published":   b.published.Load(),
		"dropped":     b.dropped.Load(),
	}
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
}
