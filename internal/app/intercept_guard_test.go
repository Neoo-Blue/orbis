package app

import (
	"testing"
	"time"
)

// A device that keeps straying is told less and less often, up to the cap, and
// starts over once it has been quiet for a while.
func TestStrayBackoff(t *testing.T) {
	var s strayHealer
	t0 := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	if !s.allow("phone", 30*time.Second, at(0)) {
		t.Fatal("the first sighting should be decided on")
	}
	if s.allow("phone", 30*time.Second, at(10*time.Second)) {
		t.Fatal("within the first wait nothing new should happen")
	}
	if !s.allow("phone", 30*time.Second, at(31*time.Second)) {
		t.Fatal("after 30s the device gets another decision")
	}
	// The second wait is doubled.
	if s.allow("phone", 30*time.Second, at(80*time.Second)) {
		t.Fatal("the second wait should be 60s")
	}
	if !s.allow("phone", 30*time.Second, at(92*time.Second)) {
		t.Fatal("after the doubled wait the device gets another decision")
	}

	// Keep it straying until the cap: waits never exceed strayMaxBackoff.
	now := at(92 * time.Second)
	var last time.Time
	for i := 0; i < 20; i++ {
		for !s.allow("phone", 30*time.Second, now) {
			now = now.Add(time.Minute)
		}
		if !last.IsZero() && now.Sub(last) > strayMaxBackoff+time.Minute {
			t.Fatalf("wait %v exceeds the cap", now.Sub(last))
		}
		last = now
	}

	// Quiet for longer than strayQuiet: back to the base wait.
	now = now.Add(strayQuiet + time.Minute)
	if !s.allow("phone", 30*time.Second, now) {
		t.Fatal("a device back after a quiet spell should be decided on at once")
	}
	if !s.allow("phone", 30*time.Second, now.Add(31*time.Second)) {
		t.Fatal("after a quiet spell the wait should start again from the base")
	}

	// Other devices are independent.
	if !s.allow("laptop", 5*time.Second, now) {
		t.Fatal("another device has its own schedule")
	}
}
