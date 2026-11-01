package app

import "testing"

func TestPowerTroubleIsSpelledOut(t *testing.T) {
	for word, want := range map[uint64]string{
		0:       "ok",
		0x50000: "since boot: under-voltage, throttled (check the power supply)",
		0x50005: "now: under-voltage, throttled; since boot: under-voltage, throttled (check the power supply)",
		0x50004: "now: throttled; since boot: under-voltage, throttled (check the power supply)",
	} {
		if got := describeThrottle(word); got != want {
			t.Errorf("%#x = %q", word, got)
		}
	}
}
