package adblock

import (
	"strings"
	"testing"
)

// The streaming list is only safe while it stays clear of every host a
// stream or a device depends on. This is the guard against a well-meaning
// addition that takes Prime Video down for a household.
func TestStreamingListNeverCoversLoadBearingHosts(t *testing.T) {
	for _, need := range streamingNeverBlock {
		for _, d := range streamingAdDomains {
			if need == d || strings.HasSuffix(need, "."+d) {
				t.Errorf("streaming list entry %q would block load-bearing host %q", d, need)
			}
		}
	}
}

func TestStreamingListEntriesAreBareDomains(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range streamingAdDomains {
		if d != strings.ToLower(strings.TrimSpace(d)) || strings.HasPrefix(d, "*.") || strings.HasSuffix(d, ".") {
			t.Errorf("entry %q should be a bare lower-case domain", d)
		}
		if !strings.Contains(d, ".") {
			t.Errorf("entry %q is not a domain", d)
		}
		if seen[d] {
			t.Errorf("entry %q is listed twice", d)
		}
		seen[d] = true
	}
	if StreamingAdDomainCount() < 50 {
		t.Fatalf("list unexpectedly short: %d", StreamingAdDomainCount())
	}
}

func TestStreamingListBlocksSubdomainsWhenEnabled(t *testing.T) {
	b := NewBuilder()
	for _, d := range streamingAdDomains {
		b.AddBlock(d, "builtin:streaming-ads", "ads", true)
	}
	m := New()
	m.Commit(b)
	for _, q := range []string{"config.samsungads.com", "us.ad.lgsmartad.com", "scribe.logs.roku.com", "aax-us-east.amazon-adsystem.com"} {
		if v := m.Lookup(q); !v.Blocked {
			t.Errorf("%s should be blocked by the streaming list", q)
		}
	}
	for _, q := range []string{"cloudservices.roku.com", "www.youtube.com", "spclient.wg.spotify.com", "dai.google.com"} {
		if v := m.Lookup(q); v.Blocked {
			t.Errorf("%s must not be blocked by the streaming list", q)
		}
	}
}
