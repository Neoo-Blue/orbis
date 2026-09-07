package dpi

import "testing"

func TestServiceForNetwork(t *testing.T) {
	if s, ok := ServiceForNetwork(15169, "Google LLC"); !ok || s.Name != "Google" {
		t.Errorf("google: %+v %v", s, ok)
	}
	if s, ok := ServiceForNetwork(2906, "Netflix Streaming Services Inc."); !ok || s.Category != CatVideo {
		t.Errorf("netflix: %+v %v", s, ok)
	}
	if _, ok := ServiceForNetwork(3462, "Chunghwa Telecom Co., Ltd."); ok {
		t.Errorf("a carrier must not become a service")
	}
}

func TestRelayHint(t *testing.T) {
	if h := RelayHint("Synology Inc.", "nas", "TW", "Chunghwa Telecom Co., Ltd."); h == "" || !contains(h, "QuickConnect") {
		t.Errorf("synology hint: %q", h)
	}
	if h := RelayHint("Synology Inc.", "nas", "US", "Google LLC"); h != "" {
		t.Errorf("no hint expected for a Synology talking to Google: %q", h)
	}
	if h := RelayHint("Xiaomi Communications", "iot", "SG", "Alibaba"); h == "" {
		t.Errorf("xiaomi hint missing")
	}
	if h := RelayHint("", "", "TW", "Chunghwa"); h != "" {
		t.Errorf("no vendor, no hint: %q", h)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
