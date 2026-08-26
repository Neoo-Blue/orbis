package backup

import (
	"encoding/json"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestPreserveSecretsKeepsLiveValues(t *testing.T) {
	live := config.Config{}
	live.AI.APIKey = "real-key"
	live.Tailscale.AuthKey = "real-ts"
	live.API.SessionKey = "real-session"
	live.Notify.Email.Password = "real-pass"

	// A bundle exported through the API carries masks, not secrets.
	in := config.Config{}
	in.AI.APIKey = config.MaskedSecret
	in.Tailscale.AuthKey = ""
	in.API.SessionKey = config.MaskedSecret
	in.Notify.Email.Password = config.MaskedSecret

	preserveSecrets(&in, &live)

	if in.AI.APIKey != "real-key" {
		t.Errorf("masked API key should be preserved, got %q", in.AI.APIKey)
	}
	if in.Tailscale.AuthKey != "real-ts" {
		t.Errorf("empty auth key should be preserved, got %q", in.Tailscale.AuthKey)
	}
	if in.API.SessionKey != "real-session" {
		t.Errorf("session key should be preserved, got %q", in.API.SessionKey)
	}
	if in.Notify.Email.Password != "real-pass" {
		t.Errorf("email password should be preserved, got %q", in.Notify.Email.Password)
	}
}

func TestPreserveSecretsLetsRealValuesThrough(t *testing.T) {
	live := config.Config{}
	live.AI.APIKey = "old"
	in := config.Config{}
	in.AI.APIKey = "brand-new-key"
	preserveSecrets(&in, &live)
	if in.AI.APIKey != "brand-new-key" {
		t.Fatalf("a genuinely new secret must not be overwritten, got %q", in.AI.APIKey)
	}
}

func TestRestoreRejectsNewerFormat(t *testing.T) {
	b := &Bundle{Version: FormatVersion + 1}
	if _, err := Restore(nil, nil, b, RestoreOptions{}); err == nil {
		t.Fatal("a bundle from a newer format must be refused, not half-applied")
	}
}

func TestRestoreRejectsNilBundle(t *testing.T) {
	if _, err := Restore(nil, nil, nil, RestoreOptions{}); err == nil {
		t.Fatal("nil bundle must error")
	}
}

func TestApplyRestoredLeavesBindingsAlone(t *testing.T) {
	// Restoring a bundle from another host must not point this node at that
	// host's listen address or database path and lock the operator out.
	dst := config.Config{}
	dst.API.Listen = ":8080"
	dst.Store.Path = "/var/lib/orbis/orbis.db"

	src := config.Config{}
	src.API.Listen = ":9999"
	src.Store.Path = "/somewhere/else.db"
	src.Mode = config.ModeInline

	applyRestored(&dst, &src)

	if dst.API.Listen != ":8080" {
		t.Errorf("listen address must not be restored, got %q", dst.API.Listen)
	}
	if dst.Store.Path != "/var/lib/orbis/orbis.db" {
		t.Errorf("store path must not be restored, got %q", dst.Store.Path)
	}
	if dst.Mode != config.ModeInline {
		t.Error("mode should be restored")
	}
}

func TestBundleRoundTrips(t *testing.T) {
	b := &Bundle{Version: FormatVersion, NodeName: "orbis"}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var out Bundle
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.NodeName != "orbis" || out.Version != FormatVersion {
		t.Fatalf("round trip lost data: %+v", out)
	}
}
