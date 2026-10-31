package confighistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func newTestManager(t *testing.T, hooks Hooks) (*config.Config, *Manager, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "orbis.yaml")
	histDir := filepath.Join(dir, "config-history")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetHistoryDir(histDir)
	mgr := New(histDir, cfg, hooks)
	t.Cleanup(mgr.Stop)
	return cfg, mgr, histDir
}

func TestTrustBoundarySecretsNeverAppearInListGetOrDiff(t *testing.T) {
	cfg, mgr, _ := newTestManager(t, Hooks{})

	const (
		aiKey1       = "sk-live-SUPER-SECRET-AI-KEY-ALPHA-9911"
		aiKey2       = "sk-live-SUPER-SECRET-AI-KEY-BETA-2288"
		sessionKey1  = "sess-SECRET-HEX-KEY-ONE-77aa33bb"
		sessionKey2  = "sess-SECRET-HEX-KEY-TWO-88cc44dd"
		adminHash1   = "$2a$12$SECRETADMINBCRYPTHASHONE999999999999"
		adminHash2   = "$2a$12$SECRETADMINBCRYPTHASHTWO888888888888"
		wgServerKey1 = "WG-SERVER-PRIVATE-KEY-SECRET-1111111111"
		wgServerKey2 = "WG-SERVER-PRIVATE-KEY-SECRET-2222222222"
		wgTunnelKey1 = "WG-TUNNEL-PRIVATE-KEY-SECRET-3333333333"
		wgTunnelPSK1 = "WG-TUNNEL-PSK-SECRET-4444444444"
		wgClientKey1 = "WG-CLIENT-PRIVATE-KEY-SECRET-5555555555"
		wgClientPSK1 = "WG-CLIENT-PSK-SECRET-6666666666"
		ghToken1     = "ghp_SUPERSECRETGITHUBTOKEN77777777"
		smtpPass1    = "SMTP-PASSWORD-SECRET-88888888"
		tsAuthKey1   = "tskey-auth-SECRETTAILSCALE999999"
	)

	allSecrets := []string{
		aiKey1, aiKey2,
		sessionKey1, sessionKey2,
		adminHash1, adminHash2,
		wgServerKey1, wgServerKey2,
		wgTunnelKey1, wgTunnelPSK1,
		wgClientKey1, wgClientPSK1,
		ghToken1, smtpPass1, tsAuthKey1,
	}

	// Version 1: populate every secret field at top-level, second-level, and
	// inside slices of structs (WireGuard server, tunnels, and clients).
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "home-fw-v1"
		c.AI.APIKey = aiKey1
		c.API.SessionKey = sessionKey1
		c.API.AdminHash = adminHash1
		c.VPN.Server.PrivateKey = wgServerKey1
		c.VPN.Tunnels = []config.TunnelConfig{{
			Name:         "mullvad",
			Interface:    "wg-mullvad",
			PrivateKey:   wgTunnelKey1,
			PresharedKey: wgTunnelPSK1,
			Addresses:    []string{"10.64.0.2/32"},
		}}
		c.VPN.Client = []config.WGClientConfig{{
			Name:       "work",
			Interface:  "wg-work",
			PrivateKey: wgClientKey1,
			PeerPSK:    wgClientPSK1,
		}}
		c.Issues.GitHub.Token = ghToken1
		c.Notify.Email.Password = smtpPass1
		c.Tailscale.AuthKey = tsAuthKey1
	}); err != nil {
		t.Fatal(err)
	}

	// Version 2: rotate secrets and change a visible field so both old and new
	// secrets participate in archived versions and diffs.
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "home-fw-v2"
		c.AI.APIKey = aiKey2
		c.API.SessionKey = sessionKey2
		c.API.AdminHash = adminHash2
		c.VPN.Server.PrivateKey = wgServerKey2
	}); err != nil {
		t.Fatal(err)
	}

	// Version 3: another change so Version 1 diffs against Version 2 and
	// Version 2 diffs against current (Version 3).
	if err := cfg.Update(func(c *config.Config) {
		c.DNS.Upstreams = []string{"9.9.9.9:53"}
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(entries))
	}

	listJSON, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretLeaked(t, "List()", string(listJSON), allSecrets)

	for _, e := range entries {
		gotYAML, err := mgr.Get(e.ID)
		if err != nil {
			t.Fatalf("Get(%s): %v", e.ID, err)
		}
		assertNoSecretLeaked(t, "Get("+e.ID+")", gotYAML, allSecrets)
		if !strings.Contains(gotYAML, RedactedPlaceholder) {
			t.Errorf("Get(%s) did not contain %q", e.ID, RedactedPlaceholder)
		}

		diffOut, err := mgr.Diff(e.ID)
		if err != nil {
			t.Fatalf("Diff(%s): %v", e.ID, err)
		}
		assertNoSecretLeaked(t, "Diff("+e.ID+")", diffOut, allSecrets)
	}
}

func assertNoSecretLeaked(t *testing.T, surface, output string, secrets []string) {
	t.Helper()
	for _, sec := range secrets {
		if strings.Contains(output, sec) {
			t.Fatalf("SECURITY FAILURE: secret %q appeared in %s output:\n%s", sec, surface, output)
		}
	}
}

func TestRedactionAtEveryDepth(t *testing.T) {
	nestedYAML := `
mode: observe
top_secret: TOP_VALUE_1
level1:
  api_key: LEVEL2_KEY_VAL
  nested:
    deep_token: LEVEL3_TOKEN_VAL
    items:
      - name: peer-a
        private_key: LEVEL5_WG_KEY_VAL
        peer_psk: LEVEL5_PSK_VAL
        extra:
          admin_hash: LEVEL6_HASH_VAL
          smtp_password: LEVEL6_PASSWORD_VAL
  keep_visible: visible-setting
`
	out, err := RedactYAML([]byte(nestedYAML))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	forbidden := []string{
		"TOP_VALUE_1",
		"LEVEL2_KEY_VAL",
		"LEVEL3_TOKEN_VAL",
		"LEVEL5_WG_KEY_VAL",
		"LEVEL5_PSK_VAL",
		"LEVEL6_HASH_VAL",
		"LEVEL6_PASSWORD_VAL",
	}
	assertNoSecretLeaked(t, "RedactYAML(deep)", text, forbidden)
	if !strings.Contains(text, "visible-setting") {
		t.Errorf("non-secret value was unexpectedly removed:\n%s", text)
	}
	if got := strings.Count(text, RedactedPlaceholder); got != len(forbidden) {
		t.Errorf("expected %d %q placeholders, got %d in:\n%s", len(forbidden), RedactedPlaceholder, got, text)
	}
}

func TestListSummaryAndUnifiedDiff(t *testing.T) {
	cfg, mgr, _ := newTestManager(t, Hooks{})

	if err := cfg.Update(func(c *config.Config) {
		c.DNS.Upstreams = []string{"9.9.9.9:53"}
		c.AdBlock.Lists = []config.BlockList{{
			Name: "oisd", URL: "https://big.oisd.nl", Enabled: true, Format: "domains",
		}}
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Summary != "dns.upstreams, adblock.lists" {
		t.Errorf("expected summary %q, got %q", "dns.upstreams, adblock.lists", entries[0].Summary)
	}
	if !entries[0].TouchesNetwork {
		t.Errorf("expected dns.upstreams change to mark TouchesNetwork=true")
	}

	diff, err := mgr.Diff(entries[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "--- "+entries[0].ID) || !strings.Contains(diff, "+++ current") {
		t.Errorf("unexpected diff header:\n%s", diff)
	}
	if !strings.Contains(diff, "-    - tls://1.1.1.1:853") || !strings.Contains(diff, "+    - 9.9.9.9:53") {
		t.Errorf("diff missing expected upstream lines:\n%s", diff)
	}
}

func TestDiffCappedOnHugeFiles(t *testing.T) {
	var oldBuf, newBuf strings.Builder
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&oldBuf, "line_%d: old_value_%d\n", i, i)
		fmt.Fprintf(&newBuf, "line_%d: new_value_%d\n", i, i)
	}
	start := time.Now()
	diff := UnifiedDiff("old", "new", []byte(oldBuf.String()), []byte(newBuf.String()))
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("capped diff took too long: %v", elapsed)
	}
	if !strings.Contains(diff, "diff capped") {
		t.Errorf("expected capped notice in huge diff, got:\n%s", diff[:minInt(len(diff), 400)])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestHistoryPruningKeepsAtMost200(t *testing.T) {
	cfg, mgr, _ := newTestManager(t, Hooks{})

	for i := 1; i <= 208; i++ {
		name := fmt.Sprintf("router-%03d", i)
		if err := cfg.Update(func(c *config.Config) {
			c.Node.Name = name
		}); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 200 {
		t.Fatalf("expected 200 entries after pruning, got %d", len(entries))
	}
	// Newest first.
	if !entries[0].Time.After(entries[len(entries)-1].Time) {
		t.Errorf("entries are not sorted newest-first")
	}
}

func TestRestoreProducesHistoryEntryPreservesSecretsAndValidates(t *testing.T) {
	var appliedKeys []string
	cfg, mgr, histDir := newTestManager(t, Hooks{
		OnApply: func(keys []string) {
			appliedKeys = append([]string(nil), keys...)
		},
	})

	const v1Secret = "sk-v1-real-unredacted-secret"
	const v2Secret = "sk-v2-different-secret"

	// Save v1 with a real secret, then advance to v2 so v1 is archived in history.
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "orbis-v1"
		c.AI.APIKey = v1Secret
		c.DNS.Upstreams = []string{"1.1.1.1:53"}
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "orbis-v2"
		c.AI.APIKey = v2Secret
		c.DNS.Upstreams = []string{"8.8.8.8:53"}
	}); err != nil {
		t.Fatal(err)
	}

	beforeEntries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeEntries) != 2 {
		t.Fatalf("expected 2 entries before restore, got %d", len(beforeEntries))
	}
	v1EntryID := beforeEntries[0].ID // most recently archived version is v1
	genBefore := cfg.Generation()

	res, err := mgr.Restore(v1EntryID, 0)
	if err != nil {
		t.Fatalf("Restore(%s): %v", v1EntryID, err)
	}
	if res.BackupID == "" {
		t.Fatalf("expected BackupID to be populated")
	}

	// Restore must increment generation, restore real unredacted secrets, and
	// create a new history entry holding the pre-restore config (orbis-v2) so
	// the restore is itself undoable.
	if cfg.Generation() <= genBefore {
		t.Errorf("expected generation to advance beyond %d, got %d", genBefore, cfg.Generation())
	}
	snap := cfg.Snapshot()
	if snap.Node.Name != "orbis-v1" {
		t.Errorf("expected restored node.name=orbis-v1, got %q", snap.Node.Name)
	}
	if snap.AI.APIKey != v1Secret {
		t.Fatalf("expected restored secret %q, got %q", v1Secret, snap.AI.APIKey)
	}
	if len(appliedKeys) == 0 {
		t.Errorf("expected OnApply hook to receive changed keys")
	}

	afterEntries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEntries) != 3 {
		t.Fatalf("expected restore to add 1 history entry (total 3), got %d", len(afterEntries))
	}
	if afterEntries[0].ID != res.BackupID {
		t.Errorf("expected newest history entry to be backup %s, got %s", res.BackupID, afterEntries[0].ID)
	}

	// Refuse invalid archived YAML and return the validation reason.
	badID := fmt.Sprintf("%d", time.Now().UnixNano()+1_000_000)
	badYAML := "mode: sideways\nstore:\n  path: /tmp/x.db\nfirewall:\n  default_forward: accept\n"
	if err := os.WriteFile(filepath.Join(histDir, badID+".yaml"), []byte(badYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Restore(badID, 0)
	if err == nil {
		t.Fatalf("expected Restore to refuse invalid mode")
	}
	if !strings.Contains(err.Error(), "observe or inline") {
		t.Errorf("expected validation reason in error, got: %v", err)
	}
	if cfg.Snapshot().Node.Name != "orbis-v1" {
		t.Errorf("refused restore mutated live config")
	}
}

func TestCommitConfirmRevertsOnTimeoutAndKeepsOnConfirm(t *testing.T) {
	var (
		mu           sync.Mutex
		autoReverted chan string
	)
	autoReverted = make(chan string, 2)

	cfg, mgr, _ := newTestManager(t, Hooks{
		OnAutoRevert: func(restoredID, revertToID string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				autoReverted <- "err:" + err.Error()
				return
			}
			autoReverted <- revertToID
		},
	})

	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "before-change"
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "steady-current"
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	targetID := entries[0].ID // "before-change"

	// 1. Restore with a short injected confirm duration and let it expire:
	// it must revert back to "steady-current".
	res, err := mgr.Restore(targetID, 60*time.Millisecond)
	if err != nil {
		t.Fatalf("Restore with confirm: %v", err)
	}
	if !res.Pending.Pending || res.Pending.RemainingSeconds < 1 {
		t.Fatalf("expected pending status immediately after restore, got %+v", res.Pending)
	}
	if got := cfg.Snapshot().Node.Name; got != "before-change" {
		t.Fatalf("expected restored value while pending, got %q", got)
	}

	// A second restore while one is pending must be refused.
	if _, err := mgr.Restore(targetID, 60*time.Millisecond); !errors.Is(err, ErrPendingRestore) {
		t.Fatalf("expected ErrPendingRestore for concurrent restore, got %v", err)
	}

	select {
	case msg := <-autoReverted:
		if strings.HasPrefix(msg, "err:") {
			t.Fatalf("auto-revert failed: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for commit-confirm auto-revert")
	}

	if got := cfg.Snapshot().Node.Name; got != "steady-current" {
		t.Fatalf("expected config to revert to steady-current after timer, got %q", got)
	}
	if mgr.Pending().Pending {
		t.Errorf("expected Pending()=false after auto-revert")
	}

	// 2. Restore with confirm and call Confirm() before the timer fires:
	// it must NOT revert after the duration elapses.
	if _, err := mgr.Restore(targetID, 70*time.Millisecond); err != nil {
		t.Fatalf("second Restore with confirm: %v", err)
	}
	confirmedID, err := mgr.Confirm()
	if err != nil {
		t.Fatalf("Confirm(): %v", err)
	}
	if confirmedID != targetID {
		t.Errorf("expected confirmed id %s, got %s", targetID, confirmedID)
	}
	if mgr.Pending().Pending {
		t.Errorf("expected Pending()=false immediately after Confirm()")
	}

	time.Sleep(120 * time.Millisecond)
	if got := cfg.Snapshot().Node.Name; got != "before-change" {
		t.Fatalf("config reverted despite Confirm(): got %q, want before-change", got)
	}
	select {
	case unexpected := <-autoReverted:
		t.Fatalf("unexpected auto-revert callback after Confirm(): %s", unexpected)
	default:
	}
}

func TestRedactionCoversWebhooksAndWiFi(t *testing.T) {
	raw := []byte(`wifi:
  passphrase: wifi-plain-secret
notify:
  webhooks:
    - name: discord
      url: https://discord.example/api/webhooks/1/token-in-the-path
      headers:
        X-Custom: header-plain-secret
adblock:
  lists:
    - url: https://lists.example/ads.txt
`)
	out, err := RedactYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"wifi-plain-secret", "token-in-the-path", "header-plain-secret"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("%q survived redaction:\n%s", leak, out)
		}
	}
	if !strings.Contains(string(out), "lists.example") {
		t.Errorf("an ordinary list URL should stay readable:\n%s", out)
	}
}

func TestRestoreKeepsTheCurrentPasswordAndSessions(t *testing.T) {
	cfg, mgr, _ := newTestManager(t, Hooks{})
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "before"
		c.API.AdminHash, c.API.SessionKey = "old-hash", "old-session-key"
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "after"
		c.API.AdminHash, c.API.SessionKey = "rotated-hash", "rotated-session-key"
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Restore(entries[0].ID, 0); err != nil {
		t.Fatal(err)
	}
	got := cfg.Snapshot()
	if got.Node.Name != "before" {
		t.Fatalf("the restore did not apply: node %q", got.Node.Name)
	}
	if got.API.AdminHash != "rotated-hash" || got.API.SessionKey != "rotated-session-key" {
		t.Fatalf("restoring old settings brought back old credentials: %q %q", got.API.AdminHash, got.API.SessionKey)
	}
}
