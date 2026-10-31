package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/go-chi/chi/v5"
)

func openMatrixTestServer(t *testing.T, cfg *config.Config) (*Server, *store.Store, chi.Router) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "matrix.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv := &Server{
		app: &app.App{Store: st, Cfg: cfg},
		cfg: cfg,
		log: func(string, ...any) {},
	}
	r := chi.NewRouter()
	srv.mount(r)
	return srv, st, r
}

func getMatrix(t *testing.T, r chi.Router) (ZoneMatrixResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/firewall/matrix", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /firewall/matrix status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out ZoneMatrixResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode matrix response: %v", err)
	}
	return out, rec.Body.String()
}

func findCell(t *testing.T, resp ZoneMatrixResponse, src, dst string) MatrixCell {
	t.Helper()
	for _, c := range resp.Cells {
		if c.Src == src && c.Dst == dst {
			return c
		}
	}
	t.Fatalf("missing cell %s -> %s in %+v", src, dst, resp.Cells)
	return MatrixCell{}
}

func insertTestFlow(t *testing.T, st *store.Store, id string, started time.Time, srcIP, dstIP string, bytesIn, bytesOut int64, verdict string) {
	t.Helper()
	_, err := st.DB().Exec(`INSERT INTO flows
		(id, started_at, last_seen, proto, src_ip, dst_ip, direction, bytes_in, bytes_out, verdict)
		VALUES (?, ?, ?, 'tcp', ?, ?, 'out', ?, ?, ?)`,
		id, started.Unix(), started.Unix(), srcIP, dstIP, bytesIn, bytesOut, verdict)
	if err != nil {
		t.Fatal(err)
	}
}

func TestZoneMatrixImplicitZonesAndObserveMode(t *testing.T) {
	cfg := config.Default()
	_, _, r := openMatrixTestServer(t, cfg)

	// Mounting /firewall/matrix must not shadow the existing /firewall/* group.
	rulesReq := httptest.NewRequest(http.MethodGet, "/firewall/rules", nil)
	rulesRec := httptest.NewRecorder()
	r.ServeHTTP(rulesRec, rulesReq)
	if rulesRec.Code != http.StatusOK {
		t.Fatalf("GET /firewall/rules shadowed or failed: status = %d", rulesRec.Code)
	}

	resp, raw := getMatrix(t, r)
	if strings.Contains(raw, "null") {
		t.Fatalf("matrix JSON contains null slice: %s", raw)
	}
	if resp.Mode != "observe" {
		t.Fatalf("mode = %q, want observe", resp.Mode)
	}
	if resp.Enforced {
		t.Fatal("enforced = true in observe mode, want false")
	}

	gotNames := make([]string, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		gotNames = append(gotNames, z.Name)
		if !z.Implicit {
			t.Errorf("zone %s should be marked implicit when config has no zones", z.Name)
		}
	}
	wantNames := []string{"LAN", "WAN", "This node"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("zones = %v, want %v", gotNames, wantNames)
	}

	wantDefaults := map[[2]string]string{
		{"LAN", "LAN"}:             "allow",
		{"LAN", "WAN"}:             "allow",
		{"LAN", "This node"}:       "block",
		{"WAN", "LAN"}:             "block",
		{"WAN", "WAN"}:             "block",
		{"WAN", "This node"}:       "block",
		{"This node", "LAN"}:       "allow",
		{"This node", "WAN"}:       "allow",
		{"This node", "This node"}: "allow",
	}
	for pair, want := range wantDefaults {
		c := findCell(t, resp, pair[0], pair[1])
		if c.DefaultAction != want {
			t.Errorf("%s -> %s default_action = %q, want %q", pair[0], pair[1], c.DefaultAction, want)
		}
		if c.Verdict != want {
			t.Errorf("%s -> %s verdict = %q, want %q", pair[0], pair[1], c.Verdict, want)
		}
	}
}

func TestZoneMatrixDefaultActionsAndBlockingRule(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeInline
	cfg.Firewall.Enabled = true
	cfg.Firewall.WANInterface = "eth0"
	cfg.Firewall.DefaultForward = "accept"
	cfg.Firewall.Zones = []config.Zone{
		{Name: "lan", Interfaces: []string{"eth1"}, Subnets: []string{"192.168.1.0/24"}, Trust: "lan"},
		{Name: "iot", Interfaces: []string{"eth2"}, Subnets: []string{"192.168.20.0/24"}, Trust: "iot"},
		{Name: "dmz", Interfaces: []string{"eth3"}, Subnets: []string{"192.168.30.0/24"}, Trust: "dmz"},
		{Name: "wan", Interfaces: []string{"eth0"}, Trust: "wan"},
	}

	_, st, r := openMatrixTestServer(t, cfg)

	rules := []store.Rule{
		{
			ID: "r-disabled", Position: 5, Enabled: false, Name: "Disabled drop",
			Chain: "forward", Action: "drop", SrcZone: "lan", DstZone: "wan",
			CounterPkts: 999, CounterBytes: 99999, Origin: "user",
		},
		{
			ID: "r-smtp-block", Position: 10, Enabled: true, Name: "Block outbound SMTP",
			Chain: "forward", Action: "drop", SrcZone: "lan", DstZone: "wan",
			Proto: "tcp", DstPort: "25", CounterPkts: 14, CounterBytes: 840, Origin: "user",
		},
		{
			ID: "r-https-log", Position: 20, Enabled: true, Name: "Count HTTPS",
			Chain: "forward", Action: "accept", SrcZone: "lan", DstZone: "wan",
			Proto: "tcp", DstPort: "443", CounterPkts: 100, CounterBytes: 64000, Origin: "user",
		},
		{
			ID: "r-dmz-cut", Position: 10, Enabled: true, Name: "Cut LAN to DMZ",
			Chain: "forward", Action: "reject", SrcZone: "lan", DstZone: "dmz",
			CounterPkts: 5, CounterBytes: 300, Origin: "user",
		},
	}
	for i := range rules {
		if err := st.SaveRule(&rules[i]); err != nil {
			t.Fatal(err)
		}
	}

	resp, _ := getMatrix(t, r)
	if !resp.Enforced {
		t.Fatal("enforced = false in inline mode with firewall enabled, want true")
	}

	// Even when DefaultForward is "accept", nftables emits explicit drop rules
	// isolating IoT from every other non-WAN zone.
	iotToLAN := findCell(t, resp, "iot", "lan")
	if iotToLAN.DefaultAction != "block" || iotToLAN.Verdict != "block" {
		t.Fatalf("iot -> lan = (%s, %s), want (block, block)", iotToLAN.DefaultAction, iotToLAN.Verdict)
	}
	iotToDMZ := findCell(t, resp, "iot", "dmz")
	if iotToDMZ.DefaultAction != "block" {
		t.Fatalf("iot -> dmz default_action = %q, want block", iotToDMZ.DefaultAction)
	}

	// Conditional block on top of an allow default produces a mixed verdict,
	// sums enabled rule counters, and ignores disabled rules.
	lanToWAN := findCell(t, resp, "lan", "wan")
	if lanToWAN.DefaultAction != "allow" {
		t.Fatalf("lan -> wan default_action = %q, want allow", lanToWAN.DefaultAction)
	}
	if lanToWAN.Verdict != "mixed" {
		t.Fatalf("lan -> wan verdict = %q, want mixed", lanToWAN.Verdict)
	}
	if !lanToWAN.HasBlock {
		t.Fatal("lan -> wan has_block = false, want true")
	}
	if lanToWAN.RuleCount != 2 {
		t.Fatalf("lan -> wan rule_count = %d, want 2", lanToWAN.RuleCount)
	}
	if lanToWAN.CounterPkts != 114 || lanToWAN.CounterBytes != 64840 {
		t.Fatalf("lan -> wan counters = (%d, %d), want (114, 64840)", lanToWAN.CounterPkts, lanToWAN.CounterBytes)
	}
	wantIDs := []string{"r-smtp-block", "r-https-log"}
	if !reflect.DeepEqual(lanToWAN.RuleIDs, wantIDs) {
		t.Fatalf("lan -> wan rule_ids = %v, want %v", lanToWAN.RuleIDs, wantIDs)
	}

	// An unconditional reject overrides DefaultForward=accept to a full block.
	lanToDMZ := findCell(t, resp, "lan", "dmz")
	if lanToDMZ.DefaultAction != "allow" || lanToDMZ.Verdict != "block" || !lanToDMZ.HasBlock {
		t.Fatalf("lan -> dmz = %+v, want default allow + verdict block + has_block", lanToDMZ)
	}
}

func TestZoneMatrixFlowAttribution(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.Zones = []config.Zone{
		// Leave LAN subnets empty so RFC1918 fallback is exercised alongside IoT's explicit /24.
		{Name: "lan", Interfaces: []string{"eth1"}, Trust: "lan"},
		{Name: "iot", Interfaces: []string{"eth2"}, Subnets: []string{"192.168.20.0/24"}, Trust: "iot"},
	}

	_, st, r := openMatrixTestServer(t, cfg)
	now := time.Now()
	recent := now.Add(-10 * time.Minute)
	old := now.Add(-3 * time.Hour)

	// IoT subnet match -> public WAN fallback.
	insertTestFlow(t, st, "f-iot-wan", recent, "192.168.20.42", "93.184.216.34", 2000, 1000, store.VerdictAllow)
	// IoT subnet match -> RFC1918 LAN fallback (blocked attempt).
	insertTestFlow(t, st, "f-iot-lan", recent, "192.168.20.42", "192.168.1.15", 0, 120, store.VerdictBlock)
	// RFC1918 10/8 LAN fallback -> public WAN fallback.
	insertTestFlow(t, st, "f-lan-wan", recent, "10.0.4.9", "1.1.1.1", 5000, 3000, store.VerdictAllow)
	// Loopback -> This node.
	insertTestFlow(t, st, "f-self", recent, "127.0.0.1", "127.0.0.1", 64, 64, store.VerdictAllow)
	// Outside the 1-hour window -> excluded.
	insertTestFlow(t, st, "f-old", old, "10.0.4.9", "1.1.1.1", 999999, 999999, store.VerdictAllow)

	resp, _ := getMatrix(t, r)

	iotWAN := findCell(t, resp, "iot", "WAN")
	if iotWAN.Flows != 1 || iotWAN.FlowBytes != 3000 || iotWAN.FlowsBlocked != 0 {
		t.Fatalf("iot -> WAN flows = (%d, %dB, %d blocked), want (1, 3000B, 0)",
			iotWAN.Flows, iotWAN.FlowBytes, iotWAN.FlowsBlocked)
	}

	iotLAN := findCell(t, resp, "iot", "lan")
	if iotLAN.Flows != 1 || iotLAN.FlowBytes != 120 || iotLAN.FlowsBlocked != 1 {
		t.Fatalf("iot -> lan flows = (%d, %dB, %d blocked), want (1, 120B, 1)",
			iotLAN.Flows, iotLAN.FlowBytes, iotLAN.FlowsBlocked)
	}

	lanWAN := findCell(t, resp, "lan", "WAN")
	if lanWAN.Flows != 1 || lanWAN.FlowBytes != 8000 {
		t.Fatalf("lan -> WAN flows = (%d, %dB), want (1, 8000B)", lanWAN.Flows, lanWAN.FlowBytes)
	}

	selfSelf := findCell(t, resp, "This node", "This node")
	if selfSelf.Flows != 1 || selfSelf.FlowBytes != 128 {
		t.Fatalf("This node -> This node flows = (%d, %dB), want (1, 128B)", selfSelf.Flows, selfSelf.FlowBytes)
	}
}
