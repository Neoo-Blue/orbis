package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// Tailscale wraps the tailscale CLI. Shelling out rather than embedding
// tsnet is deliberate: this node needs to be a *real* Tailscale node with a
// kernel interface — advertising itself as an exit node and a subnet router,
// and optionally routing LAN clients out through someone else's exit node.
// tsnet gives a userspace-only netstack that can do none of that.
type Tailscale struct {
	cfg *config.Config
	log func(string, ...any)

	mu        sync.Mutex
	available bool
	binary    string
	lastError string
	lastSync  time.Time
	cached    *Status
}

// Status is the subset of `tailscale status --json` the UI needs, plus the
// derived facts an operator actually asks about.
type Status struct {
	Available    bool   `json:"available"`
	Running      bool   `json:"running"`
	BackendState string `json:"backend_state"`
	AuthURL      string `json:"auth_url,omitempty"`
	Self         *Node  `json:"self,omitempty"`
	Peers        []Node `json:"peers"`
	// ExitNodeInUse names the peer currently carrying our egress, if any.
	ExitNodeInUse string `json:"exit_node_in_use,omitempty"`
	// AdvertisingExitNode is whether we offer ourselves as an exit node.
	AdvertisingExitNode bool `json:"advertising_exit_node"`
	// ExitNodeApproved distinguishes "advertised" from "actually usable":
	// an admin has to approve the offer in the Tailscale console, and until
	// they do, nothing can route through us. This is the single most common
	// reason a correctly-configured exit node does not work.
	ExitNodeApproved bool     `json:"exit_node_approved"`
	AdvertisedRoutes []string `json:"advertised_routes"`
	ApprovedRoutes   []string `json:"approved_routes"`
	PendingRoutes    []string `json:"pending_routes"`
	TailnetName      string   `json:"tailnet_name,omitempty"`
	MagicDNSSuffix   string   `json:"magic_dns_suffix,omitempty"`
	Version          string   `json:"version,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
	// AvailableExitNodes is the list a UI dropdown should offer.
	AvailableExitNodes []Node `json:"available_exit_nodes"`
}

type Node struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	DNSName        string    `json:"dns_name"`
	Addresses      []string  `json:"addresses"`
	OS             string    `json:"os,omitempty"`
	Online         bool      `json:"online"`
	ExitNodeOption bool      `json:"exit_node_option"`
	IsExitNode     bool      `json:"is_exit_node"`
	LastSeen       time.Time `json:"last_seen,omitzero"`
	RxBytes        int64     `json:"rx_bytes"`
	TxBytes        int64     `json:"tx_bytes"`
	Routes         []string  `json:"routes,omitempty"`
}

func NewTailscale(cfg *config.Config, log func(string, ...any)) *Tailscale {
	if log == nil {
		log = func(string, ...any) {}
	}
	t := &Tailscale{cfg: cfg, log: log}
	if path, err := exec.LookPath("tailscale"); err == nil {
		t.available, t.binary = true, path
	} else {
		t.lastError = "tailscale is not installed on this node"
	}
	return t
}

func (t *Tailscale) Available() bool { return t.available }

// Up applies the configured state. `tailscale up` is idempotent and is the
// only supported way to change these flags, so every setting change funnels
// through one command rather than a pile of `tailscale set` calls that can
// disagree with each other.
func (t *Tailscale) Up(ctx context.Context) error {
	if !t.available {
		return fmt.Errorf("%s", t.lastError)
	}
	c := t.cfg.Snapshot().Tailscale
	if !c.Enabled {
		return nil
	}

	args := []string{"up", "--reset"}

	if c.Hostname != "" {
		args = append(args, "--hostname="+c.Hostname)
	}
	if c.AuthKey != "" {
		args = append(args, "--authkey="+c.AuthKey)
	}
	if c.LoginServer != "" {
		// Headscale and other coordination servers live here.
		args = append(args, "--login-server="+c.LoginServer)
	}

	if c.AdvertiseExitNode {
		args = append(args, "--advertise-exit-node")
	}
	if c.ExitNode != "" {
		args = append(args, "--exit-node="+c.ExitNode)
		// Without this, selecting an exit node also blackholes access to the
		// local network — including this box's own UI, from a device that is
		// steered through the tunnel.
		if c.ExitNodeAllowLAN {
			args = append(args, "--exit-node-allow-lan-access")
		}
	} else {
		// Passing an empty value is how you clear a previously-set exit node.
		args = append(args, "--exit-node=")
	}

	if len(c.AdvertiseRoutes) > 0 {
		args = append(args, "--advertise-routes="+strings.Join(c.AdvertiseRoutes, ","))
	}
	// Never bring the node up with route acceptance on while a peer covers
	// our own LAN; that combination is what strands it.
	acceptRoutes := c.AcceptRoutes
	if acceptRoutes {
		if overlap := t.OverlappingRoutes(ctx); len(overlap) > 0 {
			t.log("tailscale: NOT accepting routes — a peer advertises %s, which covers this "+
				"node's own network and would take it off the LAN", strings.Join(overlap, ", "))
			acceptRoutes = false
		}
	}
	args = append(args, fmt.Sprintf("--accept-routes=%t", acceptRoutes))
	// Accepting the tailnet's DNS would override the resolver this whole
	// product exists to run, so it defaults off and is called out in the UI.
	args = append(args, fmt.Sprintf("--accept-dns=%t", c.AcceptDNS))
	if c.SSH {
		args = append(args, "--ssh")
	}
	if c.ShieldsUp {
		args = append(args, "--shields-up")
	}
	// Non-interactive: without this the command blocks forever waiting for a
	// browser login that nobody is watching for on a headless appliance.
	if c.AuthKey == "" {
		args = append(args, "--timeout=25s")
	}

	out, err := t.run(ctx, 60*time.Second, args...)
	if err != nil {
		// A node that is not logged in reports the auth URL on stderr; that
		// is actionable, not a failure, so it is surfaced rather than hidden.
		if url := extractAuthURL(out); url != "" {
			t.setError("waiting for login: " + url)
			return fmt.Errorf("tailscale needs to be authenticated: %s", url)
		}
		t.setError(err.Error())
		return err
	}
	t.setError("")
	t.invalidate()
	t.log("tailscale: applied (exit-node-advertise=%v exit-node=%q routes=%v)",
		c.AdvertiseExitNode, c.ExitNode, c.AdvertiseRoutes)
	return nil
}

func (t *Tailscale) Down(ctx context.Context) error {
	if !t.available {
		return nil
	}
	if _, err := t.run(ctx, 30*time.Second, "down"); err != nil {
		return err
	}
	t.invalidate()
	return nil
}

// Logout fully deauthenticates, which is what "remove this node" means.
func (t *Tailscale) Logout(ctx context.Context) error {
	if !t.available {
		return nil
	}
	_, err := t.run(ctx, 30*time.Second, "logout")
	t.invalidate()
	return err
}

// LoginURL starts an interactive login and returns the URL to visit.
func (t *Tailscale) LoginURL(ctx context.Context) (string, error) {
	if !t.available {
		return "", fmt.Errorf("%s", t.lastError)
	}
	out, err := t.run(ctx, 30*time.Second, "login", "--timeout=20s")
	if url := extractAuthURL(out); url != "" {
		return url, nil
	}
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("tailscale did not return a login URL (it may already be logged in)")
}

// SetExitNode switches egress to a peer, or clears it when name is empty.
// This is a hot path from the UI dropdown, so it persists the choice and
// re-applies rather than only changing the running state.
func (t *Tailscale) SetExitNode(ctx context.Context, name string) error {
	if err := t.cfg.Update(func(c *config.Config) { c.Tailscale.ExitNode = name }); err != nil {
		return err
	}
	if name == "" {
		if _, err := t.run(ctx, 30*time.Second, "set", "--exit-node="); err != nil {
			return err
		}
	} else {
		args := []string{"set", "--exit-node=" + name}
		if t.cfg.Snapshot().Tailscale.ExitNodeAllowLAN {
			args = append(args, "--exit-node-allow-lan-access=true")
		}
		if _, err := t.run(ctx, 30*time.Second, args...); err != nil {
			return err
		}
	}
	t.invalidate()
	return nil
}

// SetAdvertiseExitNode toggles offering this node as an exit node.
func (t *Tailscale) SetAdvertiseExitNode(ctx context.Context, on bool) error {
	if err := t.cfg.Update(func(c *config.Config) { c.Tailscale.AdvertiseExitNode = on }); err != nil {
		return err
	}
	if _, err := t.run(ctx, 30*time.Second, "set", fmt.Sprintf("--advertise-exit-node=%t", on)); err != nil {
		return err
	}
	t.invalidate()
	if on {
		t.log("tailscale: advertising as exit node — approve it in the Tailscale admin console before it can carry traffic")
	}
	return nil
}

// SetAdvertiseRoutes publishes LAN subnets into the tailnet, turning this
// node into a subnet router so remote devices can reach the local network
// without a VPN client on every host.
func (t *Tailscale) SetAdvertiseRoutes(ctx context.Context, routes []string) error {
	if err := t.cfg.Update(func(c *config.Config) { c.Tailscale.AdvertiseRoutes = routes }); err != nil {
		return err
	}
	arg := "--advertise-routes=" + strings.Join(routes, ",")
	if len(routes) == 0 {
		arg = "--advertise-routes="
	}
	if _, err := t.run(ctx, 30*time.Second, "set", arg); err != nil {
		return err
	}
	t.invalidate()
	return nil
}

// ---- status ----

// tailscale status --json shape. Only the fields used are declared.
type rawStatus struct {
	Version        string              `json:"Version"`
	BackendState   string              `json:"BackendState"`
	AuthURL        string              `json:"AuthURL"`
	TailscaleIPs   []string            `json:"TailscaleIPs"`
	Self           *rawNode            `json:"Self"`
	Peer           map[string]*rawNode `json:"Peer"`
	ExitNodeStatus *struct {
		ID           string   `json:"ID"`
		Online       bool     `json:"Online"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"ExitNodeStatus"`
	CurrentTailnet *struct {
		Name            string `json:"Name"`
		MagicDNSSuffix  string `json:"MagicDNSSuffix"`
		MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
	} `json:"CurrentTailnet"`
	Health []string `json:"Health"`
}

type rawNode struct {
	ID             string    `json:"ID"`
	HostName       string    `json:"HostName"`
	DNSName        string    `json:"DNSName"`
	OS             string    `json:"OS"`
	TailscaleIPs   []string  `json:"TailscaleIPs"`
	Online         bool      `json:"Online"`
	LastSeen       time.Time `json:"LastSeen"`
	RxBytes        int64     `json:"RxBytes"`
	TxBytes        int64     `json:"TxBytes"`
	ExitNode       bool      `json:"ExitNode"`
	ExitNodeOption bool      `json:"ExitNodeOption"`
	PrimaryRoutes  []string  `json:"PrimaryRoutes"`
	AllowedIPs     []string  `json:"AllowedIPs"`
}

// rawPrefs is the shape of `tailscale debug prefs`, which is the only place
// the *requested* (as opposed to approved) route set is visible.
type rawPrefs struct {
	AdvertiseRoutes        []string `json:"AdvertiseRoutes"`
	ExitNodeID             string   `json:"ExitNodeID"`
	ExitNodeIP             string   `json:"ExitNodeIP"`
	ExitNodeAllowLANAccess bool     `json:"ExitNodeAllowLANAccess"`
	RouteAll               bool     `json:"RouteAll"`
	CorpDNS                bool     `json:"CorpDNS"`
	Hostname               string   `json:"Hostname"`
	RunSSH                 bool     `json:"RunSSH"`
	ShieldsUp              bool     `json:"ShieldsUp"`
}

// Status queries the daemon. Results are cached briefly because the dashboard
// polls and each call forks a process.
func (t *Tailscale) Status(ctx context.Context) *Status {
	t.mu.Lock()
	if t.cached != nil && time.Since(t.lastSync) < 5*time.Second {
		cached := *t.cached
		t.mu.Unlock()
		return &cached
	}
	lastErr := t.lastError
	t.mu.Unlock()

	st := &Status{Available: t.available, LastError: lastErr, Peers: []Node{}, AvailableExitNodes: []Node{}}
	if !t.available {
		return st
	}

	out, err := t.run(ctx, 10*time.Second, "status", "--json", "--peers")
	if err != nil {
		st.LastError = strings.TrimSpace(out)
		if st.LastError == "" {
			st.LastError = err.Error()
		}
		return st
	}
	var raw rawStatus
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		st.LastError = "could not parse tailscale status: " + err.Error()
		return st
	}

	st.Version = raw.Version
	st.BackendState = raw.BackendState
	st.Running = raw.BackendState == "Running"
	st.AuthURL = raw.AuthURL
	if raw.CurrentTailnet != nil {
		st.TailnetName = raw.CurrentTailnet.Name
		st.MagicDNSSuffix = raw.CurrentTailnet.MagicDNSSuffix
	}
	if raw.Self != nil {
		self := convertNode(raw.Self)
		st.Self = &self
		// Tailscale signals exit-node approval by listing the default routes
		// in the node's own AllowedIPs. Advertised-but-unapproved shows the
		// flag in prefs with no matching AllowedIP.
		for _, ip := range raw.Self.AllowedIPs {
			if ip == "0.0.0.0/0" || ip == "::/0" {
				st.ExitNodeApproved = true
				break
			}
		}
		st.ApprovedRoutes = raw.Self.PrimaryRoutes
	}

	for _, p := range raw.Peer {
		n := convertNode(p)
		st.Peers = append(st.Peers, n)
		if n.ExitNodeOption {
			st.AvailableExitNodes = append(st.AvailableExitNodes, n)
		}
		if p.ExitNode {
			st.ExitNodeInUse = n.Name
		}
	}
	sort.Slice(st.Peers, func(i, j int) bool {
		if st.Peers[i].Online != st.Peers[j].Online {
			return st.Peers[i].Online
		}
		return st.Peers[i].Name < st.Peers[j].Name
	})
	sort.Slice(st.AvailableExitNodes, func(i, j int) bool {
		return st.AvailableExitNodes[i].Name < st.AvailableExitNodes[j].Name
	})

	// Prefs fill in what status cannot see.
	if prefsOut, err := t.run(ctx, 10*time.Second, "debug", "prefs"); err == nil {
		var prefs rawPrefs
		if json.Unmarshal([]byte(prefsOut), &prefs) == nil {
			for _, r := range prefs.AdvertiseRoutes {
				if r == "0.0.0.0/0" || r == "::/0" {
					st.AdvertisingExitNode = true
					continue
				}
				st.AdvertisedRoutes = append(st.AdvertisedRoutes, r)
			}
			approved := map[string]bool{}
			for _, r := range st.ApprovedRoutes {
				approved[r] = true
			}
			for _, r := range st.AdvertisedRoutes {
				if !approved[r] {
					st.PendingRoutes = append(st.PendingRoutes, r)
				}
			}
			if st.ExitNodeInUse == "" && prefs.ExitNodeIP != "" {
				st.ExitNodeInUse = prefs.ExitNodeIP
			}
		}
	}
	if len(raw.Health) > 0 && st.LastError == "" {
		st.LastError = strings.Join(raw.Health, "; ")
	}

	t.mu.Lock()
	t.cached = st
	t.lastSync = time.Now()
	t.mu.Unlock()
	cp := *st
	return &cp
}

func convertNode(n *rawNode) Node {
	name := n.HostName
	if name == "" {
		name = strings.TrimSuffix(n.DNSName, ".")
	}
	return Node{
		ID: n.ID, Name: name, DNSName: strings.TrimSuffix(n.DNSName, "."),
		Addresses: n.TailscaleIPs, OS: n.OS, Online: n.Online,
		ExitNodeOption: n.ExitNodeOption, IsExitNode: n.ExitNode,
		LastSeen: n.LastSeen, RxBytes: n.RxBytes, TxBytes: n.TxBytes,
		Routes: n.PrimaryRoutes,
	}
}

// OverlappingRoutes reports subnet routes offered by tailnet peers that cover
// a network this node is already directly attached to.
//
// This is the failure that takes a subnet-routed node off its own LAN: with
// accept-routes on, Tailscale installs the peer's route into table 52, an
// `ip rule` sends everything through that table first, and traffic destined
// for the LAN two feet away goes into the tunnel instead. The return path
// does not match, so the node simply stops answering — including on SSH.
func (t *Tailscale) OverlappingRoutes(ctx context.Context) []string {
	local := localPrefixes()
	if len(local) == 0 {
		return nil
	}
	st := t.Status(ctx)
	seen := map[string]bool{}
	var out []string
	for _, p := range st.Peers {
		for _, r := range p.Routes {
			pfx, err := netip.ParsePrefix(r)
			if err != nil || pfx.Bits() == 0 {
				continue // a default route is the exit-node case, not this
			}
			for _, l := range local {
				// Either direction of containment is a problem: a peer
				// advertising a supernet of our LAN is just as disruptive.
				if pfx.Overlaps(l) && !seen[r] {
					seen[r] = true
					out = append(out, r)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// localPrefixes returns the networks this node is directly attached to,
// excluding the tunnel itself.
func localPrefixes() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "tailscale") ||
			strings.HasPrefix(i.Name, "wg") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			pfx, err := netip.ParsePrefix(ipnet.String())
			if err != nil {
				continue
			}
			pfx = pfx.Masked()
			if pfx.Addr().IsLinkLocalUnicast() || pfx.Bits() == 0 {
				continue
			}
			out = append(out, pfx)
		}
	}
	return out
}

// SetAcceptRoutes toggles route acceptance, refusing to enable it while a
// peer advertises a prefix covering this node's own LAN.
func (t *Tailscale) SetAcceptRoutes(ctx context.Context, on bool) error {
	if on {
		if overlap := t.OverlappingRoutes(ctx); len(overlap) > 0 {
			return fmt.Errorf(
				"a tailnet peer advertises %s, which covers this node's own network — "+
					"accepting it would route local traffic into the tunnel and take this node "+
					"off the LAN. Stop advertising that route, or leave route acceptance off",
				strings.Join(overlap, ", "))
		}
	}
	if err := t.cfg.Update(func(c *config.Config) { c.Tailscale.AcceptRoutes = on }); err != nil {
		return err
	}
	if _, err := t.run(ctx, 30*time.Second, "set", fmt.Sprintf("--accept-routes=%t", on)); err != nil {
		return err
	}
	t.invalidate()
	return nil
}

// SteerPrefixes returns the LAN CIDRs whose traffic should be policy-routed
// into the Tailscale exit node. The firewall renderer uses this to mark
// packets; without marking, selecting an exit node routes the *node's own*
// traffic and leaves LAN clients going out the WAN as before.
func (t *Tailscale) SteerPrefixes() []string {
	c := t.cfg.Snapshot().Tailscale
	if !c.Enabled || c.ExitNode == "" {
		return nil
	}
	return c.SteerClients
}

func (t *Tailscale) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, t.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	combined := stdout.String()
	if stderr.Len() > 0 {
		combined = combined + stderr.String()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return combined, fmt.Errorf("tailscale %s: %s", strings.Join(args, " "), firstLines(msg, 3))
	}
	return combined, nil
}

func (t *Tailscale) setError(msg string) {
	t.mu.Lock()
	t.lastError = msg
	t.mu.Unlock()
}

func (t *Tailscale) invalidate() {
	t.mu.Lock()
	t.cached = nil
	t.mu.Unlock()
}

// extractAuthURL pulls the login link out of CLI output.
func extractAuthURL(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "https://login.tailscale.com/"); i >= 0 {
			return strings.Fields(line[i:])[0]
		}
		if i := strings.Index(line, "https://"); i >= 0 && strings.Contains(line, "/a/") {
			return strings.Fields(line[i:])[0]
		}
	}
	return ""
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// ---- policy routing for steered clients ----

// tailscaleRouteTable is the table the tailscaled daemon populates with the
// exit-node default route. Reusing it (rather than building our own) means we
// inherit Tailscale's own route management, including tearing the route down
// when the exit node goes offline.
const tailscaleRouteTable = "52"

// steerPriority sits above Tailscale's own rules (5210+) so a steered source
// address is matched before the generic ones, and above the main table so it
// wins over the normal default route.
const steerPriority = 5100

// ApplySteering installs `ip rule` entries sending the configured LAN sources
// into Tailscale's routing table, so selected devices egress through the
// chosen exit node while everything else uses the WAN.
//
// This is the piece people expect to exist and usually have to build by hand:
// `tailscale up --exit-node=X` only moves this node's own traffic.
func (t *Tailscale) ApplySteering(ctx context.Context) error {
	if !t.available {
		return nil
	}
	c := t.cfg.Snapshot().Tailscale

	// Always clear first so removing a client from the list actually stops
	// steering it, and so a changed list never leaves stale rules behind.
	t.clearSteering(ctx)

	if !c.Enabled || c.ExitNode == "" || len(c.SteerClients) == 0 {
		return nil
	}
	var failed []string
	for _, src := range c.SteerClients {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		err := run(ctx, "ip", "rule", "add", "from", src,
			"lookup", tailscaleRouteTable, "priority", fmt.Sprint(steerPriority))
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", src, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not steer %s", strings.Join(failed, ", "))
	}
	t.log("tailscale: steering %d source(s) through exit node %q", len(c.SteerClients), c.ExitNode)
	return nil
}

// clearSteering removes every rule we own. Rules are identified by priority,
// which is why a dedicated priority was chosen rather than letting the kernel
// assign one.
func (t *Tailscale) clearSteering(ctx context.Context) {
	// `ip rule del priority N` removes one rule per call; loop until the
	// kernel reports there is nothing left at that priority.
	for i := 0; i < 64; i++ {
		if err := run(ctx, "ip", "rule", "del", "priority", fmt.Sprint(steerPriority)); err != nil {
			return
		}
	}
}

// SteeringActive reports the rules currently installed, so the UI can show
// what is really in effect rather than what was configured.
func (t *Tailscale) SteeringActive(ctx context.Context) []string {
	out, err := t.runIP(ctx, "rule", "show")
	if err != nil {
		return nil
	}
	var active []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), fmt.Sprint(steerPriority)+":") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "from" && i+1 < len(fields) {
				active = append(active, fields[i+1])
			}
		}
	}
	return active
}

func (t *Tailscale) runIP(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "ip", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// InstallHint returns the command to install Tailscale, shown in the UI when
// the binary is missing so the operator does not have to go looking.
func InstallHint() string {
	return "curl -fsSL https://tailscale.com/install.sh | sh"
}
