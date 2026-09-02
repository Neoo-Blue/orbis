//go:build linux

package intercept

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// The forwarding rules for intercepted clients.
//
// Once a client believes Orbis is the gateway, its outbound packets arrive here
// with the client's own source address. Three things have to happen or the
// client is worse off than before: the packet must be forwarded to the real
// gateway, it must be masqueraded so the reply comes back to this node, and
// (optionally) its DNS and web traffic must be steered into the filters. All of
// it lives in a dedicated table so enabling and disabling interception never
// touches the main firewall ruleset.
//
// This table is intentionally separate from the ARP engine: the poisoning can
// be running while forwarding is being reconfigured, and tearing down the ARP
// side must not depend on the nftables side or vice versa.

const forwardTable = "orbis_intercept"

// ForwardConfig controls what happens to intercepted traffic.
type ForwardConfig struct {
	// LANInterface is where intercepted clients live and where their traffic
	// is masqueraded from towards the gateway.
	LANInterface string
	// Clients are the source addresses to act on. Only these are touched, so a
	// device that is not enrolled is forwarded normally with no filtering.
	Clients []netip.Addr
	// RedirectDNS steers client DNS to the local resolver, so a device with a
	// hardcoded resolver is still filtered.
	RedirectDNS bool
	DNSPort     int
	// RedirectHTTP steers ports 80/443 into the intercepting proxy. Off unless
	// the operator opted in, because a client without the CA breaks on it.
	RedirectHTTP bool
	HTTPPort     int
	HTTPSPort    int
	// HTTPScoped narrows the web redirect to HTTPClients (the ones with the
	// certificate) instead of every intercepted client. With HTTPScoped set
	// and HTTPClients empty, nobody is web-redirected: an operator who has
	// named the certificate holders and named none is not asking for every
	// device to be broken. QUIC is refused for the same set, so a browser
	// falls back to the TCP the proxy can see instead of riding HTTP/3
	// straight past it.
	HTTPScoped  bool
	HTTPClients []netip.Addr
}

// ApplyForwarding installs the intercept table. It is idempotent: the table is
// deleted and rebuilt each call, which is how a change to the client list takes
// effect without leaving stale rules behind.
func ApplyForwarding(ctx context.Context, cfg ForwardConfig) error {
	if len(cfg.Clients) == 0 {
		return RemoveForwarding(ctx)
	}
	script := renderForwarding(cfg)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply intercept rules: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveForwarding tears the table down. Safe to call when it does not exist.
func RemoveForwarding(ctx context.Context) error {
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "ip", forwardTable).Run()
	return nil
}

// renderForwarding builds the ruleset. It is a pure function of its input so it
// can be unit-tested without touching the kernel.
func renderForwarding(cfg ForwardConfig) string {
	var b strings.Builder
	w := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	clientSet := make([]string, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		if c.Is4() {
			clientSet = append(clientSet, c.String())
		}
	}
	members := strings.Join(clientSet, ", ")

	// Replace, never merge. nft -f with a bare table block adds to an existing
	// table, which is how the client set accumulates stale members and the
	// chains gain duplicate rules. add-then-delete guarantees the delete has a
	// target (a no-op add is harmless) so the script never aborts, and what
	// follows is a fresh table.
	w("add table ip %s", forwardTable)
	w("delete table ip %s", forwardTable)
	w("table ip %s {", forwardTable)

	// A named set makes the client list one atom, so matching is a set lookup
	// rather than one rule per device.
	w("  set clients {")
	w("    type ipv4_addr")
	if members != "" {
		w("    elements = { %s }", members)
	}
	w("  }")
	if cfg.RedirectHTTP && cfg.HTTPScoped && len(cfg.HTTPClients) > 0 {
		webMembers := make([]string, 0, len(cfg.HTTPClients))
		for _, a := range cfg.HTTPClients {
			webMembers = append(webMembers, a.String())
		}
		w("  set web_clients {")
		w("    type ipv4_addr")
		w("    elements = { %s }", strings.Join(webMembers, ", "))
		w("  }")
	}

	// Masquerade intercepted clients out towards the gateway. Without this the
	// reply is sent to the client's real path and never comes back here, so the
	// connection hangs.
	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat + 5; policy accept;")
	w("    ip saddr @clients oifname %q counter masquerade comment \"intercept: nat client traffic\"",
		cfg.LANInterface)
	w("  }")

	// DNS and web redirects, in a prerouting chain at a priority ahead of the
	// main proxy so an enrolled client is filtered even if the main ruleset is
	// not installed.
	w("  chain prerouting {")
	w("    type nat hook prerouting priority dstnat - 5; policy accept;")
	if cfg.RedirectDNS && cfg.DNSPort > 0 {
		w("    ip saddr @clients udp dport 53 redirect to :%d comment \"intercept: filter dns\"", cfg.DNSPort)
		w("    ip saddr @clients tcp dport 53 redirect to :%d comment \"intercept: filter dns\"", cfg.DNSPort)
	}
	web := "clients"
	webRedirect := cfg.RedirectHTTP && cfg.HTTPPort > 0 && cfg.HTTPSPort > 0
	if cfg.HTTPScoped {
		web = "web_clients"
		if len(cfg.HTTPClients) == 0 {
			webRedirect = false
		}
	}
	if webRedirect {
		w("    ip saddr @%s tcp dport 80 redirect to :%d comment \"intercept: filter http\"", web, cfg.HTTPPort)
		w("    ip saddr @%s tcp dport 443 redirect to :%d comment \"intercept: filter https\"", web, cfg.HTTPSPort)
	}
	w("  }")

	// A web-intercepted client must not be allowed to use QUIC: the proxy
	// cannot see HTTP/3, and YouTube in particular will happily use it and
	// sail past the filter. Refusing UDP/443 makes the browser fall back to
	// TCP within a second and remember that for the session.
	if webRedirect {
		w("  chain forward {")
		w("    type filter hook forward priority filter - 5; policy accept;")
		w("    ip saddr @%s udp dport 443 counter reject with icmp type port-unreachable comment \"intercept: no quic past the filter\"", web)
		w("  }")
	}

	w("}")
	return b.String()
}

// EnableForwardingSysctl turns on IP forwarding, which the kernel needs before
// it will route a packet that arrived for a different destination. Returns the
// prior value so it can be restored.
func EnableForwardingSysctl() (bool, error) {
	prior := readForwarding()
	if !prior {
		if err := writeForwarding(true); err != nil {
			return prior, err
		}
	}
	return prior, nil
}

func readForwarding() bool {
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	return err == nil && strings.TrimSpace(string(out)) == "1"
}

func writeForwarding(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sysctl", "-w", "net.ipv4.ip_forward="+v).Run()
}
