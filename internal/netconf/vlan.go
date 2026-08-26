// Package netconf manages the interfaces Orbis creates itself: 802.1Q VLANs
// today, and anything else that has to exist before zones, DHCP scopes and
// firewall rules can refer to it.
package netconf

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A VLAN is the unit of network separation people actually have: one physical
// link from the switch, several logical networks on it. Orbis creates the
// tagged interface, and zones, DHCP scopes and firewall rules then refer to
// it by name like any other interface. Doing it here rather than expecting
// the operator to configure it out of band is what makes a VLAN useful the
// moment it is created — an unzoned VLAN with no scope is inert.
type VLAN struct {
	// Name is the interface name. Defaults to <parent>.<id>, the convention
	// every other tool on the box uses.
	Name string `yaml:"name" json:"name"`
	// Parent is the physical interface carrying the tagged traffic.
	Parent string `yaml:"parent" json:"parent"`
	// ID is the 802.1Q tag, 1-4094.
	ID int `yaml:"id" json:"id"`
	// Address is this node's address on the VLAN, in CIDR form. It is the
	// gateway address for devices on it.
	Address string `yaml:"address" json:"address"`
	// MTU below the parent's is occasionally needed when an upstream link
	// does not carry the extra four bytes of tag.
	MTU     int  `yaml:"mtu" json:"mtu"`
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Zone gives the VLAN a trust level without a second configuration step.
	Zone        string `yaml:"zone" json:"zone"`
	Description string `yaml:"description" json:"description"`
}

// DefaultName is the conventional name for a tagged interface.
func (v VLAN) DefaultName() string {
	if v.Name != "" {
		return v.Name
	}
	return fmt.Sprintf("%s.%d", v.Parent, v.ID)
}

func (v VLAN) Validate() error {
	if v.Parent == "" {
		return fmt.Errorf("a VLAN needs a parent interface")
	}
	// 0 means "priority tagged" and 4095 is reserved; both are excluded.
	if v.ID < 1 || v.ID > 4094 {
		return fmt.Errorf("VLAN id %d is out of range (1-4094)", v.ID)
	}
	if v.Address != "" {
		pfx, err := netip.ParsePrefix(v.Address)
		if err != nil {
			return fmt.Errorf("VLAN %d address %q must be in CIDR form, e.g. 192.168.20.1/24", v.ID, v.Address)
		}
		if pfx.Addr().Is4() && pfx.Bits() > 30 {
			return fmt.Errorf("VLAN %d address %q leaves no room for clients", v.ID, v.Address)
		}
	}
	if len(v.DefaultName()) > 15 {
		return fmt.Errorf("interface name %q is longer than Linux allows (15 characters)", v.DefaultName())
	}
	return nil
}

// State is the live condition of a VLAN interface.
type State struct {
	VLAN
	Present   bool     `json:"present"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
	RxBytes   int64    `json:"rx_bytes"`
	TxBytes   int64    `json:"tx_bytes"`
	Error     string   `json:"error,omitempty"`
}

type Manager struct {
	log func(string, ...any)

	mu      sync.Mutex
	applied map[string]VLAN
	lastErr string
}

func NewManager(log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{log: log, applied: map[string]VLAN{}}
}

// Available reports whether tagged interfaces can be created at all. In an
// unprivileged container they cannot, and saying so once beats a stream of
// permission errors the operator has to interpret.
func (m *Manager) Available() (bool, string) {
	if _, err := exec.LookPath("ip"); err != nil {
		return false, "the ip command is not installed"
	}

	// The probe has to run against a real interface. Loopback never supports
	// VLAN tagging, so probing it reports "VLANs not supported on device"
	// whether or not the module is loaded — which is a false negative that
	// tells the operator to fix something that is not broken.
	parent := firstPhysicalInterface()
	if parent == "" {
		return false, "no physical interface to build a VLAN on"
	}

	const probe = "orbisprb0"
	_ = exec.Command("ip", "link", "del", probe).Run()
	out, err := exec.Command("ip", "link", "add", "link", parent, "name", probe,
		"type", "vlan", "id", "4094").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		switch {
		case strings.Contains(msg, "not permitted"):
			return false, "creating VLAN interfaces needs CAP_NET_ADMIN; in a container, run it privileged"
		case strings.Contains(msg, "Unknown device type"), strings.Contains(msg, "not supported"):
			return false, "the 8021q kernel module is not loaded — run `modprobe 8021q` on the host"
		case msg == "":
			return false, err.Error()
		}
		return false, msg
	}
	_ = exec.Command("ip", "link", "del", probe).Run()
	return true, ""
}

// firstPhysicalInterface picks something a VLAN can actually be built on:
// up, not loopback, not itself a tunnel or a tagged interface.
func firstPhysicalInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	skip := []string{"wg", "tailscale", "docker", "veth", "br-", "tun", "tap", "virbr"}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || strings.Contains(i.Name, ".") {
			continue
		}
		bad := false
		for _, p := range skip {
			if strings.HasPrefix(i.Name, p) {
				bad = true
				break
			}
		}
		if !bad {
			return i.Name
		}
	}
	return ""
}

// Apply reconciles the configured VLANs with what exists: creates what is
// missing, updates what changed, removes what Orbis created and the operator
// has since deleted.
//
// Only interfaces Orbis created are ever removed. A VLAN configured by hand,
// or by the host, is left strictly alone — deleting someone else's interface
// because it was not in our config would be unforgivable.
func (m *Manager) Apply(ctx context.Context, vlans []VLAN) error {
	var problems []string
	wanted := map[string]VLAN{}

	for _, v := range vlans {
		if !v.Enabled {
			continue
		}
		if err := v.Validate(); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		name := v.DefaultName()
		wanted[name] = v
		if err := m.ensure(ctx, v); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
		}
	}

	m.mu.Lock()
	previously := make(map[string]VLAN, len(m.applied))
	for k, v := range m.applied {
		previously[k] = v
	}
	m.mu.Unlock()

	for name := range previously {
		if _, still := wanted[name]; still {
			continue
		}
		if err := m.remove(ctx, name); err != nil {
			problems = append(problems, fmt.Sprintf("removing %s: %v", name, err))
			continue
		}
		m.log("network: removed VLAN interface %s", name)
	}

	m.mu.Lock()
	m.applied = wanted
	m.lastErr = strings.Join(problems, "; ")
	m.mu.Unlock()

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func (m *Manager) ensure(ctx context.Context, v VLAN) error {
	name := v.DefaultName()

	if _, err := net.InterfaceByName(v.Parent); err != nil {
		return fmt.Errorf("parent interface %s does not exist", v.Parent)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		if err := run(ctx, "ip", "link", "add", "link", v.Parent,
			"name", name, "type", "vlan", "id", strconv.Itoa(v.ID)); err != nil {
			return err
		}
		m.log("network: created VLAN %d on %s as %s", v.ID, v.Parent, name)
	}
	if v.MTU > 0 {
		_ = run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(v.MTU), "dev", name)
	}
	if v.Address != "" {
		// Compare before flushing. Removing an address and putting the same
		// one back drops every connection through the interface for no
		// reason, which on a busy VLAN is extremely visible.
		current, _ := interfaceAddresses(name)
		if !containsAddr(current, v.Address) {
			_ = run(ctx, "ip", "address", "flush", "dev", name)
			if err := run(ctx, "ip", "address", "add", v.Address, "dev", name); err != nil {
				return fmt.Errorf("address %s: %w", v.Address, err)
			}
		}
	}
	return run(ctx, "ip", "link", "set", "up", "dev", name)
}

func (m *Manager) remove(ctx context.Context, name string) error {
	if _, err := net.InterfaceByName(name); err != nil {
		return nil // already gone
	}
	return run(ctx, "ip", "link", "del", name)
}

// States reports the live condition of every configured VLAN.
func (m *Manager) States(vlans []VLAN) []State {
	out := make([]State, 0, len(vlans))
	for _, v := range vlans {
		st := State{VLAN: v}
		st.Name = v.DefaultName()
		if err := v.Validate(); err != nil {
			st.Error = err.Error()
		}
		iface, err := net.InterfaceByName(st.Name)
		if err == nil {
			st.Present = true
			st.Up = iface.Flags&net.FlagUp != 0
			st.Addresses, _ = interfaceAddresses(st.Name)
			st.RxBytes, st.TxBytes = interfaceCounters(st.Name)
		} else if v.Enabled && st.Error == "" {
			st.Error = "interface not present"
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func interfaceAddresses(name string) ([]string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipnet.String())
		}
	}
	return out, nil
}

func containsAddr(list []string, want string) bool {
	wantPfx, err := netip.ParsePrefix(want)
	if err != nil {
		return false
	}
	for _, a := range list {
		if pfx, err := netip.ParsePrefix(a); err == nil && pfx == wantPfx {
			return true
		}
	}
	return false
}

// interfaceCounters reads the kernel's per-interface byte counters, which is
// how the UI shows whether a VLAN is carrying anything at all.
func interfaceCounters(name string) (rx, tx int64) {
	read := func(file string) int64 {
		b, err := os.ReadFile("/sys/class/net/" + name + "/statistics/" + file)
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return n
	}
	return read("rx_bytes"), read("tx_bytes")
}

func run(ctx context.Context, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}
