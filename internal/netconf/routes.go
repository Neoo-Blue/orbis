package netconf

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// StaticRoute is an operator-configured route. Until this existed the only way
// to reach a network behind another router was a tunnel or a manual `ip route`
// that vanished on reboot.
type StaticRoute struct {
	Name        string `yaml:"name" json:"name"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Destination string `yaml:"destination" json:"destination"` // CIDR
	Gateway     string `yaml:"gateway" json:"gateway"`
	Interface   string `yaml:"interface" json:"interface"`
	Metric      int    `yaml:"metric" json:"metric"`
	// Table routes into a policy-routing table instead of the main one.
	Table int `yaml:"table" json:"table"`
}

// Validate rejects a route that cannot work, so the error surfaces in the UI
// rather than as an opaque failure from the ip command.
func (r StaticRoute) Validate() error {
	if r.Destination == "" {
		return fmt.Errorf("destination is required")
	}
	dst, err := netip.ParsePrefix(r.Destination)
	if err != nil {
		return fmt.Errorf("destination %q is not a CIDR: %w", r.Destination, err)
	}
	if r.Gateway == "" && r.Interface == "" {
		return fmt.Errorf("a route needs a gateway, an interface, or both")
	}
	if r.Gateway != "" {
		gw, err := netip.ParseAddr(r.Gateway)
		if err != nil {
			return fmt.Errorf("gateway %q is not an address: %w", r.Gateway, err)
		}
		if gw.Is4() != dst.Addr().Is4() {
			return fmt.Errorf("gateway and destination must be the same address family")
		}
	}
	return nil
}

// args builds the `ip route` arguments shared by add and delete.
func (r StaticRoute) args() []string {
	family := "-4"
	if p, err := netip.ParsePrefix(r.Destination); err == nil && !p.Addr().Is4() {
		family = "-6"
	}
	tail := []string{r.Destination}
	if r.Gateway != "" {
		tail = append(tail, "via", r.Gateway)
	}
	if r.Interface != "" {
		tail = append(tail, "dev", r.Interface)
	}
	if r.Metric > 0 {
		tail = append(tail, "metric", fmt.Sprint(r.Metric))
	}
	if r.Table > 0 {
		tail = append(tail, "table", fmt.Sprint(r.Table))
	}
	return append([]string{family, "route"}, tail...)
}

// ApplyRoutes reconciles the kernel with the configured set. Routes are
// replaced rather than added so re-applying is idempotent, which matters
// because this runs on every config change and at boot.
func (m *Manager) ApplyRoutes(ctx context.Context, routes []StaticRoute) error {
	var problems []string
	for _, r := range routes {
		if !r.Enabled {
			// Removing a disabled route is best effort: it may never have
			// been installed, and "route does not exist" is not an error
			// worth surfacing.
			a := r.args()
			cmd := append([]string{a[0], a[1], "del"}, a[2:]...)
			_ = exec.CommandContext(ctx, "ip", cmd...).Run()
			continue
		}
		if err := r.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		a := r.args()
		cmd := append([]string{a[0], a[1], "replace"}, a[2:]...)
		out, err := exec.CommandContext(ctx, "ip", cmd...).CombinedOutput()
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v (%s)",
				r.Name, err, strings.TrimSpace(string(out))))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// KernelRoutes lists what the kernel currently has, so the UI can show the
// difference between what was asked for and what is actually installed.
func (m *Manager) KernelRoutes(ctx context.Context, v6 bool) ([]string, error) {
	family := "-4"
	if v6 {
		family = "-6"
	}
	out, err := exec.CommandContext(ctx, "ip", family, "route", "show").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip route show: %w", err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
