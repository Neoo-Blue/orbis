package firewall

import (
	"fmt"
	"os"
	"strings"
)

// requiredSysctls are the kernel knobs a router needs. They are reported to
// the UI rather than silently forced: on a shared host (an LXC on someone
// else's Proxmox, say) changing these affects more than this service, so the
// operator decides.
var requiredSysctls = []struct {
	Key      string
	Want     string
	Why      string
	Critical bool
}{
	{"net.ipv4.ip_forward", "1", "route traffic between interfaces", true},
	{"net.ipv6.conf.all.forwarding", "1", "route IPv6 between interfaces", false},
	{"net.netfilter.nf_conntrack_acct", "1", "per-connection byte counters for the flow table", false},
	{"net.netfilter.nf_conntrack_timestamp", "1", "connection start times for accurate flow duration", false},
	{"net.netfilter.nf_conntrack_max", "262144", "connection table size for a busy network", false},
	{"net.ipv4.conf.all.rp_filter", "2", "loose reverse-path filtering (strict breaks policy routing)", false},
	{"net.ipv4.conf.all.route_localnet", "1", "allow transparent proxy redirect to a loopback listener", false},
}

type SysctlStatus struct {
	Key      string `json:"key"`
	Want     string `json:"want"`
	Current  string `json:"current"`
	OK       bool   `json:"ok"`
	Why      string `json:"why"`
	Critical bool   `json:"critical"`
	Error    string `json:"error,omitempty"`
}

// CheckSysctls reports which kernel settings are missing for inline mode.
func CheckSysctls() []SysctlStatus {
	out := make([]SysctlStatus, 0, len(requiredSysctls))
	for _, s := range requiredSysctls {
		st := SysctlStatus{Key: s.Key, Want: s.Want, Why: s.Why, Critical: s.Critical}
		cur, err := readSysctl(s.Key)
		if err != nil {
			st.Error = err.Error()
		} else {
			st.Current = cur
			st.OK = cur == s.Want || (s.Want == "262144" && cur >= s.Want)
		}
		out = append(out, st)
	}
	return out
}

// ApplySysctls writes the recommended values. Called only when the operator
// explicitly asks, and it reports each failure rather than aborting, because
// an unprivileged container will refuse some of them and that is fine.
func ApplySysctls() []SysctlStatus {
	out := make([]SysctlStatus, 0, len(requiredSysctls))
	for _, s := range requiredSysctls {
		st := SysctlStatus{Key: s.Key, Want: s.Want, Why: s.Why, Critical: s.Critical}
		if err := writeSysctl(s.Key, s.Want); err != nil {
			st.Error = err.Error()
		}
		if cur, err := readSysctl(s.Key); err == nil {
			st.Current = cur
			st.OK = cur == s.Want
		}
		out = append(out, st)
	}
	return out
}

func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

func readSysctl(key string) (string, error) {
	b, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysctl(key, value string) error {
	if err := os.WriteFile(sysctlPath(key), []byte(value), 0o644); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}
