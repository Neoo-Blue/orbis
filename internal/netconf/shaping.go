package netconf

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Traffic shaping. The single most effective thing a home gateway can do for
// perceived speed is not raising bandwidth but killing bufferbloat, so the
// default here is CAKE, which does that with one queue discipline and no
// per-class configuration.
//
// CAKE needs to be the bottleneck to work, which is why the rate is set a few
// percent below the real line rate: if the modem is still the bottleneck, it
// holds the queue and no amount of shaping downstream can help.

// ShapingConfig configures egress shaping on the WAN interface.
type ShapingConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Interface string `yaml:"interface" json:"interface"`
	// UploadKbps / DownloadKbps are the real line rates. Orbis applies the
	// headroom itself rather than making the operator do arithmetic.
	UploadKbps   int `yaml:"upload_kbps" json:"upload_kbps"`
	DownloadKbps int `yaml:"download_kbps" json:"download_kbps"`
	// HeadroomPercent is shaved off both directions so this box, not the
	// modem, owns the queue. 5 is the usual recommendation.
	HeadroomPercent int `yaml:"headroom_percent" json:"headroom_percent"`
	// Overhead accounts for link-layer framing (docsis, pppoe, ethernet).
	Overhead string `yaml:"overhead" json:"overhead"`
	// Discipline is "cake" or "fq_codel". CAKE is better but is not present
	// on every kernel, so fq_codel remains selectable.
	Discipline string `yaml:"discipline" json:"discipline"`
	// PrioritiseDNSAndACK keeps interactive traffic ahead of bulk.
	PrioritiseDNSAndACK bool `yaml:"prioritise_interactive" json:"prioritise_interactive"`
}

// ShapingStatus reports what is actually installed, which is not always what
// was asked for: CAKE may be missing from the kernel.
type ShapingStatus struct {
	Applied     bool   `json:"applied"`
	Interface   string `json:"interface"`
	Discipline  string `json:"discipline"`
	EgressRate  int    `json:"egress_kbps"`
	IngressRate int    `json:"ingress_kbps"`
	Qdisc       string `json:"qdisc,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

const ifbDevice = "ifb-orbis"

// ApplyShaping installs (or removes) shaping. Ingress shaping needs an IFB
// device because Linux can only shape egress; inbound traffic is redirected to
// the IFB and shaped on its way out of it.
func (m *Manager) ApplyShaping(ctx context.Context, cfg ShapingConfig) (*ShapingStatus, error) {
	st := &ShapingStatus{Interface: cfg.Interface}

	if !cfg.Enabled {
		m.clearShaping(ctx, cfg.Interface)
		st.Detail = "shaping removed"
		return st, nil
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("shaping needs an interface")
	}
	if cfg.UploadKbps <= 0 && cfg.DownloadKbps <= 0 {
		return nil, fmt.Errorf("set at least one of upload_kbps or download_kbps")
	}

	disc := cfg.Discipline
	if disc == "" {
		disc = "cake"
	}
	if disc == "cake" && !qdiscAvailable(ctx, "cake") {
		disc = "fq_codel"
		st.Detail = "cake is not available in this kernel; using fq_codel"
	}
	head := cfg.HeadroomPercent
	if head <= 0 || head >= 50 {
		head = 5
	}
	shave := func(kbps int) int { return kbps * (100 - head) / 100 }

	// Start from a clean slate so re-applying is idempotent.
	m.clearShaping(ctx, cfg.Interface)

	// Egress (upload).
	if cfg.UploadKbps > 0 {
		rate := shave(cfg.UploadKbps)
		if out, err := installShaper(ctx, cfg.Interface, disc, rate, cfg); err != nil {
			return nil, fmt.Errorf("egress shaping: %w (%s)", err, out)
		}
		st.EgressRate = rate
	}

	// Ingress (download) via IFB.
	if cfg.DownloadKbps > 0 {
		rate := shave(cfg.DownloadKbps)
		if err := ensureIFB(ctx); err != nil {
			// Upload shaping alone is still worth having, so report the
			// partial success rather than unwinding it.
			st.Applied = st.EgressRate > 0
			st.Discipline = disc
			st.Detail = strings.TrimSpace(st.Detail + " ingress shaping unavailable: " + err.Error())
			return st, nil
		}
		if out, err := runTC(ctx, "qdisc", "add", "dev", cfg.Interface, "handle", "ffff:", "ingress"); err != nil {
			st.Detail = strings.TrimSpace(st.Detail + " ingress hook: " + out)
		}
		if out, err := runTC(ctx, "filter", "add", "dev", cfg.Interface, "parent", "ffff:",
			"protocol", "all", "u32", "match", "u32", "0", "0",
			"action", "mirred", "egress", "redirect", "dev", ifbDevice); err != nil {
			st.Detail = strings.TrimSpace(st.Detail + " ingress redirect: " + out)
		} else {
			if out, err := installShaper(ctx, ifbDevice, disc, rate, cfg); err != nil {
				st.Detail = strings.TrimSpace(st.Detail + " ingress qdisc: " + out)
			} else {
				st.IngressRate = rate
			}
		}
	}

	st.Applied = st.EgressRate > 0 || st.IngressRate > 0
	st.Discipline = disc
	st.Qdisc = m.showQdisc(ctx, cfg.Interface)
	return st, nil
}

// installShaper installs a rate-limited queue on dev.
//
// CAKE shapes and queues in one qdisc. fq_codel cannot rate-limit at all, so it
// has to sit underneath an HTB class that does the shaping: attaching bare
// fq_codel would fix fairness while leaving the link unshaped, which is a
// silent failure that looks like success in `tc qdisc show`.
func installShaper(ctx context.Context, dev, disc string, rateKbps int, cfg ShapingConfig) (string, error) {
	if disc == "cake" {
		args := []string{"qdisc", "add", "dev", dev, "root", "cake",
			"bandwidth", fmt.Sprintf("%dkbit", rateKbps)}
		if cfg.Overhead != "" {
			args = append(args, cfg.Overhead)
		}
		if cfg.PrioritiseDNSAndACK {
			// diffserv4 gives DNS, ACKs and other latency-sensitive traffic
			// their own tin instead of one flat queue.
			args = append(args, "diffserv4", "ack-filter")
		} else {
			args = append(args, "besteffort")
		}
		return runTC(ctx, args...)
	}

	// HTB root with a single shaped class, fq_codel inside it.
	if out, err := runTC(ctx, "qdisc", "add", "dev", dev, "root", "handle", "1:",
		"htb", "default", "10"); err != nil {
		return out, err
	}
	rate := fmt.Sprintf("%dkbit", rateKbps)
	if out, err := runTC(ctx, "class", "add", "dev", dev, "parent", "1:", "classid", "1:10",
		"htb", "rate", rate, "ceil", rate); err != nil {
		return out, err
	}
	return runTC(ctx, "qdisc", "add", "dev", dev, "parent", "1:10", "handle", "10:", "fq_codel")
}

func (m *Manager) clearShaping(ctx context.Context, iface string) {
	if iface == "" {
		return
	}
	_, _ = runTC(ctx, "qdisc", "del", "dev", iface, "root")
	_, _ = runTC(ctx, "qdisc", "del", "dev", iface, "ingress")
	_, _ = runTC(ctx, "qdisc", "del", "dev", ifbDevice, "root")
}

func (m *Manager) showQdisc(ctx context.Context, iface string) string {
	out, err := exec.CommandContext(ctx, "tc", "qdisc", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ShapingStatusFor reports the installed qdisc without changing anything.
func (m *Manager) ShapingStatusFor(ctx context.Context, iface string) *ShapingStatus {
	st := &ShapingStatus{Interface: iface}
	if iface == "" {
		return st
	}
	q := m.showQdisc(ctx, iface)
	st.Qdisc = q
	lower := strings.ToLower(q)
	st.Applied = strings.Contains(lower, "cake") || strings.Contains(lower, "fq_codel") ||
		strings.Contains(lower, "htb") || strings.Contains(lower, "tbf")
	switch {
	case strings.Contains(lower, "cake"):
		st.Discipline = "cake"
	case strings.Contains(lower, "fq_codel"):
		st.Discipline = "fq_codel"
	}
	return st
}

func ensureIFB(ctx context.Context) error {
	if out, err := exec.CommandContext(ctx, "modprobe", "ifb").CombinedOutput(); err != nil {
		// A container cannot load modules; if the device already exists the
		// module is present and this failure is harmless.
		if !ifbExists(ctx) {
			return fmt.Errorf("ifb module unavailable: %s", strings.TrimSpace(string(out)))
		}
	}
	if !ifbExists(ctx) {
		if out, err := exec.CommandContext(ctx, "ip", "link", "add", ifbDevice, "type", "ifb").CombinedOutput(); err != nil {
			return fmt.Errorf("create %s: %s", ifbDevice, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.CommandContext(ctx, "ip", "link", "set", ifbDevice, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bring up %s: %s", ifbDevice, strings.TrimSpace(string(out)))
	}
	return nil
}

func ifbExists(ctx context.Context) bool {
	err := exec.CommandContext(ctx, "ip", "link", "show", ifbDevice).Run()
	return err == nil
}

func qdiscAvailable(ctx context.Context, name string) bool {
	// `tc qdisc add` against a nonexistent device fails differently depending
	// on whether the qdisc itself is known, so probe the help text instead.
	out, _ := exec.CommandContext(ctx, "tc", "qdisc", "add", "dev", "lo", "root", name, "help").CombinedOutput()
	s := strings.ToLower(string(out))
	if strings.Contains(s, "unknown qdisc") || strings.Contains(s, "not found") {
		return false
	}
	return true
}

func runTC(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
