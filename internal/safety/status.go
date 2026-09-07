package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// Layer is one part of the safety net and whether it is in place.
type Layer struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Applies says whether this layer matters for the node's placement;
	// a layer that does not apply is shown, not counted.
	Applies bool `json:"applies"`
}

// Episode is one stretch the lifeboat kept the network up.
type Episode struct {
	Started  time.Time `json:"started"`
	LastSeen time.Time `json:"last_seen"`
	Reason   string    `json:"reason"`
	Retries  int       `json:"retries"`
}

// Status is the page's view.
type Status struct {
	Method      string            `json:"method"` // systemd | other
	Placement   string            `json:"placement"`
	Layers      []Layer           `json:"layers"`
	Unit        map[string]string `json:"unit"`
	FallbackDNS string            `json:"fallback_dns"`
	LastEpisode *Episode          `json:"last_episode,omitempty"`
	Runbook     []string          `json:"runbook"`
	InstallHint string            `json:"install_hint,omitempty"`
}

var (
	probeMu sync.Mutex
	probeAt time.Time
	probeOK bool
)

// NoteProbe records the latest liveness probe for the status page.
func NoteProbe(ok bool) {
	probeMu.Lock()
	probeAt, probeOK = time.Now(), ok
	probeMu.Unlock()
}

// LastProbe returns the latest probe result and how old it is.
func LastProbe() (bool, time.Duration) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if probeAt.IsZero() {
		return false, 0
	}
	return probeOK, time.Since(probeAt)
}

// EpisodePath is where the lifeboat writes its marker.
func EpisodePath(dataDir string) string { return filepath.Join(dataDir, "lifeboat.json") }

// MarkerPath is where a running takeover is recorded.
func MarkerPath(dataDir string) string { return filepath.Join(dataDir, "intercept.active") }

// ReadEpisode returns the lifeboat's marker, if any.
func ReadEpisode(dataDir string) *Episode {
	b, err := os.ReadFile(EpisodePath(dataDir))
	if err != nil {
		return nil
	}
	var e Episode
	if json.Unmarshal(b, &e) != nil {
		return nil
	}
	return &e
}

// unitProps reads a few properties of a unit; empty when systemd is absent.
func unitProps(ctx context.Context, unit string, props ...string) map[string]string {
	out := map[string]string{}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return out
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	args := []string{"show", unit}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	b, err := exec.CommandContext(cctx, "systemctl", args...).Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// Compute builds the status from the configuration and the host.
func Compute(ctx context.Context, cfg config.Config, dataDir string, fallback string, interceptClients int, lastProbeOK bool, probeAge time.Duration) Status {
	st := Status{Unit: map[string]string{}, FallbackDNS: fallback}
	inline := cfg.Mode == config.ModeInline
	intercepting := cfg.Network.Intercept.Enabled && interceptClients > 0
	switch {
	case inline && cfg.DHCP.Enabled:
		st.Placement = "gateway"
	case inline:
		st.Placement = "gateway-no-dhcp"
	case intercepting:
		st.Placement = "intercept"
	default:
		st.Placement = "resolver"
	}

	props := unitProps(ctx, "orbis.service", "Restart", "WatchdogUSec", "OnFailure", "Type", "ExecStopPost", "NRestarts", "ActiveState", "LoadState")
	if props["LoadState"] == "loaded" {
		st.Method = "systemd"
	} else {
		st.Method = "other"
	}
	for k, v := range props {
		st.Unit[k] = v
	}
	lifeboatProps := unitProps(ctx, "orbis-lifeboat.service", "LoadState", "ActiveState")
	mgr := unitProps(ctx, "", "RuntimeWatchdogUSec")

	restartOK := props["Restart"] == "on-failure" || props["Restart"] == "always"
	wdUsec, _ := strconv.ParseInt(props["WatchdogUSec"], 10, 64)
	watchdogOK := wdUsec > 0 && props["Type"] == "notify"
	lifeboatOK := strings.Contains(props["OnFailure"], "orbis-lifeboat") && lifeboatProps["LoadState"] == "loaded"
	releaseOK := strings.Contains(props["ExecStopPost"], "-release")
	hwUsec, _ := strconv.ParseInt(mgr["RuntimeWatchdogUSec"], 10, 64)
	hwOK := hwUsec > 0
	hasHW := HasHardwareWatchdog()

	add := func(id, title string, ok, applies bool, detail string) {
		st.Layers = append(st.Layers, Layer{ID: id, Title: title, OK: ok, Applies: applies, Detail: detail})
	}
	add("restart", "Restart after a crash", restartOK, true, func() string {
		if st.Method != "systemd" {
			return "Not running under systemd; nothing restarts the daemon if it dies."
		}
		if restartOK {
			n := props["NRestarts"]
			if n == "" || n == "0" {
				return "systemd restarts the service two seconds after a failure. No restarts since boot."
			}
			return "systemd restarts the service two seconds after a failure. " + n + " restart(s) since boot."
		}
		return "The unit has no Restart= policy; a crash stays down until someone notices."
	}())
	add("watchdog", "Restart when it hangs", watchdogOK, true, func() string {
		if !watchdogOK {
			return "No software watchdog: a process that is alive but not answering would sit there. Install the safety net to add one."
		}
		s := fmt.Sprintf("systemd expects a heartbeat every %ds; the daemon only sends one while its resolver answers a test query.", wdUsec/1_000_000)
		if !cfg.Safety.LivenessProbe {
			s += " The liveness probe is off in settings, so the heartbeat is unconditional."
		} else if lastProbeOK {
			s += fmt.Sprintf(" Last probe passed %s ago.", probeAge.Round(time.Second))
		}
		return s
	}())
	add("lifeboat", "Lifeboat when it cannot come back", lifeboatOK, true, func() string {
		if !cfg.Safety.Lifeboat {
			return "Turned off in settings."
		}
		if lifeboatOK {
			s := "After five failures in two minutes systemd hands the network to the lifeboat: DNS forwarding, DHCP for the configured scopes, forwarding and NAT, all without filtering, and it retries the main service on a backoff."
			if lifeboatProps["ActiveState"] == "active" {
				s = "THE LIFEBOAT IS RUNNING NOW. " + s
			}
			return s
		}
		return "Not installed. Without it a crash loop leaves the network with no DNS at all."
	}())
	add("release", "Devices go back to the real gateway", releaseOK, intercepting || cfg.Network.Intercept.Enabled, func() string {
		if !cfg.Network.Intercept.Enabled {
			return "Not intercepting any device; nothing to hand back."
		}
		if releaseOK {
			return fmt.Sprintf("After every stop, clean or crash, the %d intercepted device(s) are told the real gateway's address, so they do not keep sending to a dead node until their ARP cache expires.", interceptClients)
		}
		return "Without the release step, a crash leaves intercepted devices pointed at this node for minutes."
	}())
	add("fallback_dns", "A second resolver in every lease", fallback != "", inline && cfg.DHCP.Enabled, func() string {
		if !(inline && cfg.DHCP.Enabled) {
			if fallback != "" {
				return "This node is not the DHCP server. Give devices a second DNS server in your router's DHCP settings: this node first, then " + fallback + "."
			}
			return "This node is not the DHCP server. Hand out a second DNS server from your router so devices survive this node being down."
		}
		if fallback == "" {
			return "Leases carry this node only; if it is down, devices cannot resolve names even though the lifeboat forwards for them within seconds."
		}
		return "Leases carry this node first and " + fallback + " second. A device tries the second when the first does not answer."
	}())
	_, confPresent := os.Stat(WatchdogConfPath)
	armedNextBoot := confPresent == nil && !hwOK
	add("hardware_watchdog", "Reboot a frozen board", hwOK || (armedNextBoot && cfg.Safety.HardwareWatchdog), hasHW && cfg.Safety.HardwareWatchdog, func() string {
		if !hasHW {
			return "No /dev/watchdog on this host (a container or a VM without one). Nothing to arm."
		}
		if !cfg.Safety.HardwareWatchdog {
			if hwOK {
				return "Armed until the next reboot; turned off in settings, so it stays off after that."
			}
			return "Off. Opt in under Settings if you want a frozen board to reset itself; it arms at the next reboot, never live."
		}
		if hwOK {
			return fmt.Sprintf("systemd pets the hardware watchdog every %ds; if the kernel freezes, the board resets and Orbis is back in about a minute.", hwUsec/1_000_000)
		}
		if armedNextBoot {
			return "Written; arms at the next reboot. It is never applied live, because re-executing systemd to arm it can reset the board."
		}
		return "The board has a watchdog but it is not armed. Install the safety net to write the setting; it arms at the next reboot."
	}())
	add("forwarding", "Traffic keeps flowing while the daemon restarts", true, inline, func() string {
		if !inline {
			return "Not the gateway; the upstream router forwards regardless of this node."
		}
		return "The firewall ruleset lives in the kernel and is left in place when the daemon stops, so NAT and forwarding continue through a restart or an update. Only DNS and DHCP pause, and the lifeboat covers those."
	}())

	if ep := ReadEpisode(dataDir); ep != nil {
		st.LastEpisode = ep
	}
	st.Runbook = runbook(st.Placement, cfg, fallback)
	if st.Method == "systemd" && (!restartOK || !watchdogOK || (cfg.Safety.Lifeboat && !lifeboatOK) || !releaseOK) {
		st.InstallHint = "Install the safety net to bring the unit up to date."
	}
	return st
}

// runbook is what to do if the box itself dies, in the order that gets a
// household back online fastest.
func runbook(placement string, cfg config.Config, fallback string) []string {
	switch placement {
	case "gateway", "gateway-no-dhcp":
		steps := []string{
			"If the interface loads but shows the lifeboat, wait: it retries the main service on its own and you can press Start Orbis there.",
			"If nothing answers on the LAN address, power-cycle the box once; the hardware watchdog should already have done this if the kernel froze.",
			"If it stays down: move the LAN cable from this box to a LAN port on the upstream router (or the switch it feeds), then turn DHCP on in that router. Devices pick up new leases within their lease time; toggling Wi-Fi on a device forces it.",
		}
		if fallback != "" {
			steps = append(steps, "Devices already hold "+fallback+" as their second DNS server, so name resolution comes back the moment they can reach the internet again.")
		}
		steps = append(steps, "Restore later from the last backup under Settings, Storage & retention; the configuration and the database are both there.")
		return steps
	case "intercept":
		return []string{
			"Intercepted devices are put back on the real gateway by the release step within seconds of a crash; if the box lost power, their ARP entries expire on their own within a few minutes, or toggle Wi-Fi on the device.",
			"Devices whose DNS points at this node need the second resolver: set it in your router's DHCP as the second DNS server" + func() string {
				if fallback != "" {
					return " (" + fallback + ")"
				}
				return ""
			}() + ".",
			"Nothing else depends on this box; the router keeps routing.",
		}
	default:
		return []string{
			"Only name resolution depends on this box. Give devices a second DNS server in your router's DHCP" + func() string {
				if fallback != "" {
					return " (" + fallback + ")"
				}
				return ""
			}() + " and they carry on unfiltered while it is down.",
		}
	}
}
