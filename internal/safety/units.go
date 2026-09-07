// Package safety is the safety net: the systemd wiring that restarts a dead
// daemon, kills a hung one, hands the network to a standby when the daemon
// cannot come back, and reboots a frozen board. The units are rendered here
// so the installer, the daemon and the settings page all install the same
// thing.
package safety

import (
	"fmt"
	"strings"
)

const (
	UnitPath         = "/etc/systemd/system/orbis.service"
	LifeboatUnitPath = "/etc/systemd/system/orbis-lifeboat.service"
	WatchdogConfPath = "/etc/systemd/system.conf.d/orbis-watchdog.conf"
	Binary           = "/usr/local/bin/orbisd"
)

// UnitOptions are the knobs the units are rendered with.
type UnitOptions struct {
	ConfigPath string
	// Lifeboat wires OnFailure= to the standby unit.
	Lifeboat bool
	// WatchdogSec is the software watchdog period; 0 disables it.
	WatchdogSec int
}

// MainUnit renders orbis.service.
func MainUnit(o UnitOptions) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("[Unit]")
	w("Description=Orbis network firewall and traffic analyser")
	w("Documentation=https://github.com/Neoo-Blue/orbis")
	w("After=network-online.target")
	w("Wants=network-online.target")
	// Five failures in two minutes is a crash loop, not a blip: stop
	// restarting and hand the network to the lifeboat instead.
	w("StartLimitIntervalSec=120")
	w("StartLimitBurst=5")
	if o.Lifeboat {
		w("OnFailure=orbis-lifeboat.service")
	}
	w("")
	w("[Service]")
	w("Type=notify")
	w("NotifyAccess=main")
	w("ExecStart=%s -config %s", Binary, o.ConfigPath)
	// After every stop, clean or not: put intercepted devices back on the
	// real gateway. Harmless after a clean stop, essential after a crash.
	w("ExecStopPost=%s -release -config %s", Binary, o.ConfigPath)
	w("Restart=on-failure")
	w("RestartSec=2")
	if o.WatchdogSec > 0 {
		w("WatchdogSec=%d", o.WatchdogSec)
	}
	w("TimeoutStartSec=120")
	w("TimeoutStopSec=25")
	w("")
	w("# Runs as root because it needs raw sockets, netfilter and network")
	w("# configuration. The capability set below is still narrowed to what is")
	w("# actually used, so a compromise does not hand over the whole machine.")
	w("User=root")
	w("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE")
	w("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_MODULE CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID")
	w("")
	w("NoNewPrivileges=yes")
	w("ProtectSystem=strict")
	w("ProtectHome=yes")
	w("PrivateTmp=yes")
	w("ReadWritePaths=/var/lib/orbis /etc/orbis /etc/resolv.conf")
	w("ProtectKernelLogs=yes")
	w("ProtectControlGroups=yes")
	w("RestrictRealtime=yes")
	w("RestrictSUIDSGID=yes")
	w("LockPersonality=yes")
	w("")
	w("# The flow table and the DNS cache are the memory footprint; this is a")
	w("# generous ceiling that still stops a runaway from taking the host down.")
	w("MemoryMax=2G")
	w("LimitNOFILE=65535")
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

// LifeboatUnit renders orbis-lifeboat.service: the standby that serves DNS
// and DHCP, keeps forwarding open and puts intercepted devices back, with
// no database, no lists and no model. It starts when orbis.service gives up
// and stops the moment orbis.service starts again.
func LifeboatUnit(o UnitOptions) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("[Unit]")
	w("Description=Orbis lifeboat: keeps DNS, DHCP and forwarding up while Orbis is down")
	w("Documentation=https://github.com/Neoo-Blue/orbis")
	w("After=network-online.target")
	w("Conflicts=orbis.service")
	w("")
	w("[Service]")
	w("Type=simple")
	w("ExecStart=%s -lifeboat -config %s", Binary, o.ConfigPath)
	w("Restart=always")
	w("RestartSec=1")
	w("User=root")
	w("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE")
	w("MemoryMax=256M")
	w("LimitNOFILE=16384")
	w("")
	w("[Install]")
	w("WantedBy=")
	return b.String()
}

// WatchdogConf arms the hardware watchdog through systemd from the next
// boot: if PID 1 stops petting it, the board resets. Fifteen seconds is the
// most a Raspberry Pi's watchdog accepts; systemd pets it twice as often.
func WatchdogConf() string {
	return "# Orbis safety net: reboot a frozen board. Managed by orbisd. Read by\n" +
		"# systemd at boot; remove this file and reboot to disarm it.\n" +
		"[Manager]\nRuntimeWatchdogSec=15s\nRebootWatchdogSec=2min\n"
}
