package safety

import (
	"strings"
	"testing"
)

func TestMainUnitHasTheSafetyDirectives(t *testing.T) {
	u := MainUnit(UnitOptions{ConfigPath: "/etc/orbis/orbis.yaml", Lifeboat: true, WatchdogSec: 90})
	for _, want := range []string{
		"Type=notify", "NotifyAccess=main", "WatchdogSec=90", "Restart=on-failure", "RestartSec=2",
		"OnFailure=orbis-lifeboat.service", "StartLimitBurst=5",
		"ExecStopPost=/usr/local/bin/orbisd -release -config /etc/orbis/orbis.yaml",
		"ProtectSystem=strict", "ReadWritePaths=/var/lib/orbis /etc/orbis /etc/resolv.conf",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("main unit lacks %q", want)
		}
	}
	plain := MainUnit(UnitOptions{ConfigPath: "/etc/orbis/orbis.yaml"})
	if strings.Contains(plain, "OnFailure=") || strings.Contains(plain, "WatchdogSec=") {
		t.Errorf("optional layers should be absent when off")
	}
}

func TestLifeboatUnit(t *testing.T) {
	u := LifeboatUnit(UnitOptions{ConfigPath: "/etc/orbis/orbis.yaml"})
	for _, want := range []string{"Conflicts=orbis.service", "-lifeboat -config /etc/orbis/orbis.yaml", "Restart=always", "CAP_NET_RAW"} {
		if !strings.Contains(u, want) {
			t.Errorf("lifeboat unit lacks %q", want)
		}
	}
	if !strings.Contains(WatchdogConf(), "RuntimeWatchdogSec=15s") {
		t.Errorf("watchdog conf: %q", WatchdogConf())
	}
}
