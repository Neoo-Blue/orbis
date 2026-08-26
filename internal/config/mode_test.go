package config

import "testing"

func TestInlineWithoutFirewallIsCorrectedToObserve(t *testing.T) {
	// A node in this state forwards without translating: replies come back
	// around it, conntrack sees one direction, and the UI claims "inline" the
	// whole time. It was never a gateway, so the honest mode is observe.
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = false

	note := c.reconcileMode()
	if c.Mode != ModeObserve {
		t.Fatalf("mode = %q, want observe", c.Mode)
	}
	if note == "" {
		t.Fatal("a silent downgrade is the bug this replaces; it must explain itself")
	}
}

func TestInlineWithoutWANIsCorrected(t *testing.T) {
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = ""
	if note := c.reconcileMode(); note == "" || c.Mode != ModeObserve {
		t.Fatalf("inline with no WAN interface should downgrade, got mode=%q note=%q", c.Mode, note)
	}
}

func TestProperlyConfiguredInlineIsLeftAlone(t *testing.T) {
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = "eth0"
	// Zones are part of "properly configured": without them the generated
	// forward chain drops everything, which is covered separately.
	c.Firewall.Zones = []Zone{
		{Name: "lan", Interfaces: []string{"eth1"}, Trust: "lan"},
		{Name: "wan", Interfaces: []string{"eth0"}, Trust: "wan"},
	}
	if note := c.reconcileMode(); note != "" {
		t.Fatalf("a working gateway must not be downgraded: %q", note)
	}
	if c.Mode != ModeInline {
		t.Fatalf("mode = %q, want inline", c.Mode)
	}
}

func TestObserveIsNeverTouched(t *testing.T) {
	c := Default()
	c.Mode = ModeObserve
	if note := c.reconcileMode(); note != "" || c.Mode != ModeObserve {
		t.Fatal("observe mode has nothing to reconcile")
	}
}

func TestInlineWithFirewallButNoZonesIsCorrected(t *testing.T) {
	// The forward chain defaults to drop and every accept rule comes from a
	// zone, so enabling the firewall with no zones routes traffic into a black
	// hole. Observed live: a container pointed at the node lost all
	// connectivity the moment this combination was applied.
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = "eth0"
	c.Firewall.DefaultForward = "drop"
	c.Firewall.Zones = nil

	note := c.reconcileMode()
	if c.Mode != ModeObserve {
		t.Fatalf("mode = %q, want observe: a drop-everything gateway is not a gateway", c.Mode)
	}
	if note == "" {
		t.Fatal("must explain why, or this looks like the mode silently reverting")
	}
}

func TestInlineWithZonesIsAllowed(t *testing.T) {
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = "eth0"
	c.Firewall.DefaultForward = "drop"
	c.Firewall.Zones = []Zone{
		{Name: "lan", Interfaces: []string{"eth1"}, Trust: "lan"},
		{Name: "wan", Interfaces: []string{"eth0"}, Trust: "wan"},
	}
	if note := c.reconcileMode(); note != "" || c.Mode != ModeInline {
		t.Fatalf("a properly zoned gateway must be left alone, got %q / %q", c.Mode, note)
	}
}

func TestAcceptDefaultForwardWithNoZonesIsAllowed(t *testing.T) {
	// default_forward=accept has no black hole to fall into, so this stays.
	c := Default()
	c.Mode = ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = "eth0"
	c.Firewall.DefaultForward = "accept"
	c.Firewall.Zones = nil
	if note := c.reconcileMode(); note != "" || c.Mode != ModeInline {
		t.Fatalf("accept policy is not a black hole, got %q / %q", c.Mode, note)
	}
}
