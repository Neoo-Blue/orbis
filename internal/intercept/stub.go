//go:build !linux

package intercept

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Target/Stats mirror the Linux types so callers compile everywhere.
type Target struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

type Stats struct {
	Running      bool   `json:"running"`
	Interface    string `json:"interface"`
	Gateway      string `json:"gateway"`
	GatewayMAC   string `json:"gateway_mac"`
	Targets      int    `json:"targets"`
	Reasserts    int64  `json:"reasserts"`
	Restores     int64  `json:"restores"`
	LastReassert string `json:"last_reassert,omitempty"`
}

type Engine struct{}

// ARP interception is Linux-only; the raw AF_PACKET socket has no portable
// equivalent, and Orbis only runs as a gateway on Linux anyway.
func New(string, netip.Addr, func(string, ...any)) (*Engine, error) {
	return nil, fmt.Errorf("ARP interception is only supported on Linux")
}

func (e *Engine) Start(context.Context) error { return nil }
func (e *Engine) Stop()                       {}
func (e *Engine) SetTargets([]Target)         {}
func (e *Engine) Running() bool               { return false }
func (e *Engine) StatsSnapshot() Stats        { return Stats{} }

type ForwardConfig struct {
	LANInterface string
	Clients      []netip.Addr
	RedirectDNS  bool
	DNSPort      int
	RedirectHTTP bool
	HTTPPort     int
	HTTPSPort    int
}

func ApplyForwarding(context.Context, ForwardConfig) error { return nil }
func RemoveForwarding(context.Context) error               { return nil }
func EnableForwardingSysctl() (bool, error)                { return false, nil }
func writeForwarding(bool) error                           { return nil }
