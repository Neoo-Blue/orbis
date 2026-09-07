//go:build linux

package intercept

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// Restore tells every device the truth about the gateway without starting a
// takeover: it resolves the real gateway's hardware address and sends each
// device an ARP reply carrying it, several times. This is what an orderly
// stop does; Restore exists so it can also be done after a crash, from a
// fresh process with nothing but the marker.
func Restore(ctx context.Context, ifaceName string, gateway netip.Addr, targets []Target, log func(string, ...any)) (int, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	if len(targets) == 0 {
		return 0, nil
	}
	e, err := New(ifaceName, gateway, log)
	if err != nil {
		return 0, err
	}
	gwMAC, err := e.resolveGatewayMAC(ctx)
	if err != nil {
		return 0, fmt.Errorf("cannot resolve gateway %s: %w", gateway, err)
	}
	fd, err := openARPSocket(e.iface.Index)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	sent := 0
	for i := 0; i < 3; i++ {
		for _, t := range targets {
			pkt := buildARP(arpOpReply, gwMAC, gateway, t.MAC, t.IP)
			e.sendTo(fd, t.MAC, pkt)
			sent++
		}
		time.Sleep(150 * time.Millisecond)
	}
	log("intercept: restored %d device(s) to gateway %s (%s)", len(targets), gateway, gwMAC)
	return len(targets), nil
}

// RestoreFromMarker is Restore driven by the marker file, then removes it.
func RestoreFromMarker(ctx context.Context, path string, log func(string, ...any)) (int, error) {
	m, err := ReadMarker(path)
	if err != nil || m == nil {
		return 0, err
	}
	gw, err := netip.ParseAddr(m.Gateway)
	if err != nil {
		return 0, fmt.Errorf("marker gateway %q: %w", m.Gateway, err)
	}
	targets := ResolveTargets(m.Clients)
	n, err := Restore(ctx, m.Interface, gw, targets, log)
	if err == nil {
		_ = RemoveForwarding(ctx)
		RemoveMarker(path)
	}
	return n, err
}
