//go:build linux

// Package intercept inserts Orbis into the traffic path of selected devices
// without becoming the network's DHCP server or gateway.
//
// It does this the way every transparent gateway on a flat L2 does: it answers
// ARP for the real gateway's address with its own MAC, so an enrolled client
// believes Orbis is the gateway and sends its outbound traffic there. Orbis
// forwards it to the real gateway and NATs the return path. Nothing on the
// client changes, nothing on the router changes, and the moment Orbis stops it
// restores the truth so the client falls straight back to the real gateway.
//
// This is ARP spoofing. Used against your own devices on your own network to
// filter their traffic it is a legitimate technique; the same mechanism used
// against a network you do not control is an attack. The distinction is
// authorization, which is why enrolment is explicit and per-device, and why the
// restore-on-stop path is treated as carefully as the takeover.
package intercept

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	arpHardwareEthernet = 1
	arpProtocolIPv4     = 0x0800

	arpOpReply   = 2
	etherTypeARP = 0x0806
	hwLen        = 6
	protoLen     = 4
)

// Target is a device Orbis is inserting itself in front of.
type Target struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// Engine poisons the ARP caches of enrolled clients so their gateway-bound
// traffic arrives at this node.
type Engine struct {
	iface   *net.Interface
	selfMAC net.HardwareAddr
	selfIP  netip.Addr
	gateway netip.Addr
	gwMAC   net.HardwareAddr
	log     func(string, ...any)

	mu       sync.RWMutex
	targets  map[netip.Addr]net.HardwareAddr
	interval time.Duration

	fd      int
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	stats Stats
}

// Stats is what the API surfaces.
type Stats struct {
	Running      bool      `json:"running"`
	Interface    string    `json:"interface"`
	Gateway      string    `json:"gateway"`
	GatewayMAC   string    `json:"gateway_mac"`
	Targets      int       `json:"targets"`
	Reasserts    int64     `json:"reasserts"`
	Restores     int64     `json:"restores"`
	LastReassert string    `json:"last_reassert,omitempty"`
	StartedAt    time.Time `json:"started_at,omitempty"`
}

// New builds an engine bound to one LAN interface.
func New(ifaceName string, gateway netip.Addr, log func(string, ...any)) (*Engine, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	self, ok := firstIPv4(iface)
	if !ok {
		return nil, fmt.Errorf("interface %s has no IPv4 address", ifaceName)
	}
	return &Engine{
		iface:    iface,
		selfMAC:  iface.HardwareAddr,
		selfIP:   self,
		gateway:  gateway,
		log:      log,
		targets:  map[netip.Addr]net.HardwareAddr{},
		interval: 2 * time.Second,
		fd:       -1,
	}, nil
}

// SetTargets replaces the enrolled set. Devices dropped from the set are
// restored immediately, because leaving a device pointed at a node that is no
// longer forwarding for it would black-hole that device.
func (e *Engine) SetTargets(targets []Target) {
	e.mu.Lock()
	old := e.targets
	next := make(map[netip.Addr]net.HardwareAddr, len(targets))
	for _, t := range targets {
		if t.IP.IsValid() && len(t.MAC) == hwLen {
			next[t.IP] = t.MAC
		}
	}
	var removed []Target
	for ip, mac := range old {
		if _, still := next[ip]; !still {
			removed = append(removed, Target{IP: ip, MAC: mac})
		}
	}
	e.targets = next
	running := e.running
	e.stats.Targets = len(next)
	e.mu.Unlock()

	if running {
		for _, t := range removed {
			e.restore(t)
		}
		// Assert immediately so a newly-enrolled device is captured now rather
		// than at the next tick.
		e.assertAll()
	}
}

// Start opens the raw socket and begins asserting.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	// Resolve the gateway's real MAC before touching any client. Everything
	// depends on being able to forward to the real gateway afterwards, so if
	// it cannot be found the takeover must not start.
	gwMAC, err := e.resolveGatewayMAC(ctx)
	if err != nil {
		return fmt.Errorf("cannot resolve gateway %s: %w", e.gateway, err)
	}

	fd, err := openARPSocket(e.iface.Index)
	if err != nil {
		return err
	}

	cctx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.fd = fd
	e.gwMAC = gwMAC
	e.running = true
	e.cancel = cancel
	e.stats.Running = true
	e.stats.Interface = e.iface.Name
	e.stats.Gateway = e.gateway.String()
	e.stats.GatewayMAC = gwMAC.String()
	e.stats.StartedAt = time.Now()
	e.mu.Unlock()

	e.wg.Add(1)
	go e.assertLoop(cctx)
	e.log("intercept: ARP takeover started on %s, gateway %s is at %s",
		e.iface.Name, e.gateway, gwMAC)
	return nil
}

// Stop restores every target and closes the socket. It is deliberately
// thorough: a half-stopped engine that has left a device poisoned but is no
// longer forwarding is worse than one that never started.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	cancel := e.cancel
	targets := make([]Target, 0, len(e.targets))
	for ip, mac := range e.targets {
		targets = append(targets, Target{IP: ip, MAC: mac})
	}
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	e.wg.Wait()

	// Send the truth several times: a single restore packet can be lost, and a
	// device left believing Orbis is the gateway after Orbis has stopped
	// forwarding loses all connectivity.
	for i := 0; i < 3; i++ {
		for _, t := range targets {
			e.restore(t)
		}
		time.Sleep(150 * time.Millisecond)
	}

	e.mu.Lock()
	if e.fd >= 0 {
		unix.Close(e.fd)
		e.fd = -1
	}
	e.running = false
	e.stats.Running = false
	e.mu.Unlock()
	e.log("intercept: ARP takeover stopped, %d target(s) restored", len(targets))
}

// assertLoop re-poisons on a timer, because a legitimate gratuitous ARP from
// the real gateway would otherwise heal the client's cache and it would drift
// back off the interception path within seconds.
func (e *Engine) assertLoop(ctx context.Context) {
	defer e.wg.Done()
	t := time.NewTicker(e.interval)
	defer t.Stop()
	e.assertAll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.assertAll()
		}
	}
}

// assertAll tells every target that the gateway lives at this node's MAC. It
// does this with a unicast ARP reply per target rather than a broadcast, so a
// device not enrolled never hears the claim and its traffic is untouched.
func (e *Engine) assertAll() {
	e.mu.RLock()
	fd := e.fd
	targets := make([]Target, 0, len(e.targets))
	for ip, mac := range e.targets {
		targets = append(targets, Target{IP: ip, MAC: mac})
	}
	e.mu.RUnlock()
	if fd < 0 || len(targets) == 0 {
		return
	}

	for _, t := range targets {
		// "The gateway (senderIP) is at my MAC (senderMAC)", sent to the
		// target. An unsolicited reply is the standard cache-poisoning form and
		// every OS accepts it.
		pkt := buildARP(arpOpReply, e.selfMAC, e.gateway, t.MAC, t.IP)
		e.sendTo(fd, t.MAC, pkt)
	}
	e.mu.Lock()
	e.stats.Reasserts++
	e.stats.LastReassert = time.Now().UTC().Format(time.RFC3339)
	e.mu.Unlock()
}

// restore sends the truth to one target: the gateway is at the gateway's real
// MAC. Called when a device is unenrolled and repeatedly at shutdown.
func (e *Engine) restore(t Target) {
	e.mu.RLock()
	fd, gwMAC := e.fd, e.gwMAC
	e.mu.RUnlock()
	if fd < 0 || len(gwMAC) != hwLen {
		return
	}
	pkt := buildARP(arpOpReply, gwMAC, e.gateway, t.MAC, t.IP)
	e.sendTo(fd, t.MAC, pkt)
	e.mu.Lock()
	e.stats.Restores++
	e.mu.Unlock()
}

// resolveGatewayMAC learns the real gateway's hardware address by asking the
// kernel's neighbour table first, and falling back to an active ARP request.
func (e *Engine) resolveGatewayMAC(ctx context.Context) (net.HardwareAddr, error) {
	if mac, ok := neighLookup(e.gateway, e.iface.Name); ok {
		return mac, nil
	}
	// Nudge the kernel into resolving it, then read the table back.
	_ = pokeARP(e.gateway)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if mac, ok := neighLookup(e.gateway, e.iface.Name); ok {
			return mac, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("no ARP entry after probing")
}

func (e *Engine) sendTo(fd int, dst net.HardwareAddr, frame []byte) {
	var addr unix.SockaddrLinklayer
	addr.Protocol = htons(etherTypeARP)
	addr.Ifindex = e.iface.Index
	addr.Halen = hwLen
	copy(addr.Addr[:], dst)
	if err := unix.Sendto(fd, frame, 0, &addr); err != nil {
		e.log("intercept: send failed: %v", err)
	}
}

// StatsSnapshot returns a copy for the API.
func (e *Engine) StatsSnapshot() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// Running reports whether takeover is active.
func (e *Engine) Running() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// ---- frame construction ----

// buildARP builds a full Ethernet + ARP frame.
func buildARP(op int, senderMAC net.HardwareAddr, senderIP netip.Addr,
	targetMAC net.HardwareAddr, targetIP netip.Addr) []byte {

	frame := make([]byte, 14+28)

	// Ethernet header.
	copy(frame[0:6], targetMAC)
	copy(frame[6:12], senderMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	// ARP payload.
	p := frame[14:]
	binary.BigEndian.PutUint16(p[0:2], arpHardwareEthernet)
	binary.BigEndian.PutUint16(p[2:4], arpProtocolIPv4)
	p[4] = hwLen
	p[5] = protoLen
	binary.BigEndian.PutUint16(p[6:8], uint16(op))
	copy(p[8:14], senderMAC)
	sip := senderIP.As4()
	copy(p[14:18], sip[:])
	copy(p[18:24], targetMAC)
	tip := targetIP.As4()
	copy(p[24:28], tip[:])
	return frame
}

func firstIPv4(iface *net.Interface) (netip.Addr, bool) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipn.IP.To4(); v4 != nil {
			if addr, ok := netip.AddrFromSlice(v4); ok {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
