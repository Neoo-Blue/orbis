package intercept

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// Enrolment is stored as address -> MAC, but the two halves of interception
// key on different things: the ARP claim is delivered to the MAC, while NAT and
// the DNS redirect match the address. When DHCP hands an enrolled device a new
// lease the halves disagree, and the device sends everything through this node
// while its replies bypass it: half-routed, with sites and sign-ins failing in
// ways that look like DNS trouble. Plan is the one place that decides what the
// enrolled set means given where each device actually is, so the claim is only
// ever made for a device whose current address is also the one being NATed.

// PlanInput is everything MakePlan needs, passed in so the decision can be
// tested without a network.
type PlanInput struct {
	Clients    map[string]string // enrolled address -> MAC, as configured
	Gateway    netip.Addr
	GatewayMAC net.HardwareAddr // nil when not yet resolved
	SelfMAC    net.HardwareAddr
	IsSelf     func(netip.Addr) bool
	// LAN bounds where a device may be followed to. Invalid means no bound;
	// a sighting outside it (the node's own Wi-Fi scope, say) is ignored.
	LAN netip.Prefix
	// Seen reports the address a MAC was most recently seen using. Nil
	// means no registry. The latest sighting wins however old it is: if it
	// disagrees with the enrolled address, the enrolled one is no fresher.
	Seen func(mac string) (netip.Addr, bool)
	// Confirm asks the network which MAC holds an address right now. Nil
	// means do not probe: a device that appears to have moved is held back
	// until a pass that can probe confirms where it went.
	Confirm func(netip.Addr) (net.HardwareAddr, bool)
}

// Plan is the enrolled set resolved against the network.
type Plan struct {
	Targets []Target          // safe to claim the gateway for
	Moves   map[string]string // enrolled address -> the address the device holds now
	Drops   map[string]string // enrolled address -> why it can never be intercepted
	Held    map[string]string // enrolled address -> why it is skipped for now
}

// MakePlan resolves the enrolled set. Entries whose MAC is unknown or
// malformed are skipped, as ResolveTargets always did.
func MakePlan(in PlanInput) Plan {
	p := Plan{Moves: map[string]string{}, Drops: map[string]string{}, Held: map[string]string{}}
	isSelf := func(a netip.Addr) bool { return in.IsSelf != nil && in.IsSelf(a) }

	// Iterate in a fixed order so logs and tests are stable.
	ips := make([]string, 0, len(in.Clients))
	for ip := range in.Clients {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ipStr := range ips {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			continue
		}
		if reason := Refusal(addr, nil, in.Gateway, in.GatewayMAC, in.SelfMAC, isSelf); reason != "" {
			p.Drops[ipStr] = reason
			continue
		}
		mac, err := net.ParseMAC(in.Clients[ipStr])
		if err != nil || len(mac) != 6 {
			continue
		}
		if reason := Refusal(netip.Addr{}, mac, in.Gateway, in.GatewayMAC, in.SelfMAC, isSelf); reason != "" {
			p.Drops[ipStr] = reason
			continue
		}

		if in.Seen != nil {
			now, ok := in.Seen(mac.String())
			if ok && now.IsValid() && now.Is4() && now != addr &&
				(!in.LAN.IsValid() || in.LAN.Contains(now)) && now != in.Gateway && !isSelf(now) {
				if _, taken := in.Clients[now.String()]; taken {
					p.Held[ipStr] = fmt.Sprintf("moved to %s, which is enrolled for another device", now)
					continue
				}
				if in.Confirm == nil {
					p.Held[ipStr] = fmt.Sprintf("appears to have moved to %s; waiting to confirm", now)
					continue
				}
				if got, ok := in.Confirm(now); ok && bytes.Equal(got, mac) {
					p.Moves[ipStr] = now.String()
					p.Targets = append(p.Targets, Target{IP: now, MAC: mac})
					continue
				}
				p.Held[ipStr] = fmt.Sprintf("appears to have moved to %s, but %s did not answer for it", now, mac)
				continue
			}
		}
		p.Targets = append(p.Targets, Target{IP: addr, MAC: mac})
	}
	return p
}

// Refusal says why a device can never be intercepted, or "" when it can. Either
// the address or the MAC may be left zero to check only the other. Claiming the
// gateway's own address to the gateway, or this node's traffic to itself, is
// never what an operator meant and only confuses the router.
func Refusal(addr netip.Addr, mac net.HardwareAddr, gateway netip.Addr, gatewayMAC, selfMAC net.HardwareAddr, isSelf func(netip.Addr) bool) string {
	if addr.IsValid() {
		if addr == gateway {
			return "it is the gateway"
		}
		if isSelf != nil && isSelf(addr) {
			return "it is this node"
		}
	}
	if len(mac) == 6 {
		if len(gatewayMAC) == 6 && bytes.Equal(mac, gatewayMAC) {
			return "it is the gateway"
		}
		if len(selfMAC) == 6 && bytes.Equal(mac, selfMAC) {
			return "it is this node"
		}
	}
	return ""
}
