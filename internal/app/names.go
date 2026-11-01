package app

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	namesEvery   = 10 * time.Minute
	namesPerPass = 128
)

// nameLoop asks the router what it calls each device. A node in observe mode
// never sees DHCP, so the router is the only place those names exist, and
// without them every device on the network reads as a bare address.
func (a *App) nameLoop() {
	defer a.wg.Done()
	next := time.After(45 * time.Second)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-next:
			a.nameDevices()
			next = time.After(namesEvery)
		}
	}
}

func (a *App) nameDevices() {
	gw := a.DefaultGateway()
	if gw == "" {
		return
	}
	asked := 0
	for _, c := range a.Registry.All() {
		// A record with no MAC is keyed by its address, so a name kept from
		// last time may belong to whoever had that address before.
		if c.Label != "" || (c.Hostname != "" && c.MAC != "") || asked >= namesPerPass {
			continue
		}
		addr, err := netip.ParseAddr(c.IP)
		if err != nil || !addr.IsPrivate() {
			continue
		}
		asked++
		if name := routerName(a.ctx, net.JoinHostPort(gw, "53"), addr); name != "" {
			a.Registry.NameDevice(addr, name)
		}
	}
}

func routerName(ctx context.Context, server string, addr netip.Addr) string {
	arpa, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return ""
	}
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	client := dns.Client{Timeout: time.Second}
	r, _, err := client.ExchangeContext(ctx, m, server)
	if err != nil || r.Rcode != dns.RcodeSuccess {
		return ""
	}
	for _, rr := range r.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return deviceName(ptr.Ptr)
		}
	}
	return ""
}

// deviceName keeps what a person would call the device, and refuses what is
// only the address written out again.
func deviceName(ptr string) string {
	name := strings.TrimSuffix(ptr, ".")
	for _, zone := range []string{".lan", ".local", ".localdomain", ".home", ".home.arpa", ".internal"} {
		name = strings.TrimSuffix(name, zone)
	}
	if name == "" || len(name) > 63 || strings.Contains(name, "in-addr") {
		return ""
	}
	if net.ParseIP(strings.ReplaceAll(name, "-", ".")) != nil || net.ParseIP(name) != nil {
		return ""
	}
	for _, r := range name {
		if r != '-' && r != '.' && r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return ""
		}
	}
	return name
}
