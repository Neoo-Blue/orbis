//go:build linux

package intercept

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"

	"golang.org/x/sys/unix"
)

// openARPSocket opens a raw AF_PACKET socket bound to one interface, for
// sending ARP frames only. It receives nothing: the engine is a talker, and
// the kernel's own neighbour table is used for reads.
func openARPSocket(ifIndex int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeARP)))
	if err != nil {
		return -1, fmt.Errorf("open packet socket (needs CAP_NET_RAW): %w", err)
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeARP),
		Ifindex:  ifIndex,
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind packet socket: %w", err)
	}
	return fd, nil
}

// neighLookup reads the kernel neighbour (ARP) table for one address on one
// interface. Shelling to `ip neigh` rather than opening a netlink socket keeps
// this dependency-free and matches how the rest of Orbis reads routing state;
// the table is tiny and this is not a hot path.
func neighLookup(ip netip.Addr, iface string) (net.HardwareAddr, bool) {
	out, err := exec.Command("ip", "-4", "neigh", "show", ip.String(), "dev", iface).Output()
	if err != nil {
		return nil, false
	}
	fields := splitFields(string(out))
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) {
			mac, err := net.ParseMAC(fields[i+1])
			if err == nil {
				return mac, true
			}
		}
	}
	return nil, false
}

// pokeARP nudges the kernel into resolving an address by sending it a single
// UDP datagram, which triggers a normal ARP request from the stack. The
// datagram going nowhere useful is the point; the ARP resolution it provokes
// is what fills the neighbour table.
func pokeARP(ip netip.Addr) error {
	conn, err := net.Dial("udp", net.JoinHostPort(ip.String(), "9"))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, _ = conn.Write([]byte{0})
	return nil
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// parseMAC is a thin wrapper so tests do not import net directly for one call.
func parseMAC(s string) (net.HardwareAddr, error) { return net.ParseMAC(s) }
