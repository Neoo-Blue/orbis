package netconf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Live diagnostics and Wake-on-LAN. Meraki calls these "live tools"; the value
// is that an operator can answer "is it the network or the site" without
// leaving the UI or finding a shell.

// WakeOnLAN sends the magic packet for a MAC address.
//
// The packet is six 0xFF bytes followed by the target MAC repeated sixteen
// times, broadcast to the local segment. It is sent to the subnet broadcast
// when one is supplied, because a router will not forward a 255.255.255.255
// packet and waking a machine on another VLAN otherwise silently fails.
func WakeOnLAN(mac string, broadcast string, port int) error {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return fmt.Errorf("invalid MAC %q: %w", mac, err)
	}
	if len(hw) != 6 {
		return fmt.Errorf("only 6-byte MAC addresses can be woken, got %d bytes", len(hw))
	}
	if port <= 0 {
		port = 9
	}
	if broadcast == "" {
		broadcast = "255.255.255.255"
	}

	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}

	addr := net.JoinHostPort(broadcast, strconv.Itoa(port))
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("send magic packet: %w", err)
	}
	return nil
}

// PingResult is one diagnostic ping run.
type PingResult struct {
	Target      string  `json:"target"`
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	LossPercent float64 `json:"loss_percent"`
	MinMS       float64 `json:"min_ms"`
	AvgMS       float64 `json:"avg_ms"`
	MaxMS       float64 `json:"max_ms"`
	Raw         string  `json:"raw"`
}

var (
	lossRe = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss`)
	rttRe  = regexp.MustCompile(`= ([\d.]+)/([\d.]+)/([\d.]+)`)
)

// Ping runs a bounded ping and parses the summary.
func Ping(ctx context.Context, target string, count int) (*PingResult, error) {
	if err := validTarget(target); err != nil {
		return nil, err
	}
	if count <= 0 || count > 20 {
		count = 4
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(cctx, "ping", "-c", strconv.Itoa(count), "-W", "2", "-n", target).CombinedOutput()
	raw := string(out)
	res := &PingResult{Target: target, Sent: count, Raw: strings.TrimSpace(raw)}

	if m := lossRe.FindStringSubmatch(raw); len(m) == 4 {
		res.Sent, _ = strconv.Atoi(m[1])
		res.Received, _ = strconv.Atoi(m[2])
		res.LossPercent, _ = strconv.ParseFloat(m[3], 64)
	}
	if m := rttRe.FindStringSubmatch(raw); len(m) == 4 {
		res.MinMS, _ = strconv.ParseFloat(m[1], 64)
		res.AvgMS, _ = strconv.ParseFloat(m[2], 64)
		res.MaxMS, _ = strconv.ParseFloat(m[3], 64)
	}
	// 100% loss is a valid result, not an error: the command exits non-zero
	// but the answer ("it is unreachable") is exactly what was asked.
	if err != nil && res.Sent == 0 {
		return nil, fmt.Errorf("ping failed: %s", strings.TrimSpace(raw))
	}
	return res, nil
}

// TracerouteHop is one hop.
type TracerouteHop struct {
	Hop     int      `json:"hop"`
	Host    string   `json:"host"`
	Address string   `json:"address"`
	RTTs    []string `json:"rtts"`
}

// Traceroute runs a bounded trace and returns parsed hops plus the raw output.
func Traceroute(ctx context.Context, target string, maxHops int) ([]TracerouteHop, string, error) {
	if err := validTarget(target); err != nil {
		return nil, "", err
	}
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 20
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	bin := "traceroute"
	if _, err := exec.LookPath(bin); err != nil {
		// Debian minimal images often ship only tracepath.
		if _, err2 := exec.LookPath("tracepath"); err2 != nil {
			return nil, "", fmt.Errorf("neither traceroute nor tracepath is installed")
		}
		out, _ := exec.CommandContext(cctx, "tracepath", "-m", strconv.Itoa(maxHops), target).CombinedOutput()
		return nil, strings.TrimSpace(string(out)), nil
	}

	out, _ := exec.CommandContext(cctx, bin, "-n", "-w", "2", "-q", "1",
		"-m", strconv.Itoa(maxHops), target).CombinedOutput()
	raw := strings.TrimSpace(string(out))

	var hops []TracerouteHop
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		h := TracerouteHop{Hop: n}
		if fields[1] == "*" {
			h.Host = "*"
		} else {
			h.Address = fields[1]
			h.Host = fields[1]
			h.RTTs = fields[2:]
		}
		hops = append(hops, h)
	}
	return hops, raw, nil
}

// validTarget keeps shell-ish input out of the diagnostic commands. The
// commands are executed without a shell, so this is defence in depth rather
// than the only barrier, but a hostname is all that should ever arrive here.
func validTarget(t string) error {
	t = strings.TrimSpace(t)
	if t == "" {
		return fmt.Errorf("target is required")
	}
	if len(t) > 253 {
		return fmt.Errorf("target is too long")
	}
	if net.ParseIP(t) != nil {
		return nil
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == ':':
		default:
			return fmt.Errorf("target contains an invalid character: %q", r)
		}
	}
	return nil
}

// BroadcastFor returns the broadcast address of the subnet containing addr, so
// Wake-on-LAN reaches the right segment.
func BroadcastFor(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return ""
	}
	ip := binary.BigEndian.Uint32(ipnet.IP.To4())
	mask := binary.BigEndian.Uint32(net.IP(ipnet.Mask).To4())
	bcast := ip | ^mask
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, bcast)
	return out.String()
}
