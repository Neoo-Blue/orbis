package flows

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// CTEntry is one kernel conntrack row, reduced to what the tracker needs.
type CTEntry struct {
	Proto        uint8
	SrcIP        netip.Addr
	SrcPort      uint16
	DstIP        netip.Addr
	DstPort      uint16
	BytesOrig    int64
	BytesReply   int64
	PacketsOrig  int64
	PacketsReply int64
	State        string
	Timeout      int
}

// conntrackPaths are tried in order. nf_conntrack is the modern location;
// ip_conntrack survives on older kernels.
var conntrackPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack",
}

// ReadConntrack parses the kernel's connection table. Byte counters require
// net.netfilter.nf_conntrack_acct=1; without it the counters read as zero and
// the sniffer's own numbers are all we have, which the caller can detect by
// the AcctEnabled return.
func ReadConntrack() (entries []CTEntry, acctEnabled bool, err error) {
	var f *os.File
	for _, p := range conntrackPaths {
		f, err = os.Open(p)
		if err == nil {
			break
		}
	}
	if f == nil {
		return nil, false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Rows are short but a heavily-loaded box can produce long ones with many
	// extension fields; give the scanner room.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		e, sawAcct, ok := parseConntrackLine(sc.Text())
		if !ok {
			continue
		}
		if sawAcct {
			acctEnabled = true
		}
		entries = append(entries, e)
	}
	return entries, acctEnabled, sc.Err()
}

// parseConntrackLine handles the space-separated key=value format:
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=1.2.3.4 sport=1234 dport=443
//	  packets=10 bytes=1000 src=1.2.3.4 dst=10.0.0.5 sport=443 dport=1234
//	  packets=12 bytes=9000 [ASSURED] mark=0 use=1
//
// The two src/dst groups are the original and reply directions; NAT means
// they are not simply mirrored, so both are parsed positionally.
func parseConntrackLine(line string) (CTEntry, bool, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return CTEntry{}, false, false
	}
	var e CTEntry
	// Find the L4 protocol number. Layout differs between ipv4/ipv6 rows and
	// kernels, so scan for the first field that is a known proto name.
	protoIdx := -1
	for i := 0; i < len(fields) && i < 5; i++ {
		switch fields[i] {
		case "tcp":
			e.Proto, protoIdx = 6, i
		case "udp":
			e.Proto, protoIdx = 17, i
		case "icmp":
			e.Proto, protoIdx = 1, i
		case "icmpv6":
			e.Proto, protoIdx = 58, i
		case "sctp":
			e.Proto, protoIdx = 132, i
		case "gre":
			e.Proto, protoIdx = 47, i
		}
		if protoIdx >= 0 {
			break
		}
	}
	if protoIdx < 0 {
		return CTEntry{}, false, false
	}
	// The state token (ESTABLISHED, TIME_WAIT, ...) appears for TCP only.
	for _, f := range fields[protoIdx:] {
		if f == strings.ToUpper(f) && strings.Contains(f, "_") || f == "ESTABLISHED" {
			e.State = f
			break
		}
	}
	if len(fields) > protoIdx+2 {
		if to, err := strconv.Atoi(fields[protoIdx+2]); err == nil {
			e.Timeout = to
		}
	}

	group := 0
	sawAcct := false
	for _, f := range fields[protoIdx:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			addr, err := netip.ParseAddr(v)
			if err != nil {
				continue
			}
			if group == 0 {
				e.SrcIP = addr
			} else if !e.DstIP.IsValid() || group == 1 {
				// Reply src is the original dst under NAT-free routing; keep
				// the original tuple as canonical and ignore the reply's.
				_ = addr
			}
		case "dst":
			addr, err := netip.ParseAddr(v)
			if err != nil {
				continue
			}
			if group == 0 {
				e.DstIP = addr
			}
		case "sport":
			p, _ := strconv.Atoi(v)
			if group == 0 {
				e.SrcPort = uint16(p)
			}
		case "dport":
			p, _ := strconv.Atoi(v)
			if group == 0 {
				e.DstPort = uint16(p)
			}
		case "packets":
			n, _ := strconv.ParseInt(v, 10, 64)
			if group == 0 {
				e.PacketsOrig = n
			} else {
				e.PacketsReply = n
			}
		case "bytes":
			n, _ := strconv.ParseInt(v, 10, 64)
			sawAcct = true
			if group == 0 {
				e.BytesOrig = n
			} else {
				e.BytesReply = n
			}
			// "bytes" terminates a direction group.
			group++
		}
	}
	if !e.SrcIP.IsValid() || !e.DstIP.IsValid() {
		return CTEntry{}, false, false
	}
	return e, sawAcct, true
}

// ConntrackPoller feeds the tracker on an interval.
type ConntrackPoller struct {
	tracker  *Tracker
	interval time.Duration
	stop     chan struct{}
	// acctWarned / errWarned keep a persistent condition from logging on
	// every tick.
	acctWarned bool
	errWarned  bool
	onWarn     func(string)
}

func NewConntrackPoller(t *Tracker, interval time.Duration, onWarn func(string)) *ConntrackPoller {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &ConntrackPoller{tracker: t, interval: interval, stop: make(chan struct{}), onWarn: onWarn}
}

func (p *ConntrackPoller) Run() {
	// Netlink is the supported interface and the only one present on current
	// kernels; procfs is kept as a fallback for older systems that still
	// build CONFIG_NF_CONNTRACK_PROCFS.
	source, closeSource := p.openSource()
	defer closeSource()
	if source == nil {
		return
	}

	tick := time.NewTicker(p.interval)
	defer tick.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-tick.C:
			entries, acct, err := source()
			if err != nil {
				if !p.errWarned && p.onWarn != nil {
					p.onWarn("conntrack read failed: " + err.Error())
					p.errWarned = true
				}
				continue
			}
			p.errWarned = false
			if !acct && !p.acctWarned && len(entries) > 0 && p.onWarn != nil {
				p.onWarn("conntrack is reporting zero byte counters. Enable accounting with: " +
					"sysctl -w net.netfilter.nf_conntrack_acct=1 (on the host, for a container)")
				p.acctWarned = true
			}
			p.tracker.SyncConntrack(entries)
		}
	}
}

// conntrackSource returns entries plus whether byte accounting appears to be
// enabled, so the operator gets a specific warning rather than silently wrong
// numbers.
type conntrackSource func() ([]CTEntry, bool, error)

func (p *ConntrackPoller) openSource() (conntrackSource, func()) {
	if nl, err := newNetlinkSource(); err == nil && nl != nil {
		// Probe once: a socket that opens but cannot dump is worse than no
		// socket, because it looks like it is working.
		if entries, _, err := nl.dump(); err == nil {
			if p.onWarn != nil {
				p.onWarn(fmt.Sprintf("conntrack: reading via netlink (%d entries)", len(entries)))
			}
			return nl.dump, nl.close
		}
		nl.close()
	}

	if _, _, err := ReadConntrack(); err == nil {
		if p.onWarn != nil {
			p.onWarn("conntrack: reading via /proc/net/nf_conntrack")
		}
		return ReadConntrack, func() {}
	}

	if p.onWarn != nil {
		p.onWarn("conntrack is unavailable, so byte counters will be limited to what the " +
			"packet filter sees. Load nf_conntrack on the host and grant the container " +
			"CAP_NET_ADMIN to enable it.")
	}
	return nil, func() {}
}

func (p *ConntrackPoller) Stop() {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
}
