//go:build linux

package flows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/dpi"
	"golang.org/x/sys/unix"
)

// Capturer reads packets straight off AF_PACKET sockets. It deliberately
// avoids libpcap and cgo: the daemon ships as a single static binary, and the
// kernel-side BPF filter (see bpf.go) does the heavy lifting so a plain
// recvfrom loop is fast enough for a gigabit edge.
type Capturer struct {
	tracker *Tracker
	snapLen int
	ifaces  []string

	// onDNS/onHTTP let the ad-block pipeline observe cleartext requests
	// without the capture layer importing it.
	onHTTP func(clientIP netip.Addr, req *dpi.HTTPRequest)

	mu       sync.Mutex
	socks    []int
	watching []string
	running  bool
	wg       sync.WaitGroup
	stop     chan struct{}
	log      func(string, ...any)

	stats CaptureStats
}

type CaptureStats struct {
	Packets      int64  `json:"packets"`
	Bytes        int64  `json:"bytes"`
	Truncated    int64  `json:"truncated"`
	KernelDrops  uint32 `json:"kernel_drops"`
	ParseErrors  int64  `json:"parse_errors"`
	Interfaces   int    `json:"interfaces"`
	FilterActive bool   `json:"filter_active"`
}

func NewCapturer(t *Tracker, snapLen int, ifaces []string, log func(string, ...any)) *Capturer {
	if snapLen <= 0 || snapLen > 65535 {
		snapLen = 512
	}
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Capturer{tracker: t, snapLen: snapLen, ifaces: ifaces, stop: make(chan struct{}), log: log}
}

func (c *Capturer) SetHTTPHook(fn func(netip.Addr, *dpi.HTTPRequest)) { c.onHTTP = fn }

// AddInterfaces starts capturing on interfaces that appeared after startup —
// a WireGuard or Tailscale device is created when the tunnel comes up, long
// after the initial scan. Without this, a VPN client's traffic is forwarded
// correctly and never shows up in the flow table.
func (c *Capturer) AddInterfaces(names []string) {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	existing := make(map[string]bool, len(c.watching))
	for _, n := range c.watching {
		existing[n] = true
	}
	c.mu.Unlock()

	filter, err := buildFilter(c.snapLen)
	if err != nil {
		c.log("capture: cannot build filter for new interfaces: %v", err)
		return
	}
	for _, name := range names {
		if name == "" || existing[name] {
			continue
		}
		fd, err := c.openSocket(name, filter)
		if err != nil {
			c.log("capture: could not watch %s: %v", name, err)
			continue
		}
		c.mu.Lock()
		c.socks = append(c.socks, fd)
		c.watching = append(c.watching, name)
		c.stats.Interfaces = len(c.watching)
		c.mu.Unlock()
		c.wg.Add(1)
		go c.readLoop(fd, name)
		c.log("capture: now watching %s", name)
	}
}

// Start opens one socket per interface. Missing interfaces are reported and
// skipped rather than aborting the whole capture.
func (c *Capturer) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("capture already running")
	}
	c.running = true
	c.mu.Unlock()

	targets := c.ifaces
	if len(targets) == 0 {
		auto, err := autoInterfaces()
		if err != nil {
			return err
		}
		targets = auto
	}
	if len(targets) == 0 {
		return errors.New("no capturable interfaces found")
	}

	filter, err := buildFilter(c.snapLen)
	if err != nil {
		// A broken filter must not silently degrade into capturing
		// everything; that is how a router falls over.
		return fmt.Errorf("build bpf filter: %w", err)
	}
	c.stats.FilterActive = true

	var opened int
	for _, name := range targets {
		fd, err := c.openSocket(name, filter)
		if err != nil {
			c.log("capture: skipping %s: %v", name, err)
			continue
		}
		c.mu.Lock()
		c.socks = append(c.socks, fd)
		c.watching = append(c.watching, name)
		c.mu.Unlock()
		opened++
		c.wg.Add(1)
		go c.readLoop(fd, name)
	}
	if opened == 0 {
		return errors.New("could not open any capture socket (CAP_NET_RAW required)")
	}
	c.stats.Interfaces = opened
	c.log("capture: listening on %d interface(s), snaplen %d", opened, c.snapLen)

	c.wg.Add(1)
	go c.statsLoop()
	return nil
}

func (c *Capturer) openSocket(name string, filter []bpfRawInstruction) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	// Attach the filter before binding so no unfiltered packet is ever queued.
	if err := setBPF(fd, filter); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach filter: %w", err)
	}
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind %s: %w", name, err)
	}
	// A generous receive buffer absorbs bursts without kernel drops.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4*1024*1024)
	// Report drop statistics on recv.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS, 1)
	// Read timeout keeps the loop responsive to shutdown.
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd, nil
}

func (c *Capturer) readLoop(fd int, ifname string) {
	defer c.wg.Done()
	runtime.LockOSThread()
	buf := make([]byte, c.snapLen+64)
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return
			}
			c.log("capture: %s recv error: %v", ifname, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n <= 0 {
			continue
		}
		c.stats.Packets++
		c.stats.Bytes += int64(n)
		if n >= c.snapLen {
			c.stats.Truncated++
		}
		c.handlePacket(buf[:n], n)
	}
}

// statsLoop periodically harvests kernel drop counters so the UI can show
// honest capture health instead of pretending nothing was missed.
func (c *Capturer) statsLoop() {
	defer c.wg.Done()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.mu.Lock()
			socks := append([]int(nil), c.socks...)
			c.mu.Unlock()
			var drops uint32
			for _, fd := range socks {
				if s, err := getPacketStats(fd); err == nil {
					drops += s.Drops
				}
			}
			c.stats.KernelDrops = drops
		}
	}
}

func (c *Capturer) Stats() CaptureStats { return c.stats }

func (c *Capturer) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	socks := c.socks
	c.socks = nil
	c.mu.Unlock()
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	for _, fd := range socks {
		unix.Close(fd)
	}
	c.wg.Wait()
}

// handlePacket decodes just enough of the headers to build a flow key, then
// hands any application-layer bytes to the DPI parsers.
func (c *Capturer) handlePacket(pkt []byte, wireLen int) {
	if len(pkt) < ethHdrLen {
		return
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	payload := pkt[ethHdrLen:]

	// 802.1Q / QinQ: step over the tag(s) to reach the real ethertype.
	for (etherType == 0x8100 || etherType == 0x88a8) && len(payload) >= 4 {
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}

	srcMAC := macString(pkt[6:12])
	dstMAC := macString(pkt[0:6])

	switch etherType {
	case etherARP:
		c.handleARP(payload, srcMAC)
		return
	case etherIPv4:
		c.handleIPv4(payload, srcMAC, dstMAC, wireLen)
	case etherIPv6:
		c.handleIPv6(payload, srcMAC, dstMAC, wireLen)
	}
}

// handleARP binds an IP to a MAC. This is how a client gets a vendor and a
// stable identity without running DHCP.
func (c *Capturer) handleARP(b []byte, srcMAC string) {
	if len(b) < 28 {
		return
	}
	// Only IPv4-over-Ethernet ARP.
	if binary.BigEndian.Uint16(b[0:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != etherIPv4 {
		return
	}
	senderMAC := macString(b[8:14])
	senderIP, ok := netip.AddrFromSlice(b[14:18])
	if !ok || senderIP.IsUnspecified() {
		return
	}
	if senderMAC == "00:00:00:00:00:00" {
		senderMAC = srcMAC
	}
	c.tracker.NoteARP(senderIP, senderMAC)
}

func (c *Capturer) handleIPv4(b []byte, srcMAC, dstMAC string, wireLen int) {
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		c.stats.ParseErrors++
		return
	}
	proto := b[9]
	src, ok1 := netip.AddrFromSlice(b[12:16])
	dst, ok2 := netip.AddrFromSlice(b[16:20])
	if !ok1 || !ok2 {
		return
	}
	c.handleL4(proto, src, dst, b[ihl:], srcMAC, dstMAC, wireLen)
}

func (c *Capturer) handleIPv6(b []byte, srcMAC, dstMAC string, wireLen int) {
	if len(b) < 40 {
		return
	}
	next := b[6]
	src, ok1 := netip.AddrFromSlice(b[8:24])
	dst, ok2 := netip.AddrFromSlice(b[24:40])
	if !ok1 || !ok2 {
		return
	}
	rest := b[40:]
	// Walk a bounded number of extension headers; a packet with more than
	// this is either pathological or an evasion attempt.
	for hops := 0; hops < 8; hops++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return
			}
			hdrLen := (int(rest[1]) + 1) * 8
			if len(rest) < hdrLen {
				return
			}
			next = rest[0]
			rest = rest[hdrLen:]
		case 44: // fragment
			if len(rest) < 8 {
				return
			}
			next = rest[0]
			rest = rest[8:]
		default:
			c.handleL4(next, src, dst, rest, srcMAC, dstMAC, wireLen)
			return
		}
	}
}

func (c *Capturer) handleL4(proto uint8, src, dst netip.Addr, b []byte, srcMAC, dstMAC string, wireLen int) {
	obs := Observation{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		Bytes:  wireLen,
		At:     time.Now(),
	}
	switch proto {
	case protoTCP:
		if len(b) < 20 {
			return
		}
		sport := binary.BigEndian.Uint16(b[0:2])
		dport := binary.BigEndian.Uint16(b[2:4])
		dataOff := int(b[12]>>4) * 4
		if dataOff < 20 || dataOff > len(b) {
			dataOff = 20
		}
		obs.TCPFlags = b[13]
		obs.Key = Key{Proto: protoTCP, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport}
		app := b[dataOff:]
		if len(app) > 0 {
			c.inspectTCPPayload(&obs, app, src, sport, dport)
		}
	case protoUDP:
		if len(b) < 8 {
			return
		}
		sport := binary.BigEndian.Uint16(b[0:2])
		dport := binary.BigEndian.Uint16(b[2:4])
		obs.Key = Key{Proto: protoUDP, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport}
		if len(b) > 8 && (dport == 443 || sport == 443) {
			c.inspectQUIC(&obs, b[8:], int(dport))
		}
	case protoICMP, 58:
		obs.Key = Key{Proto: proto, SrcIP: src, DstIP: dst}
	default:
		obs.Key = Key{Proto: proto, SrcIP: src, DstIP: dst}
	}
	c.tracker.Observe(obs)
}

func (c *Capturer) inspectTCPPayload(obs *Observation, app []byte, src netip.Addr, sport, dport uint16) {
	if app[0] == 0x16 {
		ch, err := dpi.ParseTLSRecord(app)
		if ch != nil {
			if ch.SNI != "" {
				obs.SNI = ch.SNI
				obs.App = dpi.ClassifyApp(ch.SNI)
			}
			obs.JA4 = ch.JA4
			return
		}
		// The kernel filter matches any TLS handshake record, so the server
		// side of every connection arrives here too, as does anything
		// truncated by the snap length. Neither is a fault, and counting
		// them would make the parse-error metric permanently non-zero and
		// therefore useless as a health signal.
		switch {
		case errors.Is(err, dpi.ErrNotHandshake),
			errors.Is(err, dpi.ErrNotClientHello),
			errors.Is(err, dpi.ErrIncomplete),
			errors.Is(err, dpi.ErrNoSNI):
		default:
			c.stats.ParseErrors++
		}
		return
	}
	if req, ok := dpi.ParseHTTPRequest(app); ok {
		obs.HTTPHost = req.Host
		obs.Referer = req.Referer
		if req.Host != "" {
			obs.App = dpi.ClassifyApp(req.Host)
		}
		if c.onHTTP != nil {
			c.onHTTP(src, req)
		}
	}
}

func (c *Capturer) inspectQUIC(obs *Observation, udpPayload []byte, dport int) {
	if !dpi.IsQUIC(udpPayload, dport) {
		return
	}
	obs.App = "QUIC"
	ch, err := dpi.ParseQUICInitial(udpPayload)
	if err != nil || ch == nil {
		return
	}
	c.tracker.NoteQUICDecrypt()
	if ch.SNI != "" {
		obs.SNI = ch.SNI
		if a := dpi.ClassifyApp(ch.SNI); a != "" {
			obs.App = a
		}
	}
	if ch.JA4 != "" {
		// Mark the fingerprint as QUIC-derived so it is not compared against
		// TCP JA4s, which have a different first character by spec.
		obs.JA4 = "q" + strings.TrimPrefix(ch.JA4, "t")
	}
}

// autoInterfaces picks every up, non-loopback interface that carries an
// address, skipping the virtual clutter a container host is full of.
func autoInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	skipPrefixes := []string{"lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "tailscale", "zt"}
	var out []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		skip := false
		for _, p := range skipPrefixes {
			if strings.HasPrefix(i.Name, p) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		out = append(out, i.Name)
	}
	return out, nil
}

// LocalPrefixes reports the CIDRs configured on this host, used to decide
// which side of a flow is "inside".
// LocalPrefixesExcluding is LocalPrefixes with named interfaces left out,
// used where tunnel addresses must not be treated as part of the LAN.
func LocalPrefixesExcluding(skip map[string]bool) []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || skip[i.Name] {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(ipnet.String()); err == nil {
					out = append(out, p.Masked().String())
				}
			}
		}
	}
	return out
}

func LocalPrefixes() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(ipnet.String()); err == nil {
					out = append(out, p.Masked().String())
				}
			}
		}
	}
	return out
}

func macString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

var _ = os.Getpid
