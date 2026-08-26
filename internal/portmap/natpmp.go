// Package portmap implements NAT-PMP (RFC 6886) so consoles, and anything else
// that expects to open its own inbound port, work behind Orbis.
//
// UPnP IGD is deliberately not implemented. It is a SOAP-over-HTTP protocol
// discovered by SSDP, has a long history of being reachable from the WAN by
// accident, and NAT-PMP covers the same need for every Apple device and modern
// game console. Anything that only speaks UPnP needs a manual port forward,
// which the firewall already supports.
package portmap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	opAnnounce = 0
	opMapUDP   = 1
	opMapTCP   = 2

	resultSuccess       = 0
	resultUnsupportedOp = 5
	resultNoResources   = 4
	resultRefused       = 2

	protocolVersion = 0
	natpmpPort      = 5351
)

// Mapping is one active port forward created by a client.
type Mapping struct {
	Protocol   string    `json:"protocol"`
	Client     string    `json:"client"`
	InternalPt uint16    `json:"internal_port"`
	ExternalPt uint16    `json:"external_port"`
	Expires    time.Time `json:"expires"`
	Created    time.Time `json:"created"`
}

// Config controls the service.
type Config struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen is the LAN address to serve on. Serving on the WAN would let
	// the internet punch holes in the firewall, so this must be a LAN bind.
	Listen string `yaml:"listen" json:"listen"`
	// WANInterface is where the forward is installed.
	WANInterface string `yaml:"wan_interface" json:"wan_interface"`
	// MaxLifetimeSeconds caps how long a client can hold a mapping.
	MaxLifetimeSeconds int `yaml:"max_lifetime_seconds" json:"max_lifetime_seconds"`
	// MaxPerClient stops one host exhausting the port space.
	MaxPerClient int `yaml:"max_per_client" json:"max_per_client"`
	// AllowedClients restricts who may request a mapping. Empty means any
	// LAN client, which is the point of the protocol but worth being able
	// to narrow.
	AllowedClients []string `yaml:"allowed_clients" json:"allowed_clients"`
	// MinPort/MaxPort bound the external port range handed out.
	MinPort uint16 `yaml:"min_port" json:"min_port"`
	MaxPort uint16 `yaml:"max_port" json:"max_port"`
}

// Server is the NAT-PMP responder.
type Server struct {
	cfg func() Config
	log func(string, ...any)

	mu       sync.Mutex
	conn     *net.UDPConn
	running  bool
	mappings map[string]*Mapping // key: proto/externalPort
	cancel   context.CancelFunc
	// epoch is the seconds-since-start value RFC 6886 requires so clients can
	// detect that the gateway rebooted and their mapping is gone.
	started time.Time
}

func New(cfg func() Config, log func(string, ...any)) *Server {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Server{cfg: cfg, log: log, mappings: map[string]*Mapping{}}
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Server) Start(ctx context.Context) error {
	c := s.cfg()
	if !c.Enabled {
		return nil
	}
	listen := c.Listen
	if listen == "" {
		listen = fmt.Sprintf("0.0.0.0:%d", natpmpPort)
	}
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", listen, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}

	cctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.conn = conn
	s.running = true
	s.cancel = cancel
	s.started = time.Now()
	s.mu.Unlock()

	go s.serve(cctx, conn)
	go s.expireLoop(cctx)
	s.log("portmap: NAT-PMP listening on %s", listen)
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	conn, cancel := s.conn, s.cancel
	s.conn, s.cancel = nil, nil
	s.running = false
	active := make([]*Mapping, 0, len(s.mappings))
	for _, m := range s.mappings {
		active = append(active, m)
	}
	s.mappings = map[string]*Mapping{}
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
	// Leaving forwards installed after the service stops would be a firewall
	// hole nobody is managing.
	for _, m := range active {
		s.removeForward(context.Background(), m)
	}
}

func (s *Server) serve(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		resp := s.handle(ctx, buf[:n], src)
		if len(resp) > 0 {
			_, _ = conn.WriteToUDP(resp, src)
		}
	}
}

// handle parses a request and returns the response bytes.
func (s *Server) handle(ctx context.Context, req []byte, src *net.UDPAddr) []byte {
	if len(req) < 2 || req[0] != protocolVersion {
		return nil
	}
	op := req[1]
	client, _ := netip.AddrFromSlice(src.IP)
	client = client.Unmap()

	if !s.allowed(client) {
		return s.errorResponse(op, resultRefused)
	}

	switch op {
	case opAnnounce:
		return s.announceResponse(ctx)
	case opMapUDP, opMapTCP:
		if len(req) < 12 {
			return s.errorResponse(op, resultUnsupportedOp)
		}
		internal := binary.BigEndian.Uint16(req[4:6])
		suggested := binary.BigEndian.Uint16(req[6:8])
		lifetime := binary.BigEndian.Uint32(req[8:12])
		return s.mapPort(ctx, op, client, internal, suggested, lifetime)
	default:
		return s.errorResponse(op, resultUnsupportedOp)
	}
}

func (s *Server) allowed(client netip.Addr) bool {
	c := s.cfg()
	if !client.IsValid() || !client.IsPrivate() && !client.IsLinkLocalUnicast() {
		// A request from a public address means the socket is exposed to the
		// WAN. Refusing is the only safe answer.
		return false
	}
	if len(c.AllowedClients) == 0 {
		return true
	}
	for _, a := range c.AllowedClients {
		if p, err := netip.ParsePrefix(a); err == nil && p.Contains(client) {
			return true
		}
		if addr, err := netip.ParseAddr(a); err == nil && addr == client {
			return true
		}
	}
	return false
}

func (s *Server) epoch() uint32 {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	return uint32(time.Since(started).Seconds())
}

func (s *Server) announceResponse(ctx context.Context) []byte {
	ext := s.externalAddr(ctx)
	out := make([]byte, 12)
	out[0] = protocolVersion
	out[1] = 128 // response to op 0
	binary.BigEndian.PutUint16(out[2:4], resultSuccess)
	binary.BigEndian.PutUint32(out[4:8], s.epoch())
	if ext.Is4() {
		copy(out[8:12], ext.AsSlice())
	}
	return out
}

func (s *Server) errorResponse(op byte, code uint16) []byte {
	out := make([]byte, 16)
	out[0] = protocolVersion
	out[1] = op + 128
	binary.BigEndian.PutUint16(out[2:4], code)
	binary.BigEndian.PutUint32(out[4:8], s.epoch())
	return out
}

// mapPort creates, refreshes or deletes a mapping. A lifetime of zero is the
// protocol's delete request.
func (s *Server) mapPort(ctx context.Context, op byte, client netip.Addr, internal, suggested uint16, lifetime uint32) []byte {
	c := s.cfg()
	proto := "udp"
	if op == opMapTCP {
		proto = "tcp"
	}

	if lifetime == 0 {
		s.deleteMappingsFor(ctx, client, proto, internal)
		return s.mapResponse(op, internal, 0, 0)
	}

	maxLife := uint32(c.MaxLifetimeSeconds)
	if maxLife == 0 {
		maxLife = 3600
	}
	if lifetime > maxLife {
		lifetime = maxLife
	}

	external, ok := s.pickExternal(c, client, proto, internal, suggested)
	if !ok {
		return s.errorResponse(op, resultNoResources)
	}

	m := &Mapping{
		Protocol: proto, Client: client.String(),
		InternalPt: internal, ExternalPt: external,
		Created: time.Now(), Expires: time.Now().Add(time.Duration(lifetime) * time.Second),
	}
	if err := s.installForward(ctx, m); err != nil {
		s.log("portmap: install %s %d->%s:%d failed: %v", proto, external, client, internal, err)
		return s.errorResponse(op, resultNoResources)
	}
	s.mu.Lock()
	s.mappings[key(proto, external)] = m
	s.mu.Unlock()

	s.log("portmap: %s %d -> %s:%d for %ds", proto, external, client, internal, lifetime)
	return s.mapResponse(op, internal, external, lifetime)
}

// pickExternal reuses an existing mapping for the same client and port when it
// exists (a refresh), honours the suggestion when free, and otherwise scans the
// configured range.
func (s *Server) pickExternal(c Config, client netip.Addr, proto string, internal, suggested uint16) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, m := range s.mappings {
		if m.Protocol == proto && m.Client == client.String() && m.InternalPt == internal {
			return m.ExternalPt, true
		}
	}

	count := 0
	for _, m := range s.mappings {
		if m.Client == client.String() {
			count++
		}
	}
	maxPer := c.MaxPerClient
	if maxPer <= 0 {
		maxPer = 32
	}
	if count >= maxPer {
		return 0, false
	}

	lo, hi := c.MinPort, c.MaxPort
	if lo == 0 {
		lo = 4096
	}
	if hi == 0 || hi < lo {
		hi = 65000
	}

	free := func(p uint16) bool {
		_, taken := s.mappings[key(proto, p)]
		return !taken
	}
	if suggested >= lo && suggested <= hi && free(suggested) {
		return suggested, true
	}
	for p := lo; p <= hi; p++ {
		if free(p) {
			return p, true
		}
		if p == 65535 {
			break
		}
	}
	return 0, false
}

func (s *Server) mapResponse(op byte, internal, external uint16, lifetime uint32) []byte {
	out := make([]byte, 16)
	out[0] = protocolVersion
	out[1] = op + 128
	binary.BigEndian.PutUint16(out[2:4], resultSuccess)
	binary.BigEndian.PutUint32(out[4:8], s.epoch())
	binary.BigEndian.PutUint16(out[8:10], internal)
	binary.BigEndian.PutUint16(out[10:12], external)
	binary.BigEndian.PutUint32(out[12:16], lifetime)
	return out
}

func (s *Server) deleteMappingsFor(ctx context.Context, client netip.Addr, proto string, internal uint16) {
	s.mu.Lock()
	var doomed []*Mapping
	for k, m := range s.mappings {
		if m.Client != client.String() || m.Protocol != proto {
			continue
		}
		// Internal port 0 deletes every mapping for that client and protocol.
		if internal != 0 && m.InternalPt != internal {
			continue
		}
		doomed = append(doomed, m)
		delete(s.mappings, k)
	}
	s.mu.Unlock()
	for _, m := range doomed {
		s.removeForward(ctx, m)
	}
}

func (s *Server) expireLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		s.mu.Lock()
		var doomed []*Mapping
		for k, m := range s.mappings {
			if now.After(m.Expires) {
				doomed = append(doomed, m)
				delete(s.mappings, k)
			}
		}
		s.mu.Unlock()
		for _, m := range doomed {
			s.log("portmap: expired %s %d -> %s:%d", m.Protocol, m.ExternalPt, m.Client, m.InternalPt)
			s.removeForward(ctx, m)
		}
	}
}

// Mappings returns the live table for the API.
func (s *Server) Mappings() []Mapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mapping, 0, len(s.mappings))
	for _, m := range s.mappings {
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExternalPt < out[j].ExternalPt })
	return out
}

// Delete removes a mapping administratively.
func (s *Server) Delete(proto string, external uint16) bool {
	s.mu.Lock()
	m, ok := s.mappings[key(proto, external)]
	if ok {
		delete(s.mappings, key(proto, external))
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	s.removeForward(context.Background(), m)
	return true
}

// ---- firewall plumbing ----
//
// Mappings live in their own nftables table so they can be added and removed
// without regenerating the main ruleset, which is loaded atomically and would
// otherwise have to be rebuilt on every console handshake.

const tableName = "orbis_portmap"

func (s *Server) ensureTable(ctx context.Context) error {
	script := strings.Join([]string{
		fmt.Sprintf("add table ip %s", tableName),
		fmt.Sprintf("add chain ip %s prerouting { type nat hook prerouting priority dstnat - 5 ; }", tableName),
		fmt.Sprintf("add chain ip %s forward { type filter hook forward priority filter - 5 ; }", tableName),
	}, "\n")
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Server) installForward(ctx context.Context, m *Mapping) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}
	c := s.cfg()
	comment := fmt.Sprintf("natpmp %s:%d", m.Client, m.InternalPt)
	rules := []string{
		fmt.Sprintf("add rule ip %s prerouting %s dport %d dnat to %s:%d comment %q",
			tableName, m.Protocol, m.ExternalPt, m.Client, m.InternalPt, comment),
		fmt.Sprintf("add rule ip %s forward ip daddr %s %s dport %d accept comment %q",
			tableName, m.Client, m.Protocol, m.InternalPt, comment),
	}
	if c.WANInterface != "" {
		rules[0] = fmt.Sprintf("add rule ip %s prerouting iifname %q %s dport %d dnat to %s:%d comment %q",
			tableName, c.WANInterface, m.Protocol, m.ExternalPt, m.Client, m.InternalPt, comment)
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(strings.Join(rules, "\n"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeForward deletes by matching the comment, since nftables handles are
// not stable across reloads and tracking them would drift from reality.
func (s *Server) removeForward(ctx context.Context, m *Mapping) {
	comment := fmt.Sprintf("natpmp %s:%d", m.Client, m.InternalPt)
	for _, chain := range []string{"prerouting", "forward"} {
		out, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "ip", tableName, chain).CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, comment) {
				continue
			}
			idx := strings.LastIndex(line, "# handle ")
			if idx < 0 {
				continue
			}
			handle := strings.TrimSpace(line[idx+len("# handle "):])
			_ = exec.CommandContext(ctx, "nft", "delete", "rule", "ip", tableName, chain, "handle", handle).Run()
		}
	}
}

func (s *Server) externalAddr(ctx context.Context) netip.Addr {
	c := s.cfg()
	if c.WANInterface == "" {
		return netip.Addr{}
	}
	out, err := exec.CommandContext(ctx, "ip", "-4", "-o", "addr", "show", "dev", c.WANInterface).CombinedOutput()
	if err != nil {
		return netip.Addr{}
	}
	for _, f := range strings.Fields(string(out)) {
		if !strings.Contains(f, "/") {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil && p.Addr().Is4() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

func key(proto string, port uint16) string { return fmt.Sprintf("%s/%d", proto, port) }
