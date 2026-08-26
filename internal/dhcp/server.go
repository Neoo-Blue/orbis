// Package dhcp is the DHCPv4 server. Beyond handing out addresses it is the
// single best source of device identity on a network: a DHCP exchange carries
// the MAC, the hostname, the vendor class and an option-request fingerprint
// that survives MAC randomization, all in one packet.
package dhcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// Hooks let the DHCP server feed identity into the rest of the system.
type Hooks struct {
	OnLease func(lease store.Lease, fingerprint, vendorClass string)
}

type Server struct {
	cfg   *config.Config
	st    *store.Store
	hooks Hooks
	log   func(string, ...any)

	mu      sync.Mutex
	servers []*server4.Server
	running bool

	// leases is the authoritative in-memory allocation table; the database is
	// the durable copy so a restart does not re-hand-out live addresses.
	leases   map[string]*store.Lease // keyed by MAC
	byIP     map[netip.Addr]string   // IP -> MAC
	leasesMu sync.RWMutex

	stats Stats
}

type Stats struct {
	Discovers int64 `json:"discovers"`
	Offers    int64 `json:"offers"`
	Requests  int64 `json:"requests"`
	Acks      int64 `json:"acks"`
	Naks      int64 `json:"naks"`
	Releases  int64 `json:"releases"`
	Declines  int64 `json:"declines"`
	Exhausted int64 `json:"pool_exhausted"`
}

func New(cfg *config.Config, st *store.Store, hooks Hooks, log func(string, ...any)) *Server {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Server{
		cfg: cfg, st: st, hooks: hooks, log: log,
		leases: map[string]*store.Lease{},
		byIP:   map[netip.Addr]string{},
	}
}

// Load restores leases so a restart does not double-allocate.
func (s *Server) Load() error {
	leases, err := s.st.Leases()
	if err != nil {
		return err
	}
	s.leasesMu.Lock()
	defer s.leasesMu.Unlock()
	for i := range leases {
		l := leases[i]
		mac := strings.ToLower(l.MAC)
		s.leases[mac] = &l
		if addr, err := netip.ParseAddr(l.IP); err == nil {
			s.byIP[addr] = mac
		}
	}
	// Static reservations from config are merged in and marked so they are
	// never reclaimed by the expiry sweep.
	for _, st_ := range s.cfg.Snapshot().DHCP.Static {
		mac := strings.ToLower(st_.MAC)
		addr, err := netip.ParseAddr(st_.IP)
		if err != nil {
			continue
		}
		l := &store.Lease{
			MAC: mac, IP: st_.IP, Hostname: st_.Hostname, Static: true,
			Starts: time.Now(), Expires: time.Now().AddDate(10, 0, 0),
		}
		s.leases[mac] = l
		s.byIP[addr] = mac
	}
	return nil
}

func (s *Server) Start() error {
	cfg := s.cfg.Snapshot()
	if !cfg.DHCP.Enabled || cfg.Mode != config.ModeInline {
		// Running a DHCP server on a network that already has one is the
		// fastest way to break it, so this stays off unless the node is
		// explicitly inline.
		s.log("dhcp: not started (enabled=%v mode=%s)", cfg.DHCP.Enabled, cfg.Mode)
		return nil
	}
	if err := s.Load(); err != nil {
		return err
	}

	var started []*server4.Server
	for _, scope := range cfg.DHCP.Scopes {
		if scope.Interface == "" {
			return fmt.Errorf("dhcp scope %q has no interface", scope.Name)
		}
		iface, err := net.InterfaceByName(scope.Interface)
		if err != nil {
			s.log("dhcp: scope %q interface %s unavailable: %v", scope.Name, scope.Interface, err)
			continue
		}
		laddr := &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort}
		srv, err := server4.NewServer(iface.Name, laddr, s.handler(scope))
		if err != nil {
			for _, p := range started {
				_ = p.Close()
			}
			return fmt.Errorf("dhcp listen on %s: %w", scope.Interface, err)
		}
		go func(sv *server4.Server, name string) {
			if err := sv.Serve(); err != nil {
				s.log("dhcp: server for %s stopped: %v", name, err)
			}
		}(srv, scope.Name)
		started = append(started, srv)
		s.log("dhcp: serving scope %q on %s (%s-%s)", scope.Name, scope.Interface, scope.RangeStart, scope.RangeEnd)
	}
	s.mu.Lock()
	s.servers = started
	s.running = len(started) > 0
	s.mu.Unlock()
	go s.expiryLoop()
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.running = false
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Close()
	}
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Server) handler(scope config.DHCPScope) server4.Handler {
	return func(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
		if req == nil {
			return
		}
		defer func() {
			// A malformed packet must not be able to kill the DHCP service
			// for the whole network.
			if r := recover(); r != nil {
				s.log("dhcp: recovered from panic: %v", r)
			}
		}()

		mac := strings.ToLower(req.ClientHWAddr.String())
		switch req.MessageType() {
		case dhcpv4.MessageTypeDiscover:
			s.stats.Discovers++
			s.handleDiscover(conn, peer, req, scope, mac)
		case dhcpv4.MessageTypeRequest:
			s.stats.Requests++
			s.handleRequest(conn, peer, req, scope, mac)
		case dhcpv4.MessageTypeRelease:
			s.stats.Releases++
			s.release(mac)
		case dhcpv4.MessageTypeDecline:
			s.stats.Declines++
			// A decline means the client found the address already in use;
			// blacklisting it briefly stops us handing it out again.
			s.decline(mac)
		case dhcpv4.MessageTypeInform:
			s.handleInform(conn, peer, req, scope)
		}
	}
}

func (s *Server) handleDiscover(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4, scope config.DHCPScope, mac string) {
	addr, err := s.allocate(mac, req, scope)
	if err != nil {
		s.stats.Exhausted++
		s.log("dhcp: cannot allocate for %s: %v", mac, err)
		return
	}
	reply, err := s.buildReply(req, dhcpv4.MessageTypeOffer, addr, scope)
	if err != nil {
		return
	}
	s.stats.Offers++
	s.send(conn, peer, req, reply)
}

func (s *Server) handleRequest(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4, scope config.DHCPScope, mac string) {
	requested := req.RequestedIPAddress()
	if requested == nil || requested.IsUnspecified() {
		requested = req.ClientIPAddr
	}
	addr, err := s.allocate(mac, req, scope)
	if err != nil {
		s.nak(conn, peer, req)
		return
	}
	// A client asking for an address we did not assign gets a NAK so it
	// restarts discovery instead of using a conflicting address.
	if requested != nil && !requested.IsUnspecified() && requested.String() != addr.String() {
		s.stats.Naks++
		s.nak(conn, peer, req)
		return
	}

	lease := s.commit(mac, addr, req, scope)
	reply, err := s.buildReply(req, dhcpv4.MessageTypeAck, addr, scope)
	if err != nil {
		return
	}
	s.stats.Acks++
	s.send(conn, peer, req, reply)

	if s.hooks.OnLease != nil {
		s.hooks.OnLease(lease, fingerprintOf(req), vendorClassOf(req))
	}
}

func (s *Server) handleInform(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4, scope config.DHCPScope) {
	// INFORM asks for options only; the client already has an address.
	reply, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return
	}
	reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	s.applyOptions(reply, scope)
	s.send(conn, peer, req, reply)
}

func (s *Server) nak(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	reply, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return
	}
	reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
	s.stats.Naks++
	s.send(conn, peer, req, reply)
}

func (s *Server) send(conn net.PacketConn, peer net.Addr, req, reply *dhcpv4.DHCPv4) {
	dst := peer
	// A client with no address yet cannot receive a unicast reply; RFC 2131
	// says to broadcast when the broadcast flag is set or ciaddr is zero.
	if req.IsBroadcast() || req.ClientIPAddr == nil || req.ClientIPAddr.IsUnspecified() {
		dst = &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}
	}
	if _, err := conn.WriteTo(reply.ToBytes(), dst); err != nil {
		s.log("dhcp: send failed: %v", err)
	}
}

// allocate picks an address: an existing lease if valid, the static
// reservation if there is one, otherwise the lowest free address in range.
func (s *Server) allocate(mac string, req *dhcpv4.DHCPv4, scope config.DHCPScope) (netip.Addr, error) {
	s.leasesMu.Lock()
	defer s.leasesMu.Unlock()

	if l, ok := s.leases[mac]; ok {
		if addr, err := netip.ParseAddr(l.IP); err == nil {
			if l.Static || time.Now().Before(l.Expires) || inRange(addr, scope) {
				return addr, nil
			}
		}
	}

	start, err := netip.ParseAddr(scope.RangeStart)
	if err != nil {
		return netip.Addr{}, err
	}
	end, err := netip.ParseAddr(scope.RangeEnd)
	if err != nil {
		return netip.Addr{}, err
	}
	// Hash the MAC into the range so a returning client that lost its lease
	// still tends to get the same address, which keeps firewall rules and
	// bookmarks working.
	span := int64(ipToInt(end) - ipToInt(start) + 1)
	if span <= 0 {
		return netip.Addr{}, fmt.Errorf("empty range")
	}
	preferred := intToIP(ipToInt(start) + uint32(hashMAC(mac)%uint64(span)))
	if _, taken := s.byIP[preferred]; !taken {
		return preferred, nil
	}
	for cur := start; ; cur = cur.Next() {
		if _, taken := s.byIP[cur]; !taken {
			return cur, nil
		}
		if cur == end {
			break
		}
	}
	return netip.Addr{}, fmt.Errorf("pool exhausted (%s-%s)", scope.RangeStart, scope.RangeEnd)
}

func (s *Server) commit(mac string, addr netip.Addr, req *dhcpv4.DHCPv4, scope config.DHCPScope) store.Lease {
	hours := scope.LeaseHours
	if hours <= 0 {
		hours = 12
	}
	now := time.Now()
	lease := store.Lease{
		MAC:         mac,
		IP:          addr.String(),
		Hostname:    strings.TrimSpace(req.HostName()),
		Scope:       scope.Name,
		Starts:      now,
		Expires:     now.Add(time.Duration(hours) * time.Hour),
		VendorClass: vendorClassOf(req),
		Fingerprint: fingerprintOf(req),
	}
	s.leasesMu.Lock()
	if old, ok := s.leases[mac]; ok && old.Static {
		lease.Static = true
		lease.Expires = old.Expires
	}
	if old, ok := s.leases[mac]; ok {
		if oldAddr, err := netip.ParseAddr(old.IP); err == nil && oldAddr != addr {
			delete(s.byIP, oldAddr)
		}
	}
	s.leases[mac] = &lease
	s.byIP[addr] = mac
	s.leasesMu.Unlock()

	if err := s.st.SaveLease(lease); err != nil {
		s.log("dhcp: persist lease %s: %v", mac, err)
	}
	return lease
}

func (s *Server) release(mac string) {
	s.leasesMu.Lock()
	if l, ok := s.leases[mac]; ok && !l.Static {
		if addr, err := netip.ParseAddr(l.IP); err == nil {
			delete(s.byIP, addr)
		}
		delete(s.leases, mac)
	}
	s.leasesMu.Unlock()
	_ = s.st.DeleteLease(mac)
}

func (s *Server) decline(mac string) {
	s.leasesMu.Lock()
	if l, ok := s.leases[mac]; ok && !l.Static {
		// Keep the IP marked as taken (by a phantom) so it is skipped, but
		// forget the binding so the client gets a different one next time.
		if addr, err := netip.ParseAddr(l.IP); err == nil {
			s.byIP[addr] = "declined"
		}
		delete(s.leases, mac)
	}
	s.leasesMu.Unlock()
	_ = s.st.DeleteLease(mac)
}

func (s *Server) buildReply(req *dhcpv4.DHCPv4, mt dhcpv4.MessageType, addr netip.Addr, scope config.DHCPScope) (*dhcpv4.DHCPv4, error) {
	reply, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	reply.UpdateOption(dhcpv4.OptMessageType(mt))
	reply.YourIPAddr = net.IP(addr.AsSlice())
	s.applyOptions(reply, scope)
	return reply, nil
}

func (s *Server) applyOptions(reply *dhcpv4.DHCPv4, scope config.DHCPScope) {
	_, ipnet, err := net.ParseCIDR(scope.Subnet)
	if err == nil {
		reply.UpdateOption(dhcpv4.OptSubnetMask(ipnet.Mask))
		reply.UpdateOption(dhcpv4.OptBroadcastAddress(broadcastOf(ipnet)))
	}
	if gw := net.ParseIP(scope.Gateway); gw != nil {
		reply.UpdateOption(dhcpv4.OptRouter(gw))
		reply.ServerIPAddr = gw
		reply.UpdateOption(dhcpv4.OptServerIdentifier(gw))
	}
	var dnsIPs []net.IP
	for _, d := range scope.DNS {
		if ip := net.ParseIP(d); ip != nil {
			dnsIPs = append(dnsIPs, ip)
		}
	}
	if len(dnsIPs) > 0 {
		reply.UpdateOption(dhcpv4.OptDNS(dnsIPs...))
	}
	if scope.Domain != "" {
		reply.UpdateOption(dhcpv4.OptDomainName(scope.Domain))
		reply.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionDNSDomainSearchList, []byte(scope.Domain)))
	}
	hours := scope.LeaseHours
	if hours <= 0 {
		hours = 12
	}
	reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(hours) * time.Hour))
	if scope.MTU > 0 {
		reply.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionInterfaceMTU,
			[]byte{byte(scope.MTU >> 8), byte(scope.MTU)}))
	}
	var ntpIPs []net.IP
	for _, n := range scope.NTP {
		if ip := net.ParseIP(n); ip != nil {
			ntpIPs = append(ntpIPs, ip)
		}
	}
	if len(ntpIPs) > 0 {
		reply.UpdateOption(dhcpv4.OptNTPServers(ntpIPs...))
	}
}

// expiryLoop reclaims addresses whose leases have run out.
func (s *Server) expiryLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		if !s.Running() {
			return
		}
		now := time.Now()
		var expired []string
		s.leasesMu.Lock()
		for mac, l := range s.leases {
			if !l.Static && now.After(l.Expires) {
				expired = append(expired, mac)
				if addr, err := netip.ParseAddr(l.IP); err == nil {
					delete(s.byIP, addr)
				}
				delete(s.leases, mac)
			}
		}
		s.leasesMu.Unlock()
		for _, mac := range expired {
			_ = s.st.DeleteLease(mac)
		}
		if len(expired) > 0 {
			s.log("dhcp: reclaimed %d expired lease(s)", len(expired))
		}
	}
}

// Leases returns the current allocation table.
func (s *Server) Leases() []store.Lease {
	s.leasesMu.RLock()
	defer s.leasesMu.RUnlock()
	out := make([]store.Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	return out
}

func (s *Server) Stats() map[string]any {
	s.leasesMu.RLock()
	n := len(s.leases)
	s.leasesMu.RUnlock()
	return map[string]any{
		"running": s.Running(), "leases": n,
		"discovers": s.stats.Discovers, "offers": s.stats.Offers,
		"requests": s.stats.Requests, "acks": s.stats.Acks,
		"naks": s.stats.Naks, "releases": s.stats.Releases,
		"declines": s.stats.Declines, "pool_exhausted": s.stats.Exhausted,
	}
}

// ---- option helpers ----

// fingerprintOf renders option 55 (parameter request list) as the canonical
// comma-separated fingerprint used by device-identification databases.
func fingerprintOf(req *dhcpv4.DHCPv4) string {
	list := req.ParameterRequestList()
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, o := range list {
		parts = append(parts, strconv.Itoa(int(o.Code())))
	}
	return strings.Join(parts, ",")
}

func vendorClassOf(req *dhcpv4.DHCPv4) string {
	if v := req.ClassIdentifier(); v != "" {
		return v
	}
	return ""
}

func inRange(addr netip.Addr, scope config.DHCPScope) bool {
	start, err1 := netip.ParseAddr(scope.RangeStart)
	end, err2 := netip.ParseAddr(scope.RangeEnd)
	if err1 != nil || err2 != nil {
		return false
	}
	return ipToInt(addr) >= ipToInt(start) && ipToInt(addr) <= ipToInt(end)
}

func ipToInt(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func intToIP(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// hashMAC is FNV-1a; it only needs to spread addresses across the pool, not
// resist anything.
func hashMAC(mac string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(mac); i++ {
		h ^= uint64(mac[i])
		h *= 1099511628211
	}
	return h
}

func broadcastOf(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return net.IPv4bcast
	}
	mask := n.Mask
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

var _ = context.Background
