// Package flows maintains the live connection table that the globe, the
// client list and the history view all read from.
//
// A flow is created the first time a 5-tuple is seen, enriched as the
// handshake reveals a hostname, updated with byte counters from conntrack,
// and closed either by a FIN/RST or by the idle timeout. Closed flows are
// handed to the store; open ones stay in memory so the UI can stream them.
package flows

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Key identifies a connection. The tuple is normalised so packets in both
// directions land on the same entry.
type Key struct {
	Proto   uint8
	SrcIP   netip.Addr
	SrcPort uint16
	DstIP   netip.Addr
	DstPort uint16
}

func (k Key) String() string {
	return fmt.Sprintf("%d/%s:%d-%s:%d", k.Proto, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// Canonical returns the tuple with the lower endpoint first plus a bool
// saying whether the arguments were swapped, so a reply packet updates the
// same flow as the request that opened it.
func (k Key) Canonical() (Key, bool) {
	a := k.SrcIP.Compare(k.DstIP)
	if a < 0 || (a == 0 && k.SrcPort <= k.DstPort) {
		return k, false
	}
	return Key{Proto: k.Proto, SrcIP: k.DstIP, SrcPort: k.DstPort, DstIP: k.SrcIP, DstPort: k.SrcPort}, true
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("ip/%d", p)
}

// Entry is a live flow. Access is guarded by Tracker.mu.
type Entry struct {
	store.Flow

	// key is the canonical (order-independent) map key. orient is the flow
	// as it actually happened: orient.SrcIP is the endpoint that opened the
	// connection. The two differ whenever the canonical ordering happens to
	// put the responder first, which is why direction, the service port and
	// the byte direction are all derived from orient, never from key.
	key    Key
	orient Key
	srcMAC string
	dstMAC string
	fin    bool
	rst    bool
	// syncedBytes remembers what conntrack last reported so a counter reset
	// (conntrack entry recycled) does not produce a negative delta.
	syncedIn  int64
	syncedOut int64
	// dirty marks entries changed since the last persist sweep.
	dirty bool
	// resolvedHost records where the hostname came from, for the UI badge.
	hostSource string
}

// Verdict callback: given a flow that just learned its hostname, the policy
// layer decides whether to allow, block or flag it. Returning a non-empty
// verdict updates the entry and, for blocks, triggers enforcement.
type VerdictFunc func(e *store.Flow) (verdict, reason, ruleID string)

// Enforcer terminates a flow that policy has decided to block. Implemented
// by the firewall package (nftables set insert + conntrack drop).
type Enforcer interface {
	Terminate(key string, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto uint8) error
}

// Subscriber receives live updates for the WebSocket stream.
type Subscriber func(ev Update)

type UpdateKind string

const (
	UpdateNew     UpdateKind = "flow.new"
	UpdateChanged UpdateKind = "flow.update"
	UpdateClosed  UpdateKind = "flow.close"
)

type Update struct {
	Kind UpdateKind  `json:"kind"`
	Flow *store.Flow `json:"flow"`
}

type Tracker struct {
	mu      sync.RWMutex
	entries map[Key]*Entry

	// localNets is read on the packet hot path from inside the critical
	// section that guards `entries`, so it deliberately lives outside the
	// mutex: sync.RWMutex is not reentrant, and an RLock taken while the
	// same goroutine holds Lock is a permanent deadlock, not a slow path.
	localNets atomic.Pointer[[]netip.Prefix]

	st      *store.Store
	geo     *geoip.Resolver
	subs    map[int]Subscriber
	nextSub int
	subMu   sync.RWMutex

	verdict  VerdictFunc
	enforcer Enforcer

	idleTimeout time.Duration
	maxFlows    int

	// hostHints maps a resolved IP back to the name the client asked for,
	// populated by the DNS server. This is what lets a flow to 142.250.x.x
	// show up as "youtube.com" instead of a bare address.
	hostHints   map[netip.Addr]hostHint
	hostHintsMu sync.RWMutex

	// clientIDs maps an IP to the stable client id used across the app.
	clientIDs   map[netip.Addr]string
	clientIDsMu sync.RWMutex

	stats Stats
	stop  chan struct{}
	wg    sync.WaitGroup
}

type hostHint struct {
	name    string
	expires time.Time
}

type Stats struct {
	Active        int64 `json:"active"`
	Total         int64 `json:"total"`
	Dropped       int64 `json:"dropped_capacity"`
	PacketsSeen   int64 `json:"packets_seen"`
	SNIExtracted  int64 `json:"sni_extracted"`
	QUICDecrypted int64 `json:"quic_decrypted"`
	Blocked       int64 `json:"blocked"`
}

func NewTracker(st *store.Store, geo *geoip.Resolver, idleTimeout time.Duration, maxFlows int) *Tracker {
	if idleTimeout <= 0 {
		idleTimeout = 2 * time.Minute
	}
	if maxFlows <= 0 {
		maxFlows = 65536
	}
	return &Tracker{
		entries:     make(map[Key]*Entry),
		st:          st,
		geo:         geo,
		subs:        make(map[int]Subscriber),
		hostHints:   make(map[netip.Addr]hostHint),
		clientIDs:   make(map[netip.Addr]string),
		idleTimeout: idleTimeout,
		maxFlows:    maxFlows,
		stop:        make(chan struct{}),
	}
}

func (t *Tracker) SetVerdictFunc(f VerdictFunc) { t.verdict = f }
func (t *Tracker) SetEnforcer(e Enforcer)       { t.enforcer = e }

// SetLocalNets tells the tracker which prefixes count as "inside", which is
// how direction and client attribution are decided.
func (t *Tracker) SetLocalNets(cidrs []string) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	t.localNets.Store(&out)
}

// isLocal is lock-free by design; see the note on the localNets field.
func (t *Tracker) isLocal(a netip.Addr) bool {
	if geoip.IsPrivate(a) {
		return true
	}
	nets := t.localNets.Load()
	if nets == nil {
		return false
	}
	for _, p := range *nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Subscribe registers a live-update callback and returns an unsubscribe fn.
func (t *Tracker) Subscribe(fn Subscriber) func() {
	t.subMu.Lock()
	id := t.nextSub
	t.nextSub++
	t.subs[id] = fn
	t.subMu.Unlock()
	return func() {
		t.subMu.Lock()
		delete(t.subs, id)
		t.subMu.Unlock()
	}
}

func (t *Tracker) publish(kind UpdateKind, f store.Flow) {
	t.subMu.RLock()
	defer t.subMu.RUnlock()
	if len(t.subs) == 0 {
		return
	}
	cp := f
	for _, fn := range t.subs {
		fn(Update{Kind: kind, Flow: &cp})
	}
}

// NoteHostname records a DNS answer so subsequent flows to that address can
// be labelled. TTL-bounded so a recycled CDN address does not keep an old
// name forever.
func (t *Tracker) NoteHostname(addr netip.Addr, name string, ttl time.Duration) {
	if name == "" || !addr.IsValid() {
		return
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 6*time.Hour {
		ttl = 6 * time.Hour
	}
	t.hostHintsMu.Lock()
	t.hostHints[addr] = hostHint{name: strings.TrimSuffix(name, "."), expires: time.Now().Add(ttl)}
	t.hostHintsMu.Unlock()
}

func (t *Tracker) lookupHostHint(addr netip.Addr) string {
	t.hostHintsMu.RLock()
	h, ok := t.hostHints[addr]
	t.hostHintsMu.RUnlock()
	if !ok || time.Now().After(h.expires) {
		return ""
	}
	return h.name
}

// NoteClient binds an IP to a client id so flows can be attributed even when
// the capture path never sees a MAC (routed or VPN traffic).
func (t *Tracker) NoteClient(addr netip.Addr, clientID string) {
	if clientID == "" || !addr.IsValid() {
		return
	}
	t.clientIDsMu.Lock()
	t.clientIDs[addr] = clientID
	t.clientIDsMu.Unlock()
}

func (t *Tracker) clientFor(addr netip.Addr) string {
	t.clientIDsMu.RLock()
	id := t.clientIDs[addr]
	t.clientIDsMu.RUnlock()
	return id
}

// Observation is what the capture layer hands in for each packet.
type Observation struct {
	Key      Key
	Reversed bool
	Bytes    int
	SrcMAC   string
	DstMAC   string
	TCPFlags uint8
	// Enrichment discovered by the DPI layer on this packet.
	SNI      string
	HTTPHost string
	Referer  string
	JA4      string
	App      string
	At       time.Time
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// Observe folds a packet into the flow table. Hot path: keep allocations out
// of the common case where the flow already exists and nothing new is learned.
func (t *Tracker) Observe(o Observation) {
	if o.At.IsZero() {
		o.At = time.Now()
	}
	canon, _ := o.Key.Canonical()

	t.mu.Lock()
	e, exists := t.entries[canon]
	if !exists {
		if len(t.entries) >= t.maxFlows {
			t.stats.Dropped++
			t.mu.Unlock()
			return
		}
		e = t.newEntry(canon, o)
		t.entries[canon] = e
		t.stats.Total++
		t.stats.Active = int64(len(t.entries))
	}

	// "Outbound" means travelling in the same direction the flow was opened.
	// Comparing against the stored orientation is what keeps a reply from
	// being counted as a fresh request in the opposite direction.
	outbound := o.Key.SrcIP == e.orient.SrcIP && o.Key.SrcPort == e.orient.SrcPort
	if o.Reversed {
		outbound = !outbound
	}
	if outbound {
		e.PacketsOut++
		e.BytesOut += int64(o.Bytes)
	} else {
		e.PacketsIn++
		e.BytesIn += int64(o.Bytes)
	}
	e.LastSeen = o.At
	e.dirty = true

	learned := false
	if o.SNI != "" && e.SNI == "" {
		e.SNI = o.SNI
		if e.Hostname == "" {
			e.Hostname = o.SNI
			e.hostSource = "sni"
		}
		t.stats.SNIExtracted++
		learned = true
	}
	if o.HTTPHost != "" && e.Hostname == "" {
		e.Hostname = o.HTTPHost
		e.hostSource = "http"
		learned = true
	}
	if o.JA4 != "" && e.JA4 == "" {
		e.JA4 = o.JA4
	}
	if o.App != "" && e.App == "" {
		e.App = o.App
	}
	if e.Hostname != "" && e.App == "" {
		e.App = classify(e.Hostname)
	}
	if o.TCPFlags&tcpFIN != 0 {
		e.fin = true
	}
	if o.TCPFlags&tcpRST != 0 {
		e.rst = true
	}
	if o.SrcMAC != "" && e.srcMAC == "" && o.Key.SrcIP == e.orient.SrcIP {
		e.srcMAC = o.SrcMAC
	}

	snapshot := e.Flow
	needVerdict := learned && e.Verdict == store.VerdictAllow
	closing := e.fin || e.rst
	t.mu.Unlock()

	if !exists {
		t.publish(UpdateNew, snapshot)
	}

	if needVerdict && t.verdict != nil {
		v, reason, ruleID := t.verdict(&snapshot)
		if v != "" && v != store.VerdictAllow {
			t.applyVerdict(canon, v, reason, ruleID)
		}
	} else if learned {
		t.publish(UpdateChanged, snapshot)
	}

	if closing {
		// A FIN only closes one half; wait for the reaper to confirm both
		// sides are done rather than truncating a half-closed download.
		if e.rst {
			t.Close(canon, o.At)
		}
	}
}

func (t *Tracker) newEntry(canon Key, o Observation) *Entry {
	now := o.At
	orient := t.orient(o)

	srcLocal := t.isLocal(orient.SrcIP)
	dstLocal := t.isLocal(orient.DstIP)
	dir := store.DirOutbound
	switch {
	case srcLocal && dstLocal:
		dir = store.DirLocal
	case !srcLocal && dstLocal:
		dir = store.DirInbound
	}

	// The remote end is whichever side is not on our network; that is the
	// endpoint the globe places and the one worth naming.
	remote := orient.DstIP
	if dir == store.DirInbound {
		remote = orient.SrcIP
	}
	loc := t.geo.LookupAddr(remote)

	host := t.lookupHostHint(remote)
	hostSrc := ""
	if host != "" {
		hostSrc = "dns"
	} else if name := geoip.WellKnownName(remote.String()); name != "" {
		// Local discovery chatter is a large share of any network's flow
		// count; labelling it keeps the connection log readable instead of
		// a wall of multicast addresses.
		host = name
		hostSrc = "well-known"
	}

	clientIP := orient.SrcIP
	if dir == store.DirInbound {
		clientIP = orient.DstIP
	}

	e := &Entry{
		Flow: store.Flow{
			ID:        uuid.NewString(),
			ClientID:  t.clientFor(clientIP),
			StartedAt: now,
			LastSeen:  now,
			Proto:     protoName(orient.Proto),
			SrcIP:     orient.SrcIP.String(),
			SrcPort:   int(orient.SrcPort),
			DstIP:     orient.DstIP.String(),
			DstPort:   int(orient.DstPort),
			Direction: dir,
			Hostname:  host,
			Country:   loc.Country,
			City:      loc.City,
			Lat:       loc.Lat,
			Lon:       loc.Lon,
			ASN:       loc.ASN,
			ASOrg:     loc.ASOrg,
			Verdict:   store.VerdictAllow,
		},
		key:        canon,
		orient:     orient,
		srcMAC:     o.SrcMAC,
		hostSource: hostSrc,
		dirty:      true,
	}
	if host != "" {
		e.App = classify(host)
	}
	return e
}

// orient decides which endpoint opened the connection, in descending order of
// evidence:
//
//  1. A bare SYN is definitive — that packet's source is the initiator.
//  2. Otherwise, if exactly one side is on our network, it is the initiator;
//     the alternative would mean an unsolicited inbound connection, which is
//     far rarer than joining an established flow mid-stream.
//  3. Otherwise the well-known port wins: a connection involving port 443 was
//     almost certainly opened by the other end.
//  4. Failing all that, take the packet as it came.
func (t *Tracker) orient(o Observation) Key {
	k := o.Key
	if o.Reversed {
		k = Key{Proto: k.Proto, SrcIP: k.DstIP, SrcPort: k.DstPort, DstIP: k.SrcIP, DstPort: k.SrcPort}
	}

	if k.Proto == 6 && o.TCPFlags&tcpSYN != 0 {
		// A SYN+ACK is the responder's first packet, so it needs flipping;
		// a bare SYN is the initiator's.
		if o.TCPFlags&tcpACK != 0 {
			return Key{Proto: k.Proto, SrcIP: k.DstIP, SrcPort: k.DstPort, DstIP: k.SrcIP, DstPort: k.SrcPort}
		}
		return k
	}

	srcLocal, dstLocal := t.isLocal(k.SrcIP), t.isLocal(k.DstIP)
	if srcLocal != dstLocal {
		if dstLocal {
			return Key{Proto: k.Proto, SrcIP: k.DstIP, SrcPort: k.DstPort, DstIP: k.SrcIP, DstPort: k.SrcPort}
		}
		return k
	}

	if isServicePort(k.SrcPort) && !isServicePort(k.DstPort) {
		return Key{Proto: k.Proto, SrcIP: k.DstIP, SrcPort: k.DstPort, DstIP: k.SrcIP, DstPort: k.SrcPort}
	}
	return k
}

// isServicePort reports whether a port is one a server listens on rather than
// one a client picks. Ephemeral ranges start at 32768 on Linux and 49152 by
// IANA; anything below 1024 or in the common service band is a listener.
func isServicePort(p uint16) bool {
	if p == 0 {
		return false
	}
	if p < 1024 {
		return true
	}
	switch p {
	case 1194, 1900, 3128, 3306, 3389, 5060, 5353, 5432, 6379, 8000, 8080, 8443, 8883, 9000, 9090, 9200, 27017, 51820:
		return true
	}
	return false
}

// applyVerdict records a decision and, for blocks, asks the enforcer to kill
// the connection so the client sees a reset rather than a hang.
func (t *Tracker) applyVerdict(k Key, verdict, reason, ruleID string) {
	t.mu.Lock()
	e, ok := t.entries[k]
	if !ok {
		t.mu.Unlock()
		return
	}
	e.Verdict = verdict
	e.Reason = reason
	e.RuleID = ruleID
	e.dirty = true
	if verdict == store.VerdictBlock {
		e.Risk = maxF(e.Risk, 0.8)
		t.stats.Blocked++
	}
	snapshot := e.Flow
	entryKey := e.key
	t.mu.Unlock()

	t.publish(UpdateChanged, snapshot)

	if verdict == store.VerdictBlock && t.enforcer != nil {
		_ = t.enforcer.Terminate(entryKey.String(), entryKey.SrcIP, entryKey.DstIP,
			entryKey.SrcPort, entryKey.DstPort, entryKey.Proto)
	}
}

// BlockFlow is the API-facing kill switch used by the UI and the assistant.
func (t *Tracker) BlockFlow(flowID, reason string) bool {
	t.mu.RLock()
	var found Key
	ok := false
	for k, e := range t.entries {
		if e.ID == flowID {
			found, ok = k, true
			break
		}
	}
	t.mu.RUnlock()
	if !ok {
		return false
	}
	t.applyVerdict(found, store.VerdictBlock, reason, "")
	return true
}

// Close finalises a flow and queues it for persistence.
func (t *Tracker) Close(k Key, at time.Time) {
	t.mu.Lock()
	e, ok := t.entries[k]
	if !ok {
		t.mu.Unlock()
		return
	}
	delete(t.entries, k)
	t.stats.Active = int64(len(t.entries))
	end := at
	e.EndedAt = &end
	snapshot := e.Flow
	t.mu.Unlock()

	t.st.QueueFlow(snapshot)
	t.publish(UpdateClosed, snapshot)
}

// Start launches the reaper and the periodic persist sweep.
func (t *Tracker) Start() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		reap := time.NewTicker(10 * time.Second)
		persist := time.NewTicker(5 * time.Second)
		defer reap.Stop()
		defer persist.Stop()
		for {
			select {
			case <-t.stop:
				t.persistAll()
				return
			case <-reap.C:
				t.reap()
			case <-persist.C:
				t.persistDirty()
			}
		}
	}()
}

func (t *Tracker) Stop() {
	select {
	case <-t.stop:
	default:
		close(t.stop)
	}
	t.wg.Wait()
}

// reap closes flows idle past the timeout. TCP flows that saw a FIN get a
// much shorter grace period since they are known to be finished.
func (t *Tracker) reap() {
	now := time.Now()
	var expired []Key
	t.mu.RLock()
	for k, e := range t.entries {
		timeout := t.idleTimeout
		if e.fin {
			timeout = 15 * time.Second
		}
		if k.Proto == 17 && e.DstPort == 53 {
			timeout = 10 * time.Second // DNS exchanges are one-shot
		}
		if now.Sub(e.LastSeen) > timeout {
			expired = append(expired, k)
		}
	}
	t.mu.RUnlock()
	for _, k := range expired {
		t.Close(k, now)
	}
}

// persistDirty checkpoints long-lived flows so a 4-hour video stream still
// appears in history (and in the byte totals) before it ends.
func (t *Tracker) persistDirty() {
	t.mu.Lock()
	var batch []store.Flow
	for _, e := range t.entries {
		if e.dirty {
			batch = append(batch, e.Flow)
			e.dirty = false
		}
	}
	t.mu.Unlock()
	for _, f := range batch {
		t.st.QueueFlow(f)
	}
}

func (t *Tracker) persistAll() {
	t.mu.Lock()
	batch := make([]store.Flow, 0, len(t.entries))
	now := time.Now()
	for _, e := range t.entries {
		f := e.Flow
		f.EndedAt = &now
		batch = append(batch, f)
	}
	t.entries = make(map[Key]*Entry)
	t.mu.Unlock()
	for _, f := range batch {
		t.st.QueueFlow(f)
	}
}

// Active returns a snapshot of the live table, newest first, for the globe.
func (t *Tracker) Active(limit int) []store.Flow {
	t.mu.RLock()
	out := make([]store.Flow, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, e.Flow)
	}
	t.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ActiveForClient filters the live table to one device.
func (t *Tracker) ActiveForClient(clientID string) []store.Flow {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := []store.Flow{}
	for _, e := range t.entries {
		if e.ClientID == clientID {
			out = append(out, e.Flow)
		}
	}
	return out
}

// ClientRates computes per-client throughput over the live table, which the
// client list uses for its live bars.
func (t *Tracker) ClientRates() map[string][2]float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	now := time.Now()
	out := map[string][2]float64{}
	for _, e := range t.entries {
		if e.ClientID == "" {
			continue
		}
		window := now.Sub(e.StartedAt).Seconds()
		if window < 1 {
			window = 1
		}
		cur := out[e.ClientID]
		cur[0] += float64(e.BytesIn) / window
		cur[1] += float64(e.BytesOut) / window
		out[e.ClientID] = cur
	}
	return out
}

// NoteQUICDecrypt records a successful QUIC Initial decryption. It exists so
// the capture path never has to take the tracker lock itself, which is how
// the lock ordering stays obvious.
func (t *Tracker) NoteQUICDecrypt() {
	t.mu.Lock()
	t.stats.QUICDecrypted++
	t.mu.Unlock()
}

func (t *Tracker) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.stats
	s.Active = int64(len(t.entries))
	return s
}

// SyncConntrack folds authoritative byte counters from the kernel into the
// table. The userspace sniffer only sees what the ring gives it; conntrack
// sees everything the forwarding path moved.
func (t *Tracker) SyncConntrack(entries []CTEntry) {
	now := time.Now()
	t.mu.Lock()
	for _, ct := range entries {
		k := Key{Proto: ct.Proto, SrcIP: ct.SrcIP, SrcPort: ct.SrcPort, DstIP: ct.DstIP, DstPort: ct.DstPort}
		canon, _ := k.Canonical()
		e, ok := t.entries[canon]
		if !ok {
			if len(t.entries) >= t.maxFlows {
				t.stats.Dropped++
				continue
			}
			// The conntrack tuple is already in initiator order, so hand
			// newEntry the observed key rather than the canonical one.
			e = t.newEntry(canon, Observation{Key: k, At: now})
			t.entries[canon] = e
			t.stats.Total++
		}
		// conntrack's ORIGINAL direction is, by definition, the direction
		// the connection was opened in. Align it with how we oriented the
		// flow rather than with the canonical key ordering.
		out, in := ct.BytesOrig, ct.BytesReply
		if ct.SrcIP != e.orient.SrcIP || ct.SrcPort != e.orient.SrcPort {
			in, out = out, in
		}
		// A conntrack entry recycled onto the same tuple restarts its
		// counters; treating that as a delta would produce a huge negative.
		if in >= e.syncedIn && out >= e.syncedOut {
			e.BytesIn += in - e.syncedIn
			e.BytesOut += out - e.syncedOut
		}
		e.syncedIn, e.syncedOut = in, out
		e.LastSeen = now
		e.dirty = true
	}
	t.stats.Active = int64(len(t.entries))
	t.mu.Unlock()
}

func classify(host string) string {
	return appClassifier(host)
}

// appClassifier is a package-level indirection so dpi does not have to be
// imported by every caller of the tracker.
var appClassifier = func(string) string { return "" }

// SetAppClassifier wires in the dpi classifier at startup.
func SetAppClassifier(fn func(string) string) { appClassifier = fn }

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// arpSink receives MAC/IP bindings discovered on the wire. It is set by the
// client registry at startup; until then ARP observations are dropped, which
// is correct because there is nowhere to attribute them yet.
type arpSink interface {
	Observe(ip netip.Addr, mac, hostname string) *store.Client
}

var arpTarget arpSink
var arpTargetMu sync.RWMutex

// SetARPSink wires ARP discovery into the client registry.
func SetARPSink(s arpSink) {
	arpTargetMu.Lock()
	arpTarget = s
	arpTargetMu.Unlock()
}

// NoteARP records a MAC/IP binding seen in an ARP frame.
func (t *Tracker) NoteARP(ip netip.Addr, mac string) {
	arpTargetMu.RLock()
	sink := arpTarget
	arpTargetMu.RUnlock()
	if sink == nil || !ip.IsValid() || ip.IsUnspecified() {
		return
	}
	c := sink.Observe(ip, mac, "")
	if c != nil {
		t.NoteClient(ip, c.ID)
	}
}
