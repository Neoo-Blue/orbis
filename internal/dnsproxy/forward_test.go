package dnsproxy

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/miekg/dns"
)

// fakeUpstream is a real TCP DNS server driven by answer.
type fakeUpstream struct {
	conns   atomic.Int64
	queries atomic.Int64
	spec    string
}

type countingListener struct {
	net.Listener
	up *fakeUpstream
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.up.conns.Add(1)
	}
	return c, err
}

func startUpstream(t *testing.T, delay time.Duration, answer func(q dns.Question, m *dns.Msg)) *fakeUpstream {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := &fakeUpstream{spec: "tcp://" + l.Addr().String()}
	srv := &dns.Server{Listener: countingListener{l, up}, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		up.queries.Add(1)
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		answer(r.Question[0], m)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return up
}

func goodAnswer(q dns.Question, m *dns.Msg) {
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{93, 184, 216, 34}}}
}

func nxdomain(q dns.Question, m *dns.Msg) {
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1800},
		Ns: "ns.example.com.", Mbox: "h.example.com.", Minttl: 1800}}
}

func servfailing(_ dns.Question, m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }

func newTestServer(t *testing.T, adblockOn bool, ups ...*fakeUpstream) (*Server, *adblock.Matcher) {
	t.Helper()
	cfg := &config.Config{}
	cfg.DNS.MaxTTL = 86400
	cfg.DNS.CacheSize = 100
	cfg.DNS.Strategy = "parallel"
	cfg.AdBlock.Enabled = adblockOn
	cfg.AdBlock.CNAMEUncloak = adblockOn
	for _, u := range ups {
		cfg.DNS.Upstreams = append(cfg.DNS.Upstreams, u.spec)
	}
	m := adblock.New()
	s := New(cfg, nil, m, Hooks{}, nil)
	if err := s.ReloadUpstreams(); err != nil {
		t.Fatal(err)
	}
	return s, m
}

type recordingWriter struct {
	dns.ResponseWriter
	msg  *dns.Msg
	addr net.Addr
}

func (w *recordingWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *recordingWriter) RemoteAddr() net.Addr {
	if w.addr != nil {
		return w.addr
	}
	return &net.TCPAddr{IP: net.IPv4(192, 168, 1, 9), Port: 5000}
}

func ask(t *testing.T, s *Server, name string, qtype uint16) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(name), qtype)
	w := &recordingWriter{}
	s.handle(w, r)
	if w.msg == nil {
		t.Fatalf("no answer for %s", name)
	}
	return w.msg
}

func TestNXDOMAINReachesTheClientAsNXDOMAIN(t *testing.T) {
	up := startUpstream(t, 0, nxdomain)
	s, _ := newTestServer(t, false, up)
	for _, label := range []string{"forwarded", "cached"} {
		if got := ask(t, s, "gone.example.com", dns.TypeAAAA); got.Rcode != dns.RcodeNameError {
			t.Fatalf("%s answer rcode = %s, want NXDOMAIN", label, dns.RcodeToString[got.Rcode])
		}
	}
	if up.queries.Load() != 1 {
		t.Fatalf("upstream asked %d times, the second answer should be cached", up.queries.Load())
	}
}

func TestServfailNeverWinsWhileAnotherUpstreamCanAnswer(t *testing.T) {
	bad := startUpstream(t, 0, servfailing)
	good := startUpstream(t, 40*time.Millisecond, goodAnswer)
	s, _ := newTestServer(t, false, bad, good)
	got := ask(t, s, "example.com", dns.TypeA)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers", dns.RcodeToString[got.Rcode], len(got.Answer))
	}
}

func TestEveryUpstreamFailingIsAFailureNotAnEmptySuccess(t *testing.T) {
	s, _ := newTestServer(t, false, startUpstream(t, 0, servfailing), startUpstream(t, 0, servfailing))
	if got := ask(t, s, "example.com", dns.TypeA); got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[got.Rcode])
	}
}

// A resolver holding a stale "does not exist" answers first; one that can see
// the new record is slower but inside the doubt window.
func TestPositiveAnswerBeatsAFasterStaleNegative(t *testing.T) {
	stale := startUpstream(t, 0, nxdomain)
	stale2 := startUpstream(t, 0, nxdomain)
	fresh := startUpstream(t, 60*time.Millisecond, goodAnswer)
	fresh2 := startUpstream(t, 80*time.Millisecond, goodAnswer)
	s, _ := newTestServer(t, false, stale, stale2, fresh, fresh2)
	got := ask(t, s, "new.example.com", dns.TypeA)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s with %d answers", dns.RcodeToString[got.Rcode], len(got.Answer))
	}
}

func TestAMajorityOfResolversSettlesANegative(t *testing.T) {
	var ups []*fakeUpstream
	for i := 0; i < 3; i++ {
		ups = append(ups, startUpstream(t, 0, nxdomain))
	}
	s, _ := newTestServer(t, false, append(ups, startUpstream(t, 2*time.Second, nxdomain), startUpstream(t, 2*time.Second, nxdomain))...)
	start := time.Now()
	ask(t, s, "gone.example.com", dns.TypeA)
	if d := time.Since(start); d >= doubtWindow {
		t.Fatalf("waited %v with a majority already in", d)
	}
}

func TestNegativeAnswerIsNotHeldPastTheDoubtWindow(t *testing.T) {
	s, _ := newTestServer(t, false, startUpstream(t, 0, nxdomain), startUpstream(t, 2*time.Second, goodAnswer))
	start := time.Now()
	got := ask(t, s, "gone.example.com", dns.TypeA)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
	if got.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s", dns.RcodeToString[got.Rcode])
	}
}

func TestMissingAAAANeedsTwoResolversNotAll(t *testing.T) {
	nodata := func(dns.Question, *dns.Msg) {}
	slow := startUpstream(t, 2*time.Second, goodAnswer)
	s, _ := newTestServer(t, false, startUpstream(t, 0, nodata), startUpstream(t, 0, nodata), slow)
	start := time.Now()
	ask(t, s, "v4only.example.com", dns.TypeAAAA)
	if d := time.Since(start); d > doubtWindow {
		t.Fatalf("a normal NODATA waited %v", d)
	}
}

func TestReplyEDNSBelongsToTheClient(t *testing.T) {
	up := startUpstream(t, 0, goodAnswer)
	s, _ := newTestServer(t, false, up)

	plain := ask(t, s, "example.com", dns.TypeA)
	if plain.IsEdns0() != nil {
		t.Fatal("a client that did not offer EDNS must not get an OPT record")
	}

	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)
	r.SetEdns0(1232, false)
	w := &recordingWriter{}
	s.handle(w, r)
	if w.msg.IsEdns0() == nil {
		t.Fatal("an EDNS client must get an OPT record")
	}
}

func TestUpstreamQueriesCarryNothingFromTheClient(t *testing.T) {
	var seen atomic.Pointer[dns.Msg]
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		seen.Store(r.Copy())
		m := new(dns.Msg)
		m.SetReply(r)
		goodAnswer(r.Question[0], m)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	s, _ := newTestServer(t, false, &fakeUpstream{spec: "tcp://" + l.Addr().String()})
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)
	r.CheckingDisabled = true
	r.SetEdns0(1232, true)
	opt := r.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"})
	s.handle(&recordingWriter{}, r)

	got := seen.Load()
	if got == nil {
		t.Fatal("upstream was not asked")
	}
	if o := got.IsEdns0(); o == nil || !o.Do() || len(o.Option) != 0 || got.CheckingDisabled {
		t.Fatalf("upstream saw %v", got)
	}
}

func TestLosingARaceIsNotAFailure(t *testing.T) {
	quick := startUpstream(t, 0, goodAnswer)
	slow := startUpstream(t, 80*time.Millisecond, goodAnswer)
	s, _ := newTestServer(t, false, quick, slow)
	for i := 0; i < 8; i++ {
		ask(t, s, "example.com", dns.TypeA)
		s.cache.Flush()
	}
	time.Sleep(200 * time.Millisecond)
	for _, u := range s.upstreams {
		if st := u.Status(); st["errors"].(int64) != 0 || st["healthy"] != true {
			t.Fatalf("%s: %v", u.Spec, st)
		}
	}
}

func TestStreamConnectionsAreReused(t *testing.T) {
	up := startUpstream(t, 0, goodAnswer)
	s, _ := newTestServer(t, false, up)
	for i := 0; i < 20; i++ {
		ask(t, s, "example.com", dns.TypeA)
		s.cache.Flush()
	}
	if got := up.conns.Load(); got != 1 {
		t.Fatalf("20 sequential queries opened %d connections", got)
	}
	if up.queries.Load() != 20 {
		t.Fatalf("queries = %d", up.queries.Load())
	}
}

func TestDeadReusedConnectionIsReplacedInvisibly(t *testing.T) {
	up := startUpstream(t, 0, goodAnswer)
	s, _ := newTestServer(t, false, up)
	ask(t, s, "example.com", dns.TypeA)
	s.cache.Flush()
	// The resolver hung up while the connection sat idle.
	u := s.upstreams[0]
	u.mu.Lock()
	for _, c := range u.idle {
		c.conn.Close()
	}
	u.mu.Unlock()
	if got := ask(t, s, "example.com", dns.TypeA); got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("got %s", dns.RcodeToString[got.Rcode])
	}
	if st := u.Status(); st["errors"].(int64) != 0 {
		t.Fatalf("a replaced connection is not an error: %v", st)
	}
}

func TestCloakedNameIsAskedOncePerTTLAndStaysBlocked(t *testing.T) {
	cloaked := func(q dns.Question, m *dns.Msg) {
		m.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "tracker.adnet.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "tracker.adnet.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{93, 184, 216, 34}},
		}
	}
	up := startUpstream(t, 0, cloaked)
	s, matcher := newTestServer(t, true, up)
	b := adblock.NewBuilder()
	b.AddBlock("adnet.example", "test", "ads", true)
	matcher.Commit(b)

	for i := 0; i < 5; i++ {
		got := ask(t, s, "metrics.firstparty.example", dns.TypeA)
		for _, rr := range got.Answer {
			if a, ok := rr.(*dns.A); ok && a.A.Equal(net.IPv4(93, 184, 216, 34)) {
				t.Fatalf("query %d leaked the cloaked address", i)
			}
		}
	}
	if got := up.queries.Load(); got != 1 {
		t.Fatalf("upstream asked %d times for one cached answer", got)
	}

	// A rule change reaches what is already cached.
	matcher.Commit(adblock.NewBuilder())
	got := ask(t, s, "metrics.firstparty.example", dns.TypeA)
	if len(got.Answer) != 2 {
		t.Fatalf("after the rule went away got %d answers", len(got.Answer))
	}
}

func TestRefreshReplacesAnAnswerBeforeItExpires(t *testing.T) {
	var ip atomic.Int32
	ip.Store(1)
	up := startUpstream(t, 0, func(q dns.Question, m *dns.Msg) {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{93, 184, 216, byte(ip.Load())}}}
	})
	s, _ := newTestServer(t, false, up)
	ask(t, s, "moved.example.com", dns.TypeA)

	ip.Store(2)
	jobs := s.cache.DueRefresh(time.Now().Add(280*time.Second), 10)
	if len(jobs) != 1 {
		t.Fatalf("due = %d", len(jobs))
	}
	s.refresh(jobs[0])
	got := ask(t, s, "moved.example.com", dns.TypeA)
	if a := got.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(93, 184, 216, 2)) {
		t.Fatalf("still serving %v", a.A)
	}
	if up.queries.Load() != 2 {
		t.Fatalf("upstream queries = %d", up.queries.Load())
	}
}

func TestUDPAnswerFitsWhatTheClientCanTake(t *testing.T) {
	large := func(q dns.Question, m *dns.Msg) {
		for i := 0; i < 80; i++ {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{93, 184, 216, byte(i)}})
		}
	}
	s, _ := newTestServer(t, false, startUpstream(t, 0, large))
	r := new(dns.Msg)
	r.SetQuestion("big.example.com.", dns.TypeA)
	w := &recordingWriter{addr: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 9), Port: 5000}}
	s.handle(w, r)
	if w.msg.Len() > dns.MinMsgSize || !w.msg.Truncated {
		t.Fatalf("len %d truncated %v", w.msg.Len(), w.msg.Truncated)
	}
}

func TestBlockPageIsOfferedOnlyWhereItCanWork(t *testing.T) {
	up := startUpstream(t, 0, goodAnswer)
	s, matcher := newTestServer(t, true, up)
	b := adblock.NewBuilder()
	b.AddBlock("ads.example.com", "test", "ads", false)
	matcher.Commit(b)
	s.cfg.DNS.SinkholeIPv4, s.cfg.DNS.SinkholeIPv6 = "0.0.0.0", "::"
	s.cfg.DNS.BlockPage = true

	// No hook, or a device that refused the certificate: the plain sinkhole.
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Fatalf("no hook answered %v", a.A)
	}
	offer := false
	s.hooks.BlockPageAddr = func(netip.Addr, string) (netip.Addr, bool) {
		return netip.MustParseAddr("192.168.50.75"), offer
	}
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Fatalf("declined client answered %v", a.A)
	}

	offer = true
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4(192, 168, 50, 75)) {
		t.Fatalf("answered %v", a.A)
	}
	if got := ask(t, s, "ads.example.com", dns.TypeAAAA); len(got.Answer) != 0 {
		t.Fatalf("a browser would try this AAAA first: %v", got.Answer)
	}

	s.cfg.DNS.BlockPage = false
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Fatalf("switched off, answered %v", a.A)
	}
}

func TestACloakedNameNeverResolvesToThisNode(t *testing.T) {
	up := startUpstream(t, 0, func(q dns.Question, m *dns.Msg) {
		m.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "adnet.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "adnet.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{93, 184, 216, 34}},
		}
	})
	s, matcher := newTestServer(t, true, up)
	b := adblock.NewBuilder()
	b.AddBlock("adnet.example", "test", "ads", true)
	matcher.Commit(b)
	s.cfg.DNS.SinkholeIPv4, s.cfg.DNS.SinkholeIPv6 = "0.0.0.0", "::"
	s.cfg.DNS.BlockPage = true
	s.hooks.BlockPageAddr = func(netip.Addr, string) (netip.Addr, bool) { return netip.MustParseAddr("192.168.50.75"), true }

	// Whoever owns this name owns what it serves. Pointing it at this node
	// would give their page our origin, which is DNS rebinding.
	for _, label := range []string{"forwarded", "cached"} {
		got := ask(t, s, "harmless.attacker.example", dns.TypeA)
		if len(got.Answer) != 1 {
			t.Fatalf("%s: %v", label, got.Answer)
		}
		if a := got.Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
			t.Fatalf("%s answer %v", label, a.A)
		}
	}
	if a := ask(t, s, "adnet.example", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4(192, 168, 50, 75)) {
		t.Fatalf("the blocked name itself should get the page, got %v", a.A)
	}
}

func TestOneDeadPooledConnectionFlushesTheRest(t *testing.T) {
	good := startUpstream(t, 0, goodAnswer)
	s, _ := newTestServer(t, false, good)
	u := s.upstreams[0]
	for range maxIdleConns {
		a, b := net.Pipe()
		b.Close()
		u.idle = append(u.idle, idleConn{conn: &dns.Conn{Conn: a}, since: time.Now()})
	}
	start := time.Now()
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, err := u.Exchange(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("working through dead connections took %v", elapsed)
	}
	if n := good.conns.Load(); n != 1 {
		t.Fatalf("dialled %d times", n)
	}
}

func TestAConnectionReturnedAfterCloseIsNotKept(t *testing.T) {
	good := startUpstream(t, 0, goodAnswer)
	s, _ := newTestServer(t, false, good)
	u := s.upstreams[0]
	u.Close()
	a, b := net.Pipe()
	defer b.Close()
	u.putConn(&dns.Conn{Conn: a})
	if len(u.idle) != 0 {
		t.Fatal("a retired upstream kept a connection")
	}
}

func TestAnApprovedSitePassesForThatDeviceOnly(t *testing.T) {
	up := startUpstream(t, 0, goodAnswer)
	s, matcher := newTestServer(t, true, up)
	b := adblock.NewBuilder()
	b.AddBlock("ads.example.com", "test", "ads", false)
	matcher.Commit(b)
	s.cfg.DNS.SinkholeIPv4, s.cfg.DNS.SinkholeIPv6 = "0.0.0.0", "::"
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Fatalf("blocked name answered %v", a.A)
	}
	s.hooks.Granted = func(_ netip.Addr, name string) bool { return name == "ads.example.com" }
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); a.A.Equal(net.IPv4zero) {
		t.Fatal("an approved site was still blocked")
	}
	s.hooks.Granted = func(netip.Addr, string) bool { return false }
	if a := ask(t, s, "ads.example.com", dns.TypeA).Answer[0].(*dns.A); !a.A.Equal(net.IPv4zero) {
		t.Fatalf("after the grant ended it answered %v", a.A)
	}
}
