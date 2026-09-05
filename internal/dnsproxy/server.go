package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/miekg/dns"
)

// Hooks lets the resolver notify the rest of the system without importing it.
type Hooks struct {
	// OnAnswer maps a resolved address back to the queried name, which is
	// how a flow to 142.250.72.14 gets labelled "youtube.com".
	OnAnswer func(addr netip.Addr, name string, ttl time.Duration)
	// OnQuery observes every lookup for the smart-capture pipeline.
	OnQuery func(clientIP netip.Addr, name string, blocked bool)
	// ClientFor resolves an address to a client id and its policy.
	ClientFor func(addr netip.Addr) (clientID string, policyID string)
	// PolicyFor returns the named policy.
	PolicyFor func(id string) *store.Policy
	// LocalRecords answers names from DHCP leases and static hosts.
	LocalRecords func(name string, qtype uint16) []dns.RR
	// Publish streams a query to live subscribers.
	Publish func(store.DNSQuery)
}

type Server struct {
	cfg     *config.Config
	st      *store.Store
	matcher *adblock.Matcher
	cache   *Cache
	hooks   Hooks
	log     func(string, ...any)

	mu        sync.RWMutex
	upstreams []*Upstream
	// zoneUps holds pre-parsed upstreams for conditional-forward zones, keyed
	// by zone domain. Parsing a spec per query would be wasteful.
	zoneUps   map[string][]*Upstream
	servers   []*dns.Server
	running   bool

	// inflight collapses duplicate concurrent queries for the same name, so
	// a page load with 30 parallel requests for one host makes one upstream
	// query rather than thirty.
	inflight   map[string]*inflightCall
	inflightMu sync.Mutex

	// limiter is amplification protection, keyed per client address.
	limiter *RateLimiter

	stats Stats
}

type Stats struct {
	Queries   int64 `json:"queries"`
	Blocked   int64 `json:"blocked"`
	Cached    int64 `json:"cached"`
	Errors    int64 `json:"errors"`
	Collapsed  int64 `json:"collapsed"`
	Local      int64 `json:"local"`
	RateLimited int64 `json:"rate_limited"`
	Rebind      int64 `json:"rebind_blocked"`
	Rewritten   int64 `json:"rewritten"`
}

type inflightCall struct {
	wg   sync.WaitGroup
	msg  *dns.Msg
	err  error
	from string
}

func New(cfg *config.Config, st *store.Store, m *adblock.Matcher, hooks Hooks, log func(string, ...any)) *Server {
	if log == nil {
		log = func(string, ...any) {}
	}
	c := cfg.Snapshot()
	return &Server{
		cfg:      cfg,
		st:       st,
		matcher:  m,
		cache:    NewCache(c.DNS.CacheSize),
		hooks:    hooks,
		log:      log,
		inflight: map[string]*inflightCall{},
		limiter:  NewRateLimiter(c.DNS.RateLimit),
	}
}

func (s *Server) Cache() *Cache { return s.cache }

// ReloadUpstreams rebuilds the upstream pool from config.
func (s *Server) ReloadUpstreams() error {
	c := s.cfg.Snapshot()
	var ups []*Upstream
	for _, spec := range c.DNS.Upstreams {
		u, err := ParseUpstream(spec)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", spec, err)
		}
		ups = append(ups, u)
	}
	if len(ups) == 0 {
		return fmt.Errorf("no upstreams configured")
	}

	// Conditional-forward zones get their own parsed pools. A zone whose
	// upstream fails to parse is skipped with a log rather than taking the
	// whole resolver down, since the default upstreams still work.
	zones := map[string][]*Upstream{}
	for _, z := range c.DNS.ConditionalForward {
		domain := strings.ToLower(strings.TrimSuffix(z.Domain, "."))
		if domain == "" {
			continue
		}
		var pool []*Upstream
		for _, spec := range z.Upstreams {
			u, err := ParseUpstream(spec)
			if err != nil {
				s.log("dns: conditional zone %q upstream %q: %v", domain, spec, err)
				continue
			}
			pool = append(pool, u)
		}
		if len(pool) > 0 {
			zones[domain] = pool
		}
	}

	s.mu.Lock()
	s.upstreams = ups
	s.zoneUps = zones
	s.mu.Unlock()
	return nil
}

func (s *Server) Start() error {
	if err := s.ReloadUpstreams(); err != nil {
		return err
	}
	c := s.cfg.Snapshot()
	if !c.DNS.Enabled {
		s.log("dns: disabled by config")
		return nil
	}

	var started []*dns.Server
	for _, addr := range c.DNS.Listen {
		for _, net_ := range []string{"udp", "tcp"} {
			srv := &dns.Server{
				Addr:    addr,
				Net:     net_,
				Handler: dns.HandlerFunc(s.handle),
				// A 4096-byte UDP buffer avoids truncating most modern
				// answers without risking fragmentation-based amplification.
				UDPSize:      4096,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
			}
			ready := make(chan error, 1)
			srv.NotifyStartedFunc = func() { ready <- nil }
			go func(sv *dns.Server) {
				if err := sv.ListenAndServe(); err != nil {
					select {
					case ready <- err:
					default:
						s.log("dns: %s/%s stopped: %v", sv.Addr, sv.Net, err)
					}
				}
			}(srv)
			select {
			case err := <-ready:
				if err != nil {
					// Roll back anything already listening so we do not end
					// up half-bound with a confusing partial service.
					for _, p := range started {
						_ = p.Shutdown()
					}
					return fmt.Errorf("listen %s/%s: %w", addr, net_, err)
				}
			case <-time.After(5 * time.Second):
				return fmt.Errorf("timeout binding %s/%s", addr, net_)
			}
			started = append(started, srv)
		}
	}
	s.mu.Lock()
	s.servers = started
	s.running = true
	s.mu.Unlock()
	s.log("dns: listening on %v with %d upstream(s)", c.DNS.Listen, len(s.upstreams))
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.running = false
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Shutdown()
	}
}

func (s *Server) Running() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	if len(r.Question) == 0 {
		s.refuse(w, r)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	clientAddr := remoteAddr(w)
	cfg := s.cfg.Snapshot()

	s.stats.Queries++

	// 0. Rate limit before any work. A flood must cost this node as little as
	//    possible, and a refused reply is smaller than the query that caused it.
	if s.limiter != nil {
		s.limiter.SetLimit(cfg.DNS.RateLimit)
		if !s.limiter.Allow(clientAddr, start) {
			s.stats.RateLimited++
			s.refuse(w, r)
			return
		}
	}

	logEntry := store.DNSQuery{
		TS:       start,
		ClientIP: clientAddr.String(),
		Name:     name,
		QType:    dns.TypeToString[q.Qtype],
	}
	if s.hooks.ClientFor != nil {
		id, _ := s.hooks.ClientFor(clientAddr)
		logEntry.ClientID = id
	}

	// 1. Operator rewrites win over everything: they are an explicit
	//    instruction and must not be second-guessed by a blocklist.
	if len(cfg.DNS.Rewrites) > 0 {
		if m := ApplyRewrite(cfg.DNS.Rewrites, r, q, name); m != nil {
			logEntry.RCode = dns.RcodeToString[m.Rcode]
			logEntry.LatencyMS = msSince(start)
			logEntry.Answer = answerStrings(m)
			logEntry.BlockSource = "rewrite"
			s.stats.Rewritten++
			s.finish(w, m, logEntry, cfg)
			return
		}
	}

	// 2. Local records (DHCP leases, static hosts) win over everything else.
	if s.hooks.LocalRecords != nil {
		if rrs := s.hooks.LocalRecords(q.Name, q.Qtype); len(rrs) > 0 {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = rrs
			logEntry.RCode = "NOERROR"
			logEntry.LatencyMS = msSince(start)
			s.stats.Local++
			s.finish(w, m, logEntry, cfg)
			return
		}
	}

	// 3. Per-client policy: services, DoH bypass and safe search. These are
	//    evaluated whether or not the blocklists are enabled, because they are
	//    an operator decision rather than a subscription.
	policy := s.policyFor(clientAddr)
	if policy != nil && ScheduleActive(policy.Schedule, start) {
		if svc, hit := MatchBlockedService(name, policy.BlockedServices); hit {
			m := s.blockedReply(r, q, cfg, adblock.Match{
				Blocked: true, Source: "policy:" + policy.Name, Rule: "service:" + svc,
			})
			logEntry.Blocked = true
			logEntry.BlockSource = "service:" + svc
			logEntry.RCode = dns.RcodeToString[m.Rcode]
			logEntry.LatencyMS = msSince(start)
			s.stats.Blocked++
			s.finish(w, m, logEntry, cfg)
			return
		}
		if policy.BlockDoH && IsDoHBypass(name) {
			m := s.blockedReply(r, q, cfg, adblock.Match{
				Blocked: true, Source: "policy:" + policy.Name, Rule: "doh-bypass",
			})
			logEntry.Blocked = true
			logEntry.BlockSource = "doh-bypass"
			logEntry.RCode = dns.RcodeToString[m.Rcode]
			logEntry.LatencyMS = msSince(start)
			s.stats.Blocked++
			s.finish(w, m, logEntry, cfg)
			return
		}
		if policy.SafeSearch {
			if target := SafeSearchTarget(name); target != "" && target != name {
				if m := s.safeSearchReply(r, q, target); m != nil {
					logEntry.RCode = dns.RcodeToString[m.Rcode]
					logEntry.LatencyMS = msSince(start)
					logEntry.Answer = answerStrings(m)
					logEntry.BlockSource = "safesearch"
					s.finish(w, m, logEntry, cfg)
					return
				}
			}
		}
	}

	// 4. Block policy on the queried name. A client on an unfiltered policy
	//    skips the subscriptions entirely (its own denylist was applied in
	//    step 3's spirit by evaluateBlock; here nothing from a list applies).
	unfiltered := policy != nil && policy.Unfiltered && ScheduleActive(policy.Schedule, start)
	if unfiltered {
		logEntry.BlockSource = "policy:" + policy.Name + ":unfiltered"
	}
	if cfg.AdBlock.Enabled && !unfiltered {
		if match, blocked := s.evaluateBlock(name, clientAddr, cfg); blocked {
			m := s.blockedReply(r, q, cfg, match)
			logEntry.Blocked = true
			logEntry.BlockSource = match.Source
			logEntry.RCode = dns.RcodeToString[m.Rcode]
			logEntry.LatencyMS = msSince(start)
			s.stats.Blocked++
			s.finish(w, m, logEntry, cfg)
			return
		}
	}

	// 5. Cache.
	dnssecOK := isDNSSECOK(r)
	if cached, ok, fresh := s.cache.Get(q, dnssecOK); ok && fresh {
		cached.SetReply(r)
		cached.Id = r.Id
		logEntry.Cached = true
		logEntry.RCode = dns.RcodeToString[cached.Rcode]
		logEntry.LatencyMS = msSince(start)
		logEntry.Answer = answerStrings(cached)
		s.stats.Cached++
		s.noteAnswers(cached, name)
		s.finish(w, cached, logEntry, cfg)
		return
	}

	// 6. Forward, collapsing duplicate concurrent queries.
	resp, upstream, err := s.resolve(context.Background(), r, q, name, dnssecOK)
	if err != nil || resp == nil {
		// Serve stale rather than failing outright: a brief upstream outage
		// should not take the whole network offline.
		if stale, ok, _ := s.cache.Get(q, dnssecOK); ok {
			stale.SetReply(r)
			stale.Id = r.Id
			logEntry.Cached = true
			logEntry.RCode = "STALE"
			logEntry.LatencyMS = msSince(start)
			s.finish(w, stale, logEntry, cfg)
			return
		}
		s.stats.Errors++
		logEntry.RCode = "SERVFAIL"
		logEntry.LatencyMS = msSince(start)
		s.finish(w, servfail(r), logEntry, cfg)
		return
	}

	// 7. CNAME uncloaking. A first-party name that CNAMEs into an ad network
	//    is invisible to step 4; this is where that gets caught.
	if cfg.AdBlock.Enabled && cfg.AdBlock.CNAMEUncloak && !unfiltered {
		chain := cnameChain(resp)
		if len(chain) > 0 {
			if match := s.matcher.LookupChain(chain); match.Blocked {
				m := s.blockedReply(r, q, cfg, match)
				logEntry.Blocked = true
				logEntry.BlockSource = match.Source
				logEntry.CNAMEChain = chain
				logEntry.RCode = dns.RcodeToString[m.Rcode]
				logEntry.LatencyMS = msSince(start)
				s.stats.Blocked++
				s.finish(w, m, logEntry, cfg)
				return
			}
			logEntry.CNAMEChain = chain
		}
	}

	// 8. Rebinding protection, before the answer is cached so a poisoned
	//    record never gets served twice.
	if cfg.DNS.RebindProtection && !RebindAllowed(name, cfg.DNS.LocalDomain, cfg.DNS.RebindAllowlist) {
		if n := StripRebind(resp); n > 0 {
			s.stats.Rebind++
			logEntry.BlockSource = "dns-rebind"
			s.log("dns: stripped %d private answer(s) for %s (rebinding protection)", n, name)
		}
	}

	s.cache.Put(q, dnssecOK, resp, cfg.DNS.MinTTL, cfg.DNS.MaxTTL)
	resp.SetReply(r)
	resp.Id = r.Id
	logEntry.RCode = dns.RcodeToString[resp.Rcode]
	logEntry.Upstream = upstream
	logEntry.LatencyMS = msSince(start)
	logEntry.Answer = answerStrings(resp)
	s.noteAnswers(resp, name)
	s.finish(w, resp, logEntry, cfg)
}

// evaluateBlock applies the global matcher and then any per-client policy.
func (s *Server) evaluateBlock(name string, client netip.Addr, cfg config.Config) (adblock.Match, bool) {
	match := s.matcher.Lookup(name)

	var policy *store.Policy
	if s.hooks.ClientFor != nil && s.hooks.PolicyFor != nil {
		if _, policyID := s.hooks.ClientFor(client); policyID != "" {
			policy = s.hooks.PolicyFor(policyID)
		}
	}
	if policy != nil {
		// A policy allowlist overrides a global block for that client only.
		for _, a := range policy.Allowlist {
			if domainMatches(name, a) {
				return adblock.Match{Allowed: true, Source: "policy:" + policy.Name, Rule: a}, false
			}
		}
		for _, d := range policy.Denylist {
			if domainMatches(name, d) {
				return adblock.Match{Blocked: true, Source: "policy:" + policy.Name, Rule: d}, true
			}
		}
		// Category filtering: the policy names which categories it blocks.
		if match.Blocked && len(policy.Categories) > 0 {
			allowed := false
			for _, c := range policy.Categories {
				if c == match.Category || c == "all" {
					allowed = true
					break
				}
			}
			if !allowed {
				return adblock.Match{}, false
			}
		}
	}
	if match.Allowed {
		return match, false
	}
	return match, match.Blocked
}

func domainMatches(name, pattern string) bool {
	p := strings.ToLower(strings.TrimSuffix(pattern, "."))
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		return n == base || strings.HasSuffix(n, "."+base)
	}
	return n == p
}

// blockedReply builds the sinkhole answer. Returning 0.0.0.0 makes the block
// obvious in a client's own network log; NXDOMAIN is quieter but confuses
// some apps into retrying forever. Both are offered.
func (s *Server) blockedReply(r *dns.Msg, q dns.Question, cfg config.Config, match adblock.Match) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	ttl := uint32(cfg.DNS.BlockTTL)
	if ttl == 0 {
		ttl = 10
	}

	sink4, sink6 := cfg.DNS.SinkholeIPv4, cfg.DNS.SinkholeIPv6
	if sink4 == "" && sink6 == "" {
		m.Rcode = dns.RcodeNameError
	} else {
		switch q.Qtype {
		case dns.TypeA:
			if ip := net.ParseIP(sink4); ip != nil && ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip.To4(),
				})
			}
		case dns.TypeAAAA:
			if ip := net.ParseIP(sink6); ip != nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip.To16(),
				})
			}
		case dns.TypeHTTPS, dns.TypeSVCB:
			// Answering these with NODATA stops a browser from using the
			// HTTPS record to reach the origin behind a blocked A record.
		default:
			// NODATA for everything else keeps the block from looking like
			// a broken zone.
		}
	}

	if cfg.DNS.BlockEDE {
		// RFC 8914 Extended DNS Error 17 ("Filtered") tells a capable client
		// exactly why it got nothing, instead of leaving it to guess.
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(4096)
		reason := match.Source
		if match.Rule != "" {
			reason = match.Source + " / " + match.Rule
		}
		if len(reason) > 200 {
			reason = reason[:200]
		}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{
			InfoCode:  dns.ExtendedErrorCodeFiltered,
			ExtraText: "orbis: " + reason,
		})
		m.Extra = append(m.Extra, opt)
	}
	return m
}

// resolve forwards to upstreams, collapsing duplicate concurrent requests.
func (s *Server) resolve(ctx context.Context, r *dns.Msg, q dns.Question, name string, dnssecOK bool) (*dns.Msg, string, error) {
	key := cacheKey(q, dnssecOK)

	s.inflightMu.Lock()
	if call, ok := s.inflight[key]; ok {
		s.inflightMu.Unlock()
		s.stats.Collapsed++
		call.wg.Wait()
		if call.msg == nil {
			return nil, call.from, call.err
		}
		return call.msg.Copy(), call.from, call.err
	}
	call := &inflightCall{}
	call.wg.Add(1)
	s.inflight[key] = call
	s.inflightMu.Unlock()

	msg, from, err := s.forward(ctx, r, name)
	call.msg, call.from, call.err = msg, from, err
	call.wg.Done()

	s.inflightMu.Lock()
	delete(s.inflight, key)
	s.inflightMu.Unlock()

	if msg == nil {
		return nil, from, err
	}
	return msg.Copy(), from, err
}

func (s *Server) forward(ctx context.Context, r *dns.Msg, name string) (*dns.Msg, string, error) {
	cfg := s.cfg.Snapshot()
	s.mu.RLock()
	ups := append([]*Upstream(nil), s.upstreams...)
	// A conditional-forward zone replaces the pool entirely: the whole point
	// is that this namespace must not leak to the public resolvers.
	if domain := MatchForwardZone(cfg.DNS.ConditionalForward, name); domain != "" {
		if pool, ok := s.zoneUps[domain]; ok && len(pool) > 0 {
			ups = append([]*Upstream(nil), pool...)
		}
	}
	strategy := cfg.DNS.Strategy
	s.mu.RUnlock()
	if len(ups) == 0 {
		return nil, "", fmt.Errorf("no upstreams")
	}

	healthy := make([]*Upstream, 0, len(ups))
	for _, u := range ups {
		if u.Healthy() {
			healthy = append(healthy, u)
		}
	}
	// Every upstream cooling off at once means a local network problem, not
	// an upstream problem; try them all rather than failing.
	if len(healthy) == 0 {
		healthy = ups
	}

	query := r.Copy()
	query.Id = dns.Id()

	if strategy == "sequential" {
		var lastErr error
		for _, u := range healthy {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			resp, err := u.Exchange(cctx, query)
			cancel()
			if err == nil && resp != nil {
				return resp, u.Spec, nil
			}
			lastErr = err
		}
		return nil, "", lastErr
	}

	// Parallel: race every healthy upstream, take the first good answer.
	// The cost is extra upstream queries; the benefit is that one slow
	// resolver never sets the latency floor for the whole network.
	type result struct {
		msg  *dns.Msg
		from string
		err  error
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	ch := make(chan result, len(healthy))
	for _, u := range healthy {
		go func(u *Upstream) {
			resp, err := u.Exchange(cctx, query)
			ch <- result{msg: resp, from: u.Spec, err: err}
		}(u)
	}
	var lastErr error
	for i := 0; i < len(healthy); i++ {
		select {
		case res := <-ch:
			if res.err == nil && res.msg != nil {
				return res.msg, res.from, nil
			}
			if res.err != nil {
				lastErr = res.err
			}
		case <-cctx.Done():
			return nil, "", cctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all upstreams returned no answer")
	}
	return nil, "", lastErr
}

// noteAnswers feeds resolved addresses back to the flow tracker so future
// connections can be labelled with the name the client actually asked for.
func (s *Server) noteAnswers(m *dns.Msg, name string) {
	if s.hooks.OnAnswer == nil || m == nil {
		return
	}
	for _, rr := range m.Answer {
		var addr netip.Addr
		var ok bool
		switch v := rr.(type) {
		case *dns.A:
			addr, ok = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			addr, ok = netip.AddrFromSlice(v.AAAA.To16())
		default:
			continue
		}
		if ok {
			s.hooks.OnAnswer(addr, name, time.Duration(rr.Header().Ttl)*time.Second)
		}
	}
}

func (s *Server) finish(w dns.ResponseWriter, m *dns.Msg, entry store.DNSQuery, cfg config.Config) {
	if err := w.WriteMsg(m); err != nil {
		// A client that hung up mid-answer is normal, not worth logging.
		_ = err
	}
	if cfg.DNS.LogQueries {
		s.st.QueueDNS(entry)
	}
	if s.hooks.Publish != nil {
		s.hooks.Publish(entry)
	}
	if s.hooks.OnQuery != nil {
		if addr, err := netip.ParseAddr(entry.ClientIP); err == nil {
			s.hooks.OnQuery(addr, entry.Name, entry.Blocked)
		}
	}
}

func (s *Server) refuse(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}

func servfail(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func (s *Server) Stats() map[string]any {
	out := map[string]any{
		"queries": s.stats.Queries, "blocked": s.stats.Blocked,
		"cached": s.stats.Cached, "errors": s.stats.Errors,
		"collapsed": s.stats.Collapsed, "local": s.stats.Local,
		"rate_limited": s.stats.RateLimited, "rebind_blocked": s.stats.Rebind,
		"rewritten": s.stats.Rewritten,
		"running":   s.Running(),
		"cache":     s.cache.Stats(),
	}
	s.mu.RLock()
	ups := make([]map[string]any, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		ups = append(ups, u.Status())
	}
	s.mu.RUnlock()
	out["upstreams"] = ups
	return out
}

// cnameChain extracts the CNAME targets from an answer, in order.
func cnameChain(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			out = append(out, strings.ToLower(strings.TrimSuffix(c.Target, ".")))
		}
	}
	return out
}

func answerStrings(m *dns.Msg) []string {
	out := make([]string, 0, len(m.Answer))
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.CNAME:
			out = append(out, "CNAME "+strings.TrimSuffix(v.Target, "."))
		case *dns.PTR:
			out = append(out, "PTR "+strings.TrimSuffix(v.Ptr, "."))
		case *dns.TXT:
			out = append(out, "TXT "+strings.Join(v.Txt, " "))
		case *dns.MX:
			out = append(out, "MX "+strings.TrimSuffix(v.Mx, "."))
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func isDNSSECOK(r *dns.Msg) bool {
	if opt := r.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

func remoteAddr(w dns.ResponseWriter) netip.Addr {
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			return addr.Unmap()
		}
	case *net.TCPAddr:
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			return addr.Unmap()
		}
	}
	return netip.Addr{}
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000
}

// policyFor resolves the policy attached to a client address, or nil.
func (s *Server) policyFor(client netip.Addr) *store.Policy {
	if s.hooks.ClientFor == nil || s.hooks.PolicyFor == nil {
		return nil
	}
	_, policyID := s.hooks.ClientFor(client)
	if policyID == "" {
		return nil
	}
	return s.hooks.PolicyFor(policyID)
}

// safeSearchReply resolves the engine's filtered hostname and returns its
// addresses under the originally-queried name, plus the CNAME that explains
// the substitution. Returning the CNAME alone would work for most clients but
// costs them a second round trip; resolving here keeps it to one.
//
// Only A and AAAA are rewritten. Anything else (MX, TXT, HTTPS) is left to the
// normal path, because substituting those breaks mail and connection hints for
// no filtering benefit.
func (s *Server) safeSearchReply(r *dns.Msg, q dns.Question, target string) *dns.Msg {
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}
	probe := new(dns.Msg)
	probe.SetQuestion(dns.Fqdn(target), q.Qtype)
	probe.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _, err := s.forward(ctx, probe, target)
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		return nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn(target),
	})
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(target), Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: v.Hdr.Ttl}, A: v.A})
		case *dns.AAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{Name: dns.Fqdn(target), Rrtype: dns.TypeAAAA,
					Class: dns.ClassINET, Ttl: v.Hdr.Ttl}, AAAA: v.AAAA})
		}
	}
	if len(m.Answer) < 2 {
		return nil // CNAME with no addresses is worse than not intervening
	}
	return m
}
