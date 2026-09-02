package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/dpi"
)

// Proxy is a transparent intercepting proxy. Traffic reaches it by nftables
// redirect; it recovers the original destination from the socket, peeks the
// SNI, and decides per connection whether to decrypt or splice through.
type Proxy struct {
	cfg *config.Config
	ca  *CA
	log func(string, ...any)

	filters *FilterChain

	httpLn net.Listener
	tlsLn  net.Listener

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// upstream is the client used to talk to the real origin. Keeping one
	// pooled transport keeps intercepted connections cheap.
	upstream *http.Client

	stats Stats

	// OnRequest reports every intercepted request to the ad pipeline.
	OnRequest func(clientIP netip.Addr, host, path, referer string, respBytes int64)

	// SponsorSegments answers the in-page engine's segment lookups. The
	// result is serialised as JSON. Nil disables the endpoint.
	SponsorSegments func(ctx context.Context, videoID string) (any, error)

	// sbLimiter bounds segment lookups per client, so a page cannot turn
	// Orbis into an amplifier against the segment database.
	sbLimiter clientLimiter

	// pins remembers which clients reject the certificate for which hosts,
	// so a pinned app is spliced through instead of broken.
	pins pinTracker
}

type Stats struct {
	Accepted      atomic.Int64
	Intercepted   atomic.Int64
	Spliced       atomic.Int64
	Filtered      atomic.Int64
	AdsStripped   atomic.Int64
	BeaconsKilled atomic.Int64
	// InPageStripped and InPageSkipped are reported by the injected engine
	// running on a real client, which is the only place the effect of the
	// in-page layer is observable at all.
	InPageStripped atomic.Int64
	InPageSkipped  atomic.Int64
	InPageSegments atomic.Int64
	// InPageProbes counts ad-blocker detection probes the engine answered
	// in place of the network.
	InPageProbes atomic.Int64
	// PinBypasses counts the times a client was spliced through because it
	// kept rejecting the certificate (a pinned app, or no CA installed).
	PinBypasses atomic.Int64
	// ServerStitched counts player responses whose ads are muxed into the
	// content stream. Nothing can be stripped from those; counting them is
	// what tells the difference between a filter that is broken and a stream
	// that is unfilterable.
	ServerStitched atomic.Int64
	Errors         atomic.Int64
	BytesIn        atomic.Int64
	BytesOut       atomic.Int64
}

func New(cfg *config.Config, ca *CA, log func(string, ...any)) *Proxy {
	if log == nil {
		log = func(string, ...any) {}
	}
	p := &Proxy{
		cfg:     cfg,
		ca:      ca,
		log:     log,
		filters: NewFilterChain(cfg),
		upstream: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:          128,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
				// Origin certificates are verified normally. Interception
				// must not become a downgrade to an unverified channel.
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
			// Redirects belong to the client, not the proxy: following them
			// here would hide the redirect from the browser and break auth
			// flows that depend on seeing the 302.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return p
}

func (p *Proxy) Stats() map[string]any {
	return map[string]any{
		"accepted": p.stats.Accepted.Load(), "intercepted": p.stats.Intercepted.Load(),
		"spliced": p.stats.Spliced.Load(), "filtered": p.stats.Filtered.Load(),
		"ads_stripped": p.stats.AdsStripped.Load(), "beacons_killed": p.stats.BeaconsKilled.Load(),
		"inpage_stripped": p.stats.InPageStripped.Load(), "inpage_skipped": p.stats.InPageSkipped.Load(),
		"inpage_segments": p.stats.InPageSegments.Load(), "inpage_probes": p.stats.InPageProbes.Load(),
		"pin_bypasses": p.stats.PinBypasses.Load(), "pinned": p.pins.active(time.Now()),
		"server_stitched": p.stats.ServerStitched.Load(),
		"errors":          p.stats.Errors.Load(),
		"bytes_in":        p.stats.BytesIn.Load(), "bytes_out": p.stats.BytesOut.Load(),
		"running": p.Running(),
	}
}

func (p *Proxy) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *Proxy) Start() error {
	c := p.cfg.Snapshot()
	if !c.MITM.Enabled {
		return nil
	}
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return errors.New("proxy already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.mu.Unlock()

	tlsLn, err := net.Listen("tcp", c.MITM.ListenTLS)
	if err != nil {
		cancel()
		return fmt.Errorf("listen tls %s: %w", c.MITM.ListenTLS, err)
	}
	httpLn, err := net.Listen("tcp", c.MITM.ListenHTTP)
	if err != nil {
		tlsLn.Close()
		cancel()
		return fmt.Errorf("listen http %s: %w", c.MITM.ListenHTTP, err)
	}

	p.mu.Lock()
	p.tlsLn, p.httpLn, p.running = tlsLn, httpLn, true
	p.mu.Unlock()

	p.wg.Add(2)
	go p.acceptLoop(ctx, tlsLn, true)
	go p.acceptLoop(ctx, httpLn, false)
	p.log("mitm: listening tls=%s http=%s, intercepting %d host pattern(s)",
		c.MITM.ListenTLS, c.MITM.ListenHTTP, len(c.MITM.InterceptHosts))
	return nil
}

func (p *Proxy) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	cancel := p.cancel
	tlsLn, httpLn := p.tlsLn, p.httpLn
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if tlsLn != nil {
		tlsLn.Close()
	}
	if httpLn != nil {
		httpLn.Close()
	}
	p.wg.Wait()
}

func (p *Proxy) acceptLoop(ctx context.Context, ln net.Listener, isTLS bool) {
	defer p.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		p.stats.Accepted.Add(1)
		go func() {
			defer func() {
				// A panic in a parser must not take down the proxy for every
				// other client on the network.
				if r := recover(); r != nil {
					p.stats.Errors.Add(1)
					p.log("mitm: recovered from panic handling connection: %v", r)
				}
				conn.Close()
			}()
			if isTLS {
				p.handleTLS(ctx, conn)
			} else {
				p.handleHTTP(ctx, conn)
			}
		}()
	}
}

// handleTLS peeks the ClientHello to learn the intended host, then either
// decrypts (allowlisted hosts) or splices bytes through untouched.
func (p *Proxy) handleTLS(ctx context.Context, client net.Conn) {
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))

	origDst, err := originalDestination(client)
	if err != nil {
		p.stats.Errors.Add(1)
		return
	}

	peeked, hello, err := peekClientHello(client)
	if err != nil {
		// Not TLS, or a truncated hello. Splice to the original destination
		// rather than dropping: this path must never break a protocol we
		// simply did not recognise.
		p.splice(ctx, client, origDst, peeked)
		return
	}

	host := hello.SNI
	if host == "" {
		// No SNI: fall back to the destination address. Cannot mint a valid
		// certificate for an unknown name, so splice.
		p.splice(ctx, client, origDst, peeked)
		return
	}

	clientIP := clientAddr(client)
	if !p.shouldIntercept(host, clientIP) {
		p.stats.Spliced.Add(1)
		p.splice(ctx, client, origDst, peeked)
		return
	}
	if p.pins.bypassed(clientIP, host, time.Now()) {
		// This client has told us, by rejecting the certificate, that it
		// will not accept interception for this host. Pass it through.
		p.stats.Spliced.Add(1)
		p.splice(ctx, client, origDst, peeked)
		return
	}

	leaf, err := p.ca.Leaf(host)
	if err != nil {
		p.stats.Errors.Add(1)
		p.splice(ctx, client, origDst, peeked)
		return
	}

	// Replay the bytes we consumed so the TLS server sees a complete stream.
	replayed := &replayConn{Conn: client, buf: peeked}
	tlsConn := tls.Server(replayed, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// Advertise only HTTP/1.1: the filter chain parses HTTP/1 messages,
		// and negotiating h2 here would leave us unable to inspect anything.
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.stats.Errors.Add(1)
		if rejectedCertificate(err) {
			if name, tripped := p.pins.fail(clientIP, host, time.Now()); tripped {
				p.stats.PinBypasses.Add(1)
				p.log("mitm: %s rejects the certificate for %s (%v); splicing %s for %s. "+
					"A pinned app, or the CA is not trusted on that device.",
					clientIP, host, err, name, pinBypassFor)
			}
		}
		return
	}
	p.stats.Intercepted.Add(1)
	_ = client.SetReadDeadline(time.Time{})
	p.serveHTTP(ctx, tlsConn, host, true, clientIP)
}

// handleHTTP serves cleartext HTTP, where the Host header names the target.
func (p *Proxy) handleHTTP(ctx context.Context, client net.Conn) {
	clientIP := clientAddr(client)
	p.serveHTTP(ctx, client, "", false, clientIP)
}

// serveHTTP runs the request/response loop over an already-decrypted stream.
func (p *Proxy) serveHTTP(ctx context.Context, conn net.Conn, sniHost string, secure bool, clientIP netip.Addr) {
	br := bufio.NewReaderSize(conn, 16*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		host := req.Host
		if host == "" {
			host = sniHost
		}
		if host == "" {
			writeError(conn, http.StatusBadRequest, "missing Host")
			return
		}
		scheme := "http"
		if secure {
			scheme = "https"
		}
		req.URL.Scheme = scheme
		req.URL.Host = host
		req.RequestURI = ""
		req.Host = host

		resp, filtered, err := p.roundTrip(ctx, req, host, clientIP)
		if err != nil {
			p.stats.Errors.Add(1)
			writeError(conn, http.StatusBadGateway, "orbis: upstream error")
			return
		}
		if filtered {
			p.stats.Filtered.Add(1)
		}
		keepAlive := writeResponse(conn, resp, req)
		resp.Body.Close()
		if !keepAlive {
			return
		}
	}
}

// roundTrip forwards a request and applies the filter chain to the response.
func (p *Proxy) roundTrip(ctx context.Context, req *http.Request, host string, clientIP netip.Addr) (*http.Response, bool, error) {
	path := req.URL.Path
	referer := req.Header.Get("Referer")

	// The probe script is served from the page's own origin. It carries no
	// data and takes none, so it needs no provenance check.
	if path == InPageProbePath && isYouTubeAppHost(host) {
		drainRequestBody(req)
		p.stats.InPageProbes.Add(1)
		return syntheticResponse(req, RequestVerdict{
			Status: http.StatusOK, ContentType: "application/javascript; charset=utf-8",
			Reason: "orbis-probe", Body: []byte(ProbeScript),
		}), true, nil
	}

	// The in-page engine's two endpoints are answered here and never
	// forwarded. They exist only for the engine, so anything that is not a
	// same-origin request from a YouTube page is refused outright.
	if (path == InPageSegmentsPath || path == InPageReportPath) && isYouTubeAppHost(host) {
		resp := p.engineEndpoint(ctx, req, path, clientIP)
		drainRequestBody(req)
		if p.OnRequest != nil {
			p.OnRequest(clientIP, host, path, referer, resp.ContentLength)
		}
		return resp, true, nil
	}

	// Request-side filtering: drop tracker beacons before they reach the
	// network at all, which saves the round trip and the data.
	if verdict := p.filters.FilterRequest(host, path, req); verdict.Drop {
		p.stats.BeaconsKilled.Add(1)
		// The body of a dropped request still has to leave the connection,
		// or its bytes are read as the next request line and the keep-alive
		// connection dies with the following real request on it.
		drainRequestBody(req)
		if p.OnRequest != nil {
			p.OnRequest(clientIP, host, path, referer, 0)
		}
		return syntheticResponse(req, verdict), true, nil
	}

	outReq := req.Clone(ctx)
	// Hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
	for _, h := range hopHeaders {
		outReq.Header.Del(h)
	}
	// Compression is negotiated with us, not the client, so the filter chain
	// can inspect a plain body. The response is re-sent uncompressed.
	outReq.Header.Set("Accept-Encoding", "gzip")

	resp, err := p.upstream.Do(outReq)
	if err != nil {
		return nil, false, err
	}
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	filtered, size := p.filters.FilterResponse(host, path, req, resp, &p.stats)
	if p.OnRequest != nil {
		p.OnRequest(clientIP, host, path, referer, size)
	}
	return resp, filtered, nil
}

// drainRequestBody consumes and closes a request body that will not be
// forwarded, bounded so a hostile client cannot make the proxy read forever.
func drainRequestBody(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
	req.Body.Close()
}

// engineEndpoint answers the in-page engine's report and segment paths.
func (p *Proxy) engineEndpoint(ctx context.Context, req *http.Request, path string, client netip.Addr) *http.Response {
	if !sameOriginFromYouTube(req) {
		return syntheticResponse(req, RequestVerdict{
			Status: http.StatusForbidden, ContentType: "text/plain",
			Reason: "orbis-engine-endpoint-refused", Body: []byte("same-origin only"),
		})
	}
	if path == InPageReportPath {
		p.recordInPageReport(req)
		return syntheticResponse(req, RequestVerdict{
			Status: http.StatusNoContent, ContentType: "text/plain", Reason: "orbis-inpage-report",
		})
	}
	if !p.sbLimiter.allow(client, time.Now()) {
		return syntheticResponse(req, RequestVerdict{
			Status: http.StatusTooManyRequests, ContentType: "application/json",
			Reason: "orbis-sponsorblock-limited", Body: []byte(`{"video_id":"","segments":[]}`),
		})
	}
	return p.sponsorResponse(ctx, req)
}

// sameOriginFromYouTube is the gate on the engine endpoints. The Host header
// alone is the client's to set, so the request also has to look like it came
// from a YouTube page: Sec-Fetch-Site says same-origin where the browser
// sends it, and otherwise the Origin or Referer names a YouTube host. A
// beacon from some other site, or a forged Host on the cleartext listener,
// fails both.
func sameOriginFromYouTube(req *http.Request) bool {
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		return strings.EqualFold(site, "same-origin")
	}
	for _, h := range []string{"Origin", "Referer"} {
		if v := req.Header.Get(h); v != "" {
			u, err := url.Parse(v)
			if err != nil || u.Host == "" {
				return false
			}
			return isYouTubeAppHost(u.Hostname())
		}
	}
	return false
}

// clientLimiter is a small per-client token bucket.
type clientLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	sbBurst   = 20.0
	sbPerMin  = 30.0
	sbMaxKeys = 4096
)

func (l *clientLimiter) allow(client netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[netip.Addr]*bucket{}
	}
	b := l.buckets[client]
	if b == nil {
		if len(l.buckets) >= sbMaxKeys {
			for k, v := range l.buckets {
				if now.Sub(v.last) > 5*time.Minute {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= sbMaxKeys {
				return false
			}
		}
		b = &bucket{tokens: sbBurst, last: now}
		l.buckets[client] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * sbPerMin
	if b.tokens > sbBurst {
		b.tokens = sbBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// recordInPageReport folds the injected engine's counters into the proxy
// stats. The report is best-effort by design: a malformed or oversized one is
// dropped without affecting the 204 the page already expects.
func (p *Proxy) recordInPageReport(req *http.Request) {
	if req.Body == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 4096))
	req.Body.Close()
	if err != nil {
		return
	}
	var rep struct {
		Stripped int64 `json:"stripped"`
		Burned   int64 `json:"burned"`
		Skips    int64 `json:"skips"`
		Segments int64 `json:"segments"`
		Probes   int64 `json:"probes"`
	}
	if json.Unmarshal(body, &rep) != nil {
		return
	}
	// The page reports the increase since its own last report, not a running
	// total, so several clients simply add up and a reload cannot make the
	// counter jump or go backwards. Each delta is capped: a counter is
	// evidence, and a page cannot be allowed to manufacture it.
	const maxDelta = 1000
	if rep.Stripped > 0 {
		p.stats.InPageStripped.Add(min(rep.Stripped, maxDelta))
	}
	if n := rep.Burned + rep.Skips; n > 0 {
		p.stats.InPageSkipped.Add(min(n, maxDelta))
	}
	if rep.Segments > 0 {
		p.stats.InPageSegments.Add(min(rep.Segments, maxDelta))
	}
	if rep.Probes > 0 {
		p.stats.InPageProbes.Add(min(rep.Probes, maxDelta))
	}
}

// videoIDRe is the shape of a YouTube video id. Anything else is refused
// before it reaches the segment client.
var videoIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

// sponsorResponse builds the JSON answer for a segment lookup. Failures are
// answered with an empty list rather than an error: the engine treats "no
// segments" and "could not find out" identically, and a 5xx would only make
// it retry.
func (p *Proxy) sponsorResponse(ctx context.Context, req *http.Request) *http.Response {
	c := p.cfg.Snapshot()
	vid := req.URL.Query().Get("v")
	empty := []byte(`{"video_id":"","segments":[]}`)
	verdict := RequestVerdict{Status: http.StatusOK, ContentType: "application/json", Reason: "orbis-sponsorblock", Body: empty}
	if !c.MITM.Filters.YouTube || !c.MITM.Filters.YouTubeSponsorBlock || p.SponsorSegments == nil || !videoIDRe.MatchString(vid) {
		return syntheticResponse(req, verdict)
	}
	lctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	result, err := p.SponsorSegments(lctx, vid)
	if err != nil {
		p.log("mitm: sponsorblock lookup for %s failed: %v", vid, err)
		return syntheticResponse(req, verdict)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return syntheticResponse(req, verdict)
	}
	verdict.Body = body
	return syntheticResponse(req, verdict)
}

// shouldIntercept decides per connection. Bypass wins over intercept so a
// broad pattern cannot accidentally capture a bank.
func (p *Proxy) shouldIntercept(host string, client netip.Addr) bool {
	c := p.cfg.Snapshot()
	if !c.MITM.Enabled {
		return false
	}
	for _, pat := range c.MITM.BypassHosts {
		if hostMatches(host, pat) {
			return false
		}
	}
	if len(c.MITM.OnlyClients) > 0 && client.IsValid() {
		match := false
		for _, spec := range c.MITM.OnlyClients {
			if clientMatches(client, spec) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	for _, pat := range c.MITM.InterceptHosts {
		if hostMatches(host, pat) {
			return true
		}
	}
	return false
}

func hostMatches(host, pattern string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	p := strings.ToLower(strings.TrimSuffix(pattern, "."))
	switch {
	case p == "*":
		return true
	case strings.HasPrefix(p, "*."):
		base := p[2:]
		return h == base || strings.HasSuffix(h, "."+base)
	case strings.HasSuffix(p, "*"):
		return strings.HasPrefix(h, strings.TrimSuffix(p, "*"))
	default:
		return h == p
	}
}

func clientMatches(addr netip.Addr, spec string) bool {
	if pfx, err := netip.ParsePrefix(spec); err == nil {
		return pfx.Contains(addr)
	}
	if a, err := netip.ParseAddr(spec); err == nil {
		return a == addr
	}
	return false
}

// splice copies bytes in both directions without looking at them.
func (p *Proxy) splice(ctx context.Context, client net.Conn, dst string, prefix []byte) {
	d := net.Dialer{Timeout: 10 * time.Second}
	server, err := d.DialContext(ctx, "tcp", dst)
	if err != nil {
		p.stats.Errors.Add(1)
		return
	}
	defer server.Close()
	_ = client.SetReadDeadline(time.Time{})

	if len(prefix) > 0 {
		if _, err := server.Write(prefix); err != nil {
			return
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(server, client)
		p.stats.BytesOut.Add(n)
		if tc, ok := server.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, server)
		p.stats.BytesIn.Add(n)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// peekClientHello reads exactly one TLS record, parses it, and returns the
// consumed bytes so they can be replayed to whichever path handles the
// connection.
func peekClientHello(c net.Conn) ([]byte, *dpi.ClientHello, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, nil, err
	}
	if hdr[0] != 0x16 {
		return hdr, nil, errors.New("not a TLS handshake")
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length <= 0 || length > 16384 {
		return hdr, nil, errors.New("implausible record length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c, body); err != nil {
		return hdr, nil, err
	}
	full := append(hdr, body...)
	hello, err := dpi.ParseClientHello(body)
	if hello == nil {
		return full, nil, err
	}
	// A hello with no SNI is still a usable parse for the splice path.
	return full, hello, nil
}

// replayConn re-serves already-consumed bytes before reading from the socket.
type replayConn struct {
	net.Conn
	buf []byte
	off int
}

func (r *replayConn) Read(p []byte) (int, error) {
	if r.off < len(r.buf) {
		n := copy(p, r.buf[r.off:])
		r.off += n
		return n, nil
	}
	return r.Conn.Read(p)
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func writeError(w io.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

// writeResponse serialises a response and reports whether the connection can
// be reused.
//
// The body is never re-read into memory here. The filter chain has already
// buffered anything it wanted to rewrite (and normalised the headers to
// match); everything else is still the live upstream stream, and a video
// segment has to reach the client as it arrives rather than after the proxy
// has collected all of it. Content-Encoding is likewise left exactly as the
// origin set it unless the filter chain decoded the body, because relabelling
// a body that is still compressed makes it unreadable.
func writeResponse(w net.Conn, resp *http.Response, req *http.Request) bool {
	isHead := req.Method == http.MethodHead
	// A status that can never carry a body, as opposed to a HEAD, which
	// carries the body's headers without the body.
	bodiless := resp.StatusCode < 200 ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified
	writeBody := !bodiless && !isHead

	// Framing: a known length is preferable because it keeps the connection
	// reusable; an unknown one is chunked, which HTTP/1.1 clients all speak.
	chunked := false
	switch {
	case bodiless:
		resp.Header.Del("Content-Length")
	case resp.ContentLength >= 0:
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	case isHead:
		resp.Header.Del("Content-Length")
	default:
		resp.Header.Del("Content-Length")
		chunked = true
	}
	resp.Header.Del("Transfer-Encoding")

	// resp.Close describes the upstream connection (the origin asked for it
	// to close, or the body was cut short). Only the second case is a reason
	// to close the client's connection too, and takeBody marks that.
	truncated := resp.Header.Get("X-Orbis-Truncated") != ""
	keepAlive := !truncated && req.ProtoAtLeast(1, 1) &&
		!strings.EqualFold(req.Header.Get("Connection"), "close")
	if chunked && !req.ProtoAtLeast(1, 1) {
		// HTTP/1.0 has no chunked encoding; the only length signal it has is
		// the close of the connection.
		keepAlive = false
	}
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
	} else {
		resp.Header.Set("Connection", "close")
	}
	if chunked && keepAlive {
		resp.Header.Set("Transfer-Encoding", "chunked")
	}

	var head bytes.Buffer
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", resp.StatusCode, statusText(resp.StatusCode))
	if err := resp.Header.Write(&head); err != nil {
		return false
	}
	head.WriteString("\r\n")

	_ = w.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if _, err := w.Write(head.Bytes()); err != nil {
		return false
	}
	if !writeBody {
		_ = w.SetWriteDeadline(time.Time{})
		return keepAlive
	}

	// A long download must not die on a 60 s deadline set once up front, so
	// the deadline is extended as bytes actually move.
	pw := &progressWriter{conn: w, every: 60 * time.Second}
	var err error
	if chunked && keepAlive {
		// The chunked writer emits a size line, the payload and a CRLF for
		// every Write; buffering turns those three syscalls per 32 KB into
		// one.
		bw := bufio.NewWriterSize(pw, 64*1024)
		cw := httputil.NewChunkedWriter(bw)
		_, err = io.Copy(cw, resp.Body)
		if cerr := cw.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			_, err = bw.Write([]byte("\r\n"))
		}
		if ferr := bw.Flush(); err == nil {
			err = ferr
		}
	} else {
		_, err = io.Copy(pw, resp.Body)
	}
	if err != nil {
		return false
	}
	_ = w.SetWriteDeadline(time.Time{})
	return keepAlive
}

// statusText keeps a non-standard upstream status code from producing a
// malformed status line.
func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "Status"
}

// progressWriter pushes the write deadline forward on every successful write,
// so the timeout bounds a stalled peer rather than a large transfer.
type progressWriter struct {
	conn  net.Conn
	every time.Duration
}

func (p *progressWriter) Write(b []byte) (int, error) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.every))
	return p.conn.Write(b)
}

func syntheticResponse(req *http.Request, v RequestVerdict) *http.Response {
	body := v.Body
	if body == nil {
		body = []byte{}
	}
	h := http.Header{}
	h.Set("Content-Type", v.ContentType)
	h.Set("X-Orbis-Filtered", v.Reason)
	h.Set("Cache-Control", "no-store")
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", v.Status, http.StatusText(v.Status)),
		StatusCode:    v.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func clientAddr(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}
