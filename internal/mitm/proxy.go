package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
}

type Stats struct {
	Accepted      atomic.Int64
	Intercepted   atomic.Int64
	Spliced       atomic.Int64
	Filtered      atomic.Int64
	AdsStripped   atomic.Int64
	BeaconsKilled atomic.Int64
	Errors        atomic.Int64
	BytesIn       atomic.Int64
	BytesOut      atomic.Int64
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
		"errors":   p.stats.Errors.Load(),
		"bytes_in": p.stats.BytesIn.Load(), "bytes_out": p.stats.BytesOut.Load(),
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

	// Request-side filtering: drop tracker beacons before they reach the
	// network at all, which saves the round trip and the data.
	if verdict := p.filters.FilterRequest(host, path, req); verdict.Drop {
		p.stats.BeaconsKilled.Add(1)
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
func writeResponse(w net.Conn, resp *http.Response, req *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return false
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	resp.Header.Del("Content-Encoding") // body was decompressed by the filter chain
	resp.TransferEncoding = nil

	keepAlive := !resp.Close && req.ProtoAtLeast(1, 1) &&
		!strings.EqualFold(req.Header.Get("Connection"), "close")
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
	} else {
		resp.Header.Set("Connection", "close")
	}
	_ = w.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if err := resp.Write(w); err != nil {
		return false
	}
	_ = w.SetWriteDeadline(time.Time{})
	return keepAlive
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
