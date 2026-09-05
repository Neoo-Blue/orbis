// Package dnsproxy is the recursive-forwarding resolver: it answers clients,
// enforces block policy (including CNAME uncloaking), caches, and forwards
// upstream over plain DNS, DNS-over-TLS or DNS-over-HTTPS.
package dnsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Upstream is one configured resolver.
type Upstream struct {
	Spec string // as written in config
	Kind string // "udp" | "tcp" | "tls" | "https"
	Addr string // host:port for udp/tcp/tls
	URL  string // full URL for https
	Name string // TLS server name for certificate validation

	client   *dns.Client
	httpc    *http.Client
	mu       sync.Mutex
	conn     *dns.Conn
	lastErr  error
	failures int
	// coolUntil suppresses an upstream that keeps failing so a dead resolver
	// does not add its timeout to every query.
	coolUntil time.Time

	Latency time.Duration
	Queries int64
	Errors  int64
}

// ParseUpstream accepts the forms an operator would reasonably type:
//
//	1.1.1.1                       -> udp/53
//	1.1.1.1:5353                  -> udp/5353
//	udp://1.1.1.1                 -> udp/53
//	tcp://1.1.1.1                 -> tcp/53
//	tls://1.1.1.1:853             -> DoT, SNI inferred from a known map
//	tls://one.one.one.one:853     -> DoT, SNI = hostname
//	https://cloudflare-dns.com/dns-query -> DoH
func ParseUpstream(spec string) (*Upstream, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty upstream")
	}
	u := &Upstream{Spec: spec}

	switch {
	case strings.HasPrefix(spec, "https://"):
		parsed, err := url.Parse(spec)
		if err != nil {
			return nil, err
		}
		u.Kind, u.URL, u.Name = "https", spec, parsed.Hostname()
		u.httpc = newDoHClient()

	case strings.HasPrefix(spec, "tls://"):
		host := strings.TrimPrefix(spec, "tls://")
		u.Kind = "tls"
		u.Addr = withDefaultPort(host, "853")
		u.Name = tlsServerName(u.Addr)
		u.client = &dns.Client{
			Net:     "tcp-tls",
			Timeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				ServerName: u.Name,
				MinVersion: tls.VersionTLS12,
				// Session resumption matters here: without it every query
				// after an idle period pays a full handshake.
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
		}

	case strings.HasPrefix(spec, "tcp://"):
		u.Kind = "tcp"
		u.Addr = withDefaultPort(strings.TrimPrefix(spec, "tcp://"), "53")
		u.client = &dns.Client{Net: "tcp", Timeout: 5 * time.Second}

	default:
		u.Kind = "udp"
		u.Addr = withDefaultPort(strings.TrimPrefix(spec, "udp://"), "53")
		u.client = &dns.Client{Net: "udp", Timeout: 4 * time.Second, UDPSize: 4096}
	}
	return u, nil
}

func withDefaultPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	// A bare IPv6 literal needs brackets before a port can be appended.
	if strings.Count(hostport, ":") >= 2 {
		return "[" + hostport + "]:" + port
	}
	return hostport + ":" + port
}

// tlsServerName maps the well-known DoT IPs to the name on their certificate.
// Without this, tls://1.1.1.1:853 fails validation, which is a confusing
// first-run experience for a perfectly reasonable config line.
func tlsServerName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if names, ok := knownDoTNames[host]; ok {
		return names
	}
	if net.ParseIP(host) != nil {
		// An unknown IP with no name means we cannot validate; the caller
		// will see a TLS error rather than a silent downgrade.
		return ""
	}
	return host
}

var knownDoTNames = map[string]string{
	"1.1.1.1": "one.one.one.one", "1.0.0.1": "one.one.one.one",
	"2606:4700:4700::1111": "one.one.one.one", "2606:4700:4700::1001": "one.one.one.one",
	"9.9.9.9": "dns.quad9.net", "149.112.112.112": "dns.quad9.net",
	"8.8.8.8": "dns.google", "8.8.4.4": "dns.google",
	"2001:4860:4860::8888": "dns.google", "2001:4860:4860::8844": "dns.google",
	"94.140.14.14": "dns.adguard-dns.com", "94.140.15.15": "dns.adguard-dns.com",
	"45.90.28.0": "dns.nextdns.io", "76.76.2.0": "dns.controld.com",
	"185.222.222.222": "dns.sb", "45.11.45.11": "dns.sb",
	"2a09::": "dns.sb", "2a11::": "dns.sb",
}

func newDoHClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		},
	}
	_ = http2.ConfigureTransport(tr)
	return &http.Client{Transport: tr, Timeout: 6 * time.Second}
}

// Healthy reports whether the upstream is currently in the rotation.
func (u *Upstream) Healthy() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return time.Now().After(u.coolUntil)
}

func (u *Upstream) noteResult(err error, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Queries++
	if err != nil {
		u.Errors++
		u.failures++
		u.lastErr = err
		// Exponential backoff capped at a minute: long enough to stop the
		// bleeding, short enough to recover from a transient outage.
		backoff := time.Duration(1<<minInt(u.failures, 6)) * time.Second
		if backoff > time.Minute {
			backoff = time.Minute
		}
		if u.failures >= 3 {
			u.coolUntil = time.Now().Add(backoff)
		}
		return
	}
	u.failures = 0
	u.coolUntil = time.Time{}
	// Exponential moving average keeps the number responsive without storing
	// a history.
	if u.Latency == 0 {
		u.Latency = latency
	} else {
		u.Latency = (u.Latency*3 + latency) / 4
	}
}

// Exchange sends a query and returns the response.
func (u *Upstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	var resp *dns.Msg
	var err error

	switch u.Kind {
	case "https":
		resp, err = u.exchangeDoH(ctx, m)
	default:
		resp, _, err = u.client.ExchangeContext(ctx, m, u.Addr)
		// A truncated UDP answer must be retried over TCP or the client gets
		// a partial record set, which breaks DNSSEC and large TXT lookups.
		if err == nil && resp != nil && resp.Truncated && u.Kind == "udp" {
			tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
			if r2, _, err2 := tcpClient.ExchangeContext(ctx, m, u.Addr); err2 == nil {
				resp = r2
			}
		}
	}
	u.noteResult(err, time.Since(start))
	return resp, err
}

func (u *Upstream) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

func (u *Upstream) Status() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := map[string]any{
		"spec":       u.Spec,
		"kind":       u.Kind,
		"queries":    u.Queries,
		"errors":     u.Errors,
		"latency_ms": float64(u.Latency.Microseconds()) / 1000,
		"healthy":    time.Now().After(u.coolUntil),
	}
	if u.lastErr != nil {
		st["last_error"] = u.lastErr.Error()
	}
	return st
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
