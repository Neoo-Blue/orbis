package dnsproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Encrypted DNS for clients. Until this existed Orbis spoke DoT and DoH
// upstream but served clients over plaintext port 53, which means every lookup
// on the LAN was readable by anyone on it, and a device off the network could
// not use this resolver at all.
//
// DoT (RFC 7858) is a TLS wrapper around the same wire format. DoH (RFC 8484)
// is that wire format over HTTP, either POSTed as the body or GET with a
// base64url "dns" parameter. Both hand the decoded message to the exact same
// handler as plain DNS, so every policy, block and rewrite applies identically.

// EncryptedServer owns the DoT listener and the DoH handler.
type EncryptedServer struct {
	srv *Server
	log func(string, ...any)

	mu      sync.Mutex
	dot     net.Listener
	doh     *http.Server
	running bool
	cert    *tls.Certificate
}

func NewEncrypted(s *Server, log func(string, ...any)) *EncryptedServer {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &EncryptedServer{srv: s, log: log}
}

func (e *EncryptedServer) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Start brings up whichever of DoT and DoH is configured.
func (e *EncryptedServer) Start() error {
	cfg := e.srv.cfg.Snapshot()
	ec := cfg.DNS.Encrypted
	if !ec.Enabled {
		return nil
	}

	cert, err := e.loadOrCreateCert(cfg.Node.DataDir, ec.CertFile, ec.KeyFile, ec.Hostname)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		// dot is the ALPN token for DNS-over-TLS; h2/http1.1 for DoH. Offering
		// all three lets one certificate serve both listeners.
		NextProtos: []string{"dot", "h2", "http/1.1"},
	}

	e.mu.Lock()
	e.cert = cert
	e.mu.Unlock()

	if ec.DoTListen != "" {
		ln, err := tls.Listen("tcp", ec.DoTListen, tlsCfg)
		if err != nil {
			return fmt.Errorf("dot listen %s: %w", ec.DoTListen, err)
		}
		e.mu.Lock()
		e.dot = ln
		e.mu.Unlock()
		go e.acceptDoT(ln)
		e.log("dns: DoT listening on %s", ec.DoTListen)
	}

	if ec.DoHListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", e.handleDoH)
		srv := &http.Server{
			Addr:              ec.DoHListen,
			Handler:           mux,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		ln, err := net.Listen("tcp", ec.DoHListen)
		if err != nil {
			e.Stop()
			return fmt.Errorf("doh listen %s: %w", ec.DoHListen, err)
		}
		e.mu.Lock()
		e.doh = srv
		e.mu.Unlock()
		go func() {
			if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
				e.log("dns: DoH server stopped: %v", err)
			}
		}()
		e.log("dns: DoH listening on %s/dns-query", ec.DoHListen)
	}

	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	return nil
}

func (e *EncryptedServer) Stop() {
	e.mu.Lock()
	dot, doh := e.dot, e.doh
	e.dot, e.doh = nil, nil
	e.running = false
	e.mu.Unlock()

	if dot != nil {
		_ = dot.Close()
	}
	if doh != nil {
		_ = doh.Close()
	}
}

// acceptDoT serves the length-prefixed TCP DNS format inside TLS.
func (e *EncryptedServer) acceptDoT(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go e.serveDoTConn(conn)
	}
}

func (e *EncryptedServer) serveDoTConn(conn net.Conn) {
	defer conn.Close()
	// RFC 7858 encourages connection reuse, so the loop keeps reading until
	// the client goes away or idles out.
	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		msg, err := readTCPMessage(conn)
		if err != nil {
			return
		}
		resp := e.exchange(msg, remoteAddrOf(conn))
		if resp == nil {
			return
		}
		out, err := resp.Pack()
		if err != nil {
			return
		}
		if err := writeTCPMessage(conn, out); err != nil {
			return
		}
	}
}

func (e *EncryptedServer) handleDoH(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		raw = b
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		// RFC 8484 mandates base64url with padding stripped.
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(q, "="))
		if err != nil {
			http.Error(w, "bad base64url", http.StatusBadRequest)
			return
		}
		raw = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		http.Error(w, "malformed query", http.StatusBadRequest)
		return
	}

	resp := e.exchange(msg, httpClientAddr(r))
	if resp == nil {
		http.Error(w, "no answer", http.StatusInternalServerError)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	// Caching is handled by the resolver; telling an intermediary to keep the
	// answer would leak one client's result to another.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// exchange runs a decoded message through the ordinary handler by way of a
// capturing ResponseWriter, so encrypted transports get identical treatment to
// plain DNS with no duplicated policy logic.
func (e *EncryptedServer) exchange(msg *dns.Msg, client netip.Addr) *dns.Msg {
	cw := &captureWriter{client: client}
	e.srv.handle(cw, msg)
	return cw.msg
}

// captureWriter is a dns.ResponseWriter that keeps the reply in memory and
// reports the real client address so per-client policy still applies.
type captureWriter struct {
	client netip.Addr
	msg    *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *captureWriter) RemoteAddr() net.Addr {
	if c.client.IsValid() {
		return &net.UDPAddr{IP: c.client.AsSlice(), Port: 0}
	}
	return &net.UDPAddr{IP: net.IPv4zero}
}
func (c *captureWriter) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }
func (c *captureWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	c.msg = m
	return len(b), nil
}
func (c *captureWriter) Close() error              { return nil }
func (c *captureWriter) TsigStatus() error         { return nil }
func (c *captureWriter) TsigTimersOnly(bool)       {}
func (c *captureWriter) Hijack()                   {}
func (c *captureWriter) Network() string           { return "tcp" }

// ---- framing helpers ----

func readTCPMessage(conn net.Conn) (*dns.Msg, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	if n == 0 || n > 65535 {
		return nil, fmt.Errorf("bad message length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(buf); err != nil {
		return nil, err
	}
	return m, nil
}

func writeTCPMessage(conn net.Conn, payload []byte) error {
	if len(payload) > 65535 {
		return fmt.Errorf("response too large")
	}
	framed := make([]byte, 2+len(payload))
	framed[0] = byte(len(payload) >> 8)
	framed[1] = byte(len(payload))
	copy(framed[2:], payload)
	_, err := conn.Write(framed)
	return err
}

func remoteAddrOf(conn net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func httpClientAddr(r *http.Request) netip.Addr {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

// ---- certificate ----

// loadOrCreateCert uses the operator's PEM pair when given one, and otherwise
// generates a long-lived self-signed certificate. Self-signed is honest about
// its limits: a DoT client that pins a SPKI hash is happy, a browser is not.
// The generated pair is reused across restarts so pinning stays stable.
func (e *EncryptedServer) loadOrCreateCert(dataDir, certFile, keyFile, hostname string) (*tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	if hostname == "" {
		hostname = "orbis.lan"
	}
	if dataDir == "" {
		dataDir = "/var/lib/orbis"
	}
	dir := filepath.Join(dataDir, "dns-tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	cp := filepath.Join(dir, "cert.pem")
	kp := filepath.Join(dir, "key.pem")

	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			if time.Now().Before(leaf.NotAfter.Add(-24 * time.Hour)) {
				return &c, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname, Organization: []string{"Orbis"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	// Listening addresses are usually reached by IP, so put the local
	// addresses in the SAN too or every client rejects the name.
	for _, ip := range localIPs() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(cp, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(kp, keyPEM, 0o600); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func localIPs() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP)
		}
	}
	return out
}

// SPKIPin returns the base64 SHA-256 of the SubjectPublicKeyInfo, which is
// what a DoT client pins to trust a self-signed certificate. It is the hash of
// the public key, not of the certificate, so it survives regenerating the
// certificate around the same key.
func (e *EncryptedServer) SPKIPin() string {
	e.mu.Lock()
	cert := e.cert
	e.mu.Unlock()
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
