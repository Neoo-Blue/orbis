package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPinTrackerHostThresholdAndExpiry(t *testing.T) {
	var tr pinTracker
	c := netip.MustParseAddr("192.168.50.24")
	now := time.Now()
	if tr.bypassed(c, "youtubei.googleapis.com", now) {
		t.Fatal("nothing should be bypassed before any rejection")
	}
	if name, ok := tr.fail(c, "youtubei.googleapis.com", now); ok {
		t.Fatalf("one rejection is not a pattern, got bypass for %s", name)
	}
	name, ok := tr.fail(c, "youtubei.googleapis.com", now.Add(time.Second))
	if !ok || name != "youtubei.googleapis.com" {
		t.Fatalf("second rejection within the window should bypass the host, got %q %v", name, ok)
	}
	if !tr.bypassed(c, "youtubei.googleapis.com", now.Add(2*time.Second)) {
		t.Fatal("host should now be bypassed")
	}
	// Another client is unaffected.
	if tr.bypassed(netip.MustParseAddr("192.168.50.26"), "youtubei.googleapis.com", now.Add(2*time.Second)) {
		t.Fatal("a bypass is per client")
	}
	// A different host on the same client is unaffected by the host rule.
	if tr.bypassed(c, "www.youtube.com", now.Add(2*time.Second)) {
		t.Fatal("the browser's host must not be swept up by the app's rejection")
	}
	// It expires.
	if tr.bypassed(c, "youtubei.googleapis.com", now.Add(pinBypassFor+time.Minute)) {
		t.Fatal("bypass must expire so a device that later trusts the CA is filtered again")
	}
}

func TestPinTrackerDomainThresholdGroupsCDNNodes(t *testing.T) {
	var tr pinTracker
	c := netip.MustParseAddr("192.168.50.24")
	now := time.Now()
	// Five different CDN node names, one rejection each: no single host trips,
	// but the domain does.
	hosts := []string{"rr1---sn-a.googlevideo.com", "rr2---sn-b.googlevideo.com", "rr3---sn-c.googlevideo.com", "rr4---sn-d.googlevideo.com"}
	for _, h := range hosts {
		if name, ok := tr.fail(c, h, now); ok {
			t.Fatalf("premature bypass for %s", name)
		}
	}
	name, ok := tr.fail(c, "rr5---sn-e.googlevideo.com", now)
	if !ok || name != ".googlevideo.com" {
		t.Fatalf("fifth rejection across the domain should bypass the domain, got %q %v", name, ok)
	}
	if !tr.bypassed(c, "rr9---sn-z.googlevideo.com", now.Add(time.Second)) {
		t.Fatal("a never-seen node of the bypassed domain must be spliced")
	}
	if tr.bypassed(c, "www.youtube.com", now.Add(time.Second)) {
		t.Fatal("a different domain is not affected")
	}
}

func TestPinTrackerWindowResets(t *testing.T) {
	var tr pinTracker
	c := netip.MustParseAddr("10.0.0.1")
	now := time.Now()
	tr.fail(c, "h.example.com", now)
	// A second rejection long after the first starts a new window.
	if _, ok := tr.fail(c, "h.example.com", now.Add(pinWindow+time.Minute)); ok {
		t.Fatal("rejections outside the window must not accumulate")
	}
}

// A real handshake: the client does not trust our CA and refuses the leaf.
// The classifier must call that a rejection, whatever Go's exact wording.
func TestRejectedCertificateFromRealClient(t *testing.T) {
	ca := testCA(t)
	leaf, err := ca.Leaf("www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	cconn, sconn := net.Pipe()
	server := tls.Server(sconn, &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12})
	client := tls.Client(cconn, &tls.Config{ServerName: "www.youtube.com", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12})
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errc <- server.HandshakeContext(ctx)
	}()
	_ = client.Handshake() // fails: unknown authority
	client.Close()
	serr := <-errc
	if serr == nil {
		t.Fatal("server handshake should have failed against a distrusting client")
	}
	if !rejectedCertificate(serr) {
		t.Fatalf("a distrusting client's failure must classify as rejection, got: %v", serr)
	}
}

func TestRejectedCertificateIgnoresTimeouts(t *testing.T) {
	if rejectedCertificate(context.DeadlineExceeded) {
		t.Fatal("a timeout is not a certificate rejection")
	}
	if rejectedCertificate(errors.New("tls: first record does not look like a TLS handshake")) {
		t.Fatal("a malformed hello is not a rejection")
	}
	if !rejectedCertificate(&net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}) {
		t.Fatal("a bad-certificate alert is a rejection")
	}
}

func TestSpliceFallbackOnlyForUnreachableIPv6WithAName(t *testing.T) {
	unreach := errors.New("dial tcp [2603:1063:8::371]:443: connect: network is unreachable")
	if got := spliceFallback("[2603:1063:8::371]:443", "www.linkedin.com", unreach); got != "www.linkedin.com:443" {
		t.Fatalf("an unreachable IPv6 origin with a name should retry by name over v4, got %q", got)
	}
	if got := spliceFallback("[2603:1063:8::371]:443", "", unreach); got != "" {
		t.Fatal("no name, nothing to retry")
	}
	if got := spliceFallback("13.107.42.14:443", "www.linkedin.com", errors.New("connect: network is unreachable")); got != "" {
		t.Fatal("an IPv4 failure is a real failure")
	}
	if got := spliceFallback("[2603:1063:8::371]:443", "www.linkedin.com", errors.New("connect: connection refused")); got != "" {
		t.Fatal("a refusal is not fixed by a different address")
	}
}
