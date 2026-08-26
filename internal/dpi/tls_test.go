package dpi

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// TestParseClientHelloRealHandshake drives a real Go TLS client into a pipe
// and parses what it actually put on the wire. Hand-built fixtures test the
// parser against the author's understanding of the format; this tests it
// against the format.
func TestParseClientHelloRealHandshake(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		c := tls.Client(client, &tls.Config{
			ServerName: "ads.example.com",
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		})
		// The handshake will fail (nothing answers); we only need the hello.
		_ = c.Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}

	hello, err := ParseTLSRecord(buf[:n])
	if err != nil {
		t.Fatalf("ParseTLSRecord: %v", err)
	}
	if hello.SNI != "ads.example.com" {
		t.Errorf("SNI = %q, want ads.example.com", hello.SNI)
	}
	if len(hello.ALPN) == 0 || hello.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want h2 first", hello.ALPN)
	}
	if hello.JA4 == "" {
		t.Error("JA4 is empty")
	}
	// A JA4 for a TCP hello with SNI and ALPN h2 starts "t13d" on a modern
	// stack, and always has three underscore-separated parts.
	if parts := strings.Split(hello.JA4, "_"); len(parts) != 3 {
		t.Errorf("JA4 %q has %d parts, want 3", hello.JA4, len(parts))
	}
	if !strings.HasPrefix(hello.JA4, "t") {
		t.Errorf("JA4 %q should start with the TCP marker", hello.JA4)
	}
	if !strings.Contains(hello.JA4, "d") {
		t.Errorf("JA4 %q should record that an SNI was present", hello.JA4)
	}
}

// TestJA4Stability is the property that makes the fingerprint useful: the same
// client reaching two different hosts must hash identically, or it cannot be
// used to recognise a device.
func TestJA4Stability(t *testing.T) {
	capture := func(sni string) string {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		go func() {
			_ = tls.Client(client, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}).Handshake()
		}()
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		h, err := ParseTLSRecord(buf[:n])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return h.JA4
	}
	a := capture("one.example.com")
	b := capture("a-completely-different-host.example.org")
	if a != b {
		t.Errorf("JA4 differs across destinations: %q vs %q — the SNI must not be in the hash", a, b)
	}
}

func TestParseClientHelloRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"short":            {0x16, 0x03},
		"not handshake":    {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
		"truncated body":   {0x16, 0x03, 0x01, 0x01, 0x00, 0x01},
		"lying length":     {0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00},
		"server hello":     {0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			// The contract is "never panic, always return an error"; a
			// malformed packet from a hostile client must not take the
			// capture goroutine down.
			_, err := ParseTLSRecord(input)
			if err == nil {
				t.Error("expected an error for malformed input")
			}
		})
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0xc02f, 0x0000, 0x0a0b} {
		if isGREASE(v) {
			t.Errorf("%#04x should not be GREASE", v)
		}
	}
}

func TestParseHTTPRequest(t *testing.T) {
	payload := []byte("GET /pixel.gif?id=42 HTTP/1.1\r\n" +
		"Host: tracker.example.com:443\r\n" +
		"User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)\r\n" +
		"Referer: https://news.example.org/article/1\r\n" +
		"Accept: image/webp,*/*\r\n\r\n")
	req, ok := ParseHTTPRequest(payload)
	if !ok {
		t.Fatal("did not recognise a plain GET")
	}
	if req.Host != "tracker.example.com" {
		t.Errorf("Host = %q, want the port stripped", req.Host)
	}
	if req.Path != "/pixel.gif?id=42" {
		t.Errorf("Path = %q", req.Path)
	}
	if got := RefererHost(req.Referer); got != "news.example.org" {
		t.Errorf("RefererHost = %q, want news.example.org", got)
	}
	if _, ok := ParseHTTPRequest([]byte("\x16\x03\x01 not http at all")); ok {
		t.Error("TLS bytes were parsed as HTTP")
	}
}

func TestClassifyApp(t *testing.T) {
	cases := map[string]string{
		"rr3---sn-abc.googlevideo.com": "YouTube",
		"www.youtube.com":              "YouTube",
		"notyoutube.com.evil.test":     "",
		"static.doubleclick.net":       "Ad/Tracking",
		"nowhere.invalid":              "",
	}
	for host, want := range cases {
		if got := ClassifyApp(host); got != want {
			t.Errorf("ClassifyApp(%q) = %q, want %q", host, got, want)
		}
	}
}
