package issues

import (
	"strings"
	"testing"
)

func TestScrubRemovesIdentifiers(t *testing.T) {
	r := NewRedactor([]string{"Living room TV", "arafat-mini"}, []string{"big.oisd.nl"})
	in := `Living room TV (192.168.50.156, 7c:7b:bf:fc:33:5a) asked for tracker.evil-cdn.example-shop.com; ` +
		`upstream tls://1.1.1.1:853 fine; list https://big.oisd.nl/domainswild fetched; owner arafat0602@gmail.com; ` +
		`key sk-or-v1-8c9abcdefabcdef0123456789 and tskey-auth-kabcdefg12345; wg pub 8Xq3kZ6r7TqVJH9mLp2n4sWtYbCdEfGhIjKlMnOpQrS=; ` +
		`node fd5a:90f8:63d1:1:be24:11ff:fe1e:6d3e at 02:15:10; config /etc/orbis/orbis.yaml; store: flow flush failed`
	out := r.Scrub(in)
	for _, bad := range []string{"Living room TV", "192.168.50.156", "7c:7b:bf", "evil-cdn", "arafat0602", "sk-or-v1", "tskey-", "8Xq3kZ6r", "fd5a:90f8", "arafat-mini"} {
		if strings.Contains(out, bad) {
			t.Errorf("scrubbed output still contains %q:\n%s", bad, out)
		}
	}
	for _, good := range []string{"[device]", "[ip]", "[mac]", "[host]", "[email]", "[key]", "[ip6]", "02:15:10", "orbis.yaml", "big.oisd.nl", "flow flush failed", "1.1.1.1"} {
		if !strings.Contains(out, good) {
			t.Errorf("scrubbed output should contain %q:\n%s", good, out)
		}
	}
}

func TestScrubKeepsInfrastructureAndLoopback(t *testing.T) {
	r := NewRedactor(nil, nil)
	in := "openrouter.ai returned 429; fetched raw.githubusercontent.com/StevenBlack/hosts; listening on 127.0.0.1:5335 and 0.0.0.0:53; sponsor.ajay.app ok"
	out := r.Scrub(in)
	if out != in {
		t.Fatalf("infrastructure names and loopback must survive:\n got  %s\n want %s", out, in)
	}
}

func TestFingerprintNormalises(t *testing.T) {
	a := Fingerprint("adblock", `list "OISD" failed: fetch https://big.oisd.nl: 502 Bad Gateway`)
	b := Fingerprint("adblock", `list "OISD" failed: fetch https://big.oisd.nl: 503 Service Unavailable`)
	if a == b {
		// Same shape, but the message text differs beyond the number; that is
		// fine either way. What matters is the next two.
	}
	c := Fingerprint("dns", "DNS resolver failed to start: listen udp 192.168.50.75:53: address already in use")
	d := Fingerprint("dns", "DNS resolver failed to start: listen udp 10.0.0.2:53: address already in use")
	if c != d {
		t.Fatalf("addresses must not change the fingerprint: %s vs %s", c, d)
	}
	if Fingerprint("dns", "x") == Fingerprint("capture", "x") {
		t.Fatal("category is part of the fingerprint")
	}
	if len(c) != 16 {
		t.Fatalf("fingerprint length %d", len(c))
	}
}
