package app

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDeviceNames(t *testing.T) {
	for ptr, want := range map[string]string{
		"Galaxy-S26-Ultra.": "Galaxy-S26-Ultra", "Macmini.lan.": "Macmini", "printer.home.arpa.": "printer",
		"192-168-50-9.": "", "192.168.50.9.": "", "9.50.168.192.in-addr.arpa.": "", ".": "", "<script>.": "",
	} {
		if got := deviceName(ptr); got != want {
			t.Errorf("%q = %q, want %q", ptr, got, want)
		}
	}
}

func TestTheRouterNamesADevice(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: l, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: "Galaxy-S26-Ultra."}}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	if got := routerName(context.Background(), l.LocalAddr().String(), netip.MustParseAddr("192.168.50.243")); got != "Galaxy-S26-Ultra" {
		t.Fatalf("got %q", got)
	}
}
