package consent

import (
	"testing"
	"time"
)

func req(client, host string) Request {
	return Request{ClientID: client, Host: host, DstIP: "1.2.3.4", Port: 443, Proto: "tcp"}
}

func TestOnlyEnrolledDevicesAsk(t *testing.T) {
	s := NewStore(10)
	if _, known := s.Observe(req("dev1", "example.com")); known {
		t.Fatal("unenrolled device should not produce a decision")
	}
	if len(s.Pending()) != 0 {
		t.Fatal("unenrolled device must not queue a question")
	}

	s.SetEnrolled([]string{"dev1"})
	s.Observe(req("dev1", "example.com"))
	if len(s.Pending()) != 1 {
		t.Fatalf("enrolled device should queue one question, got %d", len(s.Pending()))
	}
}

func TestRepeatedConnectionsCoalesce(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	for i := 0; i < 5; i++ {
		s.Observe(req("dev1", "example.com"))
	}
	p := s.Pending()
	if len(p) != 1 {
		t.Fatalf("expected one queued question, got %d", len(p))
	}
	if p[0].Count != 5 {
		t.Fatalf("expected count 5, got %d", p[0].Count)
	}
}

func TestDecisionIsDurableAndStopsAsking(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	s.Observe(req("dev1", "example.com"))

	rule, ok := s.Decide("dev1|example.com", Deny, "device")
	if !ok {
		t.Fatal("decide should succeed for a queued request")
	}
	if rule.Decision != Deny {
		t.Fatalf("wrong decision recorded: %v", rule.Decision)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("deciding should clear the question")
	}

	d, known := s.Observe(req("dev1", "example.com"))
	if !known || d != Deny {
		t.Fatalf("subsequent connection should return the standing deny, got %v/%v", d, known)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("a decided host must never be queued again")
	}
}

func TestNetworkScopeAppliesToAllDevices(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1", "dev2"})
	s.Observe(req("dev1", "tracker.example"))
	s.Observe(req("dev2", "tracker.example"))
	if len(s.Pending()) != 2 {
		t.Fatalf("expected two questions, got %d", len(s.Pending()))
	}

	if _, ok := s.Decide("dev1|tracker.example", Deny, "network"); !ok {
		t.Fatal("network decide failed")
	}
	// The other device's queued question is answered by the same decision.
	if len(s.Pending()) != 0 {
		t.Fatalf("network scope should clear every queued question for the host, %d left", len(s.Pending()))
	}
	if d, known := s.Observe(req("dev2", "tracker.example")); !known || d != Deny {
		t.Fatalf("network rule should apply to a different device, got %v/%v", d, known)
	}
	// And to a device that was never asked.
	s.SetEnrolled([]string{"dev1", "dev2", "dev3"})
	if d, known := s.Observe(req("dev3", "tracker.example")); !known || d != Deny {
		t.Fatal("network rule should apply to a newly enrolled device")
	}
}

func TestNetworkRuleBeatsStaleDeviceAllow(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	s.LoadRules([]Rule{
		{ClientID: "dev1", Host: "bad.example", Decision: Allow, Scope: "device"},
		{ClientID: "", Host: "bad.example", Decision: Deny, Scope: "network"},
	})
	if d, known := s.Lookup("dev1", "bad.example"); !known || d != Deny {
		t.Fatalf("network deny must win over a device allow, got %v", d)
	}
}

func TestUnenrollingDropsPending(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	s.Observe(req("dev1", "example.com"))
	s.SetEnrolled(nil)
	if len(s.Pending()) != 0 {
		t.Fatal("unenrolling a device should drop its queued questions")
	}
}

func TestQueueIsBounded(t *testing.T) {
	s := NewStore(3)
	s.SetEnrolled([]string{"dev1"})
	for _, h := range []string{"a.com", "b.com", "c.com", "d.com", "e.com"} {
		s.Observe(req("dev1", h))
	}
	if n := len(s.Pending()); n != 3 {
		t.Fatalf("queue should cap at 3, got %d", n)
	}
}

func TestFlowWithoutHostnameIsIgnored(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	// A rule keyed on a bare address would break with the next CDN response,
	// so a nameless flow must not queue anything.
	s.Observe(Request{ClientID: "dev1", DstIP: "1.2.3.4", Port: 443})
	if len(s.Pending()) != 0 {
		t.Fatal("a flow with no hostname must not be queued")
	}
}

func TestForgetReopensTheQuestion(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	s.Observe(req("dev1", "example.com"))
	s.Decide("dev1|example.com", Allow, "device")

	if !s.Forget("dev1", "example.com", "device") {
		t.Fatal("forget should find the rule")
	}
	if _, known := s.Observe(req("dev1", "example.com")); known {
		t.Fatal("after forgetting, there should be no standing decision")
	}
	if len(s.Pending()) != 1 {
		t.Fatal("after forgetting, the next connection should ask again")
	}
}

func TestHostnameIsNormalised(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	s.Observe(req("dev1", "Example.COM."))
	s.Decide("dev1|example.com", Deny, "device")
	if d, known := s.Observe(req("dev1", "example.com")); !known || d != Deny {
		t.Fatal("trailing dot and case must normalise to the same rule")
	}
}

func TestOnNewFiresOncePerHost(t *testing.T) {
	s := NewStore(10)
	s.SetEnrolled([]string{"dev1"})
	fired := 0
	s.SetOnNew(func(Request) { fired++ })
	for i := 0; i < 4; i++ {
		s.Observe(req("dev1", "example.com"))
	}
	if fired != 1 {
		t.Fatalf("callback should fire once for a repeated host, fired %d", fired)
	}
	_ = time.Now
}
