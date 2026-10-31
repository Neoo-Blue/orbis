package unblock

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func manager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(filepath.Join(t.TempDir(), "unblock.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func ask(t *testing.T, m *Manager, host, client string, now time.Time) *Request {
	t.Helper()
	r, _, err := m.Ask(Request{Host: host, ClientID: client}, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAGrantCoversTheDeviceAndSubdomainsUntilItEnds(t *testing.T) {
	m := manager(t)
	now := time.Now()
	r := ask(t, m, "Site.example.", "guest", now)
	if m.Granted("guest", "site.example", now) {
		t.Fatal("asking opens nothing")
	}
	if _, err := m.Decide(r.ID, true, time.Hour, false, "owner", now); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"site.example": true, "www.site.example.": true, "badsite.example": false} {
		if got := m.Granted("guest", name, now); got != want {
			t.Errorf("%s = %v", name, got)
		}
	}
	if m.Granted("someone-else", "site.example", now) {
		t.Fatal("a grant for one device opened it for another")
	}
	if m.Granted("guest", "site.example", now.Add(time.Hour)) {
		t.Fatal("a grant outlived its time")
	}
}

func TestEveryoneAndRevoke(t *testing.T) {
	m := manager(t)
	now := time.Now()
	r := ask(t, m, "site.example", "guest", now)
	if _, err := m.Decide(r.ID, true, 0, true, "owner", now); err != nil {
		t.Fatal(err)
	}
	if !m.Granted("anyone", "site.example", now.Add(1000*time.Hour)) {
		t.Fatal("a grant for everyone with no end should stand")
	}
	if err := m.Revoke(r.ID, now); err != nil {
		t.Fatal(err)
	}
	if m.Granted("anyone", "site.example", now) {
		t.Fatal("a revoked grant still opens the site")
	}
}

func TestAnAnswerStands(t *testing.T) {
	m := manager(t)
	now := time.Now()
	r := ask(t, m, "site.example", "guest", now)
	if _, err := m.Decide(r.ID, false, 0, false, "owner", now); err != nil {
		t.Fatal(err)
	}
	// A second tap on an old notification must not reverse the first.
	got, err := m.Decide(r.ID, true, 0, true, "link", now)
	if err != nil || got.State != Denied || m.Granted("guest", "site.example", now) {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRepeatsCollapseAndFloodsStop(t *testing.T) {
	m := manager(t)
	now := time.Now()
	first := ask(t, m, "site.example", "guest", now)
	again, isNew, err := m.Ask(Request{Host: "site.example", ClientID: "guest"}, now)
	if err != nil || isNew || again.ID != first.ID {
		t.Fatalf("a repeat should reuse the request: %v %v", isNew, err)
	}
	for i := 0; i < maxPerDevice-1; i++ {
		ask(t, m, fmt.Sprintf("s%d.example", i), "guest", now)
	}
	if _, _, err := m.Ask(Request{Host: "one-more.example", ClientID: "guest"}, now); err != ErrTooMany {
		t.Fatalf("err = %v", err)
	}
}

func TestLongNotesAreCut(t *testing.T) {
	m := manager(t)
	r, _, err := m.Ask(Request{Host: "a.example", ClientID: "c", Note: string(make([]byte, 5000))}, time.Now())
	if err != nil || len(r.Note) != maxNote {
		t.Fatalf("%d %v", len(r.Note), err)
	}
}

func TestAGrantSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unblock.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := ask(t, m, "site.example", "guest", now)
	if _, err := m.Decide(r.ID, true, time.Hour, false, "owner", now); err != nil {
		t.Fatal(err)
	}
	if err := m.Trust("mine", true); err != nil {
		t.Fatal(err)
	}
	token := m.Token(r.ID)
	again, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Granted("guest", "site.example", now) || !again.Trusted("mine") {
		t.Fatal("state was lost")
	}
	if !again.ValidToken(r.ID, token) {
		t.Fatal("a link sent before a restart should still work")
	}
}

func TestTokensBelongToOneRequest(t *testing.T) {
	m := manager(t)
	if m.ValidToken("b", m.Token("a")) || m.ValidToken("a", "") {
		t.Fatal("a token opened the wrong request")
	}
}

func TestATrustedDeviceSkipsTheQueue(t *testing.T) {
	m := manager(t)
	now := time.Now()
	r, err := m.Grant(Request{Host: "site.example", ClientID: "mine"}, time.Hour, now)
	if err != nil || r.State != Approved || !m.Granted("mine", "site.example", now) {
		t.Fatalf("%+v %v", r, err)
	}
	if p, _, _ := m.List(now); len(p) != 0 {
		t.Fatal("nothing should be left waiting")
	}
}

func TestNoGrantsMeansNoLocking(t *testing.T) {
	m := manager(t)
	ask(t, m, "site.example", "guest", time.Now())
	if m.grants.Load() != 0 {
		t.Fatal("a pending request is not a grant")
	}
}
