package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestARequestReachesAPhoneWithItsButtons(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
	}))
	defer srv.Close()
	n := New(config.Default(), func(string, ...any) {})
	err := n.postWebhook(t.Context(), config.Webhook{URL: srv.URL + "/orbis-topic", Format: "ntfy"}, store.Event{
		Title: "Guest phone asks to open site.example", Detail: "They say: homework\nAnswer in one tap: http://node/unblock/abc?t=tok",
		Data: map[string]any{"approve_url": "http://node/unblock/abc", "token": "tok", "wants": 15},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/" || got["topic"] != "orbis-topic" {
		t.Fatalf("path %q topic %v", path, got["topic"])
	}
	if strings.Contains(got["message"].(string), "unblock/abc") {
		t.Fatalf("the link belongs on the buttons: %v", got["message"])
	}
	actions := got["actions"].([]any)
	if len(actions) != 2 {
		t.Fatalf("actions %v", actions)
	}
	allow := actions[0].(map[string]any)
	if allow["label"] != "Allow 15 minutes" || allow["url"] != "http://node/unblock/abc?minutes=15" || allow["body"] != "answer=allow&t=tok" {
		t.Fatalf("allow %v", allow)
	}
}

func TestAWebhookCanHearOnlyOneCategory(t *testing.T) {
	calls := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls <- string(raw)
	}))
	defer srv.Close()
	n := New(config.Default(), func(string, ...any) {})
	c := config.NotifyConfig{Webhooks: []config.Webhook{{Name: "p", Enabled: true, URL: srv.URL, Only: "unblock"}}}
	n.deliver(c, store.Event{Category: "anomaly", Title: "other"})
	n.deliver(c, store.Event{Category: "unblock", Title: "wanted"})
	select {
	case body := <-calls:
		if !strings.Contains(body, "wanted") {
			t.Fatalf("got %s", body)
		}
	case <-time.After(time.Second):
		t.Fatal("the matching event never arrived")
	}
	if len(calls) != 0 {
		t.Fatal("another category got through")
	}
}

func TestWhatGuestsTypeCannotPingOrPoseAsALink(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	n := New(config.Default(), func(string, ...any) {})
	ev := store.Event{Severity: "warning", Title: "Phone asks", Detail: "<!channel> <http://evil|Answer> [Answer](http://evil)"}

	if err := n.postWebhook(t.Context(), config.Webhook{URL: srv.URL, Format: "slack"}, ev); err != nil {
		t.Fatal(err)
	}
	if text := got["text"].(string); strings.Contains(text, "<") {
		t.Errorf("slack: %s", text)
	}
	if err := n.postWebhook(t.Context(), config.Webhook{URL: srv.URL, Format: "discord"}, ev); err != nil {
		t.Fatal(err)
	}
	if content := got["content"].(string); strings.Contains(content, "](") {
		t.Errorf("discord: %s", content)
	}
	if got["allowed_mentions"] == nil {
		t.Error("discord could ping everyone")
	}
}

func TestAHostnameCannotAddMailHeaders(t *testing.T) {
	got := mailSubject(store.Event{Severity: "warning", Title: "Dad's iPhone\r\nX-Injected: yes\r\n\r\nFORGED asks"})
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("%q", got)
	}
}
