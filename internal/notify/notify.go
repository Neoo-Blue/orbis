// Package notify delivers events off the box. Before this existed every alert
// Orbis raised stayed in its own database, which means a node that spotted
// something at 3am told nobody until someone opened the UI.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// Notifier fans an event out to every configured sink. Delivery is best
// effort and asynchronous: a webhook that is down must never slow down or
// block the detector that produced the event.
type Notifier struct {
	cfg *config.Config
	log func(string, ...any)
	hc  *http.Client

	mu     sync.Mutex
	recent map[string]time.Time // dedupe key -> last sent
}

func New(cfg *config.Config, log func(string, ...any)) *Notifier {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Notifier{
		cfg:    cfg,
		log:    log,
		hc:     &http.Client{Timeout: 15 * time.Second},
		recent: map[string]time.Time{},
	}
}

// severityRank orders severities so a minimum-severity filter can be applied.
var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// Send delivers an event if it clears the configured severity floor and is not
// a repeat within the dedupe window.
func (n *Notifier) Send(ev store.Event) {
	c := n.cfg.Snapshot().Notify
	if !c.Enabled {
		return
	}
	if severityRank[strings.ToLower(ev.Severity)] < severityRank[strings.ToLower(c.MinSeverity)] {
		return
	}

	// Repeated identical alerts are the fastest way to train someone to
	// ignore alerts entirely, so collapse them over a window.
	key := ev.Category + "|" + ev.Title
	window := time.Duration(c.DedupeMinutes) * time.Minute
	if window > 0 {
		n.mu.Lock()
		last, seen := n.recent[key]
		if seen && time.Since(last) < window {
			n.mu.Unlock()
			return
		}
		n.recent[key] = time.Now()
		// Bound the map: without this a node that raises many distinct
		// events grows it forever.
		if len(n.recent) > 5000 {
			cutoff := time.Now().Add(-2 * window)
			for k, t := range n.recent {
				if t.Before(cutoff) {
					delete(n.recent, k)
				}
			}
		}
		n.mu.Unlock()
	}

	go n.deliver(c, ev)
}

func (n *Notifier) deliver(c config.NotifyConfig, ev store.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, hook := range c.Webhooks {
		if !hook.Enabled || hook.URL == "" {
			continue
		}
		if err := n.postWebhook(ctx, hook, ev); err != nil {
			n.log("notify: webhook %s failed: %v", hook.Name, err)
		}
	}
	if c.Email.Enabled {
		if err := n.sendEmail(c.Email, ev); err != nil {
			n.log("notify: email failed: %v", err)
		}
	}
}

// postWebhook sends the event as JSON. Slack and Discord both accept a plain
// {"text": ...} body, so the "slack" format covers the common case without a
// per-service integration.
func (n *Notifier) postWebhook(ctx context.Context, hook config.Webhook, ev store.Event) error {
	var payload any
	switch strings.ToLower(hook.Format) {
	case "slack":
		payload = map[string]string{
			"text": fmt.Sprintf("*[%s] %s*\n%s", strings.ToUpper(ev.Severity), ev.Title, ev.Detail),
		}
	case "discord":
		payload = map[string]string{
			"content": fmt.Sprintf("**[%s] %s**\n%s", strings.ToUpper(ev.Severity), ev.Title, ev.Detail),
		}
	default:
		payload = map[string]any{
			"id":       ev.ID,
			"ts":       ev.TS.Format(time.RFC3339),
			"severity": ev.Severity,
			"category": ev.Category,
			"title":    ev.Title,
			"detail":   ev.Detail,
			"data":     ev.Data,
			"source":   "orbis",
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hook.Headers {
		req.Header.Set(k, v)
	}
	resp, err := n.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendEmail(c config.EmailConfig, ev store.Event) error {
	if c.Host == "" || len(c.To) == 0 {
		return fmt.Errorf("email sink is incomplete")
	}
	from := c.From
	if from == "" {
		from = "orbis@localhost"
	}
	subject := fmt.Sprintf("[Orbis %s] %s", strings.ToUpper(ev.Severity), ev.Title)
	msg := strings.Join([]string{
		"From: " + from,
		"To: " + strings.Join(c.To, ", "),
		"Subject: " + subject,
		"Date: " + ev.TS.Format(time.RFC1123Z),
		"Content-Type: text/plain; charset=utf-8",
		"",
		ev.Detail,
		"",
		fmt.Sprintf("Category: %s", ev.Category),
		fmt.Sprintf("Time: %s", ev.TS.Format(time.RFC3339)),
	}, "\r\n")

	addr := net.JoinHostPort(c.Host, fmt.Sprint(c.Port))
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}

	// Port 465 is implicit TLS; 587 and 25 negotiate STARTTLS inside SendMail.
	if c.Port == 465 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		defer conn.Close()
		cl, err := smtp.NewClient(conn, c.Host)
		if err != nil {
			return err
		}
		defer cl.Quit()
		if auth != nil {
			if err := cl.Auth(auth); err != nil {
				return err
			}
		}
		if err := cl.Mail(from); err != nil {
			return err
		}
		for _, to := range c.To {
			if err := cl.Rcpt(to); err != nil {
				return err
			}
		}
		wc, err := cl.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write([]byte(msg)); err != nil {
			return err
		}
		return wc.Close()
	}
	return smtp.SendMail(addr, auth, from, c.To, []byte(msg))
}

// Test delivers a synthetic event so an operator can prove a sink works
// without waiting for something to go wrong.
func (n *Notifier) Test() error {
	c := n.cfg.Snapshot().Notify
	if !c.Enabled {
		return fmt.Errorf("notifications are disabled")
	}
	ev := store.Event{
		ID: "test", TS: time.Now(), Severity: "info", Category: "test",
		Title:  "Orbis test notification",
		Detail: "If you are reading this, the sink is configured correctly.",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var errs []string
	sent := 0
	for _, hook := range c.Webhooks {
		if !hook.Enabled || hook.URL == "" {
			continue
		}
		sent++
		if err := n.postWebhook(ctx, hook, ev); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", hook.Name, err))
		}
	}
	if c.Email.Enabled {
		sent++
		if err := n.sendEmail(c.Email, ev); err != nil {
			errs = append(errs, fmt.Sprintf("email: %v", err))
		}
	}
	if sent == 0 {
		return fmt.Errorf("no sink is enabled")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
