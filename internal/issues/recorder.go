package issues

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Input is one problem as seen by the code that hit it. Nothing in it is
// trusted to be clean: the recorder scrubs title and detail before storing.
type Input struct {
	Severity string
	Category string
	Title    string
	Detail   string
	// Source is "auto" for things the daemon noticed, "user" for the report
	// form, "assistant" for the chat tool.
	Source string
	// Diagnostics is attached as-is (after scrubbing) when non-nil; the
	// recorder asks its provider otherwise.
	Diagnostics map[string]any
}

// Recorder is the problem log plus the GitHub reporter.
type Recorder struct {
	cfg     *config.Config
	st      *store.Store
	http    *http.Client
	log     func(string, ...any)
	version string

	// names supplies the strings that identify this network (device labels
	// and hostnames, the node name) so they can be scrubbed.
	names func() []string
	// diag supplies the node snapshot attached to reports.
	diag func() map[string]any

	mu          sync.Mutex
	lastComment map[string]time.Time
	inflight    map[string]bool
}

func New(cfg *config.Config, st *store.Store, version string, names func() []string,
	diag func() map[string]any, log func(string, ...any)) *Recorder {
	if log == nil {
		log = func(string, ...any) {}
	}
	if names == nil {
		names = func() []string { return nil }
	}
	if diag == nil {
		diag = func() map[string]any { return map[string]any{} }
	}
	return &Recorder{
		cfg: cfg, st: st, version: version, names: names, diag: diag, log: log,
		http:        &http.Client{Timeout: 30 * time.Second},
		lastComment: map[string]time.Time{},
		inflight:    map[string]bool{},
	}
}

// SetVersion records the build string included in reports.
func (r *Recorder) SetVersion(v string) {
	r.mu.Lock()
	r.version = v
	r.mu.Unlock()
}

// Redactor builds the current scrubber from configuration and device names.
func (r *Recorder) Redactor() *Redactor {
	cfg := r.cfg.Snapshot()
	terms := append([]string{}, cfg.Issues.RedactExtra...)
	if cfg.Node.Name != "" && cfg.Node.Name != "orbis" {
		terms = append(terms, cfg.Node.Name)
	}
	terms = append(terms, r.names()...)
	var keep []string
	for _, l := range cfg.AdBlock.Lists {
		if u, err := url.Parse(l.URL); err == nil && u.Host != "" {
			keep = append(keep, strings.ToLower(u.Host))
		}
	}
	return NewRedactor(terms, keep)
}

var (
	reDigits = regexp.MustCompile(`\d+`)
	reSpaces = regexp.MustCompile(`\s+`)
)

// Fingerprint identifies a problem across occurrences and nodes: the category
// plus the title with every number, address and hash normalised away, so
// "list X failed: 502" and "list X failed: 503" are one issue.
func Fingerprint(category, title string) string {
	t := strings.ToLower(strings.TrimSpace(title))
	t = NewRedactor(nil, nil).Scrub(t)
	t = reDigits.ReplaceAllString(t, "#")
	t = reSpaces.ReplaceAllString(t, " ")
	sum := sha1.Sum([]byte(strings.ToLower(category) + "|" + t))
	return hex.EncodeToString(sum[:])[:16]
}

// Record writes a problem down. It is safe to call from any subsystem at any
// rate: duplicates collapse onto one row, and nothing leaves the node here
// unless GitHub auto-reporting is enabled, in which case filing happens in
// the background.
func (r *Recorder) Record(ctx context.Context, in Input) (*store.Issue, error) {
	cfg := r.cfg.Snapshot().Issues
	if !cfg.Enabled || r.st == nil {
		return nil, nil
	}
	if in.Source == "" {
		in.Source = "auto"
	}
	if in.Severity == "" {
		in.Severity = store.SevWarning
	}
	if in.Category == "" {
		in.Category = "general"
	}
	if strings.TrimSpace(in.Title) == "" {
		return nil, fmt.Errorf("a title is required")
	}
	red := r.Redactor()
	title := red.Scrub(strings.TrimSpace(in.Title))
	if len(title) > 160 {
		title = title[:160] + "…"
	}
	detail := red.Scrub(strings.TrimSpace(in.Detail))
	if len(detail) > 6000 {
		detail = detail[:6000] + "…"
	}
	diagJSON := ""
	if cfg.GitHub.IncludeDiagnostics || in.Source != "auto" {
		d := in.Diagnostics
		if d == nil {
			d = r.diag()
		}
		if raw, err := json.MarshalIndent(d, "", "  "); err == nil {
			diagJSON = red.Scrub(string(raw))
			if len(diagJSON) > 20000 {
				diagJSON = diagJSON[:20000] + "\n… [truncated]"
			}
		}
	}

	issue, fresh, err := r.st.UpsertIssue(store.Issue{
		ID: uuid.NewString(), Fingerprint: Fingerprint(in.Category, in.Title),
		Severity: in.Severity, Category: in.Category, Title: title, Detail: detail,
		Diagnostics: diagJSON, Source: in.Source,
	})
	if err != nil {
		return nil, err
	}
	if fresh {
		r.log("issues: recorded %s [%s] %s", issue.Severity, issue.Category, issue.Title)
	}

	// Automatic filing: only for daemon-noticed problems at warning or above,
	// only when the operator turned it on, only within the daily cap.
	if in.Source == "auto" && cfg.GitHub.Enabled && cfg.GitHub.AutoReport &&
		store.SeverityRank(issue.Severity) >= store.SeverityRank(store.SevWarning) &&
		issue.Status != "dismissed" && issue.Status != "resolved" {
		id := issue.ID
		go func() {
			bctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, err := r.Report(bctx, id, true); err != nil {
				r.log("issues: auto-report of %q failed: %v", issue.Title, err)
			}
		}()
	}
	return issue, nil
}

// Preview renders exactly what Report would send, for the UI to show before
// the operator clicks. Title and body are already scrubbed.
func (r *Recorder) Preview(id string) (title, body string, labels []string, err error) {
	issue, err := r.st.Issue(id)
	if err != nil {
		return "", "", nil, err
	}
	if issue == nil {
		return "", "", nil, fmt.Errorf("no such issue")
	}
	title, body, labels = r.render(issue)
	return title, body, labels, nil
}

func (r *Recorder) render(i *store.Issue) (title, body string, labels []string) {
	title = i.Title
	if i.Source == "auto" {
		title = "[auto] " + title
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- orbis-fp:%s -->\n", i.Fingerprint)
	fmt.Fprintf(&b, "**Reported by Orbis %s** (source: %s)\n\n", orDefault(r.version, "dev"), i.Source)
	b.WriteString("### What happened\n\n")
	if i.Detail != "" {
		b.WriteString(i.Detail)
	} else {
		b.WriteString("_No further detail was captured._")
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "**Where:** category `%s`, severity `%s`. Seen %d time(s) since %s.\n\n",
		i.Category, i.Severity, i.Occurrences, i.FirstSeen.UTC().Format("2006-01-02"))
	if i.Diagnostics != "" {
		b.WriteString("<details><summary>Diagnostics (scrubbed on the node)</summary>\n\n```json\n")
		b.WriteString(i.Diagnostics)
		b.WriteString("\n```\n</details>\n\n")
	}
	b.WriteString("_Addresses, MAC addresses, device names, hostnames outside the project's infrastructure, keys and email addresses were replaced with placeholders before this left the node._\n")
	body = b.String()
	labels = []string{"orbis-report", "severity:" + i.Severity, "area:" + sanitizeLabel(i.Category)}
	if i.Source == "auto" {
		labels = append(labels, "auto")
	}
	return title, body, labels
}

func sanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "-", " ", "-", "/", "-").Replace(s)
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		s = "general"
	}
	return s
}

// Report files the issue on GitHub (or comments on the existing one). auto
// says whether this is the daemon acting on its own, which is subject to the
// daily cap; an operator's click is not.
func (r *Recorder) Report(ctx context.Context, id string, auto bool) (*store.Issue, error) {
	cfg := r.cfg.Snapshot().Issues.GitHub
	if !cfg.Enabled {
		return nil, fmt.Errorf("GitHub reporting is off in Settings → Problem reports")
	}
	if cfg.Token == "" && cfg.RelayURL == "" {
		return nil, fmt.Errorf("add a GitHub token or a relay URL first")
	}
	issue, err := r.st.Issue(id)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, fmt.Errorf("no such issue")
	}

	r.mu.Lock()
	if r.inflight[id] {
		r.mu.Unlock()
		return issue, nil
	}
	r.inflight[id] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inflight, id)
		r.mu.Unlock()
	}()

	// Already filed: add a "seen again" comment at most once a day.
	if issue.GitHubNumber > 0 {
		r.mu.Lock()
		last := r.lastComment[id]
		r.mu.Unlock()
		if time.Since(last) < 24*time.Hour || time.Since(issue.ReportedAt) < time.Hour {
			return issue, nil
		}
		body := fmt.Sprintf("Seen again on Orbis %s: %d occurrence(s) so far, last at %s (UTC).",
			orDefault(r.version, "dev"), issue.Occurrences, issue.LastSeen.UTC().Format(time.RFC3339))
		if err := r.comment(ctx, cfg, issue, body); err != nil {
			_ = r.st.SetIssueError(id, err.Error())
			return nil, err
		}
		r.mu.Lock()
		r.lastComment[id] = time.Now()
		r.mu.Unlock()
		return issue, nil
	}

	if auto {
		max := cfg.MaxPerDay
		if max <= 0 {
			max = 5
		}
		dayStart := time.Now().UTC().Truncate(24 * time.Hour)
		if n, err := r.st.IssuesReportedSince(dayStart); err == nil && n >= max {
			return nil, fmt.Errorf("daily cap of %d automatic reports reached", max)
		}
	}

	title, body, labels := r.render(issue)
	num, htmlURL, err := r.file(ctx, cfg, issue, title, body, labels)
	if err != nil {
		_ = r.st.SetIssueError(id, err.Error())
		return nil, err
	}
	if err := r.st.MarkIssueReported(id, num, htmlURL); err != nil {
		return nil, err
	}
	r.log("issues: filed %q as %s", issue.Title, htmlURL)
	return r.st.Issue(id)
}

// file creates the issue, or finds the existing one for the fingerprint.
func (r *Recorder) file(ctx context.Context, cfg config.GitHubReport, issue *store.Issue, title, body string, labels []string) (int, string, error) {
	if cfg.RelayURL != "" && cfg.Token == "" {
		return r.relay(ctx, cfg, map[string]any{
			"action": "create", "fingerprint": issue.Fingerprint, "title": title, "body": body,
			"labels": labels, "severity": issue.Severity, "category": issue.Category,
			"version": r.version, "occurrences": issue.Occurrences,
		})
	}
	// Dedupe against the board first: another node may have filed it.
	if num, u, state, err := r.search(ctx, cfg, issue.Fingerprint); err == nil && num > 0 {
		if state == "closed" {
			_ = r.st.SetIssueStatus(issue.ID, "resolved")
		}
		return num, u, nil
	}
	payload := map[string]any{"title": title, "body": body, "labels": labels}
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := r.github(ctx, cfg, http.MethodPost, "/repos/"+cfg.Repo+"/issues", payload, &out); err != nil {
		return 0, "", err
	}
	return out.Number, out.HTMLURL, nil
}

func (r *Recorder) comment(ctx context.Context, cfg config.GitHubReport, issue *store.Issue, body string) error {
	if cfg.RelayURL != "" && cfg.Token == "" {
		_, _, err := r.relay(ctx, cfg, map[string]any{
			"action": "comment", "fingerprint": issue.Fingerprint, "number": issue.GitHubNumber,
			"body": body, "version": r.version,
		})
		return err
	}
	path := fmt.Sprintf("/repos/%s/issues/%d/comments", cfg.Repo, issue.GitHubNumber)
	return r.github(ctx, cfg, http.MethodPost, path, map[string]any{"body": body}, nil)
}

func (r *Recorder) search(ctx context.Context, cfg config.GitHubReport, fp string) (int, string, string, error) {
	q := url.QueryEscape(fmt.Sprintf(`repo:%s is:issue "orbis-fp:%s" in:body`, cfg.Repo, fp))
	var out struct {
		Items []struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
			State   string `json:"state"`
		} `json:"items"`
	}
	if err := r.github(ctx, cfg, http.MethodGet, "/search/issues?q="+q, nil, &out); err != nil {
		return 0, "", "", err
	}
	if len(out.Items) == 0 {
		return 0, "", "", nil
	}
	it := out.Items[0]
	return it.Number, it.HTMLURL, it.State, nil
}

func (r *Recorder) github(ctx context.Context, cfg config.GitHubReport, method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "orbis/"+orDefault(r.version, "dev"))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(raw))
		var ghErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &ghErr) == nil && ghErr.Message != "" {
			msg = ghErr.Message
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("GitHub returned %d: %s", resp.StatusCode, msg)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// relay posts the scrubbed payload to an endpoint that holds the project's
// token. The relay is expected to dedupe by fingerprint and to answer with
// the issue number and URL.
func (r *Recorder) relay(ctx context.Context, cfg config.GitHubReport, payload map[string]any) (int, string, error) {
	payload["repo"] = cfg.Repo
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RelayURL, bytes.NewReader(raw))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "orbis/"+orDefault(r.version, "dev"))
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return 0, "", fmt.Errorf("relay returned %d: %s", resp.StatusCode, msg)
	}
	var out struct {
		Number int    `json:"number"`
		URL    string `json:"url"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, "", fmt.Errorf("relay answer unreadable: %w", err)
	}
	if out.Error != "" {
		return 0, "", fmt.Errorf("relay: %s", out.Error)
	}
	return out.Number, out.URL, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
