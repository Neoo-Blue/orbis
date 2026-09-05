package store

import (
	"encoding/json"
	"time"
)

// Issue is one recorded problem. Title and detail are stored already
// scrubbed: the recorder redacts before it writes, so nothing in this table
// needs a second pass before it can be shown or sent.
type Issue struct {
	ID           string    `json:"id"`
	Fingerprint  string    `json:"fingerprint"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Occurrences  int       `json:"occurrences"`
	Severity     string    `json:"severity"`
	Category     string    `json:"category"`
	Title        string    `json:"title"`
	Detail       string    `json:"detail"`
	Diagnostics  string    `json:"diagnostics,omitempty"`
	Source       string    `json:"source"` // auto | user | assistant
	Status       string    `json:"status"` // open | reported | dismissed | resolved
	GitHubNumber int       `json:"github_number,omitempty"`
	GitHubURL    string    `json:"github_url,omitempty"`
	ReportedAt   time.Time `json:"reported_at,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

// UpsertIssue records an occurrence. A fingerprint that exists gets its
// counter and last-seen bumped and its detail refreshed; the GitHub state and
// the operator's status decision are kept. Returns the row and whether it
// was new.
func (s *Store) UpsertIssue(in Issue) (*Issue, bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	existing, err := s.issueByFingerprint(in.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	if existing == nil {
		if in.FirstSeen.IsZero() {
			in.FirstSeen = now
		}
		in.LastSeen = now
		if in.Occurrences <= 0 {
			in.Occurrences = 1
		}
		if in.Status == "" {
			in.Status = "open"
		}
		_, err := s.db.Exec(`INSERT INTO issues (id, fingerprint, first_seen, last_seen, occurrences, severity,
			category, title, detail, diagnostics, source, status)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			in.ID, in.Fingerprint, in.FirstSeen.Unix(), in.LastSeen.Unix(), in.Occurrences, in.Severity,
			in.Category, in.Title, in.Detail, in.Diagnostics, in.Source, in.Status)
		if err != nil {
			return nil, false, err
		}
		return &in, true, nil
	}
	// A dismissed issue that keeps happening is worth seeing again, but a
	// resolved one (closed upstream) stays resolved and just counts.
	status := existing.Status
	if status == "dismissed" && now.Sub(existing.LastSeen) > 7*24*time.Hour {
		status = "open"
	}
	sev := existing.Severity
	if SeverityRank(in.Severity) > SeverityRank(sev) {
		sev = in.Severity
	}
	_, err = s.db.Exec(`UPDATE issues SET last_seen=?, occurrences=occurrences+1, severity=?, detail=?,
		diagnostics=CASE WHEN ?='' THEN diagnostics ELSE ? END, status=? WHERE fingerprint=?`,
		now.Unix(), sev, in.Detail, in.Diagnostics, in.Diagnostics, status, in.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	existing.LastSeen = now
	existing.Occurrences++
	existing.Severity = sev
	existing.Detail = in.Detail
	if in.Diagnostics != "" {
		existing.Diagnostics = in.Diagnostics
	}
	existing.Status = status
	return existing, false, nil
}

// SeverityRank orders severities so "worse" can be compared.
func SeverityRank(sev string) int {
	switch sev {
	case SevCritical:
		return 3
	case SevWarning:
		return 2
	case SevNotice:
		return 1
	}
	return 0
}

const issueCols = `id, fingerprint, first_seen, last_seen, occurrences, severity, category, title, detail,
	diagnostics, source, status, github_number, github_url, reported_at, last_error`

func scanIssue(sc interface{ Scan(...any) error }) (*Issue, error) {
	var i Issue
	var first, last, reported int64
	if err := sc.Scan(&i.ID, &i.Fingerprint, &first, &last, &i.Occurrences, &i.Severity, &i.Category,
		&i.Title, &i.Detail, &i.Diagnostics, &i.Source, &i.Status, &i.GitHubNumber, &i.GitHubURL,
		&reported, &i.LastError); err != nil {
		return nil, err
	}
	i.FirstSeen, i.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
	if reported > 0 {
		i.ReportedAt = time.Unix(reported, 0)
	}
	return &i, nil
}

func (s *Store) issueByFingerprint(fp string) (*Issue, error) {
	rows, err := s.db.Query(`SELECT `+issueCols+` FROM issues WHERE fingerprint=?`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanIssue(rows)
}

func (s *Store) Issue(id string) (*Issue, error) {
	rows, err := s.db.Query(`SELECT `+issueCols+` FROM issues WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanIssue(rows)
}

// Issues lists recorded problems, newest activity first. status "" = all.
func (s *Store) Issues(status string, limit int) ([]Issue, error) {
	q := `SELECT ` + issueCols + ` FROM issues`
	args := []any{}
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, clampInt(limit, 1, 500))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Issue{}
	for rows.Next() {
		i, err := scanIssue(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}

func (s *Store) SetIssueStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE issues SET status=? WHERE id=?`, status, id)
	return err
}

// MarkIssueReported records the GitHub side of an issue.
func (s *Store) MarkIssueReported(id string, number int, url string) error {
	_, err := s.db.Exec(`UPDATE issues SET status='reported', github_number=?, github_url=?, reported_at=?, last_error=''
		WHERE id=?`, number, url, time.Now().Unix(), id)
	return err
}

func (s *Store) SetIssueError(id, msg string) error {
	_, err := s.db.Exec(`UPDATE issues SET last_error=? WHERE id=?`, msg, id)
	return err
}

// IssuesReportedSince counts automatic reports filed since t, for the daily cap.
func (s *Store) IssuesReportedSince(t time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM issues WHERE reported_at >= ? AND source='auto'`, t.Unix()).Scan(&n)
	return n, err
}

func (s *Store) DeleteIssue(id string) error {
	_, err := s.db.Exec(`DELETE FROM issues WHERE id=?`, id)
	return err
}

// ---- assistant recommendations ----

type Recommendation struct {
	ID         string         `json:"id"`
	TS         time.Time      `json:"ts"`
	Kind       string         `json:"kind"` // allow | block | investigate
	Domain     string         `json:"domain"`
	Reason     string         `json:"reason"`
	Confidence float64        `json:"confidence"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	Status     string         `json:"status"` // open | accepted | dismissed | expired
	DecidedAt  time.Time      `json:"decided_at,omitempty"`
	DecidedBy  string         `json:"decided_by,omitempty"`
	Model      string         `json:"model,omitempty"`
}

// UpsertRecommendation records a suggestion. An open one for the same
// kind+domain is refreshed; a decided one is left alone and reported back so
// the caller can honour the operator's memory.
func (s *Store) UpsertRecommendation(r Recommendation) (*Recommendation, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	existing, err := s.recommendationByKey(r.Kind, r.Domain)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status != "open" && existing.Status != "expired" {
		return existing, nil
	}
	ev, _ := json.Marshal(r.Evidence)
	if existing == nil {
		_, err := s.db.Exec(`INSERT INTO ai_recommendations (id, ts, kind, domain, reason, confidence, evidence, status, model)
			VALUES (?,?,?,?,?,?,?, 'open', ?)`, r.ID, r.TS.Unix(), r.Kind, r.Domain, r.Reason, r.Confidence, string(ev), r.Model)
		if err != nil {
			return nil, err
		}
		r.Status = "open"
		return &r, nil
	}
	_, err = s.db.Exec(`UPDATE ai_recommendations SET ts=?, reason=?, confidence=?, evidence=?, status='open', model=?
		WHERE kind=? AND domain=?`, r.TS.Unix(), r.Reason, r.Confidence, string(ev), r.Model, r.Kind, r.Domain)
	if err != nil {
		return nil, err
	}
	existing.TS, existing.Reason, existing.Confidence, existing.Evidence, existing.Status, existing.Model =
		r.TS, r.Reason, r.Confidence, r.Evidence, "open", r.Model
	return existing, nil
}

const recCols = `id, ts, kind, domain, reason, confidence, evidence, status, decided_at, decided_by, model`

func scanRec(sc interface{ Scan(...any) error }) (*Recommendation, error) {
	var r Recommendation
	var ts, decided int64
	var ev string
	if err := sc.Scan(&r.ID, &ts, &r.Kind, &r.Domain, &r.Reason, &r.Confidence, &ev, &r.Status, &decided, &r.DecidedBy, &r.Model); err != nil {
		return nil, err
	}
	r.TS = time.Unix(ts, 0)
	if decided > 0 {
		r.DecidedAt = time.Unix(decided, 0)
	}
	if ev != "" && ev != "{}" {
		_ = json.Unmarshal([]byte(ev), &r.Evidence)
	}
	return &r, nil
}

func (s *Store) recommendationByKey(kind, domain string) (*Recommendation, error) {
	rows, err := s.db.Query(`SELECT `+recCols+` FROM ai_recommendations WHERE kind=? AND domain=?`, kind, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanRec(rows)
}

func (s *Store) Recommendation(id string) (*Recommendation, error) {
	rows, err := s.db.Query(`SELECT `+recCols+` FROM ai_recommendations WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanRec(rows)
}

// Recommendations lists suggestions; status "" = all, newest first.
func (s *Store) Recommendations(status string, limit int) ([]Recommendation, error) {
	q := `SELECT ` + recCols + ` FROM ai_recommendations`
	args := []any{}
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, ts DESC LIMIT ?`
	args = append(args, clampInt(limit, 1, 500))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Recommendation{}
	for rows.Next() {
		r, err := scanRec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Store) DecideRecommendation(id, status, by string) error {
	_, err := s.db.Exec(`UPDATE ai_recommendations SET status=?, decided_at=?, decided_by=? WHERE id=?`,
		status, time.Now().Unix(), by, id)
	return err
}

// ExpireRecommendations retires open suggestions older than the cutoff so the
// list reflects current traffic, while keeping decided ones as memory.
func (s *Store) ExpireRecommendations(before time.Time) error {
	_, err := s.db.Exec(`UPDATE ai_recommendations SET status='expired' WHERE status='open' AND ts < ?`, before.Unix())
	return err
}

// ---- notes ----

type Note struct {
	ID     string    `json:"id"`
	TS     time.Time `json:"ts"`
	Note   string    `json:"note"`
	Source string    `json:"source"`
}

func (s *Store) SaveNote(n Note) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO ai_notes (id, ts, note, source) VALUES (?,?,?,?)`,
		n.ID, n.TS.Unix(), n.Note, n.Source)
	return err
}

func (s *Store) Notes(limit int) ([]Note, error) {
	rows, err := s.db.Query(`SELECT id, ts, note, source FROM ai_notes ORDER BY ts DESC LIMIT ?`, clampInt(limit, 1, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Note{}
	for rows.Next() {
		var n Note
		var ts int64
		if err := rows.Scan(&n.ID, &ts, &n.Note, &n.Source); err != nil {
			return nil, err
		}
		n.TS = time.Unix(ts, 0)
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) DeleteNote(id string) error {
	_, err := s.db.Exec(`DELETE FROM ai_notes WHERE id=?`, id)
	return err
}
