package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// AIIntel is one threat-intelligence assessment: the model's reading of the
// window's attacks, hits, anomalies and traffic, with findings and the
// actions it proposed.
type AIIntel struct {
	ID       string          `json:"id"`
	TS       time.Time       `json:"ts"`
	Hours    int             `json:"hours"`
	Model    string          `json:"model"`
	Risk     string          `json:"risk"` // low | guarded | elevated | high
	Headline string          `json:"headline"`
	Summary  string          `json:"summary"`
	Findings json.RawMessage `json:"findings"`
}

// AIAction is something the assessment wanted done: a timed ban or a domain
// block. Suggested until the operator applies it, or applied by active
// blocking; either way it can be undone.
type AIAction struct {
	ID         string    `json:"id"`
	IntelID    string    `json:"intel_id"`
	TS         time.Time `json:"ts"`
	Kind       string    `json:"kind"` // ban_ip | block_domain
	Value      string    `json:"value"`
	Hours      int       `json:"hours"`
	Reason     string    `json:"reason"`
	Confidence float64   `json:"confidence"`
	Status     string    `json:"status"` // suggested | applied | dismissed | undone | failed | refused
	Ref        string    `json:"ref,omitempty"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
	DecidedBy  string    `json:"decided_by,omitempty"`
}

func (s *Store) SaveAIIntel(in AIIntel) error {
	if len(in.Findings) == 0 {
		in.Findings = json.RawMessage("[]")
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO ai_intel (id, ts, hours, model, risk, headline, summary, findings)
		VALUES (?,?,?,?,?,?,?,?)`, in.ID, in.TS.Unix(), in.Hours, in.Model, in.Risk, in.Headline, in.Summary, string(in.Findings))
	return err
}

func (s *Store) AIIntels(limit int) ([]AIIntel, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.Query(`SELECT id, ts, hours, model, risk, headline, summary, findings FROM ai_intel ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIIntel{}
	for rows.Next() {
		var in AIIntel
		var ts int64
		var findings string
		if err := rows.Scan(&in.ID, &ts, &in.Hours, &in.Model, &in.Risk, &in.Headline, &in.Summary, &findings); err != nil {
			return nil, err
		}
		in.TS = time.Unix(ts, 0)
		in.Findings = json.RawMessage(findings)
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) PruneAIIntel(keep int) error {
	_, err := s.db.Exec(`DELETE FROM ai_intel WHERE id NOT IN (SELECT id FROM ai_intel ORDER BY ts DESC LIMIT ?)`, keep)
	return err
}

func (s *Store) SaveAIAction(a AIAction) error {
	var decided int64
	if !a.DecidedAt.IsZero() {
		decided = a.DecidedAt.Unix()
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO ai_actions (id, intel_id, ts, kind, value, hours, reason, confidence, status, ref, decided_at, decided_by)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.IntelID, a.TS.Unix(), a.Kind, a.Value, a.Hours, a.Reason, a.Confidence, a.Status, a.Ref, decided, a.DecidedBy)
	return err
}

func (s *Store) SetAIActionStatus(id, status, ref, by string) error {
	_, err := s.db.Exec(`UPDATE ai_actions SET status=?, ref=CASE WHEN ?='' THEN ref ELSE ? END, decided_at=?, decided_by=? WHERE id=?`,
		status, ref, ref, time.Now().Unix(), by, id)
	return err
}

func (s *Store) AIAction(id string) (*AIAction, error) {
	row := s.db.QueryRow(`SELECT id, intel_id, ts, kind, value, hours, reason, confidence, status, ref, decided_at, decided_by FROM ai_actions WHERE id=?`, id)
	a, err := scanAIAction(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// AIActions lists actions, newest first; status "" means all.
func (s *Store) AIActions(status string, limit int) ([]AIAction, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, intel_id, ts, kind, value, hours, reason, confidence, status, ref, decided_at, decided_by
		FROM ai_actions WHERE (?='' OR status=?) ORDER BY ts DESC LIMIT ?`, status, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIAction{}
	for rows.Next() {
		a, err := scanAIAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// OpenAIAction finds a live (suggested or applied) action on a value, so a
// repeat finding does not pile up duplicates.
func (s *Store) OpenAIAction(kind, value string) (*AIAction, error) {
	row := s.db.QueryRow(`SELECT id, intel_id, ts, kind, value, hours, reason, confidence, status, ref, decided_at, decided_by
		FROM ai_actions WHERE kind=? AND value=? AND status IN ('suggested','applied') ORDER BY ts DESC LIMIT 1`, kind, value)
	a, err := scanAIAction(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

type rowScanner interface{ Scan(dest ...any) error }

func scanAIAction(r rowScanner) (*AIAction, error) {
	var a AIAction
	var ts, decided int64
	if err := r.Scan(&a.ID, &a.IntelID, &ts, &a.Kind, &a.Value, &a.Hours, &a.Reason, &a.Confidence, &a.Status, &a.Ref, &decided, &a.DecidedBy); err != nil {
		return nil, err
	}
	a.TS = time.Unix(ts, 0)
	if decided > 0 {
		a.DecidedAt = time.Unix(decided, 0)
	}
	return &a, nil
}
