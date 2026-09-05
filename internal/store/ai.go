package store

import (
	"database/sql"
	"time"
)

// AIModel is one catalogue entry with its most recent probe result.
type AIModel struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Free       bool      `json:"free"`
	Context    int       `json:"context"`
	MaxOutput  int       `json:"max_output"`
	Tools      bool      `json:"tools"`
	Reasoning  bool      `json:"reasoning"`
	Structured bool      `json:"structured"`
	ToolOK     *bool     `json:"tool_ok"` // nil until probed
	JSONOK     *bool     `json:"json_ok"`
	LatencyMS  int       `json:"latency_ms"`
	LastProbe  time.Time `json:"last_probe"`
	LastError  string    `json:"last_error,omitempty"`
	ChatRank   int       `json:"chat_rank"` // 1 = best; 0 = not ranked
	FastRank   int       `json:"fast_rank"`
}

// AIUsage is one day's counters for one model.
type AIUsage struct {
	Day       string `json:"day"`
	Model     string `json:"model"`
	Requests  int    `json:"requests"`
	Failures  int    `json:"failures"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
}

// AIBrief is one periodic network check written by the assistant.
type AIBrief struct {
	ID       string    `json:"id"`
	TS       time.Time `json:"ts"`
	Hours    int       `json:"hours"`
	Model    string    `json:"model"`
	Severity string    `json:"severity"`
	Headline string    `json:"headline"`
	Body     string    `json:"body"`
}

// ReplaceAIModels swaps the whole catalogue in one transaction, so a reader
// never sees a half-written ranking.
func (s *Store) ReplaceAIModels(models []AIModel) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM ai_models`); err != nil {
		return err
	}
	for _, m := range models {
		if _, err := tx.Exec(`INSERT INTO ai_models
			(id, name, free, context, max_output, tools, reasoning, structured,
			 tool_ok, json_ok, latency_ms, last_probe, last_error, chat_rank, fast_rank)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			m.ID, m.Name, b2i(m.Free), m.Context, m.MaxOutput, b2i(m.Tools), b2i(m.Reasoning), b2i(m.Structured),
			nullBool(m.ToolOK), nullBool(m.JSONOK), m.LatencyMS, unixOrZero(m.LastProbe), m.LastError,
			m.ChatRank, m.FastRank); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AIModels() ([]AIModel, error) {
	rows, err := s.db.Query(`SELECT id, name, free, context, max_output, tools, reasoning, structured,
		tool_ok, json_ok, latency_ms, last_probe, last_error, chat_rank, fast_rank
		FROM ai_models ORDER BY CASE WHEN chat_rank=0 THEN 1 ELSE 0 END, chat_rank, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIModel{}
	for rows.Next() {
		var m AIModel
		var free, tools, reasoning, structured int
		var toolOK, jsonOK sql.NullInt64
		var probe int64
		if err := rows.Scan(&m.ID, &m.Name, &free, &m.Context, &m.MaxOutput, &tools, &reasoning, &structured,
			&toolOK, &jsonOK, &m.LatencyMS, &probe, &m.LastError, &m.ChatRank, &m.FastRank); err != nil {
			return nil, err
		}
		m.Free, m.Tools, m.Reasoning, m.Structured = free == 1, tools == 1, reasoning == 1, structured == 1
		m.ToolOK, m.JSONOK = boolPtr(toolOK), boolPtr(jsonOK)
		if probe > 0 {
			m.LastProbe = time.Unix(probe, 0)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RecordAIUsage adds one request to the day's counters for a model.
func (s *Store) RecordAIUsage(day, model string, failed bool, tokensIn, tokensOut int) error {
	fail := 0
	if failed {
		fail = 1
	}
	_, err := s.db.Exec(`INSERT INTO ai_usage (day, model, requests, failures, tokens_in, tokens_out)
		VALUES (?,?,1,?,?,?)
		ON CONFLICT(day, model) DO UPDATE SET
			requests = requests + 1,
			failures = failures + excluded.failures,
			tokens_in = tokens_in + excluded.tokens_in,
			tokens_out = tokens_out + excluded.tokens_out`,
		day, model, fail, tokensIn, tokensOut)
	return err
}

func (s *Store) AIUsage(day string) ([]AIUsage, error) {
	rows, err := s.db.Query(`SELECT day, model, requests, failures, tokens_in, tokens_out
		FROM ai_usage WHERE day=? ORDER BY requests DESC`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIUsage{}
	for rows.Next() {
		var u AIUsage
		if err := rows.Scan(&u.Day, &u.Model, &u.Requests, &u.Failures, &u.TokensIn, &u.TokensOut); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PruneAIUsage drops counters older than keep days.
func (s *Store) PruneAIUsage(keepDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -keepDays).Format("2006-01-02")
	_, err := s.db.Exec(`DELETE FROM ai_usage WHERE day < ?`, cutoff)
	return err
}

func (s *Store) SaveAIBrief(b AIBrief) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO ai_briefs (id, ts, hours, model, severity, headline, body)
		VALUES (?,?,?,?,?,?,?)`, b.ID, b.TS.Unix(), b.Hours, b.Model, b.Severity, b.Headline, b.Body)
	return err
}

func (s *Store) AIBriefs(limit int) ([]AIBrief, error) {
	rows, err := s.db.Query(`SELECT id, ts, hours, model, severity, headline, body
		FROM ai_briefs ORDER BY ts DESC LIMIT ?`, clampInt(limit, 1, 200))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIBrief{}
	for rows.Next() {
		var b AIBrief
		var ts int64
		if err := rows.Scan(&b.ID, &ts, &b.Hours, &b.Model, &b.Severity, &b.Headline, &b.Body); err != nil {
			return nil, err
		}
		b.TS = time.Unix(ts, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) PruneAIBriefs(keep int) error {
	_, err := s.db.Exec(`DELETE FROM ai_briefs WHERE id NOT IN
		(SELECT id FROM ai_briefs ORDER BY ts DESC LIMIT ?)`, keep)
	return err
}

func nullBool(b *bool) any {
	if b == nil {
		return nil
	}
	return b2i(*b)
}

func boolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 == 1
	return &b
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
