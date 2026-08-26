package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ---------- firewall rules ----------

func (s *Store) Rules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, position, enabled, name, COALESCE(description,''), chain, action,
		COALESCE(src_zone,''), COALESCE(dst_zone,''), COALESCE(src,''), COALESCE(dst,''),
		COALESCE(proto,''), COALESCE(src_port,''), COALESCE(dst_port,''), COALESCE(schedule,''),
		log, counter_pkts, counter_bytes, origin, created_at, updated_at
		FROM rules ORDER BY chain, position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var enabled, logf int
		var created, updated int64
		if err := rows.Scan(&r.ID, &r.Position, &enabled, &r.Name, &r.Description, &r.Chain, &r.Action,
			&r.SrcZone, &r.DstZone, &r.Src, &r.Dst, &r.Proto, &r.SrcPort, &r.DstPort, &r.Schedule,
			&logf, &r.CounterPkts, &r.CounterBytes, &r.Origin, &created, &updated); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.Log = logf != 0
		r.CreatedAt = time.Unix(created, 0)
		r.UpdatedAt = time.Unix(updated, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveRule(r *Rule) error {
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if r.Position == 0 {
		var maxPos sql.NullInt64
		_ = s.db.QueryRow("SELECT MAX(position) FROM rules WHERE chain=?", r.Chain).Scan(&maxPos)
		r.Position = int(maxPos.Int64) + 10
	}
	_, err := s.db.Exec(`INSERT INTO rules
		(id, position, enabled, name, description, chain, action, src_zone, dst_zone, src, dst,
		 proto, src_port, dst_port, schedule, log, counter_pkts, counter_bytes, origin, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			position=excluded.position, enabled=excluded.enabled, name=excluded.name,
			description=excluded.description, chain=excluded.chain, action=excluded.action,
			src_zone=excluded.src_zone, dst_zone=excluded.dst_zone, src=excluded.src, dst=excluded.dst,
			proto=excluded.proto, src_port=excluded.src_port, dst_port=excluded.dst_port,
			schedule=excluded.schedule, log=excluded.log, updated_at=excluded.updated_at`,
		r.ID, r.Position, b2i(r.Enabled), r.Name, r.Description, r.Chain, r.Action, r.SrcZone,
		r.DstZone, r.Src, r.Dst, r.Proto, r.SrcPort, r.DstPort, r.Schedule, b2i(r.Log),
		r.CounterPkts, r.CounterBytes, r.Origin, r.CreatedAt.Unix(), r.UpdatedAt.Unix())
	return err
}

func (s *Store) DeleteRule(id string) error {
	_, err := s.db.Exec("DELETE FROM rules WHERE id=?", id)
	return err
}

// ReorderRules rewrites positions in the order given, spaced by 10 so a
// single insert between two rules does not require a full renumber.
func (s *Store) ReorderRules(chain string, ids []string) error {
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer unlock()
	defer tx.Rollback()
	for i, id := range ids {
		if _, err := tx.Exec("UPDATE rules SET position=?, updated_at=? WHERE id=? AND chain=?",
			(i+1)*10, time.Now().Unix(), id, chain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpdateRuleCounters writes back packet/byte counters read from nftables.
func (s *Store) UpdateRuleCounters(counters map[string][2]int64) error {
	if len(counters) == 0 {
		return nil
	}
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer unlock()
	defer tx.Rollback()
	for id, c := range counters {
		if _, err := tx.Exec("UPDATE rules SET counter_pkts=?, counter_bytes=? WHERE id=?",
			c[0], c[1], id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------- policies ----------

func (s *Store) Policies() ([]Policy, error) {
	rows, err := s.db.Query(`SELECT id, name, COALESCE(description,''), categories, allowlist, denylist,
		safe_search, block_doh, COALESCE(schedule,''), COALESCE(blocked_services,'[]'),
		created_at, updated_at FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		var p Policy
		var cats, allow, deny, svcs string
		var safe, doh int
		var created, updated int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &cats, &allow, &deny, &safe, &doh,
			&p.Schedule, &svcs, &created, &updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(cats), &p.Categories)
		_ = json.Unmarshal([]byte(allow), &p.Allowlist)
		_ = json.Unmarshal([]byte(deny), &p.Denylist)
		_ = json.Unmarshal([]byte(svcs), &p.BlockedServices)
		p.SafeSearch = safe != 0
		p.BlockDoH = doh != 0
		p.CreatedAt = time.Unix(created, 0)
		p.UpdatedAt = time.Unix(updated, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SavePolicy(p *Policy) error {
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	cats, _ := json.Marshal(orEmpty(p.Categories))
	allow, _ := json.Marshal(orEmpty(p.Allowlist))
	deny, _ := json.Marshal(orEmpty(p.Denylist))
	svcs, _ := json.Marshal(orEmpty(p.BlockedServices))
	_, err := s.db.Exec(`INSERT INTO policies
		(id, name, description, categories, allowlist, denylist, safe_search, block_doh, schedule,
		 blocked_services, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description,
			categories=excluded.categories, allowlist=excluded.allowlist, denylist=excluded.denylist,
			safe_search=excluded.safe_search, block_doh=excluded.block_doh, schedule=excluded.schedule,
			blocked_services=excluded.blocked_services, updated_at=excluded.updated_at`,
		p.ID, p.Name, p.Description, string(cats), string(allow), string(deny),
		b2i(p.SafeSearch), b2i(p.BlockDoH), p.Schedule, string(svcs),
		p.CreatedAt.Unix(), p.UpdatedAt.Unix())
	return err
}

func (s *Store) DeletePolicy(id string) error {
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer unlock()
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE clients SET policy_id=NULL WHERE policy_id=?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM policies WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------- blocklists ----------

// ReplaceListDomains swaps a list's contents atomically so a partially
// downloaded refresh never leaves the resolver with half a list.
func (s *Store) ReplaceListDomains(list, category string, domains []string, wildcards []string) error {
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer unlock()
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM block_domains WHERE source=?", list); err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO block_domains (domain, source, category, wildcard) VALUES (?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, d := range domains {
		if _, err := stmt.Exec(d, list, category, 0); err != nil {
			return err
		}
	}
	for _, d := range wildcards {
		if _, err := stmt.Exec(d, list, category, 1); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE list_meta SET entries=?, last_updated=?, last_error='' WHERE name=?`,
		len(domains)+len(wildcards), time.Now().Unix(), list); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpsertListMeta(m ListMeta) error {
	var lastUpdated any
	if m.LastUpdated != nil {
		lastUpdated = m.LastUpdated.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO list_meta (name, url, category, enabled, entries, last_updated, last_error, etag)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET url=excluded.url, category=excluded.category,
			enabled=excluded.enabled, etag=COALESCE(NULLIF(excluded.etag,''), list_meta.etag)`,
		m.Name, m.URL, m.Category, b2i(m.Enabled), m.Entries, lastUpdated, m.LastError, m.ETag)
	return err
}

func (s *Store) SetListError(name, msg string) error {
	_, err := s.db.Exec("UPDATE list_meta SET last_error=? WHERE name=?", msg, name)
	return err
}

func (s *Store) ListMetas() ([]ListMeta, error) {
	rows, err := s.db.Query(`SELECT name, url, COALESCE(category,''), enabled, entries,
		last_updated, COALESCE(last_error,''), COALESCE(etag,'') FROM list_meta ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ListMeta{}
	for rows.Next() {
		var m ListMeta
		var enabled int
		var lu sql.NullInt64
		if err := rows.Scan(&m.Name, &m.URL, &m.Category, &enabled, &m.Entries, &lu, &m.LastError, &m.ETag); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		if lu.Valid {
			t := time.Unix(lu.Int64, 0)
			m.LastUpdated = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteList(name string) error {
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer unlock()
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM block_domains WHERE source=?", name); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM list_meta WHERE name=?", name); err != nil {
		return err
	}
	return tx.Commit()
}

// AllBlockDomains streams every enabled list's domains for index rebuilds.
func (s *Store) AllBlockDomains(fn func(domain, category string, wildcard bool)) error {
	rows, err := s.db.Query(`SELECT b.domain, COALESCE(b.category,''), b.wildcard
		FROM block_domains b JOIN list_meta m ON m.name = b.source WHERE m.enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d, c string
		var w int
		if err := rows.Scan(&d, &c, &w); err != nil {
			return err
		}
		fn(d, c, w != 0)
	}
	return rows.Err()
}

// ---------- local rules ----------

func (s *Store) LocalRules() ([]LocalRule, error) {
	rows, err := s.db.Query(`SELECT domain, action, wildcard, origin, COALESCE(note,''), created_at
		FROM local_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalRule{}
	for rows.Next() {
		var r LocalRule
		var wc int
		var created int64
		if err := rows.Scan(&r.Domain, &r.Action, &wc, &r.Origin, &r.Note, &created); err != nil {
			return nil, err
		}
		r.Wildcard = wc != 0
		r.CreatedAt = time.Unix(created, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveLocalRule(r LocalRule) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO local_rules (domain, action, wildcard, origin, note, created_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET action=excluded.action, wildcard=excluded.wildcard,
			origin=excluded.origin, note=excluded.note`,
		r.Domain, r.Action, b2i(r.Wildcard), r.Origin, r.Note, r.CreatedAt.Unix())
	return err
}

func (s *Store) DeleteLocalRule(domain string) error {
	_, err := s.db.Exec("DELETE FROM local_rules WHERE domain=?", domain)
	return err
}

// ---------- ad candidates ----------

// ObserveCandidate records a sighting, creating the row on first contact.
func (s *Store) ObserveCandidate(domain string, clients, referrers int) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO ad_candidates
		(domain, first_seen, last_seen, observations, distinct_clients, distinct_referrers)
		VALUES (?,?,?,1,?,?)
		ON CONFLICT(domain) DO UPDATE SET
			last_seen=excluded.last_seen,
			observations=ad_candidates.observations+1,
			distinct_clients=MAX(ad_candidates.distinct_clients, excluded.distinct_clients),
			distinct_referrers=MAX(ad_candidates.distinct_referrers, excluded.distinct_referrers)`,
		domain, now, now, clients, referrers)
	return err
}

func (s *Store) ScoreCandidate(domain string, heuristic float64, ai *float64, aiReason string, final float64, features map[string]any) error {
	f, _ := json.Marshal(features)
	_, err := s.db.Exec(`UPDATE ad_candidates SET heuristic_score=?, ai_score=?, ai_reason=?,
		final_score=?, features=? WHERE domain=?`,
		heuristic, ai, aiReason, final, string(f), domain)
	return err
}

func (s *Store) SetCandidateStatus(domain, status, by string) error {
	_, err := s.db.Exec(`UPDATE ad_candidates SET status=?, decided_by=?, decided_at=? WHERE domain=?`,
		status, by, time.Now().Unix(), domain)
	return err
}

func (s *Store) Candidates(status string, minScore float64, limit int) ([]AdCandidate, error) {
	q := `SELECT domain, first_seen, last_seen, observations, distinct_clients, distinct_referrers,
		heuristic_score, ai_score, COALESCE(ai_reason,''), final_score, status, COALESCE(decided_by,''),
		decided_at, COALESCE(features,'{}') FROM ad_candidates WHERE final_score >= ?`
	args := []any{minScore}
	if status != "" {
		q += " AND status = ?"
		args = append(args, status)
	}
	q += fmt.Sprintf(" ORDER BY final_score DESC, observations DESC LIMIT %d", clampInt(limit, 1, 2000))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdCandidate{}
	for rows.Next() {
		var c AdCandidate
		var first, last int64
		var decided sql.NullInt64
		var aiScore sql.NullFloat64
		var features string
		if err := rows.Scan(&c.Domain, &first, &last, &c.Observations, &c.DistinctClients,
			&c.DistinctReferrers, &c.HeuristicScore, &aiScore, &c.AIReason, &c.FinalScore,
			&c.Status, &c.DecidedBy, &decided, &features); err != nil {
			return nil, err
		}
		c.FirstSeen = time.Unix(first, 0)
		c.LastSeen = time.Unix(last, 0)
		if aiScore.Valid {
			v := aiScore.Float64
			c.AIScore = &v
		}
		if decided.Valid {
			t := time.Unix(decided.Int64, 0)
			c.DecidedAt = &t
		}
		_ = json.Unmarshal([]byte(features), &c.Features)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PendingCandidates returns rows that have enough observations to score but
// have not been decided yet.
func (s *Store) PendingCandidates(minObs, limit int) ([]AdCandidate, error) {
	rows, err := s.db.Query(`SELECT domain, first_seen, last_seen, observations, distinct_clients,
		distinct_referrers, heuristic_score, ai_score, COALESCE(ai_reason,''), final_score, status,
		COALESCE(decided_by,''), decided_at, COALESCE(features,'{}')
		FROM ad_candidates WHERE status IN ('candidate','review') AND observations >= ?
		ORDER BY observations DESC LIMIT ?`, minObs, clampInt(limit, 1, 2000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdCandidate{}
	for rows.Next() {
		var c AdCandidate
		var first, last int64
		var decided sql.NullInt64
		var aiScore sql.NullFloat64
		var features string
		if err := rows.Scan(&c.Domain, &first, &last, &c.Observations, &c.DistinctClients,
			&c.DistinctReferrers, &c.HeuristicScore, &aiScore, &c.AIReason, &c.FinalScore,
			&c.Status, &c.DecidedBy, &decided, &features); err != nil {
			return nil, err
		}
		c.FirstSeen = time.Unix(first, 0)
		c.LastSeen = time.Unix(last, 0)
		if aiScore.Valid {
			v := aiScore.Float64
			c.AIScore = &v
		}
		_ = json.Unmarshal([]byte(features), &c.Features)
		out = append(out, c)
	}
	return out, rows.Err()
}

// AutoBlocksToday enforces MaxAutoBlocksPerDay.
func (s *Store) AutoBlocksToday() (int, error) {
	cut := time.Now().Add(-24 * time.Hour).Unix()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM ad_candidates
		WHERE status='blocked' AND decided_by LIKE 'smart%' AND decided_at >= ?`, cut).Scan(&n)
	return n, err
}

// ---------- DHCP ----------

func (s *Store) SaveLease(l Lease) error {
	_, err := s.db.Exec(`INSERT INTO dhcp_leases
		(mac, ip, hostname, scope, starts, expires, static, client_id, vendor_class, fingerprint)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,
			hostname=COALESCE(NULLIF(excluded.hostname,''), dhcp_leases.hostname),
			scope=excluded.scope, starts=excluded.starts, expires=excluded.expires,
			static=excluded.static, client_id=excluded.client_id,
			vendor_class=COALESCE(NULLIF(excluded.vendor_class,''), dhcp_leases.vendor_class),
			fingerprint=COALESCE(NULLIF(excluded.fingerprint,''), dhcp_leases.fingerprint)`,
		l.MAC, l.IP, l.Hostname, l.Scope, l.Starts.Unix(), l.Expires.Unix(), b2i(l.Static),
		nz(l.ClientID), l.VendorClass, l.Fingerprint)
	return err
}

func (s *Store) Leases() ([]Lease, error) {
	rows, err := s.db.Query(`SELECT mac, ip, COALESCE(hostname,''), COALESCE(scope,''), starts, expires,
		static, COALESCE(client_id,''), COALESCE(vendor_class,''), COALESCE(fingerprint,'')
		FROM dhcp_leases ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Lease{}
	for rows.Next() {
		var l Lease
		var starts, expires int64
		var static int
		if err := rows.Scan(&l.MAC, &l.IP, &l.Hostname, &l.Scope, &starts, &expires, &static,
			&l.ClientID, &l.VendorClass, &l.Fingerprint); err != nil {
			return nil, err
		}
		l.Starts = time.Unix(starts, 0)
		l.Expires = time.Unix(expires, 0)
		l.Static = static != 0
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) DeleteLease(mac string) error {
	_, err := s.db.Exec("DELETE FROM dhcp_leases WHERE mac=? AND static=0", mac)
	return err
}

// LeaseForIP supports reverse lookups when only an address is known.
func (s *Store) LeaseForIP(ip string) (*Lease, error) {
	all, err := s.Leases()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].IP == ip {
			return &all[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// ---------- WireGuard ----------

func (s *Store) WGPeers() ([]WGPeer, error) {
	rows, err := s.db.Query(`SELECT id, name, public_key, COALESCE(private_key,''),
		COALESCE(preshared_key,''), address, COALESCE(allowed_ips,'[]'), enabled, COALESCE(dns,'[]'),
		keepalive, last_handshake, rx_bytes, tx_bytes, COALESCE(endpoint,''), created_at, COALESCE(note,'')
		FROM wg_peers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WGPeer{}
	for rows.Next() {
		var p WGPeer
		var allowed, dns string
		var enabled int
		var hs sql.NullInt64
		var created int64
		if err := rows.Scan(&p.ID, &p.Name, &p.PublicKey, &p.PrivateKey, &p.PresharedKey, &p.Address,
			&allowed, &enabled, &dns, &p.Keepalive, &hs, &p.RxBytes, &p.TxBytes, &p.Endpoint,
			&created, &p.Note); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(allowed), &p.AllowedIPs)
		_ = json.Unmarshal([]byte(dns), &p.DNS)
		p.Enabled = enabled != 0
		if hs.Valid && hs.Int64 > 0 {
			t := time.Unix(hs.Int64, 0)
			p.LastHandshake = &t
		}
		p.CreatedAt = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SaveWGPeer(p *WGPeer) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	allowed, _ := json.Marshal(orEmpty(p.AllowedIPs))
	dns, _ := json.Marshal(orEmpty(p.DNS))
	_, err := s.db.Exec(`INSERT INTO wg_peers
		(id, name, public_key, private_key, preshared_key, address, allowed_ips, enabled, dns,
		 keepalive, last_handshake, rx_bytes, tx_bytes, endpoint, created_at, note)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, address=excluded.address,
			allowed_ips=excluded.allowed_ips, enabled=excluded.enabled, dns=excluded.dns,
			keepalive=excluded.keepalive, note=excluded.note`,
		p.ID, p.Name, p.PublicKey, p.PrivateKey, p.PresharedKey, p.Address, string(allowed),
		b2i(p.Enabled), string(dns), p.Keepalive, 0, p.RxBytes, p.TxBytes, p.Endpoint,
		p.CreatedAt.Unix(), p.Note)
	return err
}

// UpdateWGStats writes live handshake/counter data from the kernel.
func (s *Store) UpdateWGStats(pubkey string, handshake time.Time, rx, tx int64, endpoint string) error {
	var hs any
	if !handshake.IsZero() {
		hs = handshake.Unix()
	}
	_, err := s.db.Exec(`UPDATE wg_peers SET last_handshake=?, rx_bytes=?, tx_bytes=?, endpoint=?
		WHERE public_key=?`, hs, rx, tx, endpoint, pubkey)
	return err
}

func (s *Store) DeleteWGPeer(id string) error {
	_, err := s.db.Exec("DELETE FROM wg_peers WHERE id=?", id)
	return err
}

// ---------- chat ----------

func (s *Store) SaveChatMessage(m ChatMessage) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO chat_messages
		(id, conversation, ts, role, content, tool_calls, tool_result, model, tokens_in, tokens_out)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		m.ID, m.Conversation, m.TS.Unix(), m.Role, m.Content, m.ToolCalls, m.ToolResult,
		m.Model, m.TokensIn, m.TokensOut)
	return err
}

func (s *Store) ChatHistory(conversation string, limit int) ([]ChatMessage, error) {
	rows, err := s.db.Query(`SELECT id, conversation, ts, role, content, COALESCE(tool_calls,''),
		COALESCE(tool_result,''), COALESCE(model,''), COALESCE(tokens_in,0), COALESCE(tokens_out,0)
		FROM chat_messages WHERE conversation=? ORDER BY ts DESC LIMIT ?`,
		conversation, clampInt(limit, 1, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChatMessage{}
	for rows.Next() {
		var m ChatMessage
		var ts int64
		if err := rows.Scan(&m.ID, &m.Conversation, &ts, &m.Role, &m.Content, &m.ToolCalls,
			&m.ToolResult, &m.Model, &m.TokensIn, &m.TokensOut); err != nil {
			return nil, err
		}
		m.TS = time.Unix(ts, 0)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Query is DESC so the LIMIT keeps the newest; the caller wants oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (s *Store) Conversations() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT conversation, MAX(ts) last, COUNT(*) n,
		(SELECT content FROM chat_messages m2 WHERE m2.conversation=m.conversation AND m2.role='user'
		 ORDER BY ts ASC LIMIT 1) first_msg
		FROM chat_messages m GROUP BY conversation ORDER BY last DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var conv string
		var last int64
		var n int
		var first sql.NullString
		if err := rows.Scan(&conv, &last, &n, &first); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id": conv, "last": time.Unix(last, 0), "messages": n, "title": first.String,
		})
	}
	return out, rows.Err()
}

func (s *Store) DeleteConversation(id string) error {
	_, err := s.db.Exec("DELETE FROM chat_messages WHERE conversation=?", id)
	return err
}

// ---------- stats ----------

// RecordStat writes a per-minute datapoint, summing repeats in the bucket.
func (s *Store) RecordStat(metric string, value float64, t time.Time) error {
	bucket := t.Truncate(time.Minute).Unix()
	_, err := s.db.Exec(`INSERT INTO stats_minute (bucket, metric, value) VALUES (?,?,?)
		ON CONFLICT(bucket, metric) DO UPDATE SET value = stats_minute.value + excluded.value`,
		bucket, metric, value)
	return err
}

func (s *Store) Series(metric string, since time.Time) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT bucket, value FROM stats_minute
		WHERE metric=? AND bucket >= ? ORDER BY bucket`, metric, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var b int64
		var v float64
		if err := rows.Scan(&b, &v); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"t": b, "v": v})
	}
	return out, rows.Err()
}

// Summary is the dashboard's single round-trip.
func (s *Store) Summary(since time.Time) (map[string]any, error) {
	out := map[string]any{}
	var flows, blocked, bytesIn, bytesOut sql.NullInt64
	err := s.db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END),
		SUM(bytes_in), SUM(bytes_out) FROM flows WHERE started_at >= ?`, since.Unix()).
		Scan(&flows, &blocked, &bytesIn, &bytesOut)
	if err != nil {
		return nil, err
	}
	out["flows"] = flows.Int64
	out["flows_blocked"] = blocked.Int64
	out["bytes_in"] = bytesIn.Int64
	out["bytes_out"] = bytesOut.Int64

	var dnsTotal, dnsBlocked, dnsCached sql.NullInt64
	if err := s.db.QueryRow(`SELECT COUNT(*), SUM(blocked), SUM(cached) FROM dns_queries WHERE ts >= ?`,
		since.Unix()).Scan(&dnsTotal, &dnsBlocked, &dnsCached); err != nil {
		return nil, err
	}
	out["dns_queries"] = dnsTotal.Int64
	out["dns_blocked"] = dnsBlocked.Int64
	out["dns_cached"] = dnsCached.Int64
	if dnsTotal.Int64 > 0 {
		out["block_rate"] = float64(dnsBlocked.Int64) / float64(dnsTotal.Int64)
	} else {
		out["block_rate"] = 0.0
	}

	var clients, online sql.NullInt64
	cutoff := time.Now().Add(-5 * time.Minute).Unix()
	if err := s.db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN last_seen >= ? THEN 1 ELSE 0 END)
		FROM clients`, cutoff).Scan(&clients, &online); err != nil {
		return nil, err
	}
	out["clients"] = clients.Int64
	out["clients_online"] = online.Int64

	var events sql.NullInt64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE acknowledged=0 AND severity IN ('warning','critical')`).Scan(&events)
	out["open_alerts"] = events.Int64

	var candidates sql.NullInt64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM ad_candidates WHERE status IN ('candidate','review')`).Scan(&candidates)
	out["ad_candidates"] = candidates.Int64

	var listEntries sql.NullInt64
	_ = s.db.QueryRow(`SELECT SUM(entries) FROM list_meta WHERE enabled=1`).Scan(&listEntries)
	out["blocklist_entries"] = listEntries.Int64
	return out, nil
}

// TopBlocked lists the domains being blocked most, for the ad-block page.
func (s *Store) TopBlocked(since time.Time, limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT name, COALESCE(block_source,''), COUNT(*) n
		FROM dns_queries WHERE blocked=1 AND ts >= ? GROUP BY name ORDER BY n DESC LIMIT ?`,
		since.Unix(), clampInt(limit, 1, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var name, source string
		var n int64
		if err := rows.Scan(&name, &source, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"domain": name, "source": source, "count": n})
	}
	return out, rows.Err()
}

// DNSLog returns recent queries with optional filters for the live log view.
func (s *Store) DNSLog(since time.Time, clientID string, blockedOnly bool, search string, limit int) ([]DNSQuery, error) {
	q := `SELECT id, ts, COALESCE(client_id,''), client_ip, name, qtype, COALESCE(rcode,''), blocked,
		COALESCE(block_source,''), COALESCE(cname_chain,'[]'), COALESCE(answer,'[]'),
		COALESCE(upstream,''), COALESCE(latency_ms,0), cached FROM dns_queries WHERE ts >= ?`
	args := []any{since.Unix()}
	if clientID != "" {
		q += " AND client_id = ?"
		args = append(args, clientID)
	}
	if blockedOnly {
		q += " AND blocked = 1"
	}
	if search != "" {
		q += " AND name LIKE ?"
		args = append(args, "%"+search+"%")
	}
	q += fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT %d", clampInt(limit, 1, 2000))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSQuery{}
	for rows.Next() {
		var d DNSQuery
		var ts int64
		var blocked, cached int
		var chain, answer string
		if err := rows.Scan(&d.ID, &ts, &d.ClientID, &d.ClientIP, &d.Name, &d.QType, &d.RCode,
			&blocked, &d.BlockSource, &chain, &answer, &d.Upstream, &d.LatencyMS, &cached); err != nil {
			return nil, err
		}
		d.TS = time.Unix(ts, 0)
		d.Blocked = blocked != 0
		d.Cached = cached != 0
		_ = json.Unmarshal([]byte(chain), &d.CNAMEChain)
		_ = json.Unmarshal([]byte(answer), &d.Answer)
		out = append(out, d)
	}
	return out, rows.Err()
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- geo backfill ----

// GeoBackfillTarget is one address that needs (re)locating.
type GeoBackfillTarget struct {
	IP   string
	Rows int
}

// FlowsNeedingGeo lists the destination addresses in stored history that have
// no location, or only a coarse region-level one. Rows written before a GeoIP
// database was installed keep whatever the fallback guessed — often the wrong
// continent — and nothing else would ever correct them.
func (s *Store) FlowsNeedingGeo(limit int) ([]GeoBackfillTarget, error) {
	rows, err := s.db.Query(`
		SELECT dst_ip, COUNT(*) n FROM flows
		WHERE (country IS NULL OR country = '' OR as_org IS NULL OR as_org = '')
		  AND dst_ip NOT LIKE '10.%'
		  AND dst_ip NOT LIKE '192.168.%'
		  AND dst_ip NOT LIKE '172.1_.%'
		  AND dst_ip NOT LIKE '172.2_.%'
		  AND dst_ip NOT LIKE '172.3_.%'
		  AND dst_ip NOT LIKE '127.%'
		  AND dst_ip NOT LIKE '169.254.%'
		  AND dst_ip NOT LIKE '224.%'
		  AND dst_ip NOT LIKE 'fe80:%'
		  AND dst_ip NOT LIKE 'ff0%'
		  AND dst_ip NOT LIKE '::%'
		GROUP BY dst_ip ORDER BY n DESC LIMIT ?`, clampInt(limit, 1, 50000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GeoBackfillTarget{}
	for rows.Next() {
		var t GeoBackfillTarget
		if err := rows.Scan(&t.IP, &t.Rows); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GeoUpdate is a resolved location to write back.
type GeoUpdate struct {
	IP      string
	Country string
	City    string
	Lat     float64
	Lon     float64
	ASN     int
	ASOrg   string
}

// ApplyGeoUpdates writes resolved locations onto every matching flow row.
func (s *Store) ApplyGeoUpdates(updates []GeoUpdate) (int64, error) {
	if len(updates) == 0 {
		return 0, nil
	}
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return 0, err
	}
	defer unlock()
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE flows SET country=?, city=?, lat=?, lon=?, asn=?, as_org=?
		WHERE dst_ip=?`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var total int64
	for _, u := range updates {
		res, err := stmt.Exec(u.Country, u.City, u.Lat, u.Lon, u.ASN, u.ASOrg, u.IP)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// ClearFlowGeo strips the location from the rows named. Used for local flows
// and for bogon destinations that an earlier, coarser fallback placed on a
// continent — an arc from the living room to Asia is worse than no arc.
func (s *Store) ClearFlowGeo(dstIPs []string) (int64, error) {
	tx, unlock, err := s.beginWrite()
	if err != nil {
		return 0, err
	}
	defer unlock()
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE flows SET country='', city='', lat=0, lon=0, asn=0, as_org=''
		WHERE direction = 'local' AND (country != '' OR lat != 0 OR lon != 0)`)
	if err != nil {
		return 0, err
	}
	total, _ := res.RowsAffected()

	if len(dstIPs) > 0 {
		stmt, err := tx.Prepare(`UPDATE flows SET country='', city='', lat=0, lon=0, asn=0, as_org=''
			WHERE dst_ip = ? AND (country != '' OR lat != 0 OR lon != 0 OR city != '')`)
		if err != nil {
			return total, err
		}
		defer stmt.Close()
		for _, ip := range dstIPs {
			r, err := stmt.Exec(ip)
			if err != nil {
				return total, err
			}
			n, _ := r.RowsAffected()
			total += n
		}
	}
	return total, tx.Commit()
}

// AllFlowDestinations lists every distinct destination in history, so the
// backfill can decide which are bogons that should never have a position.
func (s *Store) AllFlowDestinations(limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT dst_ip FROM flows
		WHERE country != '' OR lat != 0 OR lon != 0 OR city != '' LIMIT ?`, clampInt(limit, 1, 100000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// ---------- ask-on-first-connection ----------

// ConsentRule mirrors consent.Rule without importing that package, keeping the
// store free of dependencies on the subsystems that use it.
type ConsentRule struct {
	ClientID  string
	Host      string
	Decision  string
	Scope     string
	DecidedAt time.Time
}

func (s *Store) ConsentRules() ([]ConsentRule, error) {
	rows, err := s.db.Query(`SELECT client_id, host, decision, scope, decided_at FROM consent_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConsentRule
	for rows.Next() {
		var r ConsentRule
		var ts int64
		if err := rows.Scan(&r.ClientID, &r.Host, &r.Decision, &r.Scope, &ts); err != nil {
			return nil, err
		}
		r.DecidedAt = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveConsentRule(r ConsentRule) error {
	_, err := s.db.Exec(`INSERT INTO consent_rules (client_id, host, decision, scope, decided_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(client_id, host, scope) DO UPDATE SET
			decision=excluded.decision, decided_at=excluded.decided_at`,
		r.ClientID, r.Host, r.Decision, r.Scope, r.DecidedAt.Unix())
	return err
}

func (s *Store) DeleteConsentRule(clientID, host, scope string) error {
	_, err := s.db.Exec(`DELETE FROM consent_rules WHERE client_id=? AND host=? AND scope=?`,
		clientID, host, scope)
	return err
}
