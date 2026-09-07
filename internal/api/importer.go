package api

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"gopkg.in/yaml.v3"
)

// Importing from what people already run: a pasted or uploaded list in any
// syntax, a Pi-hole Teleporter backup (v5 or v6), Pi-hole's adlists and
// domain lists, or an AdGuard Home configuration. Everything is previewed
// first: which subscriptions would be added, which rules, and what was
// skipped and why.

type importPreview struct {
	Lists    []config.BlockList `json:"lists"`
	Block    int                `json:"block"`
	Allow    int                `json:"allow"`
	Regex    int                `json:"regex"`
	Total    int                `json:"total"`
	Sample   []string           `json:"sample"`
	Risky    []string           `json:"risky"`
	Skipped  map[string]int     `json:"skipped"`
	Detected string             `json:"detected"`
	Action   string             `json:"action"`
	DryRun   bool               `json:"dry_run"`
	Imported int                `json:"imported"`
	Added    int                `json:"lists_added"`
	Notes    []string           `json:"notes,omitempty"`

	blocks, allows []store.LocalRule
}

func (s *Server) handleImportList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		File     string `json:"file"` // base64
		Filename string `json:"filename"`
		Action   string `json:"action"` // block | allow
		Note     string `json:"note"`
		DryRun   bool   `json:"dry_run"`
		Wildcard bool   `json:"wildcard_all"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	action := req.Action
	if action != "allow" {
		action = "block"
	}
	var data []byte
	if req.File != "" {
		b, err := base64.StdEncoding.DecodeString(req.File)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "file is not valid base64")
			return
		}
		data = b
	} else {
		data = []byte(req.Text)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		writeErr(w, http.StatusBadRequest, "nothing to import")
		return
	}
	if len(data) > 64<<20 {
		writeErr(w, http.StatusBadRequest, "that is over 64 MB; add it as a subscription URL instead")
		return
	}

	pv, err := s.previewImport(data, req.Filename, action, req.Wildcard)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pv.DryRun = req.DryRun
	if pv.Total == 0 && len(pv.Lists) == 0 {
		writeErr(w, http.StatusBadRequest,
			"parsed successfully but found nothing usable. Cosmetic rules, rules with a URL path and modifiers DNS cannot honour are skipped.")
		return
	}
	if req.DryRun {
		writeOK(w, pv)
		return
	}
	if len(pv.Risky) > 0 {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"refusing to import: %v would block an entire top-level domain and take the network offline. Remove those lines and try again.", pv.Risky))
		return
	}

	note := req.Note
	if note == "" {
		note = "imported"
		if pv.Detected != "" {
			note = "imported from " + pv.Detected
		}
	}
	now := time.Now()
	n := 0
	for _, rule := range append(pv.blocks, pv.allows...) {
		rule.Note, rule.CreatedAt, rule.Origin = note, now, "import"
		if err := s.app.Store.SaveLocalRule(rule); err == nil {
			n++
		}
	}
	added := 0
	if len(pv.Lists) > 0 {
		err := s.cfg.Update(func(c *config.Config) {
			for _, l := range pv.Lists {
				dup := false
				for i := range c.AdBlock.Lists {
					if c.AdBlock.Lists[i].URL == l.URL {
						c.AdBlock.Lists[i].Enabled = l.Enabled
						dup = true
						break
					}
				}
				if !dup {
					c.AdBlock.Lists = append(c.AdBlock.Lists, l)
					added++
				}
			}
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "rules imported but the subscriptions could not be saved: "+err.Error())
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if err := s.app.Lists.UpdateAll(ctx, false); err != nil {
				s.app.Log("adblock: refresh after import: %v", err)
			}
		}()
	}
	if n > 0 {
		if err := s.app.Lists.RebuildLocal(); err != nil {
			writeErr(w, http.StatusInternalServerError, "imported but reindex failed: "+err.Error())
			return
		}
	}
	pv.Imported, pv.Added = n, added
	s.app.Store.Audit(r.RemoteAddr, "adblock.import", note, "",
		fmt.Sprintf("%d rule(s), %d subscription(s)", n, added), "ok")
	writeOK(w, pv)
}

// previewImport works out what the bytes are and what they would add.
func (s *Server) previewImport(data []byte, filename, action string, wildcardAll bool) (*importPreview, error) {
	pv := &importPreview{Action: action, Skipped: map[string]int{}}
	name := strings.ToLower(filename)
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		pv.Detected = "Pi-hole Teleporter backup"
		if err := s.importTeleporter(data, pv); err != nil {
			return nil, err
		}
	case bytes.HasPrefix(data, []byte("SQLite format 3")):
		pv.Detected = "Pi-hole gravity database"
		if err := importGravityDB(data, pv); err != nil {
			return nil, err
		}
	case looksLikeAdGuardYAML(data) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
		pv.Detected = "AdGuard Home configuration"
		if err := importAdGuardYAML(data, pv, action); err != nil {
			return nil, err
		}
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) && strings.HasSuffix(name, ".json"),
		bytes.HasPrefix(bytes.TrimSpace(data), []byte("[{")):
		pv.Detected = "Pi-hole export (JSON)"
		if err := importPiholeJSON(name, data, pv, action); err != nil {
			return nil, err
		}
	default:
		pv.Detected = "list"
		importText(data, pv, action, wildcardAll, adblock.ParseOptions{Format: formatFromName(name)})
	}
	pv.finish()
	return pv, nil
}

func formatFromName(name string) string {
	if strings.Contains(name, "regex") {
		return "regex"
	}
	return ""
}

func looksLikeAdGuardYAML(data []byte) bool {
	head := data
	if len(head) > 64<<10 {
		head = head[:64<<10]
	}
	s := string(head)
	return strings.Contains(s, "\nfilters:") || strings.Contains(s, "\nuser_rules:") || strings.Contains(s, "\nwhitelist_filters:") ||
		strings.HasPrefix(s, "filters:") || strings.Contains(s, "\nfiltering:")
}

// importText handles a pasted list: URLs become subscriptions, everything
// else is parsed as rules.
func importText(data []byte, pv *importPreview, action string, wildcardAll bool, opt adblock.ParseOptions) {
	var rules []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			if strings.Contains(t, " ") && !strings.Contains(t, "?") {
				rules = append(rules, line)
				continue
			}
			pv.addList(t, "", true)
			continue
		}
		rules = append(rules, line)
	}
	opt.Allow = action == "allow"
	e, err := adblock.Parse(strings.NewReader(strings.Join(rules, "\n")), opt)
	if err != nil {
		return
	}
	pv.addEntries(e, wildcardAll)
}

func (pv *importPreview) addList(url, name string, enabled bool) {
	for _, l := range pv.Lists {
		if l.URL == url {
			return
		}
	}
	// Pi-hole comments are often "Migrated from /etc/pihole/adlists.list";
	// a name from the URL reads better than that.
	if name == "" || strings.HasPrefix(strings.ToLower(name), "migrated") || len(name) < 4 || strings.Contains(name, "/") {
		name = listNameFromURL(url)
	}
	category := "ads"
	lu := strings.ToLower(url + " " + name)
	switch {
	case strings.Contains(lu, "malware"), strings.Contains(lu, "phish"), strings.Contains(lu, "tif"), strings.Contains(lu, "threat"), strings.Contains(lu, "urlhaus"), strings.Contains(lu, "crypto"):
		category = "malware"
	case strings.Contains(lu, "track"), strings.Contains(lu, "telemetry"), strings.Contains(lu, "privacy"), strings.Contains(lu, "spy"):
		category = "tracking"
	case strings.Contains(lu, "nsfw"), strings.Contains(lu, "porn"), strings.Contains(lu, "adult"):
		category = "adult"
	}
	pv.Lists = append(pv.Lists, config.BlockList{Name: name, URL: url, Category: category, Enabled: enabled})
}

func listNameFromURL(url string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	u = strings.TrimSuffix(u, "/")
	parts := strings.Split(u, "/")
	host := parts[0]
	host = strings.TrimPrefix(host, "raw.githubusercontent.com")
	last := parts[len(parts)-1]
	if i := strings.Index(last, "?"); i >= 0 {
		last = last[:i]
	}
	last = strings.TrimSuffix(strings.TrimSuffix(last, ".txt"), ".list")
	switch {
	case host == "" && len(parts) >= 3:
		// raw.githubusercontent.com/owner/repo/branch/path: owner/repo, plus the
		// file when it says more than the repo does.
		if last == "" || last == "hosts" || strings.EqualFold(last, parts[2]) {
			return parts[1] + "/" + parts[2]
		}
		return parts[1] + "/" + parts[2] + " " + last
	case last == "" || last == "hosts" || len(parts) == 1:
		return parts[0]
	}
	return parts[0] + " " + last
}

func (pv *importPreview) addEntries(e *adblock.Entries, wildcardAll bool) {
	for _, d := range e.Exact {
		pv.blocks = append(pv.blocks, store.LocalRule{Domain: d, Action: "block", Wildcard: wildcardAll})
	}
	for _, d := range e.Wildcard {
		pv.blocks = append(pv.blocks, store.LocalRule{Domain: d, Action: "block", Wildcard: true})
	}
	for _, p := range e.Regex {
		pv.blocks = append(pv.blocks, store.LocalRule{Domain: p, Action: "block", Regex: true})
	}
	for _, d := range e.AllowExact {
		pv.allows = append(pv.allows, store.LocalRule{Domain: d, Action: "allow"})
	}
	for _, d := range e.AllowWildcard {
		pv.allows = append(pv.allows, store.LocalRule{Domain: d, Action: "allow", Wildcard: true})
	}
	for _, p := range e.AllowRegex {
		pv.allows = append(pv.allows, store.LocalRule{Domain: p, Action: "allow", Regex: true})
	}
	for k, v := range e.Skipped {
		pv.Skipped[k] += v
	}
}

func (pv *importPreview) finish() {
	seen := map[string]bool{}
	dedupe := func(in []store.LocalRule) []store.LocalRule {
		out := in[:0]
		for _, r := range in {
			k := r.Action + ":" + r.Domain
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, r)
		}
		return out
	}
	pv.blocks = dedupe(pv.blocks)
	pv.allows = dedupe(pv.allows)
	for _, r := range pv.blocks {
		if r.Regex {
			pv.Regex++
		} else {
			pv.Block++
		}
		if r.Wildcard && !r.Regex && !strings.Contains(r.Domain, ".") {
			pv.Risky = append(pv.Risky, "*."+r.Domain)
		}
	}
	for _, r := range pv.allows {
		if r.Regex {
			pv.Regex++
		} else {
			pv.Allow++
		}
	}
	pv.Total = len(pv.blocks) + len(pv.allows)
	for _, r := range pv.blocks {
		if len(pv.Sample) >= 8 {
			break
		}
		pv.Sample = append(pv.Sample, ruleLabel(r))
	}
	for _, r := range pv.allows {
		if len(pv.Sample) >= 12 {
			break
		}
		pv.Sample = append(pv.Sample, "allow "+ruleLabel(r))
	}
	sort.Strings(pv.Sample)
	if pv.Lists == nil {
		pv.Lists = []config.BlockList{}
	}
	if pv.Sample == nil {
		pv.Sample = []string{}
	}
	if pv.Risky == nil {
		pv.Risky = []string{}
	}
}

func ruleLabel(r store.LocalRule) string {
	switch {
	case r.Regex:
		return "/" + r.Domain + "/"
	case r.Wildcard:
		return "*." + r.Domain
	}
	return r.Domain
}

// importTeleporter reads a Pi-hole backup: v5 ships JSON and text files, v6
// ships the gravity database and pihole.toml.
func (s *Server) importTeleporter(data []byte, pv *importPreview) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("not a readable zip: %w", err)
	}
	found := 0
	for _, f := range zr.File {
		base := strings.ToLower(filepath.Base(f.Name))
		if f.UncompressedSize64 > 256<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			continue
		}
		switch {
		case base == "gravity.db":
			if err := importGravityDB(body, pv); err != nil {
				pv.Notes = append(pv.Notes, "gravity.db: "+err.Error())
			} else {
				found++
			}
		case strings.HasSuffix(base, ".json"):
			if err := importPiholeJSON(base, body, pv, "block"); err == nil {
				found++
			}
		case base == "adlists.list", base == "adlist.list":
			importText(body, pv, "block", false, adblock.ParseOptions{})
			found++
		case base == "blacklist.txt", base == "black.list":
			importText(body, pv, "block", false, adblock.ParseOptions{})
			found++
		case base == "whitelist.txt", base == "white.list":
			importText(body, pv, "allow", false, adblock.ParseOptions{})
			found++
		case base == "regex.list", base == "regex.txt":
			importText(body, pv, "block", false, adblock.ParseOptions{Format: "regex"})
			found++
		case base == "custom.list", base == "05-pihole-custom-cname.conf", base == "dhcp.leases", base == "pihole.toml", base == "setupvars.conf":
			pv.Notes = append(pv.Notes, base+" holds local DNS records, leases or settings; those are not blocklist data and were left alone")
		}
	}
	if found == 0 {
		return fmt.Errorf("the backup held no adlists, domain lists or gravity database")
	}
	return nil
}

// importPiholeJSON reads the v5 Teleporter JSON files by name and shape.
func importPiholeJSON(name string, data []byte, pv *importPreview, action string) error {
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return err
	}
	lname := strings.ToLower(name)
	for _, row := range rows {
		enabled := true
		if v, ok := row["enabled"].(float64); ok {
			enabled = v != 0
		} else if v, ok := row["enabled"].(bool); ok {
			enabled = v
		}
		if addr, ok := row["address"].(string); ok && strings.HasPrefix(addr, "http") {
			comment, _ := row["comment"].(string)
			pv.addList(addr, comment, enabled)
			continue
		}
		domain, _ := row["domain"].(string)
		if domain == "" {
			continue
		}
		if !enabled {
			continue
		}
		// domainlist.json carries a type: 0 exact allow, 1 exact deny, 2 regex allow, 3 regex deny.
		kind := -1
		if v, ok := row["type"].(float64); ok {
			kind = int(v)
		}
		switch {
		case kind == 0, kind < 0 && strings.Contains(lname, "whitelist") && !strings.Contains(lname, "regex"):
			pv.allows = append(pv.allows, store.LocalRule{Domain: domain, Action: "allow"})
		case kind == 1, kind < 0 && strings.Contains(lname, "blacklist") && !strings.Contains(lname, "regex"):
			pv.blocks = append(pv.blocks, store.LocalRule{Domain: domain, Action: "block"})
		case kind == 2, kind < 0 && strings.Contains(lname, "whitelist"):
			pv.allows = append(pv.allows, store.LocalRule{Domain: domain, Action: "allow", Regex: true})
		case kind == 3, kind < 0 && strings.Contains(lname, "blacklist"), kind < 0 && strings.Contains(lname, "regex"):
			pv.blocks = append(pv.blocks, store.LocalRule{Domain: domain, Action: "block", Regex: true})
		default:
			if action == "allow" {
				pv.allows = append(pv.allows, store.LocalRule{Domain: domain, Action: "allow"})
			} else {
				pv.blocks = append(pv.blocks, store.LocalRule{Domain: domain, Action: "block"})
			}
		}
	}
	return nil
}

// importGravityDB opens a Pi-hole gravity database and reads its adlists and
// domain lists. It never touches the gravity table itself: those entries
// come back through the subscriptions.
func importGravityDB(data []byte, pv *importPreview) error {
	tmp, err := os.CreateTemp("", "orbis-gravity-*.db")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	db, err := sql.Open("sqlite", "file:"+tmp.Name()+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query("SELECT address, enabled, COALESCE(comment,'') FROM adlist")
	if err != nil {
		return fmt.Errorf("no adlist table: %w", err)
	}
	for rows.Next() {
		var addr, comment string
		var enabled int
		if err := rows.Scan(&addr, &enabled, &comment); err == nil && strings.HasPrefix(addr, "http") {
			pv.addList(addr, comment, enabled != 0)
		}
	}
	rows.Close()
	rows, err = db.Query("SELECT type, domain FROM domainlist WHERE enabled=1")
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var kind int
		var domain string
		if err := rows.Scan(&kind, &domain); err != nil {
			continue
		}
		switch kind {
		case 0:
			pv.allows = append(pv.allows, store.LocalRule{Domain: domain, Action: "allow"})
		case 1:
			pv.blocks = append(pv.blocks, store.LocalRule{Domain: domain, Action: "block"})
		case 2:
			pv.allows = append(pv.allows, store.LocalRule{Domain: domain, Action: "allow", Regex: true})
		case 3:
			pv.blocks = append(pv.blocks, store.LocalRule{Domain: domain, Action: "block", Regex: true})
		}
	}
	return nil
}

// importAdGuardYAML reads AdGuardHome.yaml: filters, whitelist_filters and
// user_rules. Rewrites and clients are settings, not lists, and are noted.
func importAdGuardYAML(data []byte, pv *importPreview, action string) error {
	var doc struct {
		Filters []struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Name    string `yaml:"name"`
		} `yaml:"filters"`
		WhitelistFilters []struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Name    string `yaml:"name"`
		} `yaml:"whitelist_filters"`
		UserRules []string `yaml:"user_rules"`
		Filtering struct {
			Rewrites []any `yaml:"rewrites"`
		} `yaml:"filtering"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("not a readable AdGuard Home configuration: %w", err)
	}
	for _, f := range doc.Filters {
		if strings.HasPrefix(f.URL, "http") {
			pv.addList(f.URL, f.Name, f.Enabled)
		}
	}
	for _, f := range doc.WhitelistFilters {
		if strings.HasPrefix(f.URL, "http") {
			pv.addList(f.URL, f.Name, f.Enabled)
			pv.Lists[len(pv.Lists)-1].Action = "allow"
		}
	}
	if len(doc.UserRules) > 0 {
		e, err := adblock.Parse(strings.NewReader(strings.Join(doc.UserRules, "\n")), adblock.ParseOptions{Allow: action == "allow"})
		if err == nil {
			pv.addEntries(e, false)
		}
	}
	if len(doc.Filtering.Rewrites) > 0 {
		pv.Notes = append(pv.Notes, fmt.Sprintf("%d DNS rewrite(s) were left alone; add them as local records on the DNS page", len(doc.Filtering.Rewrites)))
	}
	if len(pv.Lists) == 0 && len(doc.UserRules) == 0 {
		return fmt.Errorf("the configuration holds no filters or custom rules")
	}
	return nil
}
