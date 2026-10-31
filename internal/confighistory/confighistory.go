// Package confighistory versions saved YAML configurations on disk, redacts
// secrets on every read or diff, and restores prior versions with optional
// commit-confirm rollback.
package confighistory

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	// RedactedPlaceholder replaces any secret scalar or subtree in Get and Diff.
	RedactedPlaceholder = "(hidden)"

	maxHistoryFiles  = 200
	diffContextLines = 3
	maxDiffLines     = 2000
	maxLCSCells      = 400_000
	maxFallbackLines = 200
)

var (
	ErrNotFound         = errors.New("history version not found")
	ErrPendingRestore   = errors.New("another restore is waiting for confirmation")
	ErrNoPendingRestore = errors.New("no restore is waiting for confirmation")
)

// Entry describes one archived configuration version on disk.
type Entry struct {
	ID             string    `json:"id"`
	Time           time.Time `json:"time"`
	Size           int64     `json:"size"`
	Summary        string    `json:"summary"`
	Keys           []string  `json:"keys"`
	TouchesNetwork bool      `json:"touches_network"`
}

// PendingStatus reports an active commit-confirm timer, if any.
type PendingStatus struct {
	Pending          bool       `json:"pending"`
	ID               string     `json:"id,omitempty"`
	RevertToID       string     `json:"revert_to_id,omitempty"`
	Summary          string     `json:"summary,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RemainingSeconds int        `json:"remaining_seconds"`
}

// RestoreResult describes a completed restore operation.
type RestoreResult struct {
	RestoredID string        `json:"restored_id"`
	BackupID   string        `json:"backup_id"`
	Keys       []string      `json:"keys"`
	Summary    string        `json:"summary"`
	Pending    PendingStatus `json:"pending"`
}

// Hooks connects config restoration to the live subsystems and audit log.
type Hooks struct {
	// OnApply nudges subsystems affected by the changed dotted keys, matching
	// the reload path used by PATCH /config.
	OnApply func(keys []string)
	// OnAutoRevert runs after an unconfirmed restore automatically reverts.
	OnAutoRevert func(restoredID, revertToID string, err error)
}

type pendingRestore struct {
	token      uint64
	restoredID string
	revertToID string
	summary    string
	startedAt  time.Time
	expiresAt  time.Time
	preBytes   []byte
	timer      *time.Timer
}

// Manager reads, compares and restores archived configuration snapshots.
type Manager struct {
	dir   string
	cfg   *config.Config
	hooks Hooks

	mu          sync.Mutex
	nextToken   uint64
	pending     *pendingRestore
	confirmUnit time.Duration
}

// New creates a configuration history manager backed by dir.
func New(dir string, cfg *config.Config, hooks Hooks) *Manager {
	return &Manager{
		dir:         dir,
		cfg:         cfg,
		hooks:       hooks,
		confirmUnit: time.Second,
	}
}

// SetConfirmUnit overrides the duration unit multiplied by confirm_seconds on
// HTTP restore requests. Production leaves it at time.Second; tests inject a
// few milliseconds so commit-confirm timers run quickly.
func (m *Manager) SetConfirmUnit(d time.Duration) {
	if d <= 0 {
		return
	}
	m.mu.Lock()
	m.confirmUnit = d
	m.mu.Unlock()
}

// ConfirmUnit returns the duration of one confirm_seconds unit.
func (m *Manager) ConfirmUnit() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.confirmUnit <= 0 {
		return time.Second
	}
	return m.confirmUnit
}

// Stop cancels any active commit-confirm timer on daemon shutdown.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.pending != nil && m.pending.timer != nil {
		m.pending.timer.Stop()
	}
	m.pending = nil
	m.mu.Unlock()
}

type diskVersion struct {
	id   string
	ts   int64
	size int64
	path string
}

func (m *Manager) scanVersions() ([]diskVersion, error) {
	if m.dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	versions := make([]diskVersion, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ".yaml")
		ts, err := strconv.ParseInt(stem, 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		versions = append(versions, diskVersion{
			id:   stem,
			ts:   ts,
			size: info.Size(),
			path: filepath.Join(m.dir, e.Name()),
		})
	}
	// Newest first.
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ts > versions[j].ts
	})
	return versions, nil
}

func (m *Manager) currentBytes() ([]byte, error) {
	if m.cfg == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	if p := m.cfg.Path(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	snap := m.cfg.Snapshot()
	return yaml.Marshal(&snap)
}

func parseVersionID(id string) (int64, error) {
	if id == "" {
		return 0, ErrNotFound
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return 0, ErrNotFound
		}
	}
	ts, err := strconv.ParseInt(id, 10, 64)
	if err != nil || ts <= 0 {
		return 0, ErrNotFound
	}
	return ts, nil
}

func (m *Manager) versionPath(id string) (string, error) {
	ts, err := parseVersionID(id)
	if err != nil {
		return "", err
	}
	if m.dir == "" {
		return "", ErrNotFound
	}
	canonical := strconv.FormatInt(ts, 10)
	if canonical != id {
		return "", ErrNotFound
	}
	p := filepath.Join(m.dir, canonical+".yaml")
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return "", ErrNotFound
	}
	return p, nil
}

// List returns archived configuration versions, newest first, with a one-line
// summary of which top-level and second-level YAML keys changed between each
// version and the next newer one.
func (m *Manager) List() ([]Entry, error) {
	versions, err := m.scanVersions()
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return []Entry{}, nil
	}

	newerBytes, err := m.currentBytes()
	if err != nil {
		return nil, err
	}

	rawByIdx := make([][]byte, len(versions))
	for i, v := range versions {
		b, err := os.ReadFile(v.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		rawByIdx[i] = b
	}

	out := make([]Entry, 0, len(versions))
	nextNewer := newerBytes
	for i, v := range versions {
		older := rawByIdx[i]
		if older == nil {
			continue
		}
		keys := ChangedKeys(older, nextNewer)
		if keys == nil {
			keys = []string{}
		}
		out = append(out, Entry{
			ID:             v.id,
			Time:           time.Unix(0, v.ts).UTC(),
			Size:           v.size,
			Summary:        SummarizeKeys(keys),
			Keys:           keys,
			TouchesNetwork: TouchesNetwork(keys),
		})
		nextNewer = older
	}
	return out, nil
}

// Get returns the YAML for version id with every secret key redacted.
func (m *Manager) Get(id string) (string, error) {
	p, err := m.versionPath(id)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	redacted, err := RedactYAML(raw)
	if err != nil {
		return "", err
	}
	return string(redacted), nil
}

// Diff returns a unified line diff between version id and the next newer
// version, with secrets redacted in both inputs before comparison.
func (m *Manager) Diff(id string) (string, error) {
	if _, err := parseVersionID(id); err != nil {
		return "", err
	}
	versions, err := m.scanVersions()
	if err != nil {
		return "", err
	}
	idx := -1
	for i, v := range versions {
		if v.id == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", ErrNotFound
	}

	olderRaw, err := os.ReadFile(versions[idx].path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}

	var newerRaw []byte
	newerLabel := "current"
	if idx == 0 {
		newerRaw, err = m.currentBytes()
		if err != nil {
			return "", err
		}
	} else {
		newerLabel = versions[idx-1].id
		newerRaw, err = os.ReadFile(versions[idx-1].path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", ErrNotFound
			}
			return "", err
		}
	}

	olderRedacted, err := RedactYAML(olderRaw)
	if err != nil {
		return "", err
	}
	newerRedacted, err := RedactYAML(newerRaw)
	if err != nil {
		return "", err
	}

	return UnifiedDiff(id, newerLabel, olderRedacted, newerRedacted), nil
}

// Restore validates version id with the same checks Config.Update runs, saves
// the current configuration into history so the restore is itself undoable,
// and applies the unredacted version through Config.Update. When confirmFor > 0,
// a timer automatically reverts to the pre-restore configuration unless Confirm
// is called before it expires.
func (m *Manager) Restore(id string, confirmFor time.Duration) (*RestoreResult, error) {
	if confirmFor < 0 {
		return nil, fmt.Errorf("confirm duration must not be negative")
	}
	p, err := m.versionPath(id)
	if err != nil {
		return nil, err
	}
	targetBytes, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	candidate, err := decodeAndValidate(targetBytes)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if m.pending != nil {
		m.mu.Unlock()
		return nil, ErrPendingRestore
	}

	preBytes, err := m.currentBytes()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}

	backupID, err := writeHistorySnapshot(m.dir, preBytes)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("archive current configuration: %w", err)
	}

	keys := ChangedKeys(preBytes, targetBytes)
	if keys == nil {
		keys = []string{}
	}
	summary := SummarizeKeys(keys)

	if err := m.cfg.Update(func(c *config.Config) {
		c.ApplyValues(candidate)
	}); err != nil {
		_ = os.Remove(filepath.Join(m.dir, backupID+".yaml"))
		m.mu.Unlock()
		return nil, err
	}

	var status PendingStatus
	if confirmFor > 0 {
		m.nextToken++
		tok := m.nextToken
		now := time.Now().UTC()
		exp := now.Add(confirmFor)
		pend := &pendingRestore{
			token:      tok,
			restoredID: id,
			revertToID: backupID,
			summary:    summary,
			startedAt:  now,
			expiresAt:  exp,
			preBytes:   preBytes,
		}
		pend.timer = time.AfterFunc(confirmFor, func() {
			m.expirePending(tok)
		})
		m.pending = pend
		status = pendingStatusLocked(pend, now)
	}
	m.mu.Unlock()

	m.notifyApply(keys)

	return &RestoreResult{
		RestoredID: id,
		BackupID:   backupID,
		Keys:       keys,
		Summary:    summary,
		Pending:    status,
	}, nil
}

// Confirm cancels an active commit-confirm timer and keeps the restored version.
func (m *Manager) Confirm() (string, error) {
	m.mu.Lock()
	if m.pending == nil {
		m.mu.Unlock()
		return "", ErrNoPendingRestore
	}
	if m.pending.timer != nil {
		m.pending.timer.Stop()
	}
	restoredID := m.pending.restoredID
	m.pending = nil
	m.mu.Unlock()
	return restoredID, nil
}

// Revert immediately cancels an active commit-confirm timer and restores the
// pre-restore configuration without waiting for the countdown to finish.
func (m *Manager) Revert() (string, error) {
	m.mu.Lock()
	if m.pending == nil {
		m.mu.Unlock()
		return "", ErrNoPendingRestore
	}
	if m.pending.timer != nil {
		m.pending.timer.Stop()
	}
	pend := m.pending
	m.pending = nil
	revertKeys, err := m.applyPreBytesLocked(pend.preBytes)
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	m.notifyApply(revertKeys)
	return pend.revertToID, nil
}

func (m *Manager) expirePending(token uint64) {
	m.mu.Lock()
	if m.pending == nil || m.pending.token != token {
		m.mu.Unlock()
		return
	}
	pend := m.pending
	m.pending = nil
	revertKeys, err := m.applyPreBytesLocked(pend.preBytes)
	m.mu.Unlock()

	if err == nil {
		m.notifyApply(revertKeys)
	}
	if m.hooks.OnAutoRevert != nil {
		m.hooks.OnAutoRevert(pend.restoredID, pend.revertToID, err)
	}
}

func (m *Manager) applyPreBytesLocked(preBytes []byte) ([]string, error) {
	preCfg, err := decodeAndValidate(preBytes)
	if err != nil {
		return nil, err
	}
	curBytes, _ := m.currentBytes()
	keys := ChangedKeys(curBytes, preBytes)
	if err := m.cfg.Update(func(c *config.Config) {
		c.ApplyValues(preCfg)
	}); err != nil {
		return nil, err
	}
	return keys, nil
}

// Pending reports whether a commit-confirm restore is currently waiting for
// confirmation and how many seconds remain before automatic rollback.
func (m *Manager) Pending() PendingStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return pendingStatusLocked(m.pending, time.Now().UTC())
}

func pendingStatusLocked(p *pendingRestore, now time.Time) PendingStatus {
	if p == nil {
		return PendingStatus{Pending: false}
	}
	rem := p.expiresAt.Sub(now)
	secs := 0
	if rem > 0 {
		secs = int(math.Ceil(rem.Seconds()))
	}
	started := p.startedAt
	expires := p.expiresAt
	return PendingStatus{
		Pending:          true,
		ID:               p.restoredID,
		RevertToID:       p.revertToID,
		Summary:          p.summary,
		StartedAt:        &started,
		ExpiresAt:        &expires,
		RemainingSeconds: secs,
	}
}

func (m *Manager) notifyApply(keys []string) {
	if m.hooks.OnApply != nil && len(keys) > 0 {
		m.hooks.OnApply(keys)
	}
}

func decodeAndValidate(raw []byte) (*config.Config, error) {
	c := config.Default()
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := c.ValidateUpdate(); err != nil {
		return nil, err
	}
	return c, nil
}

func writeHistorySnapshot(dir string, content []byte) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("history directory is not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	existing := listSortedTimestamps(dir)
	ts := time.Now().UnixNano()
	if len(existing) > 0 && ts <= existing[len(existing)-1] {
		ts = existing[len(existing)-1] + 1
	}
	id := strconv.FormatInt(ts, 10)
	dst := filepath.Join(dir, id+".yaml")
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return "", err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	existing = append(existing, ts)
	if len(existing) > maxHistoryFiles {
		for _, old := range existing[:len(existing)-maxHistoryFiles] {
			_ = os.Remove(filepath.Join(dir, strconv.FormatInt(old, 10)+".yaml"))
		}
	}
	return id, nil
}

func listSortedTimestamps(dir string) []int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]int64, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), ".yaml")
		if ts, err := strconv.ParseInt(stem, 10, 64); err == nil && ts > 0 {
			out = append(out, ts)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---- Shared secret redaction ----

var secretKeyTokens = []string{
	"key",
	"token",
	"secret",
	"password",
	"hash",
	"psk",
	"passphrase",
}

// IsSecretKey reports whether a YAML key name holds sensitive material that
// must never cross the API read boundary.
func IsSecretKey(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, tok := range secretKeyTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// RedactYAML parses raw YAML and replaces the value of every key matching
// IsSecretKey at any nesting depth with "(hidden)". It never returns raw bytes
// on parse failure.
func RedactYAML(raw []byte) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte{}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML for redaction: %w", err)
	}
	redactNode(&doc)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		_ = enc.Close()
		return nil, fmt.Errorf("encode redacted YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close redacted YAML encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func redactNode(n *yaml.Node) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			redactNode(child)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			kNode := n.Content[i]
			vNode := n.Content[i+1]
			if IsSecretKey(kNode.Value) {
				kNode.HeadComment = ""
				kNode.LineComment = ""
				kNode.FootComment = ""
				// Mutate vNode in place as well so any YAML alias pointing at
				// this node also sees the redacted placeholder.
				*vNode = yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: RedactedPlaceholder,
				}
			} else {
				redactNode(vNode)
			}
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			redactNode(item)
		}
	case yaml.AliasNode:
		if n.Alias != nil {
			redactNode(n.Alias)
		}
	}
}

// ---- Key-level change summary ----

// ChangedKeys returns the top-level and second-level YAML keys that differ
// between older and newer, preserving document order. Only key names are
// returned, never values.
func ChangedKeys(older, newer []byte) []string {
	oldMap := parseMappingRoot(older)
	newMap := parseMappingRoot(newer)
	if oldMap == nil && newMap == nil {
		return []string{}
	}

	topOrder, oldTop, newTop := mergeMappingPairs(oldMap, newMap)
	var changed []string
	for _, k := range topOrder {
		if IsSecretKey(k) {
			if !yamlNodeEqual(oldTop[k], newTop[k]) {
				changed = append(changed, k)
			}
			continue
		}
		ov, nv := unwrapAlias(oldTop[k]), unwrapAlias(newTop[k])
		if isMappingOrNil(ov) && isMappingOrNil(nv) && (ov != nil && ov.Kind == yaml.MappingNode || nv != nil && nv.Kind == yaml.MappingNode) {
			subOrder, oldSub, newSub := mergeMappingPairs(ov, nv)
			for _, sub := range subOrder {
				if !yamlNodeEqual(oldSub[sub], newSub[sub]) {
					changed = append(changed, k+"."+sub)
				}
			}
			continue
		}
		if !yamlNodeEqual(ov, nv) {
			changed = append(changed, k)
		}
	}
	if changed == nil {
		return []string{}
	}
	return changed
}

// SummarizeKeys formats changed keys into a single concise line.
func SummarizeKeys(keys []string) string {
	if len(keys) == 0 {
		return "no field changes"
	}
	const maxShown = 5
	if len(keys) <= maxShown {
		return strings.Join(keys, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(keys[:maxShown], ", "), len(keys)-maxShown)
}

// TouchesNetwork reports whether any of the changed keys affects connectivity,
// routing, firewalling, Wi-Fi, VPNs, DHCP, DNS listeners or API listeners,
// where an unconfirmed mistake could lock the operator out.
func TouchesNetwork(keys []string) bool {
	for _, k := range keys {
		switch {
		case k == "mode",
			k == "network" || strings.HasPrefix(k, "network."),
			k == "firewall" || strings.HasPrefix(k, "firewall."),
			k == "dhcp" || strings.HasPrefix(k, "dhcp."),
			k == "vpn" || strings.HasPrefix(k, "vpn."),
			k == "tailscale" || strings.HasPrefix(k, "tailscale."),
			k == "wifi" || strings.HasPrefix(k, "wifi."),
			k == "country" || strings.HasPrefix(k, "country."),
			k == "dns.listen", k == "dns.upstreams", k == "dns.encrypted",
			k == "api.listen", k == "api.tls_cert", k == "api.tls_key":
			return true
		}
	}
	return false
}

func parseMappingRoot(raw []byte) *yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	root = unwrapAlias(root)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

func unwrapAlias(n *yaml.Node) *yaml.Node {
	for seen := 0; n != nil && n.Kind == yaml.AliasNode && seen < 8; seen++ {
		n = n.Alias
	}
	return n
}

func isMappingOrNil(n *yaml.Node) bool {
	return n == nil || n.Kind == yaml.MappingNode || (n.Kind == yaml.ScalarNode && n.Tag == "!!null")
}

func mergeMappingPairs(a, b *yaml.Node) ([]string, map[string]*yaml.Node, map[string]*yaml.Node) {
	aMap := make(map[string]*yaml.Node)
	bMap := make(map[string]*yaml.Node)
	seen := make(map[string]bool)
	var order []string

	addFrom := func(m *yaml.Node, dst map[string]*yaml.Node) {
		if m == nil || m.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			k := m.Content[i].Value
			dst[k] = m.Content[i+1]
			if !seen[k] {
				seen[k] = true
				order = append(order, k)
			}
		}
	}
	// Prefer newer order first so newly added sections appear naturally,
	// while existing sections keep config struct order.
	addFrom(b, bMap)
	addFrom(a, aMap)
	return order, aMap, bMap
}

func yamlNodeEqual(a, b *yaml.Node) bool {
	a = unwrapAlias(a)
	b = unwrapAlias(b)
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return isEmptyCollectionOrNull(a) && isEmptyCollectionOrNull(b)
	}
	if a.Kind != b.Kind {
		return isEmptyCollectionOrNull(a) && isEmptyCollectionOrNull(b)
	}
	switch a.Kind {
	case yaml.ScalarNode:
		return a.Tag == b.Tag && a.Value == b.Value
	case yaml.SequenceNode:
		if len(a.Content) != len(b.Content) {
			return false
		}
		for i := range a.Content {
			if !yamlNodeEqual(a.Content[i], b.Content[i]) {
				return false
			}
		}
		return true
	case yaml.MappingNode:
		order, am, bm := mergeMappingPairs(a, b)
		if len(am) != len(bm) {
			// Check whether missing keys are merely empty/null.
			for _, k := range order {
				if !yamlNodeEqual(am[k], bm[k]) {
					return false
				}
			}
			return true
		}
		for _, k := range order {
			if !yamlNodeEqual(am[k], bm[k]) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func isEmptyCollectionOrNull(n *yaml.Node) bool {
	if n == nil {
		return true
	}
	if n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Value == "") {
		return false
	}
	if (n.Kind == yaml.SequenceNode || n.Kind == yaml.MappingNode) && len(n.Content) == 0 {
		return true
	}
	return false
}

// ---- Pure Go LCS unified diff ----

type editKind uint8

const (
	opEqual editKind = iota
	opDelete
	opInsert
)

type editOp struct {
	kind editKind
	text string
	oldN int // 1-based line number in old, when applicable
	newN int // 1-based line number in new, when applicable
}

// UnifiedDiff computes a unified diff with 3 lines of context between two
// byte slices. Huge inputs fall back to a capped linear hunk so a request
// cannot stall CPU or exhaust memory on a small board.
func UnifiedDiff(oldLabel, newLabel string, oldBytes, newBytes []byte) string {
	aLines := splitLines(string(oldBytes))
	bLines := splitLines(string(newBytes))

	prefix := 0
	for prefix < len(aLines) && prefix < len(bLines) && aLines[prefix] == bLines[prefix] {
		prefix++
	}
	if prefix == len(aLines) && prefix == len(bLines) {
		return ""
	}

	suffix := 0
	for suffix < len(aLines)-prefix && suffix < len(bLines)-prefix &&
		aLines[len(aLines)-1-suffix] == bLines[len(bLines)-1-suffix] {
		suffix++
	}

	aMid := aLines[prefix : len(aLines)-suffix]
	bMid := bLines[prefix : len(bLines)-suffix]

	if len(aMid) > maxDiffLines || len(bMid) > maxDiffLines || int64(len(aMid))*int64(len(bMid)) > maxLCSCells {
		return fallbackUnifiedDiff(oldLabel, newLabel, aLines, bLines, prefix, suffix)
	}

	midOps := computeLCSOps(aMid, bMid, prefix+1, prefix+1)

	// Attach only the context window around the middle region rather than
	// materialising thousands of equal prefix/suffix ops.
	leadStart := prefix - diffContextLines
	if leadStart < 0 {
		leadStart = 0
	}
	tailEnd := len(aLines) - suffix + diffContextLines
	if tailEnd > len(aLines) {
		tailEnd = len(aLines)
	}

	ops := make([]editOp, 0, (prefix-leadStart)+len(midOps)+(tailEnd-(len(aLines)-suffix)))
	for i := leadStart; i < prefix; i++ {
		ops = append(ops, editOp{
			kind: opEqual,
			text: aLines[i],
			oldN: i + 1,
			newN: i + 1,
		})
	}
	ops = append(ops, midOps...)
	newTailBase := len(bLines) - suffix
	oldTailBase := len(aLines) - suffix
	for i := 0; i < tailEnd-oldTailBase; i++ {
		ops = append(ops, editOp{
			kind: opEqual,
			text: aLines[oldTailBase+i],
			oldN: oldTailBase + i + 1,
			newN: newTailBase + i + 1,
		})
	}

	return formatUnifiedHunks(oldLabel, newLabel, ops)
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return []string{""}
	}
	return strings.Split(s, "\n")
}

func computeLCSOps(a, b []string, oldBase, newBase int) []editOp {
	n, m := len(a), len(b)
	cols := m + 1
	dp := make([]int32, (n+1)*cols)
	for i := n - 1; i >= 0; i-- {
		row := i * cols
		nextRow := (i + 1) * cols
		ai := a[i]
		for j := m - 1; j >= 0; j-- {
			if ai == b[j] {
				dp[row+j] = dp[nextRow+j+1] + 1
			} else {
				down := dp[nextRow+j]
				right := dp[row+j+1]
				if down >= right {
					dp[row+j] = down
				} else {
					dp[row+j] = right
				}
			}
		}
	}

	ops := make([]editOp, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			ops = append(ops, editOp{kind: opEqual, text: a[i], oldN: oldBase + i, newN: newBase + j})
			i++
			j++
		} else if dp[(i+1)*cols+j] >= dp[i*cols+j+1] {
			ops = append(ops, editOp{kind: opDelete, text: a[i], oldN: oldBase + i})
			i++
		} else {
			ops = append(ops, editOp{kind: opInsert, text: b[j], newN: newBase + j})
			j++
		}
	}
	for i < n {
		ops = append(ops, editOp{kind: opDelete, text: a[i], oldN: oldBase + i})
		i++
	}
	for j < m {
		ops = append(ops, editOp{kind: opInsert, text: b[j], newN: newBase + j})
		j++
	}
	return ops
}

func formatUnifiedHunks(oldLabel, newLabel string, ops []editOp) string {
	type span struct{ start, end int } // indices into ops
	var changes []int
	for idx, op := range ops {
		if op.kind != opEqual {
			changes = append(changes, idx)
		}
	}
	if len(changes) == 0 {
		return ""
	}

	var hunks []span
	for _, cIdx := range changes {
		s := cIdx - diffContextLines
		if s < 0 {
			s = 0
		}
		e := cIdx + diffContextLines + 1
		if e > len(ops) {
			e = len(ops)
		}
		if len(hunks) > 0 && s <= hunks[len(hunks)-1].end {
			if e > hunks[len(hunks)-1].end {
				hunks[len(hunks)-1].end = e
			}
		} else {
			hunks = append(hunks, span{start: s, end: e})
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldLabel, newLabel)

	for _, h := range hunks {
		slice := ops[h.start:h.end]
		oldStart, newStart := 0, 0
		oldCount, newCount := 0, 0
		for _, op := range slice {
			switch op.kind {
			case opEqual:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				if newStart == 0 {
					newStart = op.newN
				}
				oldCount++
				newCount++
			case opDelete:
				if oldStart == 0 {
					oldStart = op.oldN
				}
				oldCount++
			case opInsert:
				if newStart == 0 {
					newStart = op.newN
				}
				newCount++
			}
		}
		if oldStart == 0 && len(slice) > 0 {
			oldStart = inferStartLine(ops, h.start, true)
		}
		if newStart == 0 && len(slice) > 0 {
			newStart = inferStartLine(ops, h.start, false)
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, op := range slice {
			switch op.kind {
			case opEqual:
				b.WriteByte(' ')
			case opDelete:
				b.WriteByte('-')
			case opInsert:
				b.WriteByte('+')
			}
			b.WriteString(op.text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func inferStartLine(ops []editOp, idx int, wantOld bool) int {
	for i := idx - 1; i >= 0; i-- {
		if wantOld && ops[i].oldN > 0 {
			return ops[i].oldN
		}
		if !wantOld && ops[i].newN > 0 {
			return ops[i].newN
		}
	}
	return 0
}

func fallbackUnifiedDiff(oldLabel, newLabel string, aLines, bLines []string, prefix, suffix int) string {
	ctxStart := prefix - diffContextLines
	if ctxStart < 0 {
		ctxStart = 0
	}
	aMid := aLines[prefix : len(aLines)-suffix]
	bMid := bLines[prefix : len(bLines)-suffix]

	aShown := aMid
	bShown := bMid
	truncated := false
	if len(aShown) > maxFallbackLines {
		aShown = aShown[:maxFallbackLines]
		truncated = true
	}
	if len(bShown) > maxFallbackLines {
		bShown = bShown[:maxFallbackLines]
		truncated = true
	}

	leadCount := prefix - ctxStart
	oldCount := leadCount + len(aShown)
	newCount := leadCount + len(bShown)
	oldStart := ctxStart + 1
	newStart := ctxStart + 1
	if len(aLines) == 0 {
		oldStart = 0
	}
	if len(bLines) == 0 {
		newStart = 0
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldLabel, newLabel)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for i := ctxStart; i < prefix; i++ {
		b.WriteByte(' ')
		b.WriteString(aLines[i])
		b.WriteByte('\n')
	}
	for _, line := range aShown {
		b.WriteByte('-')
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, line := range bShown {
		b.WriteByte('+')
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if truncated {
		fmt.Fprintf(&b, "\\ diff capped at %d lines per side (%d removed, %d added total)\n",
			maxFallbackLines, len(aMid), len(bMid))
	}
	return b.String()
}
