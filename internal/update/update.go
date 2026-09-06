// Package update notices a newer Orbis release on GitHub and, where the node
// runs the bare binary under systemd or by hand, installs it in place: the
// right asset for this architecture is downloaded, checked against the
// release's checksum file, swapped in next to a rollback copy, and the
// service is restarted. A container is told to pull instead.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

const releasesURL = "https://api.github.com/repos/Neoo-Blue/orbis/releases/latest"

// Release is what GitHub says about the latest tagged release.
type Release struct {
	Tag         string    `json:"tag"`
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	Notes       string    `json:"notes"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset is one downloadable file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// Hooks are what the application lends the updater.
type Hooks struct {
	Emit func(store.Event)
}

// Manager checks for and applies updates.
type Manager struct {
	current string
	hooks   Hooks
	log     func(string, ...any)
	http    *http.Client
	dataDir string

	mu        sync.Mutex
	latest    *Release
	checkedAt time.Time
	checkErr  string
	announced string
	state     string // idle | checking | downloading | verifying | installing | restarting | error
	progress  float64
	stateErr  string
	kick      chan struct{}
}

func NewManager(current, dataDir string, hooks Hooks, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{
		current: current, dataDir: dataDir, hooks: hooks, log: log,
		http: &http.Client{Timeout: 5 * time.Minute}, state: "idle", kick: make(chan struct{}, 1),
	}
}

// Method says how this node was installed, which decides whether it can
// update itself: systemd (restart after swapping), binary (swap, restart by
// hand), docker (pull the image), or dev (a go run, leave alone).
func Method() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			return "docker"
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	if strings.Contains(exe, "go-build") || strings.HasSuffix(exe, "/orbisd-mac") {
		return "dev"
	}
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "is-active", "orbis").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
			return "systemd"
		}
	}
	return "binary"
}

// CanApply reports whether a click can install a release here.
func CanApply() bool {
	switch Method() {
	case "systemd", "binary":
		return runtime.GOOS == "linux"
	}
	return false
}

// Run checks at start (after a short delay so the network is up) and every
// hour; a kick checks now.
func (m *Manager) Run(ctx context.Context) {
	m.announceInstalled()
	first := time.NewTimer(2 * time.Minute)
	defer first.Stop()
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			m.Check(ctx)
		case <-m.kick:
			m.Check(ctx)
		case <-tick.C:
			m.Check(ctx)
		}
	}
}

// RequestCheck asks the loop to check now.
func (m *Manager) RequestCheck() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Check fetches the latest release and announces it once.
func (m *Manager) Check(ctx context.Context) (*Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "orbis/"+m.current)
	resp, err := m.http.Do(req)
	if err != nil {
		m.setCheck(nil, err)
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("github returned http %d", resp.StatusCode)
		if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "rate limit") {
			err = fmt.Errorf("github's rate limit for unauthenticated checks is used up; try later")
		}
		m.setCheck(nil, err)
		return nil, err
	}
	var raw struct {
		TagName     string    `json:"tag_name"`
		Name        string    `json:"name"`
		Body        string    `json:"body"`
		HTMLURL     string    `json:"html_url"`
		PublishedAt time.Time `json:"published_at"`
		Prerelease  bool      `json:"prerelease"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		m.setCheck(nil, err)
		return nil, err
	}
	rel := &Release{Tag: raw.TagName, Version: strings.TrimPrefix(raw.TagName, "v"), Name: raw.Name, Notes: raw.Body, URL: raw.HTMLURL, PublishedAt: raw.PublishedAt}
	for _, a := range raw.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, URL: a.URL, Size: a.Size})
	}
	m.setCheck(rel, nil)
	if Newer(rel.Version, m.current) {
		m.mu.Lock()
		announce := m.announced != rel.Version
		m.announced = rel.Version
		m.mu.Unlock()
		if announce && m.hooks.Emit != nil {
			detail := fmt.Sprintf("You are running %s. ", m.current)
			if CanApply() {
				detail += "Install it with one click from Settings, About & diagnostics, or the banner on the Overview."
			} else if Method() == "docker" {
				detail += "This node runs in a container: pull the new image and recreate it."
			} else {
				detail += "Download it from the release page."
			}
			m.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo, Category: "update",
				Title: "Orbis " + rel.Version + " is available", Detail: detail, Data: map[string]any{"version": rel.Version, "url": rel.URL}})
		}
	}
	return rel, nil
}

func (m *Manager) setCheck(rel *Release, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkedAt = time.Now()
	if err != nil {
		m.checkErr = err.Error()
		return
	}
	m.checkErr = ""
	m.latest = rel
}

// Newer reports whether a is a higher version than b, comparing dotted
// numbers; anything unparseable (dev builds) is never older.
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	f := strings.Split(v, ".")
	if len(f) < 2 {
		return nil
	}
	out := []int{0, 0, 0}
	for i := 0; i < len(f) && i < 3; i++ {
		n, err := strconv.Atoi(f[i])
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}

// Status is the page's view.
func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{
		"current": m.current, "method": Method(), "can_apply": CanApply(), "state": m.state,
		"progress": m.progress, "error": m.stateErr, "check_error": m.checkErr, "arch": runtime.GOARCH,
	}
	if !m.checkedAt.IsZero() {
		out["checked_at"] = m.checkedAt
	}
	if m.latest != nil {
		out["latest"] = m.latest
		out["available"] = Newer(m.latest.Version, m.current)
	} else {
		out["available"] = false
	}
	return out
}

func (m *Manager) setState(state string, progress float64, err error) {
	m.mu.Lock()
	m.state, m.progress = state, progress
	if err != nil {
		m.stateErr = err.Error()
	} else if state != "error" {
		m.stateErr = ""
	}
	m.mu.Unlock()
}

// Apply installs the latest release. It runs in the background; Status
// reports progress, and a successful install ends in a restart.
func (m *Manager) Apply(ctx context.Context) error {
	if !CanApply() {
		return fmt.Errorf("this node cannot update itself: install method is %s", Method())
	}
	m.mu.Lock()
	rel := m.latest
	busy := m.state != "idle" && m.state != "error"
	m.mu.Unlock()
	if busy {
		return fmt.Errorf("an update is already in progress")
	}
	if rel == nil {
		r, err := m.Check(ctx)
		if err != nil {
			return err
		}
		rel = r
	}
	if !Newer(rel.Version, m.current) {
		return fmt.Errorf("already on %s; %s is the latest release", m.current, rel.Version)
	}
	go m.apply(rel)
	return nil
}

func (m *Manager) apply(rel *Release) {
	fail := func(err error) {
		m.log("update: %v", err)
		m.setState("error", 0, err)
	}
	want := "orbisd-linux-" + runtime.GOARCH
	var asset, sums *Asset
	for i := range rel.Assets {
		switch rel.Assets[i].Name {
		case want:
			asset = &rel.Assets[i]
		case "sha256sums.txt":
			sums = &rel.Assets[i]
		}
	}
	if asset == nil {
		fail(fmt.Errorf("release %s has no %s asset", rel.Version, want))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fail(err)
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	m.setState("downloading", 0, nil)
	// Stage next to the binary when we may write there; a hardened unit
	// (ProtectSystem=strict) cannot, so the data directory takes it and a
	// transient systemd unit outside our sandbox does the swap.
	tmp, inPlace, err := m.stagePath(exe)
	if err != nil {
		fail(err)
		return
	}
	sum, err := m.download(ctx, asset, tmp)
	if err != nil {
		os.Remove(tmp)
		fail(fmt.Errorf("download: %w", err))
		return
	}

	m.setState("verifying", 1, nil)
	if sums != nil {
		expected, err := m.fetchSum(ctx, sums.URL, asset.Name)
		if err != nil {
			os.Remove(tmp)
			fail(fmt.Errorf("checksums: %w", err))
			return
		}
		if expected != "" && expected != sum {
			os.Remove(tmp)
			fail(fmt.Errorf("checksum mismatch for %s: the download does not match the release", asset.Name))
			return
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		fail(err)
		return
	}
	// The new binary must at least run and say who it is.
	out, err := exec.CommandContext(ctx, tmp, "-version").Output()
	if err != nil || !strings.Contains(string(out), rel.Version) {
		os.Remove(tmp)
		fail(fmt.Errorf("the downloaded binary did not identify as %s (%q, %v)", rel.Version, strings.TrimSpace(string(out)), err))
		return
	}

	m.setState("installing", 1, nil)
	if m.dataDir != "" {
		_ = os.WriteFile(filepath.Join(m.dataDir, "update-pending"), []byte(m.current+" -> "+rel.Version), 0o644)
	}
	prev := exe + ".prev"
	if !inPlace {
		if Method() != "systemd" {
			os.Remove(tmp)
			fail(fmt.Errorf("cannot write %s from here; run: sudo orbisd -update", filepath.Dir(exe)))
			return
		}
		// Swap and restart from a transient unit that has the whole
		// filesystem, then let it take us down.
		m.setState("restarting", 1, nil)
		script := fmt.Sprintf("cp -a %q %q; install -m0755 %q %q && rm -f %q; systemctl restart orbis",
			exe, prev, tmp, exe, tmp)
		if err := transientRun(script); err != nil {
			os.Remove(tmp)
			m.clearPending()
			fail(fmt.Errorf("could not hand the install to systemd: %w. Run: sudo orbisd -update", err))
			return
		}
		m.log("update: installing %s over %s through systemd (rollback copy at %s)", rel.Version, m.current, prev)
		return
	}
	_ = os.Remove(prev)
	if err := copyFile(exe, prev); err != nil {
		m.log("update: could not keep a rollback copy: %v", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		m.clearPending()
		fail(fmt.Errorf("install: %w", err))
		return
	}
	m.log("update: installed %s over %s (rollback copy at %s)", rel.Version, m.current, prev)

	if Method() == "systemd" {
		m.setState("restarting", 1, nil)
		if err := transientRun("systemctl restart orbis"); err != nil {
			fail(fmt.Errorf("installed, but the restart failed: %w. Run: systemctl restart orbis", err))
			return
		}
		return
	}
	m.setState("installed", 1, nil)
	if m.hooks.Emit != nil {
		m.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevNotice, Category: "update",
			Title: "Orbis " + rel.Version + " is installed; restart to use it", Detail: "The binary at " + exe + " was replaced. Restart the process to run the new version."})
	}
}

func (m *Manager) download(ctx context.Context, a *Asset, dst string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "orbis/"+m.current)
	resp, err := m.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 256*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return "", err
			}
			h.Write(buf[:n])
			done += int64(n)
			if a.Size > 0 {
				m.setState("downloading", float64(done)/float64(a.Size), nil)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return "", rerr
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m *Manager) fetchSum(ctx context.Context, url, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "orbis/"+m.current)
	resp, err := m.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.TrimPrefix(f[1], "*") == name || len(f) >= 2 && strings.HasSuffix(f[1], "/"+name) {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, st.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// transientRun hands a shell command to systemd as a transient unit outside
// our own cgroup and sandbox, so it can touch the system tree and survive our
// shutdown. Without systemd-run a detached shell does the job after a moment.
func transientRun(script string) error {
	unit := fmt.Sprintf("orbis-self-update-%d", time.Now().Unix())
	if p, err := exec.LookPath("systemd-run"); err == nil {
		out, err := exec.Command(p, "--quiet", "--collect", "--unit="+unit, "/bin/sh", "-c", script).CombinedOutput()
		if err == nil {
			return nil
		}
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 2; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// stagePath picks where the download lands: beside the binary if we may
// write there, else in the data directory. inPlace says which.
func (m *Manager) stagePath(exe string) (path string, inPlace bool, err error) {
	next := exe + ".new"
	if f, err := os.OpenFile(next, os.O_CREATE|os.O_WRONLY, 0o700); err == nil {
		f.Close()
		return next, true, nil
	}
	dir := m.dataDir
	if dir == "" {
		dir = os.TempDir()
	}
	staged := filepath.Join(dir, "orbisd.new")
	f, err := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY, 0o700)
	if err != nil {
		return "", false, fmt.Errorf("no writable place for the download: %w", err)
	}
	f.Close()
	return staged, false, nil
}

func (m *Manager) clearPending() {
	if m.dataDir != "" {
		_ = os.Remove(filepath.Join(m.dataDir, "update-pending"))
	}
}

// announceInstalled turns the marker left before a restart into an event,
// so the interface can say the update landed.
func (m *Manager) announceInstalled() {
	if m.dataDir == "" {
		return
	}
	p := filepath.Join(m.dataDir, "update-pending")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	_ = os.Remove(p)
	if m.hooks.Emit != nil {
		m.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo, Category: "update",
			Title: "Orbis updated to " + m.current, Detail: "Self-update completed: " + strings.TrimSpace(string(b)) + ". The previous binary is kept next to the new one as orbisd.prev."})
	}
}
