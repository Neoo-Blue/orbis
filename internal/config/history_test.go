package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSaveWritesHistoryWhenChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	histDir := filepath.Join(dir, "config-history")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.SetHistoryDir(histDir)

	// Re-saving identical bytes should not create a history entry.
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(histDir); len(entries) != 0 {
		t.Fatalf("expected 0 history files after identical save, got %d", len(entries))
	}

	firstOnDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Mutating and saving archives the replaced version as <unix-nanos>.yaml with 0600.
	if err := c.Update(func(cfg *Config) {
		cfg.Node.Name = "gateway-east"
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(histDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 history file, got %d", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasSuffix(name, ".yaml") {
		t.Fatalf("expected .yaml suffix, got %q", name)
	}
	stem := strings.TrimSuffix(name, ".yaml")
	if _, err := strconv.ParseInt(stem, 10, 64); err != nil {
		t.Fatalf("expected unix-nanos filename, got %q: %v", name, err)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected mode 0600, got %04o", perm)
	}
	archived, err := os.ReadFile(filepath.Join(histDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if string(archived) != string(firstOnDisk) {
		t.Errorf("archived version does not match previous on-disk config")
	}
}

func TestSavePrunesHistoryTo200Files(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	histDir := filepath.Join(dir, "config-history")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.SetHistoryDir(histDir)

	const totalChanges = 212
	for i := 1; i <= totalChanges; i++ {
		name := fmt.Sprintf("node-%03d", i)
		if err := c.Update(func(cfg *Config) {
			cfg.Node.Name = name
		}); err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}

	stamps := listHistoryTimestamps(histDir)
	if len(stamps) != maxHistoryFiles {
		t.Fatalf("expected %d history files after %d changes, got %d", maxHistoryFiles, totalChanges, len(stamps))
	}

	// Change #1 archived default ("orbis"), change #12 archived "node-011",
	// change #13 archived "node-012". With 212 changes keeping 200 newest,
	// the oldest surviving file must hold "node-012" and the newest "node-211".
	oldestBytes, err := os.ReadFile(filepath.Join(histDir, strconv.FormatInt(stamps[0], 10)+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(oldestBytes), "name: node-012") {
		t.Errorf("oldest surviving history entry missing node-012; got:\n%s", oldestBytes)
	}
	newestBytes, err := os.ReadFile(filepath.Join(histDir, strconv.FormatInt(stamps[len(stamps)-1], 10)+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(newestBytes), "name: node-211") {
		t.Errorf("newest history entry missing node-211; got:\n%s", newestBytes)
	}
}

func TestSaveHistoryFailureIsBestEffortAndSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Point historyDir under a regular file so MkdirAll fails.
	c.SetHistoryDir(filepath.Join(blocker, "history"))

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	updateErr := c.Update(func(cfg *Config) {
		cfg.Node.Name = "still-saves"
	})
	_ = w.Close()
	os.Stdout = origStdout

	out, _ := io.ReadAll(r)
	_ = r.Close()

	if updateErr != nil {
		t.Fatalf("Save failed when history directory was unwritable: %v", updateErr)
	}
	if len(out) != 0 {
		t.Errorf("expected no stdout output from config package, got %q", string(out))
	}
}
