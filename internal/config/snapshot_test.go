package config

import "testing"

func TestSnapshotCacheFollowsUpdates(t *testing.T) {
	c := Default()
	c.path = t.TempDir() + "/orbis.yaml"
	a := c.Snapshot()
	b := c.Snapshot()
	if a.Node.Name != b.Node.Name || a.mu != nil {
		t.Fatal("snapshots should agree and carry no mutex")
	}
	if err := c.Update(func(x *Config) { x.Node.Name = "renamed" }); err != nil {
		t.Fatal(err)
	}
	if got := c.Snapshot().Node.Name; got != "renamed" {
		t.Fatalf("snapshot after update = %q, want renamed", got)
	}
	// A failed update rolls back and must not expose a half-applied value.
	_ = c.Update(func(x *Config) { x.Node.Name = "bad"; x.Firewall.DefaultForward = "maybe" })
	if got := c.Snapshot().Node.Name; got != "renamed" {
		t.Fatalf("snapshot after a rejected update = %q, want renamed", got)
	}
	// Snapshots of snapshots still work and stay independent copies.
	s := c.Snapshot()
	s2 := s.Snapshot()
	if s2.Node.Name != "renamed" {
		t.Fatal("snapshot of a snapshot lost its value")
	}
}
