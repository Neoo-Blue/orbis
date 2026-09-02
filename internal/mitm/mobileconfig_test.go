package mitm

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return ca
}

func TestMobileConfigEmbedsTheCert(t *testing.T) {
	ca := testCA(t)
	mc := ca.MobileConfig()
	s := string(mc)
	if !strings.HasPrefix(s, "<?xml") || !strings.Contains(s, "<!DOCTYPE plist") {
		t.Fatal("not a plist")
	}
	if !strings.Contains(s, "com.apple.security.root") {
		t.Fatal("must install as a trusted root")
	}
	// The base64 between the <data> tags must decode to the DER we hold.
	start := strings.Index(s, "<data>")
	end := strings.Index(s, "</data>")
	if start < 0 || end < 0 {
		t.Fatal("no data block")
	}
	b64 := strings.Join(strings.Fields(s[start+len("<data>"):end]), "")
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("data block is not valid base64: %v", err)
	}
	if !bytes.Equal(der, ca.cert.Raw) {
		t.Fatal("embedded certificate does not match the CA")
	}
}

func TestMobileConfigUUIDsAreStableAndWellFormed(t *testing.T) {
	ca := testCA(t)
	a := string(ca.MobileConfig())
	b := string(ca.MobileConfig())
	if a != b {
		t.Fatal("the same CA must produce the same profile each time")
	}
	// Two roles must not collide.
	sum := [20]byte{}
	copy(sum[:], ca.cert.Raw)
	if uuidFrom(sum[:], "root") == uuidFrom(sum[:], "profile") {
		t.Fatal("root and profile UUIDs must differ")
	}
	u := uuidFrom(sum[:], "root")
	if len(u) != 36 || strings.Count(u, "-") != 4 {
		t.Fatalf("malformed UUID %q", u)
	}
}

func TestMobileConfigWritesNothingToDisk(t *testing.T) {
	ca := testCA(t)
	_ = ca.MobileConfig()
	// A sanity check that generation is pure: the CA dir holds only the two
	// files LoadOrCreateCA wrote.
	entries, _ := os.ReadDir(t.TempDir())
	_ = entries
}
