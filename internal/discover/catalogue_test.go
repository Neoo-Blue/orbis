package discover

import "testing"

func TestIdentify(t *testing.T) {
	cases := []struct {
		port   int
		fp     *Fingerprint
		vendor string
		name   string
		kind   string
	}{
		{32400, &Fingerprint{Title: "Plex"}, "", "Plex", "app"},
		{8096, &Fingerprint{Title: "Jellyfin"}, "", "Jellyfin", "app"},
		{8096, nil, "", "Port 8096 (usually Jellyfin or Emby)", "other"},
		{5001, &Fingerprint{Title: "HomeServer - Synology NAS", Body: "<html>"}, "Synology", "Synology DSM", "admin"},
		{5001, &Fingerprint{Title: "nas", Body: "<html>"}, "Synology", "Synology DSM", "admin"},
		{5000, nil, "Synology", "Synology DSM", "admin"},
		{5000, &Fingerprint{Title: "Frigate"}, "", "Frigate", "app"},
		{9000, &Fingerprint{Title: "Portainer"}, "", "Portainer", "admin"},
		{9000, &Fingerprint{Title: "Some Dashboard"}, "", "Some Dashboard", "admin"},
		{445, nil, "", "SMB file sharing", "storage"},
		{21198, &Fingerprint{Title: "EduCompanion"}, "", "EduCompanion", "web"},
		{21199, &Fingerprint{}, "", "Web service", "web"},
		{21200, nil, "", "Open port", "other"},
		{8080, &Fingerprint{Body: `{"ApiVersion":"1.43"}`}, "", "Docker Engine API", "infra"},
		{8090, &Fingerprint{Title: "n.eko", Body: "<p>run it in docker</p>"}, "", "n.eko", "web"},
		{3000, &Fingerprint{Title: "Mem0 - Log in", Body: "api gateway router"}, "", "Mem0 - Log in", "app"},
		{5055, &Fingerprint{Title: "Sign In - Seerr"}, "", "Seerr (requests)", "app"},
		{9443, &Fingerprint{Title: "Complex Dashboard"}, "", "Complex Dashboard", "admin"},
	}
	for _, c := range cases {
		name, kind, _, _ := Identify(c.port, c.fp, c.vendor)
		if name != c.name || kind != c.kind {
			t.Errorf("Identify(%d, %+v, %q) = %q/%q, want %q/%q", c.port, c.fp, c.vendor, name, kind, c.name, c.kind)
		}
	}
}

func TestIsStorage(t *testing.T) {
	if IsStorage("Intel", "workstation", []int{445}) {
		t.Error("a PC with file sharing is not storage")
	}
	if !IsStorage("Intel", "server", []int{445, 2049}) {
		t.Error("NFS makes it storage")
	}
	if !IsStorage("Synology", "", nil) {
		t.Error("a Synology is storage before any port answers")
	}
	if !IsStorage("", "", []int{445, 548}) {
		t.Error("two file protocols make it storage")
	}
	if IsStorage("", "", []int{445, 5006}) {
		t.Error("SMB plus a web app on 5006 is not storage unless the box is a Synology")
	}
	if !IsStorage("", "nas", nil) {
		t.Error("the identifier's verdict counts")
	}
}

func TestPortsDeduplicated(t *testing.T) {
	ports := Ports([]int{21198, 445, 0, 70000})
	seen := map[int]bool{}
	for _, p := range ports {
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
	if !seen[21198] || seen[0] || seen[70000] {
		t.Errorf("extra ports handled wrong: %v", ports)
	}
}
