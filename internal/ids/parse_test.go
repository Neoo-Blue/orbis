package ids

import "testing"

func TestParseLines(t *testing.T) {
	cases := []struct {
		line string
		kind string
		ip   string
		w    int
	}{
		{"Sep  5 02:08:38 ad sshd[33718]: Failed password for invalid user ad from 203.0.113.9 port 65108 ssh2", "ssh-auth-fail", "203.0.113.9", 1},
		{"sshd[33720]: Invalid user arafat from 198.51.100.7 port 59726", "ssh-auth-fail", "198.51.100.7", 1},
		{"sshd[1]: error: maximum authentication attempts exceeded for root from 198.51.100.8 port 1 ssh2 [preauth]", "ssh-auth-fail", "198.51.100.8", 3},
		{"sshd[2]: Did not receive identification string from 198.51.100.9 port 40000", "ssh-probe", "198.51.100.9", 1},
		{"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.10  user=root", "auth-fail", "198.51.100.10", 1},
		{"User [admin] from [198.51.100.11] failed to log in via [DSM] due to authorization failure.", "nas-auth-fail", "198.51.100.11", 1},
		{`198.51.100.12 - - [06/Sep/2026:01:00:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl"`, "http-auth-fail", "198.51.100.12", 1},
		{`198.51.100.13 - - [06/Sep/2026:01:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "x"`, "http-probe", "198.51.100.13", 1},
		{`{"level":"info","ts":1,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.14","remote_port":"1"},"status":401}`, "http-auth-fail", "198.51.100.14", 1},
		{"homeassistant: Login attempt or request with invalid authentication from 198.51.100.15 (198.51.100.15). Requested URL: '/auth/login_flow'", "app-auth-fail", "198.51.100.15", 1},
		{"Login failed: 'bob' (Remote IP: '198.51.100.16')", "app-auth-fail", "198.51.100.16", 1},
		{"vaultwarden: Username or password is incorrect. Try again. IP: 198.51.100.17. Username: a@b.c.", "app-auth-fail", "198.51.100.17", 1},
		{"Accepted password for aerkin from 192.168.50.163 port 51277 ssh2", "", "", 0},
		{"kernel: eth0: link up", "", "", 0},
	}
	for _, c := range cases {
		h, ok := Parse(c.line)
		if c.kind == "" {
			if ok {
				t.Errorf("%q should not match, got %+v", c.line, h)
			}
			continue
		}
		if !ok || h.Kind != c.kind || h.IP.String() != c.ip || h.Weight != c.w {
			t.Errorf("%q -> %+v %v, want %s %s w%d", c.line, h, ok, c.kind, c.ip, c.w)
		}
	}
}

func TestParseSyslog(t *testing.T) {
	m := ParseSyslog("<38>Sep  6 01:50:02 nas sshd[57941]: Failed password for root from 198.51.100.1 port 2 ssh2")
	if m.Host != "nas" || m.Program != "sshd" || !contains(m.Message, "Failed password") {
		t.Errorf("rfc3164: %+v", m)
	}
	m = ParseSyslog(`<38>1 2026-09-06T01:50:02Z nas sshd 57941 - - Failed password for root from 198.51.100.1 port 2 ssh2`)
	if m.Host != "nas" || m.Program != "sshd" || !contains(m.Message, "Failed password") {
		t.Errorf("rfc5424: %+v", m)
	}
	m = ParseSyslog("Sep  6 01:50:02 synology synoscgi[1]: User [admin] from [198.51.100.2] failed to log in via [DSM].")
	if m.Host != "synology" || m.Program != "synoscgi" {
		t.Errorf("bare: %+v", m)
	}
	m = ParseSyslog("just a line")
	if m.Host != "" || m.Message != "just a line" {
		t.Errorf("unknown: %+v", m)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
