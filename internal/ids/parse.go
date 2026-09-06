// Package ids is the built-in intrusion detection. It turns log lines
// (this node's journal, syslog from other hosts, Orbis's own login page) and
// flow-table behaviour (scans, sweeps, floods) into scenario hits per
// address, and when a scenario's threshold is crossed inside its window it
// bans the address at the gateway for a while, longer each time it comes
// back. No cloud, no community feed: what it sees is what it acts on.
package ids

import (
	"net/netip"
	"regexp"
	"strings"
)

// Hit is one observation attributed to an address.
type Hit struct {
	Kind string // scenario key
	IP   netip.Addr
	// Weight lets one line count for more than one failure, e.g. sshd's
	// "maximum authentication attempts exceeded".
	Weight int
	User   string
	Sample string
}

type parser struct {
	kind   string
	weight int
	re     *regexp.Regexp
	ipIdx  int
	usrIdx int
}

// parsers are tried in order against every line, whatever program produced
// it, since forwarded syslog often loses the program name.
var parsers = []parser{
	// sshd
	{"ssh-auth-fail", 1, regexp.MustCompile(`Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) port \d+`), 2, 1},
	{"ssh-auth-fail", 1, regexp.MustCompile(`Invalid user (\S*) ?from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 2, 1},
	{"ssh-auth-fail", 3, regexp.MustCompile(`maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 2, 1},
	{"ssh-auth-fail", 1, regexp.MustCompile(`Connection closed by (?:invalid|authenticating) user (\S+) (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) port \d+ \[preauth\]`), 2, 1},
	{"ssh-auth-fail", 1, regexp.MustCompile(`Disconnected from (?:invalid|authenticating) user (\S+) (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) port \d+ \[preauth\]`), 2, 1},
	{"ssh-probe", 1, regexp.MustCompile(`Did not receive identification string from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"ssh-probe", 1, regexp.MustCompile(`banner exchange: Connection from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) port \d+: invalid format`), 1, 0},
	// PAM and generic Linux services (vsftpd, dovecot, postfix, sudo, login)
	{"auth-fail", 1, regexp.MustCompile(`authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"auth-fail", 1, regexp.MustCompile(`FAILED LOGIN .* FROM (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"auth-fail", 1, regexp.MustCompile(`(?i)auth failed.*rip=(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"auth-fail", 1, regexp.MustCompile(`(?i)SASL (?:LOGIN|PLAIN) authentication failed.*\[(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\]`), 1, 0},
	// Synology DSM and QNAP
	{"nas-auth-fail", 1, regexp.MustCompile(`User \[(\S+)\] from \[(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\] failed to log in`), 2, 1},
	{"nas-auth-fail", 1, regexp.MustCompile(`(?i)Failed to login (?:via \S+ )?from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"nas-auth-fail", 1, regexp.MustCompile(`(?i)\[Login\] .* from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) .*(?:failed|fail)`), 1, 0},
	// Web servers: combined log format, 401 and 403 are auth failures,
	// 404 bursts are probing.
	{"http-auth-fail", 1, regexp.MustCompile(`^(?:\S+ )?(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) \S+ \S+ \[[^\]]+\] "[^"]*" (?:401|403) `), 1, 0},
	{"http-probe", 1, regexp.MustCompile(`^(?:\S+ )?(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) \S+ \S+ \[[^\]]+\] "[^"]*" 404 `), 1, 0},
	// Caddy / Traefik JSON access logs
	{"http-auth-fail", 1, regexp.MustCompile(`"(?:remote_ip|ClientAddr|client_ip)":"(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)(?::\d+)?".*"(?:status|DownstreamStatus)":(?:401|403)\b`), 1, 0},
	{"http-probe", 1, regexp.MustCompile(`"(?:remote_ip|ClientAddr|client_ip)":"(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)(?::\d+)?".*"(?:status|DownstreamStatus)":404\b`), 1, 0},
	// Home Assistant, Nextcloud, Vaultwarden, Jellyfin
	{"app-auth-fail", 1, regexp.MustCompile(`Login attempt or request with invalid authentication from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"app-auth-fail", 1, regexp.MustCompile(`Login failed: '?(\S+?)'? \(Remote IP: '?(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)'?\)`), 2, 1},
	{"app-auth-fail", 1, regexp.MustCompile(`(?i)Username or password is incorrect\. Try again\. IP: (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
	{"app-auth-fail", 1, regexp.MustCompile(`(?i)Authentication request for "(\S+)" .* from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 2, 1},
	// Windows-style RDP failures relayed through syslog agents
	{"rdp-auth-fail", 1, regexp.MustCompile(`(?i)An account failed to log on.*Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)`), 1, 0},
	// WireGuard / OpenVPN
	{"vpn-auth-fail", 1, regexp.MustCompile(`(?i)TLS Error: .* from \[AF_INET\](\d+\.\d+\.\d+\.\d+):\d+`), 1, 0},
	{"vpn-auth-fail", 1, regexp.MustCompile(`(?i)Invalid handshake initiation from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)`), 1, 0},
}

// Parse extracts a hit from a line, or reports none.
func Parse(line string) (Hit, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Hit{}, false
	}
	for _, p := range parsers {
		m := p.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ipStr := strings.Trim(m[p.ipIdx], "[]")
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		h := Hit{Kind: p.kind, IP: addr.Unmap(), Weight: p.weight, Sample: truncate(line, 200)}
		if p.usrIdx > 0 && p.usrIdx < len(m) {
			h.User = m[p.usrIdx]
		}
		return h, true
	}
	return Hit{}, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Syslog is one received syslog message, already split from its framing.
type Syslog struct {
	Host    string
	Program string
	Message string
}

var (
	rfc3164 = regexp.MustCompile(`^<(\d{1,3})>(?:[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(?:([^\s:\[]+)(?:\[\d+\])?:\s*)?(.*)$`)
	rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|\[[^\]]*\]) ?(.*)$`)
)

// ParseSyslog splits an RFC 3164 or RFC 5424 message into host, program and
// message. Anything else is treated as a bare line from an unknown host.
func ParseSyslog(raw string) Syslog {
	raw = strings.TrimRight(raw, "\r\n\x00")
	if m := rfc5424.FindStringSubmatch(raw); m != nil {
		prog := m[4]
		if prog == "-" {
			prog = ""
		}
		host := m[3]
		if host == "-" {
			host = ""
		}
		return Syslog{Host: host, Program: prog, Message: m[7]}
	}
	if m := rfc3164.FindStringSubmatch(raw); m != nil {
		return Syslog{Host: m[2], Program: m[3], Message: m[4]}
	}
	// A line without a priority: some senders strip it. Try to read
	// "host program[pid]: message" anyway.
	if m := regexp.MustCompile(`^(?:[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}\s+)?(\S+)\s+([^\s:\[]+)(?:\[\d+\])?:\s*(.*)$`).FindStringSubmatch(raw); m != nil && !strings.Contains(m[1], "=") {
		return Syslog{Host: m[1], Program: m[2], Message: m[3]}
	}
	return Syslog{Message: raw}
}
