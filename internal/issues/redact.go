// Package issues records what goes wrong on a node, scrubs it of anything that
// identifies the network, and can file it on the project's issue board so the
// same bug gets fixed for everyone. The scrubbing is the point: a bug report
// is only useful if people are willing to send it, and they are only willing
// to send it if they can see it carries nothing about their home.
package issues

import (
	"regexp"
	"sort"
	"strings"
)

// Redactor replaces identifying detail with placeholders. Rules run from most
// to least specific so a device name containing an address is scrubbed as a
// device, not as a bare address.
type Redactor struct {
	terms     []string // exact strings: device names, node name, operator-supplied
	keepHosts []string // hostnames (or parent domains) allowed to remain
}

// keepHostsDefault are infrastructure names that carry no information about
// the operator and make a report readable: the project, the model providers,
// the resolvers, and the list sources.
var keepHostsDefault = []string{
	"github.com", "githubusercontent.com", "adguardteam.github.io",
	"openrouter.ai", "api.openai.com", "api.anthropic.com", "openai.com", "anthropic.com",
	"sponsor.ajay.app", "youtube.com", "googlevideo.com", "googleapis.com", "ytimg.com",
	"cloudflare.com", "cloudflare-dns.com", "one.one.one.one", "dns.google", "quad9.net",
	"tailscale.com", "orbis.lan", "example.com", "example.org", "localhost",
	"oisd.nl", "urlhaus.abuse.ch", "abuse.ch", "phishing.army", "pgl.yoyo.org", "hagezi",
	"firebog.net", "adaway.org", "molinero.dev", "jsdelivr.net", "db-ip.com", "frogeye.fr",
	"pkgs.tailscale.com", "pkg.cloudflare.com", "wikipedia.org",
}

// publicResolvers are kept verbatim: they identify an upstream, not a home.
var publicResolvers = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true, "94.140.14.14": true, "94.140.15.15": true,
	"208.67.222.222": true, "208.67.220.220": true,
}

// fileExts keeps "orbis.yaml" and "main.go" from being read as hostnames.
var fileExts = map[string]bool{
	"go": true, "yaml": true, "yml": true, "json": true, "txt": true, "db": true, "service": true,
	"log": true, "md": true, "ts": true, "tsx": true, "js": true, "css": true, "html": true, "py": true,
	"sh": true, "conf": true, "mmdb": true, "pem": true, "crt": true, "key": true, "sock": true,
	"wal": true, "shm": true, "bak": true, "tgz": true, "gz": true, "deb": true, "xz": true, "ko": true,
	"toml": true, "ini": true, "cfg": true, "lock": true, "pid": true, "target": true, "mount": true,
}

var (
	reEmail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)
	reMAC    = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	reIPv4   = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:/\d{1,2})?\b`)
	reIPv6   = regexp.MustCompile(`(?i)(?:^|[^0-9a-z:])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?:/\d{1,3})?`)
	reKeySK  = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`)
	reKeyTS  = regexp.MustCompile(`\btskey-[A-Za-z0-9_-]{6,}\b`)
	reKeyGH  = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,}\b`)
	reBearer = regexp.MustCompile(`(?i)\b(bearer|token|authorization)(["' :=]+)\S{8,}`)
	reB64Key = regexp.MustCompile(`(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{42,43}=)`)
	reHex    = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	reHost   = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,}\b`)
	reTime   = regexp.MustCompile(`^\d{1,2}:\d{2}(?::\d{2})?$`)
)

// NewRedactor builds a scrubber. terms are exact strings to remove (device
// names, the node name, operator additions); keepHosts extend the built-in
// list of infrastructure names allowed to remain.
func NewRedactor(terms, keepHosts []string) *Redactor {
	r := &Redactor{}
	seen := map[string]bool{}
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if len(t) < 3 || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		r.terms = append(r.terms, t)
	}
	// Longest first so "living room tv" wins over "tv".
	sort.Slice(r.terms, func(i, j int) bool { return len(r.terms[i]) > len(r.terms[j]) })
	r.keepHosts = append(r.keepHosts, keepHostsDefault...)
	for _, h := range keepHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			r.keepHosts = append(r.keepHosts, h)
		}
	}
	return r
}

// Scrub returns s with identifying detail replaced.
func (r *Redactor) Scrub(s string) string {
	if s == "" {
		return s
	}
	// 1. Exact terms (case-insensitive).
	for _, t := range r.terms {
		s = replaceFold(s, t, "[device]")
	}
	// 2. Credentials, before anything shorter could eat part of them.
	s = reKeySK.ReplaceAllString(s, "[key]")
	s = reKeyTS.ReplaceAllString(s, "[key]")
	s = reKeyGH.ReplaceAllString(s, "[key]")
	s = reBearer.ReplaceAllString(s, "${1}${2}[token]")
	s = reB64Key.ReplaceAllString(s, "${1}[key]")
	s = reHex.ReplaceAllString(s, "[hex]")
	// 3. Identities.
	s = reEmail.ReplaceAllString(s, "[email]")
	s = reMAC.ReplaceAllString(s, "[mac]")
	s = reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		ip := m
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		switch {
		case ip == "0.0.0.0", ip == "255.255.255.255", strings.HasPrefix(ip, "127."):
			return m
		case publicResolvers[ip]:
			// Well-known resolvers say nothing about the operator and a lot
			// about which upstream misbehaved.
			return m
		}
		return "[ip]"
	})
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		// The match includes the leading delimiter; keep it.
		lead := ""
		body := m
		if len(m) > 0 && !isHexOrColon(m[0]) {
			lead, body = m[:1], m[1:]
		}
		if i := strings.IndexByte(body, '/'); i >= 0 {
			body = body[:i]
		}
		if reTime.MatchString(body) || strings.Count(body, ":") < 2 {
			return m
		}
		if !strings.Contains(body, "::") && !strings.ContainsAny(strings.ToLower(body), "abcdef") {
			// Digits and colons only, e.g. a timestamp fragment.
			return m
		}
		if body == "::" || body == "::1" {
			return m
		}
		return lead + "[ip6]"
	})
	// 4. Hostnames not on the keep list.
	s = reHost.ReplaceAllStringFunc(s, func(h string) string {
		lower := strings.ToLower(h)
		if i := strings.LastIndexByte(lower, '.'); i >= 0 && fileExts[lower[i+1:]] {
			return h
		}
		if r.keep(lower) {
			return h
		}
		return "[host]"
	})
	return s
}

func (r *Redactor) keep(host string) bool {
	for _, k := range r.keepHosts {
		if host == k || strings.HasSuffix(host, "."+k) || strings.Contains(host, k) && strings.HasPrefix(k, "hagezi") {
			return true
		}
	}
	return false
}

func isHexOrColon(b byte) bool {
	return b == ':' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// replaceFold is a case-insensitive strings.ReplaceAll.
func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	lower := strings.ToLower(s)
	needle := strings.ToLower(old)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(lower[i:], needle)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		b.WriteString(s[i : i+j])
		b.WriteString(repl)
		i += j + len(needle)
	}
}
