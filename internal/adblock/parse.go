package adblock

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Entries is what a list parses to. Blocks and exceptions are kept apart
// because a DNS blocker applies them in different places, and every line the
// parser could not honour is counted by reason so the operator can see what
// a list really contributed.
type Entries struct {
	Exact    []string
	Wildcard []string
	Regex    []string
	// Important marks entries carrying AdGuard's $important modifier: they
	// win over exceptions that came from lists.
	Important map[string]bool

	AllowExact    []string
	AllowWildcard []string
	AllowRegex    []string

	Skipped map[string]int
	Lines   int
}

func (e *Entries) Blocks() int { return len(e.Exact) + len(e.Wildcard) + len(e.Regex) }
func (e *Entries) Allows() int {
	return len(e.AllowExact) + len(e.AllowWildcard) + len(e.AllowRegex)
}
func (e *Entries) Total() int { return e.Blocks() + e.Allows() }

// ParseOptions steer the parser where a list's own syntax cannot.
type ParseOptions struct {
	// Format: "" or "auto" detects per line; "regex" treats every line as a
	// regular expression (Pi-hole's regex.list); "hosts" and "domains"
	// are accepted for clarity and behave like auto.
	Format string
	// Allow turns the whole list into exceptions, which is what AdGuard
	// Home calls an allowlist filter.
	Allow bool
}

type parser struct {
	opt      ParseOptions
	out      *Entries
	abp      bool // an [Adblock Plus] header was seen: bare names match subdomains
	exact    map[string]struct{}
	wild     map[string]struct{}
	regex    map[string]struct{}
	aExact   map[string]struct{}
	aWild    map[string]struct{}
	aRegex   map[string]struct{}
	imp      map[string]bool
	skipped  map[string]int
	lineOpts lineOptions
}

type lineOptions struct {
	allow     bool
	important bool
	denyallow []string
}

// Parse reads any of the formats a DNS blocker meets in the wild:
//
//	hosts:      0.0.0.0 ads.example.com   (127.0.0.1, ::, ::1 too)
//	domains:    ads.example.com
//	wildcard:   *.ads.example.com  |  .ads.example.com
//	AdGuard:    ||ads.example.com^  @@||cdn.example.com^  ||ads.example.com^$important
//	            ||ad*.example.com^  /^ads?[0-9]*\./  ||example.com^$denyallow=sub.example.com
//	dnsmasq:    address=/ads.example.com/0.0.0.0   server=/ads.example.com/
//	unbound:    local-zone: "ads.example.com" always_nxdomain
//	RPZ:        ads.example.com CNAME .   *.ads.example.com CNAME .
//	Pi-hole:    (\.|^)ads\.example\.com$   with regex.list options after ";"
//
// Cosmetic rules, rules with a path, and modifiers DNS cannot honour
// ($dnstype, $client, $dnsrewrite to a real address, request-type filters)
// are skipped and counted, because pretending to apply them overblocks.
func Parse(r io.Reader, opt ParseOptions) (*Entries, error) {
	p := &parser{
		opt: opt, out: &Entries{},
		exact: make(map[string]struct{}, 1<<16), wild: make(map[string]struct{}, 1<<12),
		regex: map[string]struct{}{}, aExact: map[string]struct{}{}, aWild: map[string]struct{}{},
		aRegex: map[string]struct{}{}, imp: map[string]bool{}, skipped: map[string]int{},
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		p.line(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return p.finish(), nil
}

// ParseList is the older shape: block entries only, exceptions dropped.
func ParseList(r io.Reader) (exact []string, wildcard []string, err error) {
	e, err := Parse(r, ParseOptions{})
	if err != nil {
		return nil, nil, err
	}
	return e.Exact, e.Wildcard, nil
}

func (p *parser) skip(reason string) { p.skipped[reason]++ }

func (p *parser) line(raw string) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return
	}
	switch {
	case line[0] == '#', line[0] == '!', strings.HasPrefix(line, "//"):
		return
	case line[0] == '[' && strings.HasSuffix(line, "]"):
		if strings.Contains(strings.ToLower(line), "adblock") {
			p.abp = true
		}
		return
	}
	p.out.Lines++
	p.lineOpts = lineOptions{allow: p.opt.Allow}

	if strings.EqualFold(p.opt.Format, "regex") {
		p.regexLine(line)
		return
	}

	// Cosmetic and scriptlet rules: not DNS.
	for _, marker := range []string{"##", "#@#", "#?#", "#$#", "#%#", "$$", "$@$"} {
		if strings.Contains(line, marker) {
			p.skip("cosmetic")
			return
		}
	}

	switch {
	case strings.HasPrefix(line, "address=/"), strings.HasPrefix(line, "server=/"), strings.HasPrefix(line, "local=/"):
		body := line[strings.Index(line, "/")+1:]
		if i := strings.Index(body, "/"); i > 0 {
			p.addWild(body[:i])
		} else {
			p.skip("invalid")
		}
	case strings.HasPrefix(line, "local-zone:"):
		// unbound: local-zone: "ads.example.com" always_nxdomain
		body := strings.TrimSpace(strings.TrimPrefix(line, "local-zone:"))
		body = strings.Trim(strings.Fields(body + " x")[0], "\"'")
		p.addWild(body)
	case p.looksLikeRegex(line):
		// A Pi-hole style expression: anchored at the start or opening a group.
		p.regexLine(line)
	case strings.HasSuffix(line, " CNAME .") || strings.HasSuffix(line, "\tCNAME ."):
		// RPZ, whose wildcard form starts with "*." and must not read as a URL pattern.
		p.plainLine(line)
	case strings.HasPrefix(line, "||"), strings.HasPrefix(line, "|"), strings.HasPrefix(line, "@@"),
		strings.HasPrefix(line, "/"), strings.HasSuffix(line, "^"), strings.Contains(line, "^$"), strings.Contains(line, "$important"),
		strings.Contains(line, "://"), strings.Contains(line, "$"), strings.Contains(line, "|"), strings.ContainsAny(line, "*?&="):
		// Anything with AdBlock syntax in it is a network rule, and a network
		// rule that is not anchored to a host is a URL pattern DNS cannot
		// honour. It must never reach the plain path, where a stray "|" or
		// "*" would read as a regular expression.
		p.abpLine(line)
	default:
		p.plainLine(line)
	}
}

// plainLine handles hosts files, bare domains, wildcards, RPZ and Pi-hole
// regex lines, which share the property of having no rule syntax to go on.
func (p *parser) plainLine(line string) {
	// Inline comments after whitespace.
	if i := strings.Index(line, " #"); i > 0 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "\t#"); i > 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	switch {
	case len(fields) >= 3 && strings.EqualFold(fields[len(fields)-2], "CNAME") && fields[len(fields)-1] == ".":
		// RPZ: name [IN] CNAME .
		name := strings.TrimSuffix(fields[0], ".")
		if strings.HasPrefix(name, "*.") {
			p.addWild(name[2:])
		} else {
			p.addExact(name)
		}
		return
	case len(fields) >= 2:
		ip := fields[0]
		if isNullAddress(ip) {
			for _, h := range fields[1:] {
				if isHostsNoise(h) {
					continue
				}
				p.addExact(h)
			}
			return
		}
		if looksLikeIP(ip) {
			// A hosts line pointing somewhere real is a local record, not a block.
			p.skip("hosts-rewrite")
			return
		}
		if p.looksLikeRegex(line) {
			p.regexLine(line)
			return
		}
		p.skip("not-dns")
		return
	}
	host := fields[0]
	switch {
	case strings.HasPrefix(host, "*."):
		p.addWild(host[2:])
	case strings.HasPrefix(host, ".") && !strings.HasPrefix(host, ".*"):
		p.addWild(host[1:])
	case normalize(host) != "":
		if p.abp {
			// In an AdBlock-style list a bare name covers its subdomains.
			p.addWild(host)
		} else {
			p.addExact(host)
		}
	case p.looksLikeRegex(host):
		p.regexLine(host)
	default:
		p.skip("not-dns")
	}
}

// abpLine handles AdGuard / uBlock network rules.
func (p *parser) abpLine(line string) {
	rule := line
	if strings.HasPrefix(rule, "@@") {
		p.lineOpts.allow = true
		rule = rule[2:]
	}
	// A regular-expression rule: /pattern/ with optional $options.
	if strings.HasPrefix(rule, "/") {
		end := strings.LastIndex(rule, "/")
		if end <= 0 {
			p.skip("invalid")
			return
		}
		if opts := rule[end+1:]; opts != "" {
			if !strings.HasPrefix(opts, "$") || !p.options(opts[1:]) {
				return
			}
		}
		p.addRegex(rule[1:end])
		return
	}
	pattern := rule
	if i := strings.LastIndex(rule, "$"); i >= 0 {
		if !p.options(rule[i+1:]) {
			return
		}
		pattern = rule[:i]
	}
	anchored := false
	switch {
	case strings.HasPrefix(pattern, "||"):
		anchored = true
		pattern = pattern[2:]
	case strings.HasPrefix(pattern, "|"):
		pattern = pattern[1:]
	}
	pattern = strings.TrimSuffix(pattern, "|")
	for _, scheme := range []string{"http://", "https://", "*://", "://", "ws://", "wss://"} {
		pattern = strings.TrimPrefix(pattern, scheme)
	}
	pattern = strings.TrimSuffix(pattern, "^")
	pattern = strings.TrimSuffix(pattern, "/")
	switch {
	case pattern == "":
		p.skip("invalid")
	case strings.ContainsAny(pattern, "/^|?&=:"):
		p.skip("path")
	case strings.Contains(pattern, "*"):
		if strings.HasPrefix(pattern, "*.") && !strings.Contains(pattern[2:], "*") {
			p.addWild(pattern[2:])
			return
		}
		if !anchored {
			// "ads*.gif" is a URL substring rule, not a hostname.
			p.skip("url-pattern")
			return
		}
		body := strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, "[^.]*")
		p.addRegex(`^(.*\.)?` + body + "$")
	case anchored:
		p.addWild(pattern)
	default:
		if normalize(pattern) == "" {
			p.skip("url-pattern")
			return
		}
		if p.abp && !strings.HasPrefix(rule, "|") {
			p.addWild(pattern)
		} else {
			p.addExact(pattern)
		}
	}
}

// options reads $modifiers and says whether the rule is still one DNS can
// apply. Anything that narrows a rule by client, record type or request
// kind is skipped rather than widened.
func (p *parser) options(raw string) bool {
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		name, val, _ := strings.Cut(o, "=")
		switch strings.ToLower(name) {
		case "important":
			p.lineOpts.important = true
		case "denyallow":
			p.lineOpts.denyallow = strings.Split(val, "|")
		case "dnsrewrite":
			// A rewrite to nothing, to a null address, or to a sinkhole host
			// (AdGuard's own lists point popups at ad-block.dns.adguard.com)
			// is a block. A rewrite to a real host is a redirect and skipped.
			v := strings.ToUpper(val)
			switch {
			case v == "", v == "0.0.0.0", v == "::", v == "NXDOMAIN", v == "REFUSED", v == "SERVFAIL",
				strings.HasPrefix(v, "NXDOMAIN;"), strings.HasPrefix(v, "REFUSED;"),
				strings.HasSuffix(v, ";0.0.0.0"), strings.HasSuffix(v, ";::"),
				strings.Contains(v, "ADGUARD"), strings.Contains(v, "BLOCK"), strings.Contains(v, "SINKHOLE"),
				strings.Contains(v, "BLACKHOLE"), strings.Contains(v, "NULL"):
			default:
				p.skip("rewrite")
				return false
			}
		case "dnstype":
			p.skip("dnstype")
			return false
		case "client", "ctag":
			p.skip("client")
			return false
		case "badfilter":
			p.skip("badfilter")
			return false
		case "domain":
			// $domain=... scopes a rule to pages that embed it; DNS has no page.
			p.skip("not-dns")
			return false
		case "all", "document", "doc", "popup", "empty", "mp4", "network", "app", "match-case",
			"third-party", "~third-party", "3p", "~3p", "1p", "~1p", "first-party", "~first-party",
			"script", "~script", "image", "~image", "stylesheet", "~stylesheet", "css", "object", "~object",
			"xmlhttprequest", "~xmlhttprequest", "xhr", "~xhr", "subdocument", "~subdocument", "frame",
			"font", "~font", "media", "~media", "websocket", "~websocket", "other", "~other", "ping", "~ping",
			"webrtc", "elemhide", "generichide", "genericblock", "specifichide", "urlblock", "content",
			"jsinject", "extension", "removeparam", "removeheader", "redirect", "redirect-rule", "csp",
			"replace", "cookie", "header", "permissions", "method", "to", "from", "strict1p", "strict3p",
			"object-subrequest", "ipset", "cname", "~cname":
			p.skip("not-dns")
			return false
		default:
			p.skip("unknown-modifier")
			return false
		}
	}
	return true
}

func (p *parser) regexLine(line string) {
	pat := strings.TrimSpace(line)
	// Pi-hole regex options ride after a semicolon: ;querytype=A ;invert ;reply=NXDOMAIN
	if i := strings.Index(pat, ";"); i >= 0 {
		opts := strings.ToLower(pat[i+1:])
		pat = strings.TrimSpace(pat[:i])
		if strings.Contains(opts, "querytype") || strings.Contains(opts, "invert") {
			p.skip("querytype")
			return
		}
	}
	if strings.HasPrefix(pat, "/") && strings.HasSuffix(pat, "/") && len(pat) > 2 {
		pat = pat[1 : len(pat)-1]
	}
	p.addRegex(pat)
}

// looksLikeRegex accepts what a Pi-hole regex list holds: an expression
// anchored at the start or opening a group, the shapes "(\.|^)ads\." and
// "^ad[0-9]+\." take. A bare token that merely contains an odd character
// is not a regex; it is a URL pattern or a typo, and treating it as a
// pattern is how an empty alternation once blocked every name.
func (p *parser) looksLikeRegex(s string) bool {
	if strings.ContainsAny(s, " \t") {
		return false
	}
	return strings.HasPrefix(s, "^") || strings.HasPrefix(s, "(")
}

func (p *parser) addExact(host string) {
	d := normalize(host)
	if d == "" {
		p.skip("invalid")
		return
	}
	if p.lineOpts.allow {
		p.aExact[d] = struct{}{}
		return
	}
	p.exact[d] = struct{}{}
	if p.lineOpts.important {
		p.imp[d] = true
	}
	p.denyallow()
}

func (p *parser) addWild(host string) {
	d := normalize(strings.TrimPrefix(host, "*."))
	if d == "" {
		p.skip("invalid")
		return
	}
	if p.lineOpts.allow {
		p.aWild[d] = struct{}{}
		return
	}
	p.wild[d] = struct{}{}
	if p.lineOpts.important {
		p.imp[d] = true
	}
	p.denyallow()
}

func (p *parser) addRegex(pat string) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		p.skip("invalid")
		return
	}
	re, err := compileRegex(pat)
	if err != nil {
		p.skip("bad-regex")
		return
	}
	if TooBroad(re) {
		p.skip("broad-regex")
		return
	}
	if p.lineOpts.allow {
		p.aRegex[pat] = struct{}{}
		return
	}
	p.regex[pat] = struct{}{}
	if p.lineOpts.important {
		p.imp[pat] = true
	}
}

// denyallow turns ||example.com^$denyallow=a.example.com into a block plus
// exceptions for the named hosts, which is the closest DNS can get.
func (p *parser) denyallow() {
	for _, d := range p.lineOpts.denyallow {
		if n := normalize(d); n != "" {
			p.aWild[n] = struct{}{}
		}
	}
}

func (p *parser) finish() *Entries {
	out := p.out
	out.Exact = make([]string, 0, len(p.exact))
	for d := range p.exact {
		if _, ok := p.wild[d]; !ok {
			out.Exact = append(out.Exact, d)
		}
	}
	out.Wildcard = make([]string, 0, len(p.wild))
	for d := range p.wild {
		out.Wildcard = append(out.Wildcard, d)
	}
	out.Regex = make([]string, 0, len(p.regex))
	for r := range p.regex {
		out.Regex = append(out.Regex, r)
	}
	out.AllowExact = keys(p.aExact)
	out.AllowWildcard = keys(p.aWild)
	out.AllowRegex = keys(p.aRegex)
	out.Important = p.imp
	out.Skipped = p.skipped
	return out
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func isNullAddress(ip string) bool {
	switch ip {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "0.0.0.0.0", "255.255.255.255", "0", "127.0.0.2":
		return true
	}
	return false
}

func looksLikeIP(s string) bool {
	if strings.Count(s, ":") >= 2 {
		return true
	}
	if isAllDigitsAndDots(s) && strings.Count(s, ".") == 3 {
		return true
	}
	return false
}

func isHostsNoise(h string) bool {
	switch h {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
		"ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0":
		return true
	}
	return false
}

// TooBroad rejects a pattern that would match ordinary names. A list
// entry has no business matching example.com, and one that does is a
// parse artefact or a typo that would take the network offline.
func TooBroad(re *compiledRegex) bool {
	for _, probe := range []string{"example.com", "www.example.org", "a.b", "orbis.invalid"} {
		if re.MatchString(probe) {
			return true
		}
	}
	return false
}
