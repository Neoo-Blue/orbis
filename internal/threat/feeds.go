package threat

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// reservedV4 are ranges no feed should ever make this node drop: private
// space, this host, link-local, documentation, benchmarking, multicast and
// the class E block. Aggregated feeds carry some of these as anti-spoofing
// bogons, which is a WAN-edge concern, not this node's.
var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

var (
	globalV6   = netip.MustParsePrefix("2000::/3")
	docV6      = netip.MustParsePrefix("2001:db8::/32")
	teredoV6   = netip.MustParsePrefix("2001::/32")
	sixToFour4 = netip.MustParsePrefix("2002::/16")
)

// Usable reports whether a prefix may be enforced: valid, publicly routable,
// and not so wide that a broken feed could black out the internet.
func Usable(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	a := p.Addr().Unmap()
	p = netip.PrefixFrom(a, p.Bits()-(p.Addr().BitLen()-a.BitLen()))
	if a.Is4() {
		if p.Bits() < 8 {
			return false
		}
		for _, r := range reservedV4 {
			if r.Overlaps(p) {
				return false
			}
		}
		return true
	}
	if p.Bits() < 16 || !globalV6.Contains(a) {
		return false
	}
	if docV6.Overlaps(p) || teredoV6.Overlaps(p) || sixToFour4.Overlaps(p) {
		return false
	}
	return true
}

// ParsePrefix accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::1" or a v6 CIDR.
func ParsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		a := p.Addr().Unmap()
		return netip.PrefixFrom(a, p.Bits()-(p.Addr().BitLen()-a.BitLen())).Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// ParseFeed reads the formats address feeds ship in: one address or CIDR per
// line, comments after # or ;, anything after the first field ignored. It
// returns the usable prefixes in file order without duplicates, and how many
// lines were skipped as unparseable or unenforceable.
func ParseFeed(r io.Reader) (prefixes []netip.Prefix, skipped int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := map[netip.Prefix]bool{}
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field := strings.Fields(line)[0]
		p, ok := ParsePrefix(field)
		if !ok || !Usable(p) {
			skipped++
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		prefixes = append(prefixes, p)
	}
	return prefixes, skipped
}
