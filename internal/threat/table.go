// Package threat is IP-level threat intelligence for the gateway: address
// feeds (hijacked netblocks, live command servers, addresses seen attacking),
// timed ban decisions from the operator, the assistant, the anomaly detector
// or a CrowdSec engine, and the lookups that turn a new connection into a
// recorded hit and, where this node is in the path, a dropped packet.
package threat

import (
	"net/netip"
	"sort"
)

// Entry is one listed prefix and where it came from.
type Entry struct {
	Prefix netip.Prefix
	// Source is the feed name or the decision source (manual, assistant,
	// scan, crowdsec).
	Source string
	// Reason is a category for a feed entry or the stated reason of a ban.
	Reason string
}

// Table answers "is this address listed" in constant-ish time: exact hosts in
// maps, ranges bucketed by their leading octet (v4) or leading 16 bits (v6),
// and the handful of very wide ranges scanned last.
type Table struct {
	v4exact map[netip.Addr]Entry
	v6exact map[netip.Addr]Entry
	v4      map[uint8][]Entry
	v6      map[uint16][]Entry
	v4wide  []Entry
	v6wide  []Entry
	count   int
}

// Build indexes entries, dropping any that overlap an allowed prefix. It
// returns the table and how many entries the allow list excluded.
func Build(entries []Entry, allow []netip.Prefix) (*Table, int) {
	t := &Table{
		v4exact: map[netip.Addr]Entry{}, v6exact: map[netip.Addr]Entry{},
		v4: map[uint8][]Entry{}, v6: map[uint16][]Entry{},
	}
	excluded := 0
	seen := map[netip.Prefix]bool{}
	for _, e := range entries {
		p := e.Prefix.Masked()
		if !p.IsValid() || seen[p] {
			continue
		}
		if overlapsAny(p, allow) {
			excluded++
			continue
		}
		seen[p] = true
		e.Prefix = p
		t.count++
		a := p.Addr()
		switch {
		case a.Is4() && p.Bits() == 32:
			t.v4exact[a] = e
		case a.Is4() && p.Bits() >= 8:
			t.v4[a.As4()[0]] = append(t.v4[a.As4()[0]], e)
		case a.Is4():
			t.v4wide = append(t.v4wide, e)
		case p.Bits() == 128:
			t.v6exact[a] = e
		case p.Bits() >= 16:
			b := a.As16()
			key := uint16(b[0])<<8 | uint16(b[1])
			t.v6[key] = append(t.v6[key], e)
		default:
			t.v6wide = append(t.v6wide, e)
		}
	}
	return t, excluded
}

func overlapsAny(p netip.Prefix, allow []netip.Prefix) bool {
	for _, a := range allow {
		if a.Overlaps(p) {
			return true
		}
	}
	return false
}

// Lookup reports whether an address is listed and by what.
func (t *Table) Lookup(a netip.Addr) (Entry, bool) {
	if t == nil || !a.IsValid() {
		return Entry{}, false
	}
	a = a.Unmap()
	if a.Is4() {
		if e, ok := t.v4exact[a]; ok {
			return e, true
		}
		for _, e := range t.v4[a.As4()[0]] {
			if e.Prefix.Contains(a) {
				return e, true
			}
		}
		for _, e := range t.v4wide {
			if e.Prefix.Contains(a) {
				return e, true
			}
		}
		return Entry{}, false
	}
	if e, ok := t.v6exact[a]; ok {
		return e, true
	}
	b := a.As16()
	for _, e := range t.v6[uint16(b[0])<<8|uint16(b[1])] {
		if e.Prefix.Contains(a) {
			return e, true
		}
	}
	for _, e := range t.v6wide {
		if e.Prefix.Contains(a) {
			return e, true
		}
	}
	return Entry{}, false
}

// Len is the number of distinct listed prefixes.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return t.count
}

// Elements renders the table as nftables set elements, sorted so two builds
// of the same data produce the same script.
func (t *Table) Elements() (v4, v6 []string) {
	if t == nil {
		return nil, nil
	}
	add := func(dst *[]string, p netip.Prefix) {
		if (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 128) {
			*dst = append(*dst, p.Addr().String())
		} else {
			*dst = append(*dst, p.String())
		}
	}
	for a := range t.v4exact {
		add(&v4, netip.PrefixFrom(a, 32))
	}
	for _, list := range t.v4 {
		for _, e := range list {
			add(&v4, e.Prefix)
		}
	}
	for _, e := range t.v4wide {
		add(&v4, e.Prefix)
	}
	for a := range t.v6exact {
		add(&v6, netip.PrefixFrom(a, 128))
	}
	for _, list := range t.v6 {
		for _, e := range list {
			add(&v6, e.Prefix)
		}
	}
	for _, e := range t.v6wide {
		add(&v6, e.Prefix)
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}
