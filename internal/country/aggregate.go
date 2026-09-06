package country

import (
	"net/netip"
	"sort"
)

// Aggregate collapses a list of prefixes: drops any contained in another and
// merges sibling pairs into their parent, repeatedly, so a country that the
// city-level database splits into a hundred thousand fragments becomes a
// list the packet filter loads in a second.
func Aggregate(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() {
			ps = append(ps, p.Masked())
		}
	}
	for {
		sort.Slice(ps, func(i, j int) bool {
			a, b := ps[i].Addr(), ps[j].Addr()
			if c := a.Compare(b); c != 0 {
				return c < 0
			}
			return ps[i].Bits() < ps[j].Bits()
		})
		// Drop prefixes contained in the one before them.
		kept := ps[:0]
		for _, p := range ps {
			if n := len(kept); n > 0 && kept[n-1].Contains(p.Addr()) && kept[n-1].Bits() <= p.Bits() {
				continue
			}
			kept = append(kept, p)
		}
		ps = kept
		// Merge siblings: two prefixes of the same length whose parent is
		// the same become the parent.
		merged := make([]netip.Prefix, 0, len(ps))
		changed := false
		for i := 0; i < len(ps); i++ {
			if i+1 < len(ps) && ps[i].Bits() == ps[i+1].Bits() && ps[i].Bits() > 0 {
				parent := netip.PrefixFrom(ps[i].Addr(), ps[i].Bits()-1).Masked()
				if parent == netip.PrefixFrom(ps[i+1].Addr(), ps[i+1].Bits()-1).Masked() && parent.Addr() == ps[i].Addr() {
					merged = append(merged, parent)
					changed = true
					i++
					continue
				}
			}
			merged = append(merged, ps[i])
		}
		ps = merged
		if !changed {
			return ps
		}
	}
}
