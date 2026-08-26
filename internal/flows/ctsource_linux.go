//go:build linux

package flows

// netlinkSource adapts the ctnetlink client to the poller's source signature.
type netlinkSource struct {
	nl *ConntrackNetlink
}

func newNetlinkSource() (*netlinkSource, error) {
	nl, err := NewConntrackNetlink()
	if err != nil {
		return nil, err
	}
	return &netlinkSource{nl: nl}, nil
}

func (s *netlinkSource) dump() ([]CTEntry, bool, error) {
	entries, err := s.nl.Dump()
	if err != nil {
		return nil, false, err
	}
	// Accounting is on if any entry reports a non-zero byte count. A brand
	// new table can legitimately be all zeros, so this only reports false
	// once there is something to look at.
	acct := false
	for _, e := range entries {
		if e.BytesOrig > 0 || e.BytesReply > 0 {
			acct = true
			break
		}
	}
	return entries, acct, nil
}

func (s *netlinkSource) close() { _ = s.nl.Close() }
