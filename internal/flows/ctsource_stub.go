//go:build !linux

package flows

import "errors"

// Conntrack is a netfilter feature; there is nothing to read elsewhere.
type netlinkSource struct{}

func newNetlinkSource() (*netlinkSource, error) { return nil, errors.New("conntrack requires Linux") }
func (s *netlinkSource) dump() ([]CTEntry, bool, error) {
	return nil, false, errors.New("conntrack requires Linux")
}
func (s *netlinkSource) close() {}
