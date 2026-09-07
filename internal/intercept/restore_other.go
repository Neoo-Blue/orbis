//go:build !linux

package intercept

import (
	"context"
	"fmt"
	"net/netip"
)

// Restore needs raw sockets, which only the Linux build has.
func Restore(ctx context.Context, ifaceName string, gateway netip.Addr, targets []Target, log func(string, ...any)) (int, error) {
	return 0, fmt.Errorf("ARP restore is only available on Linux")
}

func RestoreFromMarker(ctx context.Context, path string, log func(string, ...any)) (int, error) {
	m, err := ReadMarker(path)
	if err != nil || m == nil {
		return 0, err
	}
	return 0, fmt.Errorf("ARP restore is only available on Linux")
}
