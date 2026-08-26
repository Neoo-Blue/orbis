//go:build linux || darwin

package flows

import (
	"os"
	"syscall"
)

// interruptSignal is SIGINT, which makes tcpdump flush and exit cleanly so the
// partial capture is a valid pcap file rather than a truncated one.
func interruptSignal() os.Signal { return syscall.SIGINT }
