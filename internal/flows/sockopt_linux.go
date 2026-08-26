//go:build linux

package flows

import (
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// bpfRawInstruction mirrors struct sock_filter. x/net/bpf already produces
// this layout; the alias keeps the capture code readable.
type bpfRawInstruction = bpf.RawInstruction

// sockFprog is struct sock_fprog from <linux/filter.h>.
type sockFprog struct {
	Len    uint16
	pad    [6]byte
	Filter *bpfRawInstruction
}

// setBPF attaches a classic BPF program to a socket and locks it, so nothing
// can later swap in a permissive filter.
func setBPF(fd int, prog []bpfRawInstruction) error {
	if len(prog) == 0 {
		return nil
	}
	fprog := sockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_SOCKET), uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&fprog)), unsafe.Sizeof(fprog), 0)
	if errno != 0 {
		return errno
	}
	// Draining anything queued before the filter was attached would let a
	// pre-filter packet through; the socket is unbound at this point so the
	// queue is empty, and locking prevents later replacement.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_LOCK_FILTER, 1); err != nil {
		// Older kernels lack SO_LOCK_FILTER. The filter is still attached.
		_ = err
	}
	return nil
}

// packetStats is struct tpacket_stats.
type packetStats struct {
	Packets uint32
	Drops   uint32
}

func getPacketStats(fd int) (packetStats, error) {
	var st packetStats
	size := uint32(unsafe.Sizeof(st))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_PACKET), uintptr(unix.PACKET_STATISTICS),
		uintptr(unsafe.Pointer(&st)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return st, errno
	}
	return st, nil
}
