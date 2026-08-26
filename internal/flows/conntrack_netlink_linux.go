//go:build linux

package flows

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Reading the kernel connection table over NFNETLINK_CONNTRACK rather than
// /proc/net/nf_conntrack.
//
// The procfs interface needs CONFIG_NF_CONNTRACK_PROCFS, which current Debian,
// Ubuntu and Proxmox kernels ship disabled — the file simply does not exist.
// Netlink is the supported interface, it is what the conntrack(8) tool uses,
// and it avoids forking a process every couple of seconds to parse text.

const (
	netlinkNetfilter = 12 // NETLINK_NETFILTER

	nfnlSubsysCTNetlink = 1 // NFNL_SUBSYS_CTNETLINK
	ipctnlMsgCTGet      = 1 // IPCTNL_MSG_CT_GET

	// Top-level CTA_* attributes.
	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaStatus        = 3
	ctaTimeout       = 7
	ctaCountersOrig  = 9
	ctaCountersReply = 10

	// Nested inside a tuple.
	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	ctaCountersPackets   = 1
	ctaCountersBytes     = 2
	ctaCounters32Packets = 3
	ctaCounters32Bytes   = 4

	// Netlink attribute header flags that must be masked off the type.
	nlaFNested       = 0x8000
	nlaFNetByteOrder = 0x4000
	nlaTypeMask      = ^uint16(nlaFNested | nlaFNetByteOrder)
)

// nfgenmsg is the netfilter generic message header that follows nlmsghdr.
type nfgenmsg struct {
	Family  uint8
	Version uint8
	ResID   uint16 // big-endian on the wire
}

// ConntrackNetlink holds a persistent socket. Reconnecting per poll would
// cost a syscall round trip and, worse, lose the receive buffer sizing.
type ConntrackNetlink struct {
	mu  sync.Mutex
	fd  int
	seq uint32
	buf []byte
}

func NewConntrackNetlink() (*ConntrackNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// A dump of a busy table is large; a small buffer turns into ENOBUFS
	// and a silently truncated view of the network.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8*1024*1024)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8*1024*1024)
	tv := unix.Timeval{Sec: 5}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	return &ConntrackNetlink{fd: fd, buf: make([]byte, 512*1024)}, nil
}

func (c *ConntrackNetlink) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd >= 0 {
		err := unix.Close(c.fd)
		c.fd = -1
		return err
	}
	return nil
}

// Dump requests the whole connection table and returns the parsed entries.
func (c *ConntrackNetlink) Dump() ([]CTEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil, os.ErrClosed
	}

	c.seq++
	req := make([]byte, unix.NLMSG_HDRLEN+4)
	binary.LittleEndian.PutUint32(req[0:4], uint32(len(req)))                        // nlmsg_len
	binary.LittleEndian.PutUint16(req[4:6], (nfnlSubsysCTNetlink<<8)|ipctnlMsgCTGet) // nlmsg_type
	binary.LittleEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)      // nlmsg_flags
	binary.LittleEndian.PutUint32(req[8:12], c.seq)                                  // nlmsg_seq
	binary.LittleEndian.PutUint32(req[12:16], 0)                                     // nlmsg_pid
	// nfgenmsg: AF_UNSPEC dumps both IPv4 and IPv6 in one pass.
	req[16] = unix.AF_UNSPEC
	req[17] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(req[18:20], 0)

	if err := unix.Sendto(c.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("conntrack dump request: %w", err)
	}

	var entries []CTEntry
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, 0)
		if err != nil {
			if err == unix.ENOBUFS {
				// The kernel dropped messages because our buffer filled.
				// Returning what we have is better than nothing; the next
				// poll starts clean.
				return entries, nil
			}
			return entries, fmt.Errorf("conntrack dump read: %w", err)
		}
		if n < unix.NLMSG_HDRLEN {
			break
		}

		done := false
		data := c.buf[:n]
		for len(data) >= unix.NLMSG_HDRLEN {
			msgLen := int(binary.LittleEndian.Uint32(data[0:4]))
			msgType := binary.LittleEndian.Uint16(data[4:6])
			if msgLen < unix.NLMSG_HDRLEN || msgLen > len(data) {
				break
			}
			payload := data[unix.NLMSG_HDRLEN:msgLen]

			switch msgType {
			case unix.NLMSG_DONE:
				done = true
			case unix.NLMSG_ERROR:
				if len(payload) >= 4 {
					if errno := int32(binary.LittleEndian.Uint32(payload[0:4])); errno != 0 {
						return entries, fmt.Errorf("conntrack dump: %w", unix.Errno(-errno))
					}
				}
				done = true
			default:
				// nfgenmsg is 4 bytes, then the attribute stream.
				if len(payload) > 4 {
					if e, ok := parseCTEntry(payload[4:]); ok {
						entries = append(entries, e)
					}
				}
			}

			// Messages are aligned to 4 bytes.
			aligned := (msgLen + 3) &^ 3
			if aligned > len(data) {
				break
			}
			data = data[aligned:]
		}
		if done {
			break
		}
	}
	return entries, nil
}

// parseCTEntry walks the attribute stream of one conntrack entry.
func parseCTEntry(attrs []byte) (CTEntry, bool) {
	var e CTEntry
	var haveOrig bool

	forEachAttr(attrs, func(t uint16, v []byte) {
		switch t {
		case ctaTupleOrig:
			if src, dst, sport, dport, proto, ok := parseTuple(v); ok {
				e.SrcIP, e.DstIP = src, dst
				e.SrcPort, e.DstPort = sport, dport
				e.Proto = proto
				haveOrig = true
			}
		case ctaCountersOrig:
			e.PacketsOrig, e.BytesOrig = parseCounters(v)
		case ctaCountersReply:
			e.PacketsReply, e.BytesReply = parseCounters(v)
		case ctaTimeout:
			if len(v) >= 4 {
				e.Timeout = int(binary.BigEndian.Uint32(v))
			}
		case ctaStatus:
			if len(v) >= 4 {
				// IPS_ASSURED (0x04) marks a connection that has seen
				// traffic both ways, which is the useful "established"
				// signal without decoding the full protocol state.
				if binary.BigEndian.Uint32(v)&0x04 != 0 {
					e.State = "ASSURED"
				}
			}
		}
	})
	return e, haveOrig && e.SrcIP.IsValid() && e.DstIP.IsValid()
}

func parseTuple(b []byte) (src, dst netip.Addr, sport, dport uint16, proto uint8, ok bool) {
	forEachAttr(b, func(t uint16, v []byte) {
		switch t {
		case ctaTupleIP:
			forEachAttr(v, func(it uint16, iv []byte) {
				switch it {
				case ctaIPv4Src:
					if len(iv) == 4 {
						src, _ = netip.AddrFromSlice(iv)
					}
				case ctaIPv4Dst:
					if len(iv) == 4 {
						dst, _ = netip.AddrFromSlice(iv)
					}
				case ctaIPv6Src:
					if len(iv) == 16 {
						src, _ = netip.AddrFromSlice(iv)
					}
				case ctaIPv6Dst:
					if len(iv) == 16 {
						dst, _ = netip.AddrFromSlice(iv)
					}
				}
			})
		case ctaTupleProto:
			forEachAttr(v, func(pt uint16, pv []byte) {
				switch pt {
				case ctaProtoNum:
					if len(pv) >= 1 {
						proto = pv[0]
					}
				case ctaProtoSrcPort:
					if len(pv) >= 2 {
						sport = binary.BigEndian.Uint16(pv)
					}
				case ctaProtoDstPort:
					if len(pv) >= 2 {
						dport = binary.BigEndian.Uint16(pv)
					}
				}
			})
		}
	})
	return src, dst, sport, dport, proto, src.IsValid() && dst.IsValid()
}

func parseCounters(b []byte) (packets, bytes int64) {
	forEachAttr(b, func(t uint16, v []byte) {
		switch t {
		case ctaCountersPackets:
			if len(v) >= 8 {
				packets = int64(binary.BigEndian.Uint64(v))
			}
		case ctaCountersBytes:
			if len(v) >= 8 {
				bytes = int64(binary.BigEndian.Uint64(v))
			}
		case ctaCounters32Packets:
			if len(v) >= 4 {
				packets = int64(binary.BigEndian.Uint32(v))
			}
		case ctaCounters32Bytes:
			if len(v) >= 4 {
				bytes = int64(binary.BigEndian.Uint32(v))
			}
		}
	})
	return packets, bytes
}

// forEachAttr walks a netlink attribute stream, masking the nested and
// byte-order flags off each type. Bounds are checked on every step because
// this is kernel-supplied data being decoded in a long-running daemon.
func forEachAttr(b []byte, fn func(t uint16, v []byte)) {
	for len(b) >= 4 {
		length := int(binary.LittleEndian.Uint16(b[0:2]))
		typ := binary.LittleEndian.Uint16(b[2:4]) & nlaTypeMask
		if length < 4 || length > len(b) {
			return
		}
		fn(typ, b[4:length])
		aligned := (length + 3) &^ 3
		if aligned >= len(b) {
			return
		}
		b = b[aligned:]
	}
}
