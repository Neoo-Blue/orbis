//go:build linux

package mitm

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// originalDestination recovers the address the client was actually trying to
// reach, before nftables redirected the connection here. Without it a
// transparent proxy has no idea where to forward a connection it decides not
// to intercept.
func originalDestination(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr string
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// IPv6 sockets accepting a v4-mapped connection still answer the v4
		// option, so try it first and fall back.
		if a, e := getOrigDst4(int(fd)); e == nil {
			addr = a
			return
		}
		if a, e := getOrigDst6(int(fd)); e == nil {
			addr = a
			return
		} else {
			sockErr = e
		}
	})
	if err != nil {
		return "", err
	}
	if addr == "" {
		if sockErr != nil {
			return "", sockErr
		}
		// Falling back to the socket's own local address is correct for a
		// non-redirected (explicitly proxied) connection.
		return conn.LocalAddr().String(), nil
	}
	return addr, nil
}

// ntohs converts a network-byte-order value held in a native uint16.
func ntohs(v uint16) uint16 { return v<<8 | v>>8 }

func getOrigDst4(fd int) (string, error) {
	sa, err := unix.GetsockoptIPv6Mreq(fd, unix.SOL_IP, unix.SO_ORIGINAL_DST)
	if err != nil {
		return "", err
	}
	// The kernel returns a sockaddr_in packed into the mreq struct.
	port := binary.BigEndian.Uint16(sa.Multiaddr[2:4])
	ip := net.IPv4(sa.Multiaddr[4], sa.Multiaddr[5], sa.Multiaddr[6], sa.Multiaddr[7])
	if ip.IsUnspecified() || port == 0 {
		return "", fmt.Errorf("no original destination")
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
}

func getOrigDst6(fd int) (string, error) {
	// SOL_IPV6 = 41, IP6T_SO_ORIGINAL_DST = 80
	const solIPv6 = 41
	const ip6tOrigDst = 80
	sa, err := unix.GetsockoptIPv6MTUInfo(fd, solIPv6, ip6tOrigDst)
	if err != nil {
		return "", err
	}
	// sin6_port sits in the struct in network byte order; reading it as a
	// native uint16 on a little-endian host yields the bytes reversed.
	p := ntohs(sa.Addr.Port)
	ip := net.IP(sa.Addr.Addr[:])
	if ip.IsUnspecified() {
		return "", fmt.Errorf("no original destination")
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(p)), nil
}
