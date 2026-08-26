//go:build !linux

package mitm

import "net"

// Transparent redirection is a netfilter feature; elsewhere the proxy can only
// serve explicitly-configured clients, so the local address is the best answer.
func originalDestination(conn net.Conn) (string, error) {
	return conn.LocalAddr().String(), nil
}
