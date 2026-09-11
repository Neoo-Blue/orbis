package intercept

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	arpHardwareEthernet = 1
	arpProtocolIPv4     = 0x0800

	arpOpRequest = 1
	arpOpReply   = 2
	etherTypeARP = 0x0806
	hwLen        = 6
	protoLen     = 4
)

// buildARP builds a full Ethernet + ARP frame. The Ethernet source is the
// sender's MAC, which is right only when the sender is this node.
func buildARP(op int, senderMAC net.HardwareAddr, senderIP netip.Addr,
	targetMAC net.HardwareAddr, targetIP netip.Addr) []byte {

	frame := make([]byte, 14+28)

	// Ethernet header.
	copy(frame[0:6], targetMAC)
	copy(frame[6:12], senderMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	// ARP payload.
	p := frame[14:]
	binary.BigEndian.PutUint16(p[0:2], arpHardwareEthernet)
	binary.BigEndian.PutUint16(p[2:4], arpProtocolIPv4)
	p[4] = hwLen
	p[5] = protoLen
	binary.BigEndian.PutUint16(p[6:8], uint16(op))
	copy(p[8:14], senderMAC)
	sip := senderIP.As4()
	copy(p[14:18], sip[:])
	copy(p[18:24], targetMAC)
	tip := targetIP.As4()
	copy(p[24:28], tip[:])
	return frame
}

// truthFrames are the frames that put a device back on the real gateway: an
// ARP reply addressed to its current address, and a gratuitous announcement of
// the gateway, both delivered only to that device. A Windows laptop kept
// routing through this node after restores that named an address it no longer
// held (its connections kept working through us, so it never asked again); it
// moved back once it got both frames at its current address.
//
// The gateway's MAC goes only in the ARP payload, which is what the device's
// cache reads. The Ethernet source stays this node's own MAC (ethSrc): a frame
// sourced from the router's MAC would teach every switch between here and the
// router that the router lives on this node's port, and the whole LAN's
// gateway traffic would follow it until the router next transmitted.
func truthFrames(ethSrc, gwMAC net.HardwareAddr, gateway netip.Addr, t Target) [][]byte {
	reply := buildARP(arpOpReply, gwMAC, gateway, t.MAC, t.IP)
	announce := buildARP(arpOpRequest, gwMAC, gateway, make(net.HardwareAddr, hwLen), gateway)
	for _, f := range [][]byte{reply, announce} {
		copy(f[0:6], t.MAC)
		copy(f[6:12], ethSrc)
	}
	return [][]byte{reply, announce}
}
