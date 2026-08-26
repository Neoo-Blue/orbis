package geoip

import "net/netip"

// WellKnownName labels the addresses that show up constantly on any network
// but are not "destinations" in any meaningful sense. Without this they fill
// the connection log as bare addresses and the operator has to recognise
// 224.0.0.251 by sight.
func WellKnownName(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if name, ok := wellKnown[addr]; ok {
		return name
	}
	switch {
	case addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return "link-local multicast"
	case addr.IsMulticast():
		return "multicast"
	case addr.Is4() && addr.As4() == [4]byte{255, 255, 255, 255}:
		return "broadcast"
	case addr.IsLinkLocalUnicast():
		return "link-local"
	}
	return ""
}

var wellKnown = map[netip.Addr]string{
	netip.MustParseAddr("224.0.0.251"):     "mDNS (Bonjour)",
	netip.MustParseAddr("ff02::fb"):        "mDNS (Bonjour)",
	netip.MustParseAddr("224.0.0.252"):     "LLMNR",
	netip.MustParseAddr("ff02::1:3"):       "LLMNR",
	netip.MustParseAddr("239.255.255.250"): "SSDP (UPnP discovery)",
	netip.MustParseAddr("ff02::c"):         "SSDP (UPnP discovery)",
	netip.MustParseAddr("224.0.0.1"):       "all hosts",
	netip.MustParseAddr("224.0.0.2"):       "all routers",
	netip.MustParseAddr("224.0.0.22"):      "IGMP",
	netip.MustParseAddr("224.0.0.9"):       "RIPv2",
	netip.MustParseAddr("224.0.1.1"):       "NTP multicast",
	netip.MustParseAddr("ff02::1"):         "all nodes",
	netip.MustParseAddr("ff02::2"):         "all routers",
	netip.MustParseAddr("ff02::16"):        "MLDv2",
	netip.MustParseAddr("ff02::1:2"):       "DHCPv6 relay",
	netip.MustParseAddr("224.0.0.18"):      "VRRP",
	netip.MustParseAddr("224.0.0.102"):     "HSRP/GLBP",
}

// PublicAddrOf returns the first globally-routable address from a list, which
// is how the node locates itself on the globe without asking an external
// service where it is.
func PublicAddrOf(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if a.IsValid() && !IsPrivate(a) {
			return a, true
		}
	}
	return netip.Addr{}, false
}
