//go:build !linux

package flows

import (
	"errors"
	"net"
	"net/netip"

	"github.com/Neoo-Blue/orbis/internal/dpi"
)

// The capture path is AF_PACKET-specific. On other platforms the daemon still
// builds and runs — useful for developing the UI and the API against a copied
// database — but reports capture as unavailable instead of silently showing
// an empty flow table.

type CaptureStats struct {
	Packets      int64  `json:"packets"`
	Bytes        int64  `json:"bytes"`
	Truncated    int64  `json:"truncated"`
	KernelDrops  uint32 `json:"kernel_drops"`
	ParseErrors  int64  `json:"parse_errors"`
	Interfaces   int    `json:"interfaces"`
	FilterActive bool   `json:"filter_active"`
}

type Capturer struct {
	tracker *Tracker
	log     func(string, ...any)
}

func NewCapturer(t *Tracker, snapLen int, ifaces []string, log func(string, ...any)) *Capturer {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Capturer{tracker: t, log: log}
}

func (c *Capturer) SetHTTPHook(fn func(netip.Addr, *dpi.HTTPRequest)) {}
func (c *Capturer) AddInterfaces(names []string)                      {}

func (c *Capturer) Start() error {
	return errors.New("packet capture requires Linux (AF_PACKET)")
}

func (c *Capturer) Stop()               {}
func (c *Capturer) Stats() CaptureStats { return CaptureStats{} }

// LocalPrefixesExcluding is LocalPrefixes with named interfaces left out,
// used where tunnel addresses must not be treated as part of the LAN.
func LocalPrefixesExcluding(skip map[string]bool) []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || skip[i.Name] {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(ipnet.String()); err == nil {
					out = append(out, p.Masked().String())
				}
			}
		}
	}
	return out
}

func LocalPrefixes() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(ipnet.String()); err == nil {
					out = append(out, p.Masked().String())
				}
			}
		}
	}
	return out
}
