// Package topology works out what the devices on a network actually are and
// how they relate, so the map shows "Proxmox host with nine containers" rather
// than nineteen anonymous dots.
//
// Classification is evidence-based and says how it knows. A MAC prefix is a
// strong signal about the hypervisor that minted an interface but says nothing
// about what runs inside it; an open port on 8006 is near-proof of Proxmox but
// only if something answered. Every verdict carries its evidence and a
// confidence, because a topology map that quietly guesses is worse than one
// that admits what it could not determine.
package topology

import (
	"sort"
	"strings"
)

// Role is what a device does on the network.
type Role string

const (
	RoleGateway     Role = "gateway"
	RoleHypervisor  Role = "hypervisor"
	RoleVM          Role = "vm"
	RoleContainer   Role = "container"
	RoleServer      Role = "server"
	RoleNAS         Role = "nas"
	RoleWorkstation Role = "workstation"
	RoleMobile      Role = "mobile"
	RoleIoT         Role = "iot"
	RolePrinter     Role = "printer"
	RoleAP          Role = "access_point"
	RoleUnknown     Role = "unknown"
)

// Confidence separates what was proven from what was inferred.
type Confidence string

const (
	Confirmed Confidence = "confirmed" // a service answered, or DHCP said so
	Inferred  Confidence = "inferred"  // a MAC prefix or behaviour suggests it
	Guessed   Confidence = "guessed"   // weakest signal, shown but not relied on
)

// virtualOUI maps a MAC prefix to the platform that generated it. These are
// the ranges hypervisors mint addresses from, so a match tells you an
// interface is virtual and who made it, but nothing about the guest OS.
var virtualOUI = map[string]string{
	"bc:24:11": "Proxmox VE",
	"00:15:5d": "Hyper-V",
	"52:54:00": "KVM/QEMU",
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"00:05:69": "VMware",
	"00:1c:14": "VMware",
	"08:00:27": "VirtualBox",
	"0a:00:27": "VirtualBox",
	"02:42:ac": "Docker",
	"00:16:3e": "Xen/LXC",
	"00:03:ff": "Hyper-V (legacy)",
	"00:1c:42": "Parallels",
	"00:21:f6": "Oracle VM",
}

// probePort is a port worth knocking on, with what an answer implies.
type probePort struct {
	Port     int
	Service  string
	Role     Role
	Platform string
	// Strong marks a port that is close to proof rather than a hint. 8006 is
	// only ever Proxmox; 22 is on almost everything.
	Strong bool
}

// ProbePorts is deliberately short. A full scan of a home network is slow,
// looks like an attack to anything watching, and adds little: the ports below
// separate a hypervisor from a NAS from a workstation, which is the whole job.
var ProbePorts = []probePort{
	{8006, "Proxmox VE", RoleHypervisor, "Proxmox VE", true},
	{5985, "WinRM", RoleHypervisor, "Hyper-V", false},
	{5986, "WinRM (TLS)", RoleHypervisor, "Hyper-V", false},
	{902, "VMware ESXi", RoleHypervisor, "VMware ESXi", true},
	{5000, "Synology DSM", RoleNAS, "Synology", false},
	{5001, "Synology DSM (TLS)", RoleNAS, "Synology", false},
	{445, "SMB", RoleNAS, "", false},
	{2049, "NFS", RoleNAS, "", false},
	{22, "SSH", RoleServer, "", false},
	{3389, "RDP", RoleWorkstation, "Windows", false},
	{80, "HTTP", RoleServer, "", false},
	{443, "HTTPS", RoleServer, "", false},
	{9100, "JetDirect", RolePrinter, "", true},
	{631, "IPP", RolePrinter, "", false},
	{53, "DNS", RoleServer, "", false},
	{8080, "HTTP alt", RoleServer, "", false},
}

// Signals is everything known about one device before classification.
type Signals struct {
	IP         string
	MAC        string
	Hostname   string
	Vendor     string
	OSGuess    string
	DeviceType string
	// OpenPorts is what answered a probe. Empty means not scanned, which is
	// not the same as nothing listening.
	OpenPorts []int
	Scanned   bool
	// IsGateway is set when this address is the network's default route.
	IsGateway bool
	// ConnsIn counts connections opened towards this device, which is what
	// separates something being used from something merely running.
	ConnsIn  int
	ConnsOut int
}

// Verdict is the classification result.
type Verdict struct {
	Role       Role       `json:"role"`
	Platform   string     `json:"platform,omitempty"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence"`
	// Virtual marks an interface minted by a hypervisor.
	Virtual bool `json:"virtual"`
}

// Classify decides what a device is from whatever signals exist.
//
// Order matters: the gateway is known from routing rather than guessed, an
// answering service beats a MAC prefix, and a MAC prefix beats behaviour. The
// first strong signal wins and the rest becomes supporting evidence.
func Classify(s Signals) Verdict {
	v := Verdict{Role: RoleUnknown, Confidence: Guessed}
	ev := []string{}

	mac := strings.ToLower(strings.TrimSpace(s.MAC))
	oui := ""
	if len(mac) >= 8 {
		oui = mac[:8]
	}
	platform, isVirtual := virtualOUI[oui]
	if isVirtual {
		v.Virtual = true
		v.Platform = platform
		ev = append(ev, "MAC prefix "+oui+" belongs to "+platform)
	}

	// 1. The gateway is a fact from the routing table, not an inference.
	if s.IsGateway {
		v.Role = RoleGateway
		v.Confidence = Confirmed
		v.Evidence = append(ev, "is this network's default route")
		return v
	}

	// 2. A service that answered. Strong ports settle it outright.
	byPort := map[int]probePort{}
	for _, p := range ProbePorts {
		byPort[p.Port] = p
	}
	var best *probePort
	for _, port := range s.OpenPorts {
		p, ok := byPort[port]
		if !ok {
			continue
		}
		ev = append(ev, "port "+itoa(port)+" open ("+p.Service+")")
		if best == nil || (p.Strong && !best.Strong) {
			cp := p
			best = &cp
		}
	}
	if best != nil && best.Strong {
		v.Role = best.Role
		if best.Platform != "" {
			v.Platform = best.Platform
		}
		v.Confidence = Confirmed
		v.Evidence = ev
		return v
	}

	// 3. A virtual MAC means a guest. Which kind depends on the platform:
	//    Proxmox mints the same prefix for VMs and containers, so calling it
	//    a container would be a guess dressed as a fact.
	if isVirtual {
		switch platform {
		case "Docker":
			v.Role = RoleContainer
		case "Proxmox VE", "Xen/LXC":
			v.Role = RoleVM // covers containers too; see Guest note in the UI
		default:
			v.Role = RoleVM
		}
		v.Confidence = Inferred
		// A guest that also answers on a service port is a server that happens
		// to be virtual, which is more useful than "a VM".
		if best != nil {
			v.Role = best.Role
			v.Confidence = Confirmed
		}
		v.Evidence = ev
		return v
	}

	// 4. A weak service hint.
	if best != nil {
		v.Role = best.Role
		if best.Platform != "" {
			v.Platform = best.Platform
		}
		v.Confidence = Inferred
		v.Evidence = ev
		return v
	}

	// 5. Fall back to what the DHCP fingerprint and user agent suggested.
	switch strings.ToLower(s.DeviceType) {
	case "laptop", "desktop":
		v.Role = RoleWorkstation
		v.Confidence = Inferred
		ev = append(ev, "device fingerprint says "+s.DeviceType)
	case "phone", "tablet", "mobile":
		v.Role = RoleMobile
		v.Confidence = Inferred
		ev = append(ev, "device fingerprint says "+s.DeviceType)
	case "server":
		v.Role = RoleServer
		v.Confidence = Inferred
		ev = append(ev, "device fingerprint says server")
	}
	if v.Role == RoleUnknown && s.Vendor != "" {
		if r, why := roleFromVendor(s.Vendor); r != RoleUnknown {
			v.Role = r
			v.Confidence = Guessed
			ev = append(ev, why)
		}
	}
	// 6. Behaviour, weakest of all: something that mostly receives connections
	//    is acting as a server whatever it calls itself.
	if v.Role == RoleUnknown && s.ConnsIn > 0 && s.ConnsIn > s.ConnsOut*3 {
		v.Role = RoleServer
		v.Confidence = Guessed
		ev = append(ev, "receives far more connections than it opens")
	}
	if s.Scanned && len(s.OpenPorts) == 0 {
		ev = append(ev, "scanned, nothing listening on the probed ports")
	}
	v.Evidence = ev
	return v
}

// roleFromVendor reads the MAC vendor string for well-known device classes.
func roleFromVendor(vendor string) (Role, string) {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "raspberry"):
		return RoleServer, "MAC vendor is Raspberry Pi"
	case strings.Contains(v, "synology"), strings.Contains(v, "qnap"):
		return RoleNAS, "MAC vendor is a NAS maker"
	case strings.Contains(v, "ubiquiti"), strings.Contains(v, "eero"),
		strings.Contains(v, "aruba"), strings.Contains(v, "ruckus"):
		return RoleAP, "MAC vendor makes access points"
	case strings.Contains(v, "hewlett"), strings.Contains(v, "brother"),
		strings.Contains(v, "canon"), strings.Contains(v, "epson"):
		return RolePrinter, "MAC vendor makes printers"
	case strings.Contains(v, "apple"):
		return RoleWorkstation, "MAC vendor is Apple"
	case strings.Contains(v, "espressif"), strings.Contains(v, "tuya"),
		strings.Contains(v, "shelly"), strings.Contains(v, "sonoff"):
		return RoleIoT, "MAC vendor makes smart-home hardware"
	}
	return RoleUnknown, ""
}

// SortRoles gives the UI a stable, meaningful order: infrastructure first,
// then things that serve, then things that consume.
func SortRoles(nodes []Node) {
	rank := map[Role]int{
		RoleGateway: 0, RoleAP: 1, RoleHypervisor: 2, RoleNAS: 3,
		RoleServer: 4, RoleVM: 5, RoleContainer: 6,
		RoleWorkstation: 7, RoleMobile: 8, RolePrinter: 9, RoleIoT: 10,
		RoleUnknown: 11,
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		ri, rj := rank[nodes[i].Role], rank[nodes[j].Role]
		if ri != rj {
			return ri < rj
		}
		return nodes[i].IP < nodes[j].IP
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
