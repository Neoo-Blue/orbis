package topology

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Node is one device on the map.
type Node struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Label    string `json:"label"`
	Vendor   string `json:"vendor,omitempty"`

	Role       Role       `json:"role"`
	Platform   string     `json:"platform,omitempty"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence,omitempty"`
	Virtual    bool       `json:"virtual"`

	// ParentID links a guest to the hypervisor hosting it, when that can be
	// established. Empty when it cannot.
	ParentID string `json:"parent_id,omitempty"`
	// ParentBasis explains the link, because on a flat network the association
	// is an inference and the map should not present it as fact.
	ParentBasis string `json:"parent_basis,omitempty"`

	Services []string `json:"services,omitempty"`
	Online   bool     `json:"online"`

	// Traffic, split by direction. Inbound means connections opened towards
	// this device from elsewhere, which is what distinguishes something being
	// used from something merely running.
	BytesIn   int64 `json:"bytes_in"`
	BytesOut  int64 `json:"bytes_out"`
	ConnsIn   int   `json:"conns_in"`
	ConnsOut  int   `json:"conns_out"`
	ExtConns  int   `json:"external_conns"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// Edge is an observed relationship. Kind is "hosts" for hypervisor to guest,
// or "traffic" for an internal conversation.
type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Bytes int64  `json:"bytes,omitempty"`
	Conns int    `json:"conns,omitempty"`
	// Direction is which way the conversation was opened.
	Direction string `json:"direction,omitempty"`
}

// Graph is the whole map.
type Graph struct {
	Nodes     []Node    `json:"nodes"`
	Edges     []Edge    `json:"edges"`
	Subnet    string    `json:"subnet,omitempty"`
	ScannedAt string    `json:"scanned_at,omitempty"`
	Notes     []string  `json:"notes,omitempty"`
}

// Scanner probes the LAN. It is deliberately gentle: a handful of ports, a
// short timeout, and a small worker pool. A fast full scan looks like an attack
// to anything watching the network and buys nothing here, since the point is
// to tell a hypervisor from a NAS rather than to inventory every service.
type Scanner struct {
	Concurrency int
	Timeout     time.Duration

	mu      sync.Mutex
	lastRun time.Time
	results map[string][]int
}

func NewScanner() *Scanner {
	return &Scanner{Concurrency: 12, Timeout: 700 * time.Millisecond, results: map[string][]int{}}
}

// Scan probes the given addresses and caches what answered.
func (s *Scanner) Scan(ctx context.Context, ips []string) map[string][]int {
	conc := s.Concurrency
	if conc <= 0 {
		conc = 12
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}

	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := map[string][]int{}

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn, err := d.DialContext(ctx, "tcp",
					net.JoinHostPort(j.ip, itoa(j.port)))
				if err != nil {
					continue
				}
				conn.Close()
				mu.Lock()
				found[j.ip] = append(found[j.ip], j.port)
				mu.Unlock()
			}
		}()
	}

	for _, ip := range ips {
		for _, p := range ProbePorts {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return found
			case jobs <- job{ip, p.Port}:
			}
		}
	}
	close(jobs)
	wg.Wait()

	for _, ports := range found {
		sort.Ints(ports)
	}
	s.mu.Lock()
	s.lastRun = time.Now()
	s.results = found
	s.mu.Unlock()
	return found
}

// Cached returns the last scan without probing again.
func (s *Scanner) Cached() (map[string][]int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]int, len(s.results))
	for k, v := range s.results {
		out[k] = append([]int(nil), v...)
	}
	return out, s.lastRun
}

// DeviceInput is one device as the caller knows it, before classification.
type DeviceInput struct {
	ID       string
	IP       string
	MAC      string
	Hostname string
	Label    string
	Vendor   string
	OSGuess  string
	Type     string
	Online   bool
	LastSeen time.Time
}

// FlowInput is one observed conversation, already aggregated.
type FlowInput struct {
	SrcIP    string
	DstIP    string
	Bytes    int64
	Conns    int
	External bool // the far end is off this network
}

// Build assembles the graph.
func Build(devices []DeviceInput, flows []FlowInput, ports map[string][]int,
	gateway string, scannedAt time.Time) Graph {

	g := Graph{}
	byIP := map[string]*Node{}

	for _, d := range devices {
		open := ports[d.IP]
		v := Classify(Signals{
			IP: d.IP, MAC: d.MAC, Hostname: d.Hostname, Vendor: d.Vendor,
			OSGuess: d.OSGuess, DeviceType: d.Type,
			OpenPorts: open, Scanned: ports != nil,
			IsGateway: d.IP == gateway,
		})
		n := Node{
			ID: d.ID, IP: d.IP, MAC: d.MAC, Hostname: d.Hostname,
			Label: displayLabel(d), Vendor: d.Vendor,
			Role: v.Role, Platform: v.Platform, Confidence: v.Confidence,
			Evidence: v.Evidence, Virtual: v.Virtual, Online: d.Online,
			Services: serviceNames(open),
		}
		if !d.LastSeen.IsZero() {
			n.LastSeen = d.LastSeen.UTC().Format(time.RFC3339)
		}
		g.Nodes = append(g.Nodes, n)
	}
	// Index only after the slice has stopped growing. Taking pointers into a
	// slice that is still being appended to hands out addresses that append
	// invalidates the moment it reallocates, and the writes land on a dead
	// array with no error anywhere.
	for i := range g.Nodes {
		byIP[g.Nodes[i].IP] = &g.Nodes[i]
	}

	// Traffic, split by direction and kept separate from the hosting edges.
	for _, f := range flows {
		src := byIP[f.SrcIP]
		dst := byIP[f.DstIP]
		if src != nil {
			src.BytesOut += f.Bytes
			src.ConnsOut += f.Conns
			if f.External {
				src.ExtConns += f.Conns
			}
		}
		if dst != nil {
			dst.BytesIn += f.Bytes
			dst.ConnsIn += f.Conns
		}
		// Only internal conversations become edges: an arc to the internet
		// belongs on the globe, not on a map of this network.
		if src != nil && dst != nil && f.SrcIP != f.DstIP {
			g.Edges = append(g.Edges, Edge{
				From: src.ID, To: dst.ID, Kind: "traffic",
				Bytes: f.Bytes, Conns: f.Conns, Direction: "out",
			})
		}
	}

	// Re-classify anything whose role depended on connection counts, now that
	// the traffic is folded in. Behaviour is the weakest signal, so it only
	// gets to speak for devices nothing else identified.
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Role != RoleUnknown {
			continue
		}
		if n.ConnsIn > 0 && n.ConnsIn > n.ConnsOut*3 {
			n.Role = RoleServer
			n.Confidence = Guessed
			n.Evidence = append(n.Evidence, "receives far more connections than it opens")
		}
	}

	g.Edges = append(g.Edges, linkGuests(g.Nodes, &g)...)
	SortRoles(g.Nodes)
	if !scannedAt.IsZero() {
		g.ScannedAt = scannedAt.UTC().Format(time.RFC3339)
	}
	return g
}

// linkGuests associates virtual machines with the hypervisor that minted them.
//
// On a flat network there is no protocol that reveals this: a Proxmox guest's
// MAC prefix identifies Proxmox, not which Proxmox. So the link is only drawn
// when exactly one host of that platform is present, and it is labelled as an
// inference. With two hosts the honest answer is to draw no line and say why,
// which is what the note is for.
func linkGuests(nodes []Node, g *Graph) []Edge {
	hostsByPlatform := map[string][]string{}
	for _, n := range nodes {
		if n.Role != RoleHypervisor {
			continue
		}
		p := n.Platform
		if p == "" {
			p = "unknown"
		}
		hostsByPlatform[p] = append(hostsByPlatform[p], n.ID)
	}

	var edges []Edge
	ambiguous := map[string]int{}
	for i := range nodes {
		n := &nodes[i]
		if !n.Virtual || n.Role == RoleHypervisor {
			continue
		}
		hosts := hostsByPlatform[n.Platform]
		switch len(hosts) {
		case 0:
			// The guest's platform has no visible host, which usually means
			// the hypervisor is on another subnet or does not answer probes.
		case 1:
			n.ParentID = hosts[0]
			n.ParentBasis = "only " + n.Platform + " host on this network"
			edges = append(edges, Edge{From: hosts[0], To: n.ID, Kind: "hosts"})
		default:
			ambiguous[n.Platform]++
		}
	}
	for platform, count := range ambiguous {
		g.Notes = append(g.Notes, fmt.Sprintf(
			"%d %s guests could not be attributed: more than one %s host is present and a "+
				"guest's MAC identifies the platform, not which host minted it.",
			count, platform, platform))
	}
	return edges
}

func displayLabel(d DeviceInput) string {
	switch {
	case d.Label != "":
		return d.Label
	case d.Hostname != "":
		return d.Hostname
	default:
		return d.IP
	}
}

func serviceNames(ports []int) []string {
	if len(ports) == 0 {
		return nil
	}
	byPort := map[int]string{}
	for _, p := range ProbePorts {
		byPort[p.Port] = p.Service
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if name, ok := byPort[p]; ok {
			out = append(out, name)
		} else {
			out = append(out, itoa(p))
		}
	}
	return out
}

// LocalSubnet reports the CIDR of the interface carrying the default route,
// used to decide which addresses are worth probing.
func LocalSubnet(gateway string) string {
	gw, err := netip.ParseAddr(gateway)
	if err != nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(ipn.String())
			if err != nil {
				continue
			}
			if p.Contains(gw) {
				return p.Masked().String()
			}
		}
	}
	return ""
}
