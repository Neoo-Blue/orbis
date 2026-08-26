package flows

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/ident"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// ClientRegistry keeps the mapping between MACs, IPs and the stable client id
// used everywhere else. It is the thing that makes "per client" views work:
// without it a device that changes address looks like two devices, and a
// device behind a router looks like none.
type ClientRegistry struct {
	mu      sync.RWMutex
	byMAC   map[string]*store.Client
	byIP    map[netip.Addr]*store.Client
	pending map[string]bool // ids with unflushed changes

	st      *store.Store
	tracker *Tracker
	onNew   func(*store.Client)
	stop    chan struct{}
	wg      sync.WaitGroup
}

func NewClientRegistry(st *store.Store, t *Tracker) *ClientRegistry {
	r := &ClientRegistry{
		byMAC:   make(map[string]*store.Client),
		byIP:    make(map[netip.Addr]*store.Client),
		pending: make(map[string]bool),
		st:      st,
		tracker: t,
		stop:    make(chan struct{}),
	}
	return r
}

func (r *ClientRegistry) SetOnNew(fn func(*store.Client)) { r.onNew = fn }

// Load restores known devices at boot so history and labels survive restarts.
func (r *ClientRegistry) Load() error {
	clients, err := r.st.Clients()
	if err != nil {
		return err
	}
	r.mu.Lock()
	for i := range clients {
		c := clients[i]
		if c.MAC != "" {
			r.byMAC[strings.ToLower(c.MAC)] = &c
		}
		if addr, err := netip.ParseAddr(c.IP); err == nil {
			r.byIP[addr] = &c
			if r.tracker != nil {
				r.tracker.NoteClient(addr, c.ID)
			}
		}
	}
	r.mu.Unlock()
	return nil
}

// ClientID derives a stable identifier. A real MAC gives a permanent id; a
// randomized MAC or a routed address falls back to hashing the address, and
// the UI flags that the identity is weaker.
func ClientID(mac string, ip netip.Addr) string {
	if mac != "" && mac != "00:00:00:00:00:00" && !ident.IsRandomizedMAC(mac) {
		sum := sha256.Sum256([]byte("mac:" + strings.ToLower(mac)))
		return "c_" + hex.EncodeToString(sum[:8])
	}
	if mac != "" && mac != "00:00:00:00:00:00" {
		// Randomized MACs are still stable per-network, so keep using them,
		// but tag the id so the UI can explain repeat appearances.
		sum := sha256.Sum256([]byte("rmac:" + strings.ToLower(mac)))
		return "r_" + hex.EncodeToString(sum[:8])
	}
	sum := sha256.Sum256([]byte("ip:" + ip.String()))
	return "i_" + hex.EncodeToString(sum[:8])
}

// Observe records that mac/ip were seen together, creating or updating the
// client. Called from ARP, DHCP and the capture path.
func (r *ClientRegistry) Observe(ip netip.Addr, mac, hostname string) *store.Client {
	mac = strings.ToLower(strings.TrimSpace(mac))
	now := time.Now()

	r.mu.Lock()
	var c *store.Client
	if mac != "" {
		c = r.byMAC[mac]
	}
	if c == nil {
		c = r.byIP[ip]
		// An existing IP-keyed record that just learned its MAC gets
		// upgraded rather than duplicated.
		if c != nil && mac != "" && c.MAC == "" {
			c.MAC = mac
			c.ID = ClientID(mac, ip)
			r.byMAC[mac] = c
		}
	}
	isNew := false
	if c == nil {
		c = &store.Client{
			ID:        ClientID(mac, ip),
			MAC:       mac,
			IP:        ip.String(),
			Hostname:  hostname,
			FirstSeen: now,
			LastSeen:  now,
		}
		if mac != "" {
			c.Vendor = ident.Vendor(mac)
			if ident.IsRandomizedMAC(mac) {
				if c.Meta == nil {
					c.Meta = map[string]string{}
				}
				c.Meta["randomized_mac"] = "true"
			}
		}
		class, os := ident.DeviceClass(c.Vendor, hostname, "", "")
		c.DeviceType, c.OSGuess = class, os
		isNew = true
		if mac != "" {
			r.byMAC[mac] = c
		}
	}
	// An address change is normal (DHCP renew into a new lease); keep the
	// identity and move the index.
	if c.IP != ip.String() {
		if old, err := netip.ParseAddr(c.IP); err == nil {
			delete(r.byIP, old)
		}
		c.IP = ip.String()
	}
	r.byIP[ip] = c
	c.LastSeen = now
	if hostname != "" && c.Hostname == "" {
		c.Hostname = hostname
		if class, os := ident.DeviceClass(c.Vendor, hostname, "", ""); class != "unknown" {
			c.DeviceType, c.OSGuess = class, os
		}
	}
	r.pending[c.ID] = true
	snapshot := *c
	r.mu.Unlock()

	if r.tracker != nil {
		r.tracker.NoteClient(ip, c.ID)
	}
	if isNew {
		_ = r.st.UpsertClient(&snapshot)
		if r.onNew != nil {
			r.onNew(&snapshot)
		}
	}
	return c
}

// NoteUserAgent refines the OS guess when a cleartext User-Agent shows up.
func (r *ClientRegistry) NoteUserAgent(ip netip.Addr, ua string) {
	if ua == "" {
		return
	}
	r.mu.Lock()
	c := r.byIP[ip]
	if c == nil || c.OSGuess != "" {
		r.mu.Unlock()
		return
	}
	class, os := ident.DeviceClass(c.Vendor, c.Hostname, ua, "")
	if os != "" {
		c.OSGuess = os
		if c.DeviceType == "" || c.DeviceType == "unknown" {
			c.DeviceType = class
		}
		r.pending[c.ID] = true
	}
	r.mu.Unlock()
}

// NoteDHCP folds a lease into the client record, which is the highest-quality
// identity signal available: MAC, hostname, vendor class and option fingerprint
// all arrive together.
func (r *ClientRegistry) NoteDHCP(ip netip.Addr, mac, hostname, vendorClass, fingerprint string) {
	c := r.Observe(ip, mac, hostname)
	r.mu.Lock()
	defer r.mu.Unlock()
	if class, os := ident.DeviceClass(c.Vendor, hostname, "", fingerprint); class != "unknown" {
		c.DeviceType = class
		if os != "" {
			c.OSGuess = os
		}
	}
	if vendorClass != "" {
		if c.Meta == nil {
			c.Meta = map[string]string{}
		}
		c.Meta["dhcp_vendor_class"] = vendorClass
		c.Meta["dhcp_fingerprint"] = fingerprint
	}
	r.pending[c.ID] = true
}

func (r *ClientRegistry) ByIP(ip netip.Addr) *store.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.byIP[ip]; ok {
		cp := *c
		return &cp
	}
	return nil
}

func (r *ClientRegistry) ByID(id string) *store.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.byMAC {
		if c.ID == id {
			cp := *c
			return &cp
		}
	}
	for _, c := range r.byIP {
		if c.ID == id {
			cp := *c
			return &cp
		}
	}
	return nil
}

// All returns every known client decorated with live state.
func (r *ClientRegistry) All() []store.Client {
	seen := map[string]bool{}
	out := []store.Client{}
	r.mu.RLock()
	for _, c := range r.byIP {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, *c)
	}
	for _, c := range r.byMAC {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, *c)
	}
	r.mu.RUnlock()

	if r.tracker != nil {
		rates := r.tracker.ClientRates()
		active := map[string]int{}
		for _, f := range r.tracker.Active(0) {
			if f.ClientID != "" {
				active[f.ClientID]++
			}
		}
		cutoff := time.Now().Add(-5 * time.Minute)
		for i := range out {
			if rt, ok := rates[out[i].ID]; ok {
				out[i].RateIn, out[i].RateOut = rt[0], rt[1]
			}
			out[i].ActiveFlows = active[out[i].ID]
			out[i].Online = out[i].LastSeen.After(cutoff) || out[i].ActiveFlows > 0
		}
	}
	return out
}

// Start persists dirty clients on a slow ticker; the capture path touches
// last_seen constantly and writing each touch would dominate disk I/O.
func (r *ClientRegistry) Start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				r.persist()
				return
			case <-t.C:
				r.persist()
			}
		}
	}()
}

func (r *ClientRegistry) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.wg.Wait()
}

func (r *ClientRegistry) persist() {
	r.mu.Lock()
	var batch []store.Client
	seen := map[string]bool{}
	for id := range r.pending {
		for _, c := range r.byIP {
			if c.ID == id && !seen[id] {
				seen[id] = true
				batch = append(batch, *c)
			}
		}
		for _, c := range r.byMAC {
			if c.ID == id && !seen[id] {
				seen[id] = true
				batch = append(batch, *c)
			}
		}
	}
	r.pending = make(map[string]bool)
	r.mu.Unlock()

	for i := range batch {
		// Counters are accumulated in the flow table, not here; zero them so
		// the upsert's additive columns do not double-count.
		c := batch[i]
		c.RxBytes, c.TxBytes = 0, 0
		_ = r.st.UpsertClient(&c)
	}
}
