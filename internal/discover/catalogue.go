// Package discover finds what is hosted on the network: the services behind
// open ports on each device, named by HTTP fingerprint where a page answers,
// the containers behind them where a Docker Engine API is reachable, and the
// storage devices (NAS and SAN) by vendor and protocol. It also owns the port
// forwards this node creates for those services.
package discover

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Known is a port worth knocking on and what an answer usually is.
type Known struct {
	Port      int
	Name      string
	Kind      string // app | admin | storage | infra | web
	Category  string
	HTTP      bool // worth fetching a page from
	TLS       bool // try https first
	Sensitive bool // exposing it to the internet deserves a warning
}

// Catalogue is the probe list. It is the well-known self-hosted stack plus
// the ports that separate a NAS from a hypervisor from a workstation.
var Catalogue = []Known{
	// Storage protocols.
	{445, "SMB file sharing", "storage", "smb", false, false, true},
	{139, "NetBIOS", "storage", "smb", false, false, true},
	{2049, "NFS", "storage", "nfs", false, false, true},
	{111, "RPC portmapper (NFS)", "storage", "nfs", false, false, true},
	{548, "AFP (Apple file sharing)", "storage", "afp", false, false, true},
	{3260, "iSCSI target", "storage", "iscsi", false, false, true},
	{873, "rsync", "storage", "rsync", false, false, true},
	{21, "FTP", "storage", "ftp", false, false, true},
	{990, "FTPS", "storage", "ftp", false, false, true},
	{5005, "WebDAV", "storage", "webdav", true, false, true},
	{5006, "WebDAV (TLS)", "storage", "webdav", true, true, true},
	{6690, "Synology Drive", "storage", "sync", false, false, true},
	{8384, "Syncthing", "app", "sync", true, false, false},
	{9000, "MinIO or Portainer", "admin", "", true, false, true},
	{9001, "MinIO console", "admin", "s3", true, false, true},
	// Storage and hypervisor management.
	{5000, "Synology DSM", "admin", "nas", true, false, true},
	{5001, "Synology DSM (TLS)", "admin", "nas", true, true, true},
	{8006, "Proxmox VE", "admin", "hypervisor", true, true, true},
	{8007, "Proxmox Backup Server", "admin", "backup", true, true, true},
	{902, "VMware ESXi", "admin", "hypervisor", false, false, true},
	{9090, "Cockpit or Prometheus", "admin", "", true, false, true},
	{10000, "Webmin", "admin", "", true, true, true},
	{9443, "Portainer (TLS)", "admin", "containers", true, true, true},
	{2375, "Docker Engine API (no TLS)", "infra", "containers", true, false, true},
	{2376, "Docker Engine API (TLS)", "infra", "containers", false, false, true},
	{81, "Nginx Proxy Manager", "admin", "proxy", true, false, true},
	{19999, "Netdata", "admin", "monitoring", true, false, false},
	{3001, "Uptime Kuma", "app", "monitoring", true, false, false},
	{3000, "Grafana or a Node app", "app", "", true, false, false},
	{8086, "InfluxDB", "infra", "database", true, false, true},
	{5601, "Kibana", "admin", "monitoring", true, false, true},
	{9200, "Elasticsearch", "infra", "database", true, false, true},
	// Media.
	{32400, "Plex", "app", "media", true, false, false},
	{8096, "Jellyfin or Emby", "app", "media", true, false, false},
	{8920, "Jellyfin (TLS)", "app", "media", true, true, false},
	{8989, "Sonarr", "app", "media", true, false, false},
	{7878, "Radarr", "app", "media", true, false, false},
	{8686, "Lidarr", "app", "media", true, false, false},
	{8787, "Readarr", "app", "media", true, false, false},
	{9696, "Prowlarr", "app", "media", true, false, false},
	{6767, "Bazarr", "app", "media", true, false, false},
	{5055, "Overseerr or Jellyseerr", "app", "media", true, false, false},
	{8181, "Tautulli", "app", "media", true, false, false},
	{8080, "Web service", "web", "", true, false, false},
	{8081, "Web service", "web", "", true, false, false},
	{8090, "Web service", "web", "", true, false, false},
	{8112, "Deluge", "app", "downloads", true, false, false},
	{9091, "Transmission", "app", "downloads", true, false, false},
	{6789, "NZBGet", "app", "downloads", true, false, false},
	{4533, "Navidrome", "app", "media", true, false, false},
	{13378, "Audiobookshelf", "app", "media", true, false, false},
	{8083, "Calibre-Web", "app", "media", true, false, false},
	{2283, "Immich", "app", "photos", true, false, false},
	{2342, "PhotoPrism", "app", "photos", true, false, false},
	{11470, "Stremio server", "app", "media", true, false, false},
	// Home and automation.
	{8123, "Home Assistant", "app", "home", true, false, true},
	{1880, "Node-RED", "app", "home", true, false, true},
	{1883, "MQTT broker", "infra", "home", false, false, true},
	{6052, "ESPHome", "app", "home", true, false, true},
	{8581, "Homebridge", "app", "home", true, false, true},
	{5000, "Frigate or Kavita", "app", "", true, false, false},
	// Dev and productivity.
	{3306, "MySQL / MariaDB", "infra", "database", false, false, true},
	{5432, "PostgreSQL", "infra", "database", false, false, true},
	{6379, "Redis", "infra", "database", false, false, true},
	{27017, "MongoDB", "infra", "database", false, false, true},
	{11211, "memcached", "infra", "database", false, false, true},
	{3389, "Remote Desktop", "infra", "remote", false, false, true},
	{5900, "VNC", "infra", "remote", false, false, true},
	{22, "SSH", "infra", "remote", false, false, true},
	{23, "Telnet", "infra", "remote", false, false, true},
	{53, "DNS", "infra", "dns", false, false, false},
	{80, "Web server", "web", "", true, false, false},
	{443, "Web server (TLS)", "web", "", true, true, false},
	{8443, "Web service (TLS)", "web", "", true, true, false},
	{631, "Printer (IPP)", "infra", "printer", true, false, false},
	{9100, "Printer (JetDirect)", "infra", "printer", false, false, false},
	{3000, "Gitea or Grafana", "app", "", true, false, false},
	{8929, "GitLab", "app", "dev", true, false, false},
	{8929, "GitLab", "app", "dev", true, false, false},
	{5678, "n8n", "app", "automation", true, false, true},
	{8000, "Web service", "web", "", true, false, false},
	{8888, "Jupyter or a web service", "app", "dev", true, false, true},
	{11434, "Ollama", "app", "ai", true, false, true},
	{1234, "LM Studio", "app", "ai", true, false, true},
	{7860, "Gradio app", "app", "ai", true, false, false},
	{8188, "ComfyUI", "app", "ai", true, false, false},
	{3080, "LibreChat", "app", "ai", true, false, false},
	{25, "SMTP", "infra", "mail", false, false, true},
	{993, "IMAP (TLS)", "infra", "mail", false, false, true},
	{51820, "WireGuard", "infra", "vpn", false, false, false},
	{1194, "OpenVPN", "infra", "vpn", false, false, false},
	{161, "SNMP", "infra", "monitoring", false, false, true},
}

// Ports is the deduplicated, sorted probe list.
func Ports(extra []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, k := range Catalogue {
		if !seen[k.Port] {
			seen[k.Port] = true
			out = append(out, k.Port)
		}
	}
	for _, p := range extra {
		if p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

func known(port int) (Known, bool) {
	for _, k := range Catalogue {
		if k.Port == port {
			return k, true
		}
	}
	return Known{}, false
}

// Fingerprint is what an HTTP probe learned.
type Fingerprint struct {
	Scheme   string
	Status   int
	Title    string
	Server   string
	Location string
	Realm    string
	Body     string
}

// Signature names an application from what its front page says.
type Signature struct {
	Name      string
	Kind      string
	Category  string
	Sensitive bool
	match     *regexp.Regexp
	// titleOnly restricts loose patterns to the title, server header and
	// auth realm; page bodies mention routers and printers far too often.
	titleOnly bool
}

var signatures = []Signature{
	{"Plex", "app", "media", false, regexp.MustCompile(`(?i)\bplex\b`), false},
	{"Jellyfin", "app", "media", false, regexp.MustCompile(`(?i)jellyfin`), false},
	{"Emby", "app", "media", false, regexp.MustCompile(`(?i)\bemby\b`), false},
	{"Sonarr", "app", "media", false, regexp.MustCompile(`(?i)sonarr`), false},
	{"Radarr", "app", "media", false, regexp.MustCompile(`(?i)radarr`), false},
	{"Lidarr", "app", "media", false, regexp.MustCompile(`(?i)lidarr`), false},
	{"Readarr", "app", "media", false, regexp.MustCompile(`(?i)readarr`), false},
	{"Prowlarr", "app", "media", false, regexp.MustCompile(`(?i)prowlarr`), false},
	{"Bazarr", "app", "media", false, regexp.MustCompile(`(?i)bazarr`), false},
	{"Overseerr", "app", "media", false, regexp.MustCompile(`(?i)overseerr`), false},
	{"Seerr (requests)", "app", "media", false, regexp.MustCompile(`(?i)\bseerr\b`), false},
	{"Jellyseerr", "app", "media", false, regexp.MustCompile(`(?i)jellyseerr`), false},
	{"Tautulli", "app", "media", false, regexp.MustCompile(`(?i)tautulli`), false},
	{"SABnzbd", "app", "downloads", false, regexp.MustCompile(`(?i)sabnzbd`), false},
	{"NZBGet", "app", "downloads", false, regexp.MustCompile(`(?i)nzbget`), false},
	{"qBittorrent", "app", "downloads", false, regexp.MustCompile(`(?i)qbittorrent`), false},
	{"Transmission", "app", "downloads", false, regexp.MustCompile(`(?i)transmission web`), false},
	{"Deluge", "app", "downloads", false, regexp.MustCompile(`(?i)deluge`), false},
	{"Riven", "app", "media", false, regexp.MustCompile(`(?i)\briven\b`), false},
	{"Stremio", "app", "media", false, regexp.MustCompile(`(?i)stremio`), false},
	{"Navidrome", "app", "media", false, regexp.MustCompile(`(?i)navidrome`), false},
	{"Audiobookshelf", "app", "media", false, regexp.MustCompile(`(?i)audiobookshelf`), false},
	{"Kavita", "app", "media", false, regexp.MustCompile(`(?i)kavita`), false},
	{"Calibre-Web", "app", "media", false, regexp.MustCompile(`(?i)calibre`), false},
	{"Immich", "app", "photos", false, regexp.MustCompile(`(?i)immich`), false},
	{"PhotoPrism", "app", "photos", false, regexp.MustCompile(`(?i)photoprism`), false},
	{"Nextcloud", "app", "files", false, regexp.MustCompile(`(?i)nextcloud`), false},
	{"Vaultwarden", "app", "passwords", true, regexp.MustCompile(`(?i)vaultwarden|bitwarden`), false},
	{"Portainer", "admin", "containers", true, regexp.MustCompile(`(?i)portainer`), false},
	{"Dockge", "admin", "containers", true, regexp.MustCompile(`(?i)dockge`), false},
	{"Proxmox VE", "admin", "hypervisor", true, regexp.MustCompile(`(?i)proxmox`), false},
	{"Synology DSM", "admin", "nas", true, regexp.MustCompile(`(?i)synology|diskstation|dsm`), false},
	{"QNAP QTS", "admin", "nas", true, regexp.MustCompile(`(?i)qnap|\bqts\b`), false},
	{"TrueNAS", "admin", "nas", true, regexp.MustCompile(`(?i)truenas|freenas`), false},
	{"Unraid", "admin", "nas", true, regexp.MustCompile(`(?i)unraid`), false},
	{"OpenMediaVault", "admin", "nas", true, regexp.MustCompile(`(?i)openmediavault`), false},
	{"MinIO", "storage", "s3", true, regexp.MustCompile(`(?i)minio`), false},
	{"Home Assistant", "app", "home", true, regexp.MustCompile(`(?i)home assistant`), false},
	{"Node-RED", "app", "home", true, regexp.MustCompile(`(?i)node-red`), false},
	{"Zigbee2MQTT", "app", "home", true, regexp.MustCompile(`(?i)zigbee2mqtt`), false},
	{"Frigate", "app", "cameras", false, regexp.MustCompile(`(?i)frigate`), false},
	{"Scrypted", "app", "cameras", false, regexp.MustCompile(`(?i)scrypted`), false},
	{"Grafana", "app", "monitoring", false, regexp.MustCompile(`(?i)grafana`), false},
	{"Prometheus", "admin", "monitoring", false, regexp.MustCompile(`(?i)prometheus`), true},
	{"Uptime Kuma", "app", "monitoring", false, regexp.MustCompile(`(?i)uptime kuma`), false},
	{"Netdata", "admin", "monitoring", false, regexp.MustCompile(`(?i)netdata`), false},
	{"Cockpit", "admin", "server", true, regexp.MustCompile(`(?i)cockpit`), true},
	{"Pi-hole", "admin", "dns", true, regexp.MustCompile(`(?i)pi-hole`), false},
	{"AdGuard Home", "admin", "dns", true, regexp.MustCompile(`(?i)adguard`), false},
	{"Orbis", "admin", "network", true, regexp.MustCompile(`(?i)^orbis\b`), true},
	{"Nginx Proxy Manager", "admin", "proxy", true, regexp.MustCompile(`(?i)nginx proxy manager`), false},
	{"Traefik", "admin", "proxy", true, regexp.MustCompile(`(?i)traefik`), false},
	{"Gitea", "app", "dev", false, regexp.MustCompile(`(?i)gitea`), false},
	{"Forgejo", "app", "dev", false, regexp.MustCompile(`(?i)forgejo`), false},
	{"GitLab", "app", "dev", false, regexp.MustCompile(`(?i)gitlab`), false},
	{"Jenkins", "admin", "dev", true, regexp.MustCompile(`(?i)jenkins`), false},
	{"code-server", "app", "dev", true, regexp.MustCompile(`(?i)code-server|visual studio code`), false},
	{"Jupyter", "app", "dev", true, regexp.MustCompile(`(?i)jupyter`), false},
	{"n8n", "app", "automation", true, regexp.MustCompile(`(?i)\bn8n\b`), false},
	{"Ollama", "app", "ai", true, regexp.MustCompile(`(?i)ollama is running`), false},
	{"Open WebUI", "app", "ai", false, regexp.MustCompile(`(?i)open webui`), false},
	{"ComfyUI", "app", "ai", false, regexp.MustCompile(`(?i)comfyui`), false},
	{"Homarr", "app", "dashboard", false, regexp.MustCompile(`(?i)homarr`), false},
	{"Homepage", "app", "dashboard", false, regexp.MustCompile(`(?i)^homepage$`), true},
	{"Heimdall", "app", "dashboard", false, regexp.MustCompile(`(?i)heimdall`), false},
	{"Syncthing", "app", "sync", false, regexp.MustCompile(`(?i)syncthing`), false},
	{"Paperless", "app", "documents", false, regexp.MustCompile(`(?i)paperless`), false},
	{"Docker Engine API", "infra", "containers", true, regexp.MustCompile(`"ApiVersion"|\{"message":"page not found"\}`), false},
	{"Kibana", "admin", "monitoring", true, regexp.MustCompile(`(?i)kibana`), false},
	{"Elasticsearch", "infra", "database", true, regexp.MustCompile(`"cluster_name"|(?i)\belasticsearch\b`), false},
	{"InfluxDB", "infra", "database", true, regexp.MustCompile(`(?i)influxdb`), false},
	{"Webmin", "admin", "server", true, regexp.MustCompile(`(?i)webmin`), false},
	{"Printer", "infra", "printer", false, regexp.MustCompile(`(?i)\bhp\b|brother|canon|epson|printer|\bcups\b`), true},
	{"Router admin", "admin", "network", true, regexp.MustCompile(`(?i)\brouter\b|\beero\b|\basus\b|netgear|tp-link|\bunifi\b|openwrt|pfsense|opnsense`), true},
}

// Identify names a service from its port, what its page said, and who made
// the device. The page wins over the port; the port wins over nothing.
func Identify(port int, fp *Fingerprint, vendor string) (name, kind, category string, sensitive bool) {
	k, isKnown := known(port)
	if fp != nil {
		head := fp.Title + "\n" + fp.Server + "\n" + fp.Realm
		hay := head + "\n" + fp.Body
		for _, sig := range signatures {
			target := hay
			if sig.titleOnly {
				target = head
			}
			if sig.match.MatchString(target) {
				return sig.Name, sig.Kind, sig.Category, sig.Sensitive || (isKnown && k.Sensitive && sig.Kind != "app")
			}
		}
	}
	if isKnown {
		name = k.Name
		if fp != nil && fp.Title != "" && !titleSupports(fp.Title, name) {
			// The page named itself as something else, or the port is only a
			// generic guess: the page wins over the port.
			name = fp.Title
		}
		if k.HTTP && fp == nil && (k.Kind == "app" || k.Kind == "admin") && !((port == 5000 || port == 5001) && strings.EqualFold(vendor, "Synology")) {
			// The port is open but nothing spoke HTTP, so the catalogue's guess
			// is a guess. Say so instead of naming an app that is not there.
			return fmt.Sprintf("Port %d (usually %s)", port, k.Name), "other", k.Category, k.Sensitive
		}
		if (port == 5000 || port == 5001) && strings.EqualFold(vendor, "Synology") {
			return "Synology DSM", "admin", "nas", true
		}
		return name, k.Kind, k.Category, k.Sensitive
	}
	if fp != nil && fp.Title != "" {
		return fp.Title, "web", "", false
	}
	if fp != nil {
		return "Web service", "web", "", false
	}
	return "Open port", "other", "", false
}

// titleSupports reports whether a page title agrees with the catalogue's
// name for the port. A generic catalogue entry ("Web service") or an
// ambiguous one ("X or Y") is never support; otherwise the title has to
// mention the product's first word ("Synology" in "HomeServer - Synology NAS").
func titleSupports(title, catalogueName string) bool {
	if strings.Contains(catalogueName, " or ") || strings.HasPrefix(catalogueName, "Web s") {
		return false
	}
	first := strings.ToLower(strings.Fields(catalogueName)[0])
	first = strings.Trim(first, "(),")
	return strings.Contains(strings.ToLower(title), first)
}

// StorageProtocol names the protocol a storage port speaks, or "".
func StorageProtocol(port int) string {
	switch port {
	case 445, 139:
		return "SMB"
	case 2049, 111:
		return "NFS"
	case 548:
		return "AFP"
	case 3260:
		return "iSCSI"
	case 873:
		return "rsync"
	case 21, 990:
		return "FTP"
	case 5005, 5006:
		return "WebDAV"
	case 6690:
		return "Synology Drive"
	}
	return ""
}

var nasVendors = []string{"synology", "qnap", "western digital", "wd ", "netgear", "asustor", "terramaster", "terra master", "buffalo", "ixsystems", "drobo", "seagate", "lacie", "thecus", "ugreen"}

// IsStorage decides whether a device is a NAS or SAN from its vendor, the
// device type the identifier settled on, and the storage protocols it
// serves. A Windows PC with file sharing on is not storage; a box serving
// NFS, iSCSI, AFP or two storage protocols is.
func IsStorage(vendor, deviceType string, ports []int) bool {
	v := strings.ToLower(vendor)
	for _, n := range nasVendors {
		if n != "" && strings.Contains(v, n) {
			return true
		}
	}
	if deviceType == "nas" {
		return true
	}
	protocols := map[string]bool{}
	for _, p := range ports {
		switch p {
		case 2049, 3260, 548, 873:
			return true
		case 5005, 5006, 6690:
			// Synology's WebDAV and Drive ports; on anything else 5005/5006
			// is just another web app.
			continue
		}
		if sp := StorageProtocol(p); sp != "" {
			protocols[sp] = true
		}
	}
	return len(protocols) >= 2
}
