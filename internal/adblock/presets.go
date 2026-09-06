package adblock

import "github.com/Neoo-Blue/orbis/internal/config"

// Preset is a well-known list an operator can add with one click. The
// catalogue is the short list people migrate from Pi-hole and AdGuard Home
// with, not everything that exists.
type Preset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Category    string `json:"category"`
	Format      string `json:"format,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description"`
	// Recommended marks the sensible defaults for a home network.
	Recommended bool `json:"recommended"`
	Installed   bool `json:"installed"`
}

var presets = []Preset{
	{ID: "stevenblack", Name: "StevenBlack unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Category: "ads", Recommended: true,
		Description: "Pi-hole's default. Ads and malware hosts merged from several curated sources."},
	{ID: "adguard-dns", Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Category: "ads", Recommended: true,
		Description: "AdGuard Home's default. Ads, trackers and phishing in AdGuard syntax, with the exceptions that keep sites working."},
	{ID: "oisd-small", Name: "OISD small", URL: "https://small.oisd.nl/", Category: "ads",
		Description: "Aggressive on ads and telemetry with almost no breakage. The safe pick for a family network."},
	{ID: "oisd-big", Name: "OISD big", URL: "https://big.oisd.nl/", Category: "ads",
		Description: "The full OISD set: ads, trackers, malware, scams. Broad and still maintained for zero breakage."},
	{ID: "hagezi-pro", Name: "HaGeZi Multi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Category: "ads",
		Description: "Balanced protection: ads, tracking, telemetry, scam and phishing. AdGuard syntax."},
	{ID: "hagezi-tif", Name: "HaGeZi threat intelligence feeds", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", Category: "malware", Recommended: true,
		Description: "Malware, cryptojacking, spam and phishing domains from many threat feeds, refreshed daily."},
	{ID: "urlhaus", Name: "URLhaus malware", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Category: "malware", Recommended: true,
		Description: "abuse.ch's list of hosts distributing malware, as a hosts file."},
	{ID: "phishing-army", Name: "Phishing Army", URL: "https://phishing.army/download/phishing_army_blocklist_extended.txt", Category: "malware",
		Description: "Phishing domains aggregated from OpenPhish, PhishTank and others."},
	{ID: "easyprivacy", Name: "EasyPrivacy", URL: "https://easylist.to/easylist/easyprivacy.txt", Category: "tracking",
		Description: "The tracker half of EasyList. Only its DNS-applicable rules are used."},
	{ID: "peter-lowe", Name: "Peter Lowe's ad and tracking servers", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Category: "ads",
		Description: "A small, conservative list maintained since 2001."},
	{ID: "nocoin", Name: "NoCoin", URL: "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", Category: "malware",
		Description: "Browser cryptomining scripts and pools."},
	{ID: "hagezi-nsfw", Name: "HaGeZi NSFW", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt", Category: "adult",
		Description: "Adult content, for a kids' profile rather than the whole network."},
	{ID: "windows-spy", Name: "WindowsSpyBlocker", URL: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", Category: "tracking",
		Description: "Windows telemetry endpoints."},
	{ID: "smart-tv", Name: "Perflyst smart TV", URL: "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", Category: "tracking",
		Description: "Smart-TV telemetry and ad hosts, the Pi-hole community's list."},
}

// Presets returns the catalogue with Installed set from the configured lists.
func Presets(lists []config.BlockList) []Preset {
	byURL := map[string]bool{}
	for _, l := range lists {
		byURL[l.URL] = true
	}
	out := make([]Preset, len(presets))
	for i, p := range presets {
		p.Installed = byURL[p.URL]
		out[i] = p
	}
	return out
}

// Preset looks one up by id.
func PresetByID(id string) (Preset, bool) {
	for _, p := range presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
