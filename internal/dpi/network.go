package dpi

import "strings"

// Naming a connection that never told us its name. A flow with no DNS
// lookup behind it and no readable handshake (QUIC with an encrypted
// hello, a device with its own resolver, a relay) still lands in a network
// that often belongs to one company, and the device that opened it often
// says the rest: a Synology talking to Taiwan is its QuickConnect relay.

type orgMatcher struct {
	name     string
	category string
	contains []string
}

var orgMatchers = []orgMatcher{
	{name: "Google", category: CatPlatform, contains: []string{"google"}},
	{name: "Apple", category: CatPlatform, contains: []string{"apple inc", "apple, inc"}},
	{name: "Microsoft", category: CatPlatform, contains: []string{"microsoft"}},
	{name: "Meta", category: CatSocial, contains: []string{"facebook", "meta platforms"}},
	{name: "Netflix", category: CatVideo, contains: []string{"netflix"}},
	{name: "Amazon Web Services", category: CatCloud, contains: []string{"amazon"}},
	{name: "Akamai CDN", category: CatCDN, contains: []string{"akamai"}},
	{name: "Cloudflare", category: CatCDN, contains: []string{"cloudflare"}},
	{name: "Fastly CDN", category: CatCDN, contains: []string{"fastly"}},
	{name: "Edgecast CDN", category: CatCDN, contains: []string{"edgecast", "edgio"}},
	{name: "Limelight CDN", category: CatCDN, contains: []string{"limelight"}},
	{name: "Steam", category: CatGaming, contains: []string{"valve corp"}},
	{name: "PlayStation Network", category: CatGaming, contains: []string{"sony interactive", "playstation"}},
	{name: "Nintendo", category: CatGaming, contains: []string{"nintendo"}},
	{name: "Xbox Live", category: CatGaming, contains: []string{"xbox"}},
	{name: "Roblox", category: CatGaming, contains: []string{"roblox"}},
	{name: "Epic Games", category: CatGaming, contains: []string{"epic games"}},
	{name: "Riot Games", category: CatGaming, contains: []string{"riot games"}},
	{name: "Blizzard", category: CatGaming, contains: []string{"blizzard"}},
	{name: "TikTok", category: CatSocial, contains: []string{"bytedance", "tiktok"}},
	{name: "Twitch", category: CatVideo, contains: []string{"twitch"}},
	{name: "Spotify", category: CatMusic, contains: []string{"spotify"}},
	{name: "Zoom", category: CatWork, contains: []string{"zoom video"}},
	{name: "Discord", category: CatMessaging, contains: []string{"discord"}},
	{name: "Telegram", category: CatMessaging, contains: []string{"telegram"}},
	{name: "Dropbox", category: CatStorage, contains: []string{"dropbox"}},
	{name: "OpenAI", category: CatAI, contains: []string{"openai"}},
	{name: "Anthropic", category: CatAI, contains: []string{"anthropic"}},
	{name: "Tailscale", category: CatVPN, contains: []string{"tailscale"}},
	{name: "Ubiquiti", category: CatSmartHome, contains: []string{"ubiquiti"}},
	{name: "Synology", category: CatStorage, contains: []string{"synology"}},
	{name: "Oracle Cloud", category: CatCloud, contains: []string{"oracle"}},
	{name: "DigitalOcean", category: CatCloud, contains: []string{"digitalocean"}},
	{name: "Hetzner", category: CatCloud, contains: []string{"hetzner"}},
	{name: "OVH", category: CatCloud, contains: []string{"ovh"}},
	{name: "Linode", category: CatCloud, contains: []string{"linode", "akamai connected cloud"}},
	{name: "Vultr", category: CatCloud, contains: []string{"vultr", "choopa"}},
	{name: "Alibaba Cloud", category: CatCloud, contains: []string{"alibaba", "aliyun"}},
	{name: "Tencent Cloud", category: CatCloud, contains: []string{"tencent"}},
}

// ServiceForNetwork names the company behind a network when the operator
// is one whose address space is used mostly for its own services. A transit
// or residential carrier says nothing about what runs on it and returns
// false.
func ServiceForNetwork(asn int, org string) (Service, bool) {
	o := strings.ToLower(org)
	if o == "" {
		return Service{}, false
	}
	for _, m := range orgMatchers {
		for _, c := range m.contains {
			if strings.Contains(o, c) {
				return Service{Name: m.name, Category: m.category}, true
			}
		}
	}
	_ = asn
	return Service{}, false
}

type relayHint struct {
	vendors   []string // matched against the source device's vendor, lower case
	countries []string // where the vendor's cloud relays live
	orgs      []string // or a network operator that gives it away
	hint      string
}

var relayHints = []relayHint{
	{vendors: []string{"synology"}, countries: []string{"TW"}, orgs: []string{"synology", "chunghwa"}, hint: "Synology QuickConnect relay, most likely: the NAS keeps a tunnel to Synology's relay servers in Taiwan so the mobile apps reach it from outside"},
	{vendors: []string{"qnap"}, countries: []string{"TW"}, orgs: []string{"qnap", "chunghwa"}, hint: "QNAP myQNAPcloud relay, most likely"},
	{vendors: []string{"xiaomi", "roborock", "dreame", "yeelight", "aqara"}, countries: []string{"CN", "SG", "DE"}, hint: "Xiaomi cloud, most likely: the device reports to and takes commands from Mi Home servers"},
	{vendors: []string{"tp-link", "tplink", "tapo", "kasa"}, countries: []string{"CN", "SG", "US", "IE"}, orgs: []string{"tp-link", "alibaba", "aliyun", "amazon"}, hint: "TP-Link cloud, most likely: Tapo and Kasa devices stay connected to it for remote control"},
	{vendors: []string{"tuya", "smart life"}, countries: []string{"CN", "SG", "US", "DE"}, orgs: []string{"tuya", "alibaba", "amazon"}, hint: "Tuya cloud, most likely: the platform behind many budget smart-home brands"},
	{vendors: []string{"hikvision", "hangzhou hikvision", "ezviz"}, countries: []string{"CN", "SG"}, hint: "Hikvision or EZVIZ cloud, most likely"},
	{vendors: []string{"reolink"}, countries: []string{"CN", "SG", "US"}, hint: "Reolink cloud relay, most likely"},
	{vendors: []string{"ring", "amazon technologies", "wyze", "blink"}, orgs: []string{"amazon"}, hint: "the camera's cloud on AWS, most likely"},
	{vendors: []string{"samsung"}, countries: []string{"KR"}, orgs: []string{"samsung"}, hint: "Samsung's cloud (SmartThings, TV services), most likely"},
	{vendors: []string{"lg electronics", "lg "}, countries: []string{"KR"}, orgs: []string{"lg "}, hint: "LG's cloud (webOS services), most likely"},
	{vendors: []string{"hisense", "tcl"}, countries: []string{"CN"}, hint: "the TV maker's cloud in China, most likely (telemetry and app services)"},
	{vendors: []string{"sonos"}, orgs: []string{"amazon", "sonos"}, hint: "Sonos cloud, most likely"},
	{vendors: []string{"roku"}, orgs: []string{"roku", "amazon", "google"}, hint: "Roku's services, most likely"},
	{vendors: []string{"ubiquiti"}, orgs: []string{"ubiquiti", "amazon"}, hint: "UniFi cloud (remote access, backups), most likely"},
	{vendors: []string{"espressif", "sonoff", "shelly"}, countries: []string{"CN", "SG", "DE", "US"}, hint: "the device's smart-home cloud, most likely"},
	{vendors: []string{"apple"}, orgs: []string{"apple", "akamai", "amazon", "google"}, hint: "Apple services (iCloud, updates, push), most likely"},
	{vendors: []string{"google", "nest"}, orgs: []string{"google"}, hint: "Google services (Nest, Cast, updates), most likely"},
}

// RelayHint guesses what an unnamed connection is from the device that
// opened it and where it went. It is a guess and is worded as one.
func RelayHint(srcVendor, srcType, dstCountry, dstOrg string) string {
	v := strings.ToLower(srcVendor + " " + srcType)
	o := strings.ToLower(dstOrg)
	c := strings.ToUpper(dstCountry)
	for _, h := range relayHints {
		matched := false
		for _, vv := range h.vendors {
			if strings.Contains(v, vv) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, cc := range h.countries {
			if cc == c {
				return h.hint
			}
		}
		for _, oo := range h.orgs {
			if strings.Contains(o, oo) {
				return h.hint
			}
		}
	}
	return ""
}
