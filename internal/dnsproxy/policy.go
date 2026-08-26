package dnsproxy

import (
	"strconv"
	"strings"
	"time"
)

// This file implements the parts of a per-client policy that act on the
// resolver: time windows, safe search, blocked service bundles and the
// per-policy DoH block. Before this existed the policy struct carried these
// fields, persisted them and showed them in the API, and the resolver ignored
// all of them.

// ---- schedules ----

// ScheduleActive reports whether a policy's schedule window covers `now`.
// The syntax matches the firewall's rule schedules so an operator learns it
// once: a day or day range, a clock range, or both, space separated.
//
//	"mon-fri 09:00-17:00"   weekdays, working hours
//	"sat sun"               weekends, all day
//	"22:00-06:00"           overnight, every day (wraps midnight)
//
// An empty schedule means always active. An unparseable schedule also means
// always active: a policy that silently stops applying because of a typo is a
// worse failure than one that applies too broadly.
func ScheduleActive(spec string, now time.Time) bool {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return true
	}
	var (
		dayOK   = true
		daySeen bool
		timeOK  = true
		timeSet bool
	)
	for _, field := range strings.Fields(spec) {
		if strings.Contains(field, ":") {
			from, to, ok := strings.Cut(field, "-")
			if !ok {
				continue
			}
			start, err1 := parseClock(from)
			end, err2 := parseClock(to)
			if err1 != nil || err2 != nil {
				continue
			}
			mins := now.Hour()*60 + now.Minute()
			timeSet = true
			if start <= end {
				timeOK = mins >= start && mins < end
			} else {
				// A window like 22:00-06:00 wraps past midnight.
				timeOK = mins >= start || mins < end
			}
			continue
		}
		if from, to, ok := strings.Cut(field, "-"); ok {
			days := expandDayRange(from, to)
			if len(days) == 0 {
				continue
			}
			daySeen = true
			if days[int(now.Weekday())] {
				dayOK = true
			} else if !dayMatchedElsewhere(spec, now) {
				dayOK = false
			}
			continue
		}
		if d, ok := dayIndex(field); ok {
			daySeen = true
			if int(now.Weekday()) == d {
				dayOK = true
			} else if !dayMatchedElsewhere(spec, now) {
				dayOK = false
			}
		}
	}
	if !daySeen {
		dayOK = true
	}
	if !timeSet {
		timeOK = true
	}
	return dayOK && timeOK
}

// dayMatchedElsewhere reports whether any day token in the spec covers today,
// so that "sat sun" is a union rather than a contradiction.
func dayMatchedElsewhere(spec string, now time.Time) bool {
	today := int(now.Weekday())
	for _, field := range strings.Fields(spec) {
		if strings.Contains(field, ":") {
			continue
		}
		if from, to, ok := strings.Cut(field, "-"); ok {
			if days := expandDayRange(from, to); len(days) > 0 && days[today] {
				return true
			}
			continue
		}
		if d, ok := dayIndex(field); ok && d == today {
			return true
		}
	}
	return false
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, strconv.ErrSyntax
	}
	hh, err := strconv.Atoi(h)
	if err != nil {
		return 0, err
	}
	mm, err := strconv.Atoi(m)
	if err != nil {
		return 0, err
	}
	if hh < 0 || hh > 24 || mm < 0 || mm > 59 {
		return 0, strconv.ErrRange
	}
	return hh*60 + mm, nil
}

var dayNames = map[string]int{
	"sun": 0, "sunday": 0,
	"mon": 1, "monday": 1,
	"tue": 2, "tues": 2, "tuesday": 2,
	"wed": 3, "weds": 3, "wednesday": 3,
	"thu": 4, "thur": 4, "thurs": 4, "thursday": 4,
	"fri": 5, "friday": 5,
	"sat": 6, "saturday": 6,
}

func dayIndex(s string) (int, bool) {
	d, ok := dayNames[strings.TrimSpace(s)]
	return d, ok
}

// expandDayRange returns a 7-element mask for an inclusive range, wrapping
// across the end of the week ("fri-mon").
func expandDayRange(from, to string) []bool {
	a, ok1 := dayIndex(from)
	b, ok2 := dayIndex(to)
	if !ok1 || !ok2 {
		return nil
	}
	mask := make([]bool, 7)
	for i := 0; i < 7; i++ {
		d := (a + i) % 7
		mask[d] = true
		if d == b {
			break
		}
	}
	return mask
}

// ---- safe search ----

// safeSearchTargets maps a search host to the hostname that serves its
// filtered results. Answering with a CNAME to these is how every filtering
// resolver enforces safe search: the engines publish these names precisely so
// a network operator can point clients at them.
var safeSearchTargets = map[string]string{
	"google.com":       "forcesafesearch.google.com",
	"www.google.com":   "forcesafesearch.google.com",
	"bing.com":         "strict.bing.com",
	"www.bing.com":     "strict.bing.com",
	"duckduckgo.com":   "safe.duckduckgo.com",
	"www.duckduckgo.com": "safe.duckduckgo.com",
	"youtube.com":      "restrictmoderate.youtube.com",
	"www.youtube.com":  "restrictmoderate.youtube.com",
	"m.youtube.com":    "restrictmoderate.youtube.com",
	"youtubei.googleapis.com":  "restrictmoderate.youtube.com",
	"youtube.googleapis.com":   "restrictmoderate.youtube.com",
	"www.youtube-nocookie.com": "restrictmoderate.youtube.com",
	"pixabay.com":     "safesearch.pixabay.com",
	"www.pixabay.com": "safesearch.pixabay.com",
	"yandex.com":      "familysearch.yandex.ru",
	"www.yandex.com":  "familysearch.yandex.ru",
	"yandex.ru":       "familysearch.yandex.ru",
}

// SafeSearchTarget returns the filtered hostname for a search domain, or "".
// Country variants of Google (google.co.uk, google.de, ...) all resolve to the
// same forcesafesearch host, so they are matched by prefix rather than listed.
func SafeSearchTarget(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if t, ok := safeSearchTargets[n]; ok {
		return t
	}
	// google.<tld> and www.google.<tld>
	base := strings.TrimPrefix(n, "www.")
	if strings.HasPrefix(base, "google.") && strings.Count(base, ".") <= 2 {
		return "forcesafesearch.google.com"
	}
	return ""
}

// ---- blocked services ----

// BlockedService is a curated bundle of domains for one consumer service, so
// an operator can switch off TikTok without knowing its CDN hostnames. Lists
// are deliberately conservative: a false positive here blocks something the
// household expects to work, which erodes trust in the whole product.
type BlockedService struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// BlockedServices is the catalogue offered in the UI.
var BlockedServices = []BlockedService{
	{"tiktok", "TikTok", []string{
		"tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
		"musical.ly", "tiktokcdn-us.com", "ibytedtos.com", "ttwstatic.com",
	}},
	{"instagram", "Instagram", []string{
		"instagram.com", "cdninstagram.com", "ig.me",
	}},
	{"facebook", "Facebook", []string{
		"facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "messenger.com",
	}},
	{"snapchat", "Snapchat", []string{
		"snapchat.com", "sc-cdn.net", "snap.com", "snapkit.com",
	}},
	{"x", "X (Twitter)", []string{
		"twitter.com", "x.com", "t.co", "twimg.com", "twitpic.com",
	}},
	{"reddit", "Reddit", []string{
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
	}},
	{"youtube", "YouTube", []string{
		"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
		"youtube-nocookie.com", "youtubei.googleapis.com", "youtubekids.com",
	}},
	{"netflix", "Netflix", []string{
		"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net",
	}},
	{"twitch", "Twitch", []string{
		"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net",
	}},
	{"discord", "Discord", []string{
		"discord.com", "discordapp.com", "discord.gg", "discordapp.net",
	}},
	{"roblox", "Roblox", []string{
		"roblox.com", "rbxcdn.com", "roblox.cn",
	}},
	{"steam", "Steam", []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com",
		"steamcontent.com", "steamusercontent.com",
	}},
	{"epicgames", "Epic Games / Fortnite", []string{
		"epicgames.com", "unrealengine.com", "fortnite.com", "epicgames.dev",
	}},
	{"whatsapp", "WhatsApp", []string{
		"whatsapp.com", "whatsapp.net", "wa.me",
	}},
	{"telegram", "Telegram", []string{
		"telegram.org", "telegram.me", "t.me", "telesco.pe", "tdesktop.com",
	}},
	{"pinterest", "Pinterest", []string{
		"pinterest.com", "pinimg.com", "pinterest.ca", "pinterest.co.uk",
	}},
	{"tumblr", "Tumblr", []string{
		"tumblr.com", "tumblr.co", "srvcs.tumblr.com",
	}},
	{"spotify", "Spotify", []string{
		"spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi",
	}},
	{"disneyplus", "Disney+", []string{
		"disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com",
	}},
	{"primevideo", "Prime Video", []string{
		"primevideo.com", "aiv-cdn.net", "aiv-delivery.net",
	}},
}

// blockedServiceIndex is built once for O(1) lookups by id.
var blockedServiceIndex = func() map[string]BlockedService {
	m := make(map[string]BlockedService, len(BlockedServices))
	for _, s := range BlockedServices {
		m[s.ID] = s
	}
	return m
}()

// MatchBlockedService reports the service whose bundle covers name, or "".
// Matching is suffix-based so any subdomain of a listed domain is covered.
func MatchBlockedService(name string, ids []string) (string, bool) {
	if len(ids) == 0 {
		return "", false
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, id := range ids {
		svc, ok := blockedServiceIndex[id]
		if !ok {
			continue
		}
		for _, d := range svc.Domains {
			if n == d || strings.HasSuffix(n, "."+d) {
				return svc.Name, true
			}
		}
	}
	return "", false
}

// ---- DoH bypass ----

// dohBypassHosts are the well-known public DoH/DoQ endpoints a device can use
// to route around this resolver entirely. The global BlockDNSBypass setting
// sinkholes a much larger downloaded list; this small built-in set is what the
// per-policy toggle enforces so it works with no subscription installed.
var dohBypassHosts = []string{
	"dns.google", "dns64.dns.google",
	"cloudflare-dns.com", "one.one.one.one", "mozilla.cloudflare-dns.com",
	"security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com",
	"dns.nextdns.io", "dns.adguard.com", "dns.adguard-dns.com",
	"unfiltered.adguard-dns.com", "family.adguard-dns.com",
	"doh.cleanbrowsing.org", "doh.dns.sb", "dns.alidns.com",
	"doh.pub", "dns.twnic.tw", "odvr.nic.cz", "dnsforge.de",
	"basic.rethinkdns.com", "sky.rethinkdns.com", "doh.mullvad.net",
	"adblock.doh.mullvad.net", "dns.controld.com", "freedns.controld.com",
}

// IsDoHBypass reports whether a name is a known public encrypted-DNS endpoint.
func IsDoHBypass(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, h := range dohBypassHosts {
		if n == h || strings.HasSuffix(n, "."+h) {
			return true
		}
	}
	return false
}
