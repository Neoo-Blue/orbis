package adblock

import (
	"math"
	"strings"
)

// Heuristic scores how likely a domain is to be ad or tracking infrastructure,
// on 0..1. Every term is a signal an experienced operator would actually cite
// when looking at a request log, and each contributes a bounded amount so no
// single weak signal can carry a verdict on its own.
func Heuristic(e DomainEvidence) float64 {
	score := 0.0

	// 1. Name keywords. "pixel", "adserver", "beacon" in a hostname are close
	//    to a declaration of intent. Weighted by how specific the word is.
	kwWeight := 0.0
	for _, k := range e.KeywordHits {
		kwWeight += keywordWeights[k]
	}
	score += math.Min(kwWeight, 0.45)

	// 2. Third-party ratio. A host that is only ever loaded from other
	//    people's pages is, by construction, third-party infrastructure.
	if e.ThirdPartyRatio > 0 {
		score += 0.22 * e.ThirdPartyRatio
	}

	// 3. Referrer breadth. Appearing across many unrelated sites is the
	//    defining property of an ad network and is rare for anything else.
	switch n := len(e.ReferringSites); {
	case n >= 8:
		score += 0.20
	case n >= 4:
		score += 0.13
	case n >= 2:
		score += 0.06
	}

	// 4. Device breadth. Something contacted by every device on the network
	//    but belonging to no visible app is usually embedded SDK telemetry.
	switch {
	case e.DistinctClients >= 6:
		score += 0.10
	case e.DistinctClients >= 3:
		score += 0.05
	}

	// 5. Beacon-sized responses. Trackers answer with a 1x1 GIF, a 204, or a
	//    couple of hundred bytes of JSON. Real content does not.
	if e.AvgResponseBytes > 0 {
		switch {
		case e.AvgResponseBytes < 200:
			score += 0.14
		case e.AvgResponseBytes < 1500:
			score += 0.07
		case e.AvgResponseBytes > 100_000:
			// Large payloads argue for real content; pull the score down.
			score -= 0.12
		}
	}

	// 6. Path shape. /pixel, /collect, /rtb, /impression are ad-tech verbs.
	pathHit := false
	for _, p := range e.SamplePaths {
		lp := strings.ToLower(p)
		for _, frag := range adPathFragments {
			if strings.Contains(lp, frag) {
				pathHit = true
				break
			}
		}
		if pathHit {
			break
		}
	}
	if pathHit {
		score += 0.16
	}

	// 7. Random-looking labels. Ad networks rotate through generated
	//    subdomains to dodge static lists; high entropy plus depth is the
	//    signature. On its own it is weak (CDN shards look the same), so it
	//    is capped low.
	if e.LabelEntropy > 3.6 && e.SubdomainDepth >= 2 {
		score += 0.08
	}
	if e.LabelEntropy > 4.0 && e.SubdomainDepth >= 3 {
		score += 0.05
	}

	// 8. Known ad-tech network operators.
	if org := strings.ToLower(e.ASOrg); org != "" {
		for _, frag := range adNetworkOperators {
			if strings.Contains(org, frag) {
				score += 0.12
				break
			}
		}
	}

	// 9. Registrable domain on the ad-tech shortlist. This catches new
	//    subdomains of a known network before any list ships them.
	reg := registrable(e.Domain)
	if _, ok := knownAdRegistrable[reg]; ok {
		score += 0.35
	}

	// Dampeners — the guardrails that stop this from breaking the network.
	// A domain the whole household reaches constantly with first-party
	// referrers is a service, not a tracker, no matter what it is called.
	if e.ThirdPartyRatio > 0 && e.ThirdPartyRatio < 0.2 && e.Observations > 20 {
		score -= 0.18
	}
	if isLikelyCDN(e.Domain) {
		score -= 0.15
	}
	if isInfrastructure(e.Domain) {
		score -= 0.5
	}
	// Very little evidence should not produce a confident answer either way.
	if e.Observations < 5 {
		score *= 0.6
	}

	return clamp01(score)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// keywordWeights encodes how much each token in a hostname means. "adserver"
// is near-conclusive; "cdn" means nothing on its own.
var keywordWeights = map[string]float64{
	"doubleclick": 0.40, "adserver": 0.35, "adservice": 0.32, "adsystem": 0.32,
	"adnxs": 0.30, "adsrvr": 0.30, "adtech": 0.28, "advertising": 0.28,
	"adform": 0.26, "rtb": 0.26, "prebid": 0.26, "openrtb": 0.28,
	"pixel": 0.24, "beacon": 0.24, "impression": 0.24, "trackers": 0.24,
	"tracking": 0.22, "tracker": 0.22, "telemetry": 0.20, "analytics": 0.18,
	"metrics": 0.16, "collector": 0.16, "adsense": 0.26, "syndication": 0.22,
	"banner": 0.18, "popads": 0.30, "popunder": 0.32, "interstitial": 0.24,
	"sponsor": 0.14, "promoted": 0.14, "affiliate": 0.16, "clicktrack": 0.30,
	"clickserve": 0.30, "adclick": 0.30, "adimg": 0.22, "adcdn": 0.22,
	"admob": 0.28, "adjust": 0.18, "appsflyer": 0.26, "amplitude": 0.16,
	"mixpanel": 0.18, "segment": 0.12, "heap": 0.10, "hotjar": 0.20,
	"fullstory": 0.20, "clarity": 0.12, "quantserve": 0.28, "scorecard": 0.24,
	"taboola": 0.32, "outbrain": 0.32, "criteo": 0.32, "moat": 0.22,
	"bidder": 0.26, "bidswitch": 0.28, "smartadserver": 0.34, "pubmatic": 0.30,
	"rubicon": 0.24, "sharethrough": 0.26, "teads": 0.26, "yieldmo": 0.28,
	"ssp": 0.14, "dsp": 0.14, "dmp": 0.16, "cmp": 0.08,
}

func keywordHits(domain string) []string {
	d := strings.ToLower(domain)
	var out []string
	for k := range keywordWeights {
		if strings.Contains(d, k) {
			out = append(out, k)
		}
	}
	return out
}

var adPathFragments = []string{
	"/pixel", "/beacon", "/collect", "/track", "/impression", "/imp?",
	"/rtb", "/bid", "/prebid", "/ads/", "/ad?", "/adserver", "/adcall",
	"/telemetry", "/analytics", "/event", "/log?", "/metrics", "/csi",
	"/pagead", "/adsid", "/gen_204", "/1x1", "/clear.gif", "/px.gif",
	"/utm", "/conversion", "/retarget", "/sync?", "/cookiesync", "/usersync",
}

var adNetworkOperators = []string{
	"criteo", "taboola", "outbrain", "pubmatic", "rubicon", "magnite",
	"appnexus", "xandr", "the trade desk", "adform", "smartadserver",
	"index exchange", "openx", "sovrn", "triplelift", "media.net",
	"integral ad science", "doubleverify", "liveramp", "lotame",
}

// knownAdRegistrable is a curated shortlist of registrable domains whose
// every subdomain is ad infrastructure. Unlike a subscribed list this is
// about catching *new* subdomains instantly rather than exhaustive coverage.
var knownAdRegistrable = map[string]struct{}{
	"doubleclick.net": {}, "googlesyndication.com": {}, "googleadservices.com": {},
	"googletagservices.com": {}, "googletagmanager.com": {}, "adnxs.com": {},
	"adsrvr.org": {}, "criteo.com": {}, "criteo.net": {}, "taboola.com": {},
	"outbrain.com": {}, "pubmatic.com": {}, "rubiconproject.com": {},
	"openx.net": {}, "smartadserver.com": {}, "adform.net": {},
	"casalemedia.com": {}, "3lift.com": {}, "sharethrough.com": {},
	"teads.tv": {}, "yieldmo.com": {}, "bidswitch.net": {}, "moatads.com": {},
	"adsafeprotected.com": {}, "scorecardresearch.com": {}, "quantserve.com": {},
	"amazon-adsystem.com": {}, "advertising.com": {}, "adcolony.com": {},
	"applovin.com": {}, "unityads.unity3d.com": {}, "vungle.com": {},
	"chartboost.com": {}, "inmobi.com": {}, "mopub.com": {}, "smaato.net": {},
	"appsflyer.com": {}, "adjust.com": {}, "branch.io": {}, "kochava.com": {},
	"crashlytics.com": {}, "mixpanel.com": {}, "amplitude.com": {},
	"segment.io": {}, "hotjar.com": {}, "fullstory.com": {}, "mouseflow.com": {},
	"onetrust.com": {}, "cookielaw.org": {}, "trustarc.com": {},
	"demdex.net": {}, "omtrdc.net": {}, "everesttech.net": {}, "2o7.net": {},
	"bluekai.com": {}, "krxd.net": {}, "rlcdn.com": {}, "agkn.com": {},
	"exelator.com": {}, "mathtag.com": {}, "turn.com": {}, "adsymptotic.com": {},
	"serving-sys.com": {}, "flashtalking.com": {}, "sizmek.com": {},
	"zemanta.com": {}, "revcontent.com": {}, "mgid.com": {}, "propellerads.com": {},
	"popads.net": {}, "adcash.com": {}, "exoclick.com": {}, "trafficjunky.com": {},
}

// isLikelyCDN dampens the score for hosts that are shared content delivery
// infrastructure. Blocking these breaks real pages, and they score high on
// entropy and third-party ratio for entirely innocent reasons.
func isLikelyCDN(domain string) bool {
	reg := registrable(domain)
	_, ok := cdnRegistrable[reg]
	return ok
}

var cdnRegistrable = map[string]struct{}{
	"cloudfront.net": {}, "akamaized.net": {}, "akamai.net": {}, "akamaiedge.net": {},
	"fastly.net": {}, "fastlylb.net": {}, "cloudflare.net": {}, "cdn77.org": {},
	"edgekey.net": {}, "edgesuite.net": {}, "llnwd.net": {}, "stackpathdns.com": {},
	"jsdelivr.net": {}, "unpkg.com": {}, "cdnjs.com": {}, "bootstrapcdn.com": {},
	"gstatic.com": {}, "googleusercontent.com": {}, "googleapis.com": {},
	"azureedge.net": {}, "azurefd.net": {}, "windows.net": {}, "amazonaws.com": {},
	"bunnycdn.com": {}, "b-cdn.net": {}, "keycdn.com": {}, "cachefly.net": {},
}

// isInfrastructure marks names that must never be auto-blocked: blocking them
// takes the network down rather than removing an ad.
func isInfrastructure(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "" {
		return true
	}
	// Local and reverse-lookup zones.
	for _, suffix := range []string{
		".local", ".lan", ".home", ".internal", ".arpa", ".localhost",
		".in-addr.arpa", ".ip6.arpa", ".home.arpa",
	} {
		if strings.HasSuffix(d, suffix) || d == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	if !strings.Contains(d, ".") {
		return true // single label: a local hostname, not an internet domain
	}
	reg := registrable(d)
	_, ok := criticalRegistrable[reg]
	return ok
}

// criticalRegistrable are the domains that carry OS updates, time, captive
// portal detection, certificate validation and push notifications. Blocking
// any of them produces symptoms that look nothing like "an ad is missing".
var criticalRegistrable = map[string]struct{}{
	"apple.com": {}, "icloud.com": {}, "mzstatic.com": {}, "cdn-apple.com": {},
	"push.apple.com": {}, "microsoft.com": {}, "windowsupdate.com": {},
	"office.com": {}, "office365.com": {}, "live.com": {}, "msftconnecttest.com": {},
	"msftncsi.com": {}, "windows.com": {}, "digicert.com": {}, "verisign.com": {},
	"letsencrypt.org": {}, "ocsp.pki.goog": {}, "pki.goog": {}, "sectigo.com": {},
	"globalsign.com": {}, "entrust.net": {}, "ntp.org": {}, "pool.ntp.org": {},
	"time.windows.com": {}, "nist.gov": {}, "gvt1.com": {}, "gvt2.com": {},
	"android.com": {}, "gstatic.com": {}, "googleapis.com": {},
	"debian.org": {}, "ubuntu.com": {}, "canonical.com": {}, "archlinux.org": {},
	"fedoraproject.org": {}, "github.com": {}, "githubusercontent.com": {},
	"mozilla.org": {}, "mozilla.net": {}, "cloudflare.com": {},
	"root-servers.net": {}, "iana.org": {}, "in-addr.arpa": {},
}

// registrable returns the effective second-level domain. It is a heuristic,
// not a full public-suffix implementation: it handles the multi-label public
// suffixes that actually show up (co.uk, com.au, ...) and treats everything
// else as label+TLD. A full PSL would be more correct but adds a megabyte of
// data to keep current for a marginal accuracy gain here.
func registrable(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(domain), ".")
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return d
	}
	if len(parts) >= 3 {
		last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if _, ok := multiLabelSuffixes[last2]; ok {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

var multiLabelSuffixes = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "gov.uk": {}, "me.uk": {}, "net.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"co.nz": {}, "net.nz": {}, "org.nz": {}, "co.za": {}, "org.za": {},
	"com.br": {}, "net.br": {}, "org.br": {}, "gov.br": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {}, "ac.jp": {}, "go.jp": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {},
	"co.in": {}, "net.in": {}, "org.in": {}, "gov.in": {}, "ac.in": {},
	"com.mx": {}, "com.ar": {}, "com.tr": {}, "com.sg": {}, "com.hk": {},
	"com.tw": {}, "co.kr": {}, "or.kr": {}, "com.my": {}, "co.id": {},
	"com.ph": {}, "co.th": {}, "com.vn": {}, "com.pl": {}, "com.ua": {},
	"co.il": {}, "com.eg": {}, "com.sa": {}, "com.ng": {}, "com.pk": {},
}

// labelEntropy measures the Shannon entropy of the leftmost label, which is
// how algorithmically-generated hostnames give themselves away.
func labelEntropy(domain string) float64 {
	label, _, _ := strings.Cut(domain, ".")
	if len(label) < 4 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range label {
		freq[r]++
	}
	n := float64(len(label))
	h := 0.0
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
