package mitm

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// RequestVerdict is the outcome of request-side filtering.
type RequestVerdict struct {
	Drop        bool
	Status      int
	Body        []byte
	ContentType string
	Reason      string
}

// FilterChain applies the configured response rewriters.
type FilterChain struct {
	cfg *config.Config
}

func NewFilterChain(cfg *config.Config) *FilterChain { return &FilterChain{cfg: cfg} }

// transparentGIF is the classic 1x1 tracking pixel, returned in place of one
// so a page's layout does not shift when a beacon is blocked.
var transparentGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// FilterRequest decides whether a request should even leave the network.
func (f *FilterChain) FilterRequest(host, path string, req *http.Request) RequestVerdict {
	c := f.cfg.Snapshot()
	if !c.MITM.Enabled {
		return RequestVerdict{}
	}
	lp := strings.ToLower(path)

	if c.MITM.Filters.YouTube && isYouTubeHost(host) {
		// These endpoints exist solely to report ad playback and to fetch ad
		// creatives. Dropping them removes the ad request round-trip and
		// stops the "did the ad play" telemetry loop from retrying.
		for _, frag := range youtubeAdEndpoints {
			if strings.Contains(lp, frag) {
				return RequestVerdict{
					Drop: true, Status: http.StatusNoContent,
					ContentType: "text/plain", Reason: "youtube-ad-endpoint",
				}
			}
		}
	}

	if c.MITM.Filters.TrackerBeacons {
		for _, frag := range beaconPathFragments {
			if strings.Contains(lp, frag) {
				// Answer image requests with a pixel and everything else with
				// 204; a hard failure makes some SDKs retry in a tight loop.
				if isImageRequest(lp, req) {
					return RequestVerdict{
						Drop: true, Status: http.StatusOK, Body: transparentGIF,
						ContentType: "image/gif", Reason: "tracker-beacon",
					}
				}
				return RequestVerdict{
					Drop: true, Status: http.StatusNoContent,
					ContentType: "text/plain", Reason: "tracker-beacon",
				}
			}
		}
	}
	return RequestVerdict{}
}

// FilterResponse rewrites a response body in place. It returns whether the
// body was modified and the (post-filter) body size for the ad pipeline.
func (f *FilterChain) FilterResponse(host, path string, req *http.Request, resp *http.Response, stats *Stats) (bool, int64) {
	c := f.cfg.Snapshot()
	if !c.MITM.Enabled || resp.Body == nil {
		return false, resp.ContentLength
	}

	ctype := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(ctype, "json")
	isHTML := strings.Contains(ctype, "html")

	// Only buffer bodies that could plausibly be rewritten. A 200 MB video
	// segment must stream straight through.
	if !isJSON && !isHTML {
		return false, resp.ContentLength
	}
	const maxBody = 24 << 20
	if resp.ContentLength > maxBody {
		return false, resp.ContentLength
	}

	body, err := readBody(resp)
	if err != nil {
		return false, 0
	}
	original := len(body)
	modified := false

	switch {
	case c.MITM.Filters.YouTube && isYouTubeHost(host) && isJSON:
		if out, n := stripYouTubeAds(body); n > 0 {
			body = out
			modified = true
			stats.AdsStripped.Add(int64(n))
		}
	case c.MITM.Filters.YouTube && isYouTubeHost(host) && isHTML:
		// The watch page embeds the same player response inline; the app
		// reads it from there without ever calling the API.
		if out, n := stripYouTubeInlineAds(body); n > 0 {
			body = out
			modified = true
			stats.AdsStripped.Add(int64(n))
		}
	case c.MITM.Filters.GenericJSONAds && isJSON:
		if out, n := stripGenericJSONAds(body); n > 0 {
			body = out
			modified = true
			stats.AdsStripped.Add(int64(n))
		}
	}

	if c.MITM.Filters.HTMLCosmetic && isHTML {
		if out, ok := injectCosmeticCSS(body); ok {
			body = out
			modified = true
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if modified {
		resp.Header.Set("X-Orbis-Filtered", "1")
		// A rewritten body must not be cached by the client under the
		// origin's original validators.
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
		resp.Header.Set("Cache-Control", "no-store")
	}
	_ = original
	return modified, int64(len(body))
}

// readBody decompresses and reads the full body.
func readBody(resp *http.Response) ([]byte, error) {
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Some origins mislabel; fall back to the raw bytes rather than
			// failing the whole response.
			return io.ReadAll(io.LimitReader(resp.Body, 24<<20))
		}
		defer gz.Close()
		r = gz
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(r, 24<<20))
}

func isYouTubeHost(host string) bool {
	h := strings.ToLower(host)
	for _, s := range []string{
		"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
		"youtube-nocookie.com", "youtubei.googleapis.com", "youtubekids.com",
	} {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// youtubeAdEndpoints are request paths that only ever carry ad traffic.
var youtubeAdEndpoints = []string{
	"/pagead/", "/ptracking", "/api/stats/ads", "/get_midroll_info",
	"/youtubei/v1/player/ad_break", "/pcs/activeview", "/aclk",
	"/pagead/viewthroughconversion", "/api/stats/qoe?ad",
	"/youtubei/v1/att/get", "/generate_204?", "/csi_204",
}

// beaconPathFragments are analytics endpoints across the wider web.
var beaconPathFragments = []string{
	"/collect?", "/g/collect", "/gen_204", "/b/ss/", "/pixel?", "/px.gif",
	"/track/", "/tracking/", "/beacon", "/telemetry", "/i/adsct",
	"/tr?id=", "/impression", "/rtb/", "/usersync", "/cookiesync",
	"/analytics/log", "/log_event?ad", "/metrics/v1", "/v1/events/batch",
}

func isImageRequest(path string, req *http.Request) bool {
	if strings.HasSuffix(path, ".gif") || strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".webp") {
		return true
	}
	return strings.Contains(req.Header.Get("Accept"), "image/")
}

// ---- YouTube ----

// youtubeAdKeys are the top-level keys of an InnerTube player response that
// carry advertising. Removing them makes the player behave exactly as it does
// for a video that genuinely has no ads: it goes straight to content.
//
// This targets client-side ad insertion, which is how the overwhelming
// majority of YouTube ads are still delivered. Server-side stitched ads (SSAI),
// where ad frames are muxed into the same video stream, cannot be removed this
// way by anyone — the ad and the content are literally the same bytes.
var youtubeAdKeys = []string{
	"adPlacements",
	"playerAds",
	"adSlots",
	"adBreakHeartbeatParams",
	"adParams",
	"adServingDataEntity",
	"adsEngagementPanels",
	"importantForAds",
}

// stripYouTubeAds removes ad structures from an InnerTube JSON response and
// reports how many were removed.
func stripYouTubeAds(body []byte) ([]byte, int) {
	// A cheap prefilter: most responses are not player responses at all, and
	// unmarshalling a 2 MB JSON blob for nothing is wasteful.
	if !bytes.Contains(body, []byte("adPlacements")) &&
		!bytes.Contains(body, []byte("playerAds")) &&
		!bytes.Contains(body, []byte("adSlots")) {
		return body, 0
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, 0
	}
	removed := 0
	for _, k := range youtubeAdKeys {
		if _, ok := doc[k]; ok {
			delete(doc, k)
			removed++
		}
	}
	// Nested locations used by the newer response shape.
	removed += removeNested(doc, []string{"playerResponse"}, youtubeAdKeys)
	removed += removeNested(doc, []string{"playerConfig", "adConfig"}, nil)
	removed += removeNested(doc, []string{"playbackTracking", "atrUrl"}, nil)
	removed += removeNested(doc, []string{"playbackTracking", "ptrackingUrl"}, nil)
	removed += removeNested(doc, []string{"playbackTracking", "qoeUrl"}, nil)

	// The player refuses to start when it expects an ad that never arrives,
	// so tell it there is nothing to wait for.
	if pr, ok := doc["playerResponse"].(map[string]any); ok {
		clearAdState(pr)
	}
	clearAdState(doc)

	if removed == 0 {
		return body, 0
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, 0
	}
	return out, removed
}

// clearAdState normalises the flags the player checks before deciding to run
// an ad break.
func clearAdState(doc map[string]any) {
	if vd, ok := doc["videoDetails"].(map[string]any); ok {
		// A video marked as monetised makes the player poll for ad breaks
		// even after the placements are gone.
		delete(vd, "isLiveContent_adBreak")
	}
	if pc, ok := doc["playerConfig"].(map[string]any); ok {
		delete(pc, "adConfig")
		delete(pc, "adPlaybackConfig")
	}
	if sd, ok := doc["streamingData"].(map[string]any); ok {
		// Ad-only format entries occasionally ride along in adaptiveFormats.
		for _, key := range []string{"adaptiveFormats", "formats"} {
			if arr, ok := sd[key].([]any); ok {
				filtered := arr[:0]
				for _, item := range arr {
					m, ok := item.(map[string]any)
					if ok {
						if _, isAd := m["isAdFormat"]; isAd {
							continue
						}
					}
					filtered = append(filtered, item)
				}
				sd[key] = filtered
			}
		}
	}
}

func removeNested(doc map[string]any, path []string, keys []string) int {
	if len(path) == 0 {
		return 0
	}
	cur := doc
	for i, p := range path {
		if i == len(path)-1 {
			if keys == nil {
				if _, ok := cur[p]; ok {
					delete(cur, p)
					return 1
				}
				return 0
			}
			nested, ok := cur[p].(map[string]any)
			if !ok {
				return 0
			}
			n := 0
			for _, k := range keys {
				if _, ok := nested[k]; ok {
					delete(nested, k)
					n++
				}
			}
			return n
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			return 0
		}
		cur = next
	}
	return 0
}

// stripYouTubeInlineAds rewrites the ytInitialPlayerResponse embedded in the
// watch page HTML. The web client reads it from there on first load, so
// filtering only the API endpoint leaves the first video's ad intact.
func stripYouTubeInlineAds(body []byte) ([]byte, int) {
	const marker = "var ytInitialPlayerResponse = "
	idx := bytes.Index(body, []byte(marker))
	if idx < 0 {
		return body, 0
	}
	start := idx + len(marker)
	end := matchJSONObject(body, start)
	if end <= start {
		return body, 0
	}
	rewritten, n := stripYouTubeAds(body[start:end])
	if n == 0 {
		return body, 0
	}
	out := make([]byte, 0, len(body)+len(rewritten)-(end-start))
	out = append(out, body[:start]...)
	out = append(out, rewritten...)
	out = append(out, body[end:]...)
	return out, n
}

// matchJSONObject finds the end of the JSON object starting at `start`,
// respecting string literals and escapes so a brace inside a title does not
// terminate the scan early.
func matchJSONObject(b []byte, start int) int {
	if start >= len(b) || b[start] != '{' {
		return -1
	}
	depth := 0
	inStr := false
	escaped := false
	for i := start; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// ---- generic ----

// genericAdKeys are keys that, across a wide range of mobile and web APIs,
// carry advertising payloads. Removing them makes apps render as if the ad
// slot was unfilled, which they all handle gracefully.
var genericAdKeys = []string{
	"ads", "advertisements", "adUnits", "ad_units", "adSlots", "ad_slots",
	"adConfig", "ad_config", "adBreaks", "ad_breaks", "preroll", "midroll",
	"postroll", "sponsoredContent", "sponsored_content", "promotedItems",
	"promoted_items", "interstitials", "adMarkers", "ad_markers",
}

func stripGenericJSONAds(body []byte) ([]byte, int) {
	hit := false
	for _, k := range genericAdKeys {
		if bytes.Contains(body, []byte(`"`+k+`"`)) {
			hit = true
			break
		}
	}
	if !hit {
		return body, 0
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, 0
	}
	removed := walkStrip(doc, 0)
	if removed == 0 {
		return body, 0
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, 0
	}
	return out, removed
}

// walkStrip recurses through a decoded document removing ad keys. Depth is
// bounded so a hostile deeply-nested document cannot blow the stack.
func walkStrip(node any, depth int) int {
	if depth > 32 {
		return 0
	}
	removed := 0
	switch v := node.(type) {
	case map[string]any:
		for _, k := range genericAdKeys {
			if _, ok := v[k]; ok {
				delete(v, k)
				removed++
			}
		}
		for _, child := range v {
			removed += walkStrip(child, depth+1)
		}
	case []any:
		for _, child := range v {
			removed += walkStrip(child, depth+1)
		}
	}
	return removed
}

// cosmeticCSS hides the containers that survive network-level blocking. It is
// deliberately conservative: broad selectors break layouts, and a page that
// looks broken is worse than a page with an empty ad slot.
const cosmeticCSS = `<style id="orbis-cosmetic">` +
	`ins.adsbygoogle,div[id^="google_ads_"],div[id^="div-gpt-ad"],` +
	`iframe[src*="doubleclick.net"],iframe[src*="googlesyndication.com"],` +
	`iframe[id^="google_ads_iframe"],div[class*="ad-slot"],div[class*="adsbox"],` +
	`div[data-ad-slot],aside[aria-label="Advertisement"]` +
	`{display:none!important;height:0!important;min-height:0!important}` +
	`</style>`

func injectCosmeticCSS(body []byte) ([]byte, bool) {
	if bytes.Contains(body, []byte("orbis-cosmetic")) {
		return body, false
	}
	idx := bytes.Index(bytes.ToLower(body), []byte("</head>"))
	if idx < 0 {
		return body, false
	}
	out := make([]byte, 0, len(body)+len(cosmeticCSS))
	out = append(out, body[:idx]...)
	out = append(out, cosmeticCSS...)
	out = append(out, body[idx:]...)
	return out, true
}
