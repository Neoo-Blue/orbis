package mitm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
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
//
// A response is only buffered when it is a plausible rewrite target. Anything
// else — video segments above all — keeps its original body, its original
// Content-Encoding and its original framing, and streams through untouched.
func (f *FilterChain) FilterResponse(host, path string, req *http.Request, resp *http.Response, stats *Stats) (bool, int64) {
	c := f.cfg.Snapshot()
	if !c.MITM.Enabled || resp.Body == nil {
		return false, resp.ContentLength
	}
	// Responses that cannot carry a body are never rewritten, and buffering
	// one would strip the framing the client is waiting for.
	if req != nil && req.Method == http.MethodHead {
		return false, resp.ContentLength
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified:
		return false, resp.ContentLength
	}
	// A ranged response is a slice of a document, not a document; rewriting
	// one would produce bytes that do not match the range that was asked for.
	if resp.StatusCode == http.StatusPartialContent {
		return false, resp.ContentLength
	}

	ctype := strings.ToLower(resp.Header.Get("Content-Type"))
	isJSON := strings.Contains(ctype, "json")
	isHTML := strings.Contains(ctype, "html")

	// Only buffer bodies that could plausibly be rewritten. A 200 MB video
	// segment must stream straight through.
	if !isJSON && !isHTML {
		return false, resp.ContentLength
	}
	if resp.ContentLength > maxRewriteBody {
		return false, resp.ContentLength
	}

	body, ok := takeBody(resp)
	if !ok {
		// takeBody has already restored a streamable body.
		return false, resp.ContentLength
	}
	modified := false

	switch {
	case c.MITM.Filters.YouTube && isYouTubeHost(host) && isJSON && wantsYouTubeFilter(path):
		if hasServerStitchedAds(body) {
			stats.ServerStitched.Add(1)
		}
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

	// The in-page engine goes in last so it sits after any rewrite above, and
	// only on YouTube documents, where it is the layer that survives a
	// response-shape change the static filter has not learned yet.
	if c.MITM.Filters.YouTube && c.MITM.Filters.YouTubeInPage && isHTML && isYouTubeAppHost(host) {
		if out, n := rewriteProbeSrc(body); n > 0 {
			body = out
			modified = true
		}
		if out, ok := injectPlayerEngine(body, InPageOptions{
			SponsorBlock: c.MITM.Filters.YouTubeSponsorBlock,
		}); ok {
			body = out
			modified = true
		}
	}

	if c.MITM.Filters.HTMLCosmetic && isHTML {
		if out, ok := injectCosmeticCSS(body); ok {
			body = out
			modified = true
		}
	}

	setPlainBody(resp, body)
	if modified {
		resp.Header.Set("X-Orbis-Filtered", "1")
		// A rewritten body must not be cached by the client under the
		// origin's original validators.
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
		resp.Header.Set("Cache-Control", "no-store")
	}
	return modified, int64(len(body))
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

// isYouTubeAppHost is the narrower set of hosts that serve the YouTube
// *application* documents: the ones the in-page engine belongs in and the
// only origins its endpoints answer. Account, consent and API hosts are
// YouTube hosts but not places to inject a script.
func isYouTubeAppHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch h {
	case "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com",
		"tv.youtube.com", "www.youtube-nocookie.com", "youtube-nocookie.com",
		"www.youtubekids.com", "youtubekids.com":
		return true
	}
	return false
}

// youtubeAdEndpoints are request paths that only ever carry ad traffic.
var youtubeAdEndpoints = []string{
	"/pagead/", "/ptracking", "/api/stats/ads", "/get_midroll_info",
	"/youtubei/v1/player/ad_break", "/pcs/activeview", "/aclk",
	"/pagead/viewthroughconversion", "/api/stats/qoe?ad",
	"/youtubei/v1/att/get", "/generate_204?", "/csi_204",
	// The ad-serving and measurement paths the player retries against when
	// it cannot place an ad. Dropping them stops the retry loop rather than
	// leaving it spinning.
	"/youtubei/v1/log_interaction", "/api/stats/atr",
	"/doubleclick", "/googleads", "/adservice",
}

// youtubeFilterPaths are the responses worth rewriting. Everything else on a
// YouTube host — thumbnails, video segments, the static bundle — is passed
// through untouched, which is what keeps the interception cheap.
var youtubeFilterPaths = []string{
	"/youtubei/v1/player",
	"/youtubei/v1/next",
	"/youtubei/v1/browse",
	"/youtubei/v1/search",
	"/youtubei/v1/reel/reel_item_watch",
	"/youtubei/v1/reel/reel_watch_sequence",
	"/youtubei/v1/guide",
	"/get_video_info",
	"/watch",
	"/results",
	"/shorts",
}

// wantsYouTubeFilter reports whether a path is one of the responses that
// carries ad structures.
func wantsYouTubeFilter(path string) bool {
	lp := strings.ToLower(path)
	for _, p := range youtubeFilterPaths {
		if strings.HasPrefix(lp, p) || strings.Contains(lp, p) {
			return true
		}
	}
	return false
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
	// Newer response shapes. YouTube renames and relocates these regularly,
	// which is why the filter removes a set of keys rather than matching one
	// exact document layout — a rename should cost one line here, not a
	// rewrite, and an unrecognised key simply is not removed rather than
	// corrupting the response.
	"adBreakParams",
	"adRequestParams",
	"playerAdParams",
	"adsData",
	"clientForcedAdParams",
	"instreamAdPlayerOverlayRenderer",
	"adNotify",
	// The slot/layout metadata the newer InnerTube shapes hang ads off. These
	// appear beside a renderer rather than inside it, so removing the
	// renderer alone leaves the player still expecting a slot to fill.
	"adPlacementRenderer",
	"adSlotMetadata",
	"adSlotLoggingData",
	"adLayoutMetadata",
	"adLayoutLoggingData",
	"playerLegacyDesktopWatchAdsRenderer",
	"clientSideAdConfig",
	"adPlaybackContextParams",
	"adPlacementConfig",
	"adCpn",
	// The anti-adblock enforcement dialog travels inside the same responses
	// as the ads it complains about.
	"enforcementMessageViewModel",
	"adBlockMessageViewModel",
}

// serverStitchedMarkers identify a response whose ads are muxed into the same
// media stream as the content (server-side ad insertion). There is nothing to
// remove in that case — the ad and the video are literally the same bytes —
// but knowing it happened is the difference between "the filter is broken"
// and "this stream cannot be filtered by anyone", so it is counted and
// surfaced rather than passed over in silence.
var serverStitchedMarkers = []string{
	"ssaMetadata",
	"serverStitchedAdPlacement",
	"AD_PLACEMENT_KIND_SERVER_STITCHED",
}

// hasServerStitchedAds reports whether a player response carries SSAI markers.
func hasServerStitchedAds(body []byte) bool {
	for _, m := range serverStitchedMarkers {
		if bytes.Contains(body, []byte(m)) {
			return true
		}
	}
	return false
}

// stripYouTubeAds removes ad structures from an InnerTube JSON response and
// reports how many were removed.
func stripYouTubeAds(body []byte) ([]byte, int) {
	// A cheap prefilter: most responses are not player responses at all, and
	// unmarshalling a multi-megabyte JSON blob for nothing is wasteful. The
	// probe set has to include every key the walker removes, or a response
	// carrying only a newer key would be skipped entirely — which is how a
	// feed full of promotedVideoRenderer used to sail straight through while
	// the walker that would have caught it never ran.
	if !containsAnyKey(body, youtubeAdKeys) && !containsAnyKey(body, adRenderers) {
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
	// Nested locations used by the newer response shapes.
	removed += removeNested(doc, []string{"playerResponse"}, youtubeAdKeys)
	// The watch page (/youtubei/v1/next) and Shorts (reel_item_watch) carry
	// ads in their own containers, which the player-response keys miss.
	removed += walkRemoveKeys(doc, youtubeAdKeys, 0)
	removed += walkRemoveRenderers(doc, 0)
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

// containsAnyKey is the prefilter: a cheap byte scan for any of the keys the
// walker would remove.
func containsAnyKey(body []byte, keys []string) bool {
	for _, k := range keys {
		if bytes.Contains(body, []byte(`"`+k+`"`)) {
			return true
		}
	}
	return false
}

// walkRemoveKeys removes the named keys wherever they appear, not only at the
// top level. YouTube moves them between response shapes, and a filter that
// only knows one layout stops working the week the layout changes.
func walkRemoveKeys(node any, keys []string, depth int) int {
	if depth > 40 {
		return 0
	}
	removed := 0
	switch v := node.(type) {
	case map[string]any:
		for _, k := range keys {
			if _, ok := v[k]; ok {
				delete(v, k)
				removed++
			}
		}
		for _, child := range v {
			removed += walkRemoveKeys(child, keys, depth+1)
		}
	case []any:
		for _, child := range v {
			removed += walkRemoveKeys(child, keys, depth+1)
		}
	}
	return removed
}

// adRenderers are the container types YouTube uses for promoted items in feed
// and watch-page responses. Removing the item that holds one leaves a gap the
// client handles as an unfilled slot.
var adRenderers = []string{
	"adSlotRenderer",
	"promotedSparklesWebRenderer",
	"promotedSparklesTextSearchRenderer",
	"promotedVideoRenderer",
	"displayAdRenderer",
	"searchPyvRenderer",
	"compactPromotedVideoRenderer",
	"instreamVideoAdRenderer",
	"bannerPromoRenderer",
	"statementBannerRenderer",
	"backgroundPromoRenderer",
	"brandVideoSingletonRenderer",
	"brandVideoShelfRenderer",
	"inFeedAdLayoutRenderer",
	// Masthead, carousel and companion units, plus the Shorts and mobile
	// shapes. Each is a whole entry in a list, so dropping the entry is what
	// makes the row close up rather than leave a blank card behind.
	"carouselAdRenderer",
	"primetimePromoRenderer",
	"videoMastheadAdV3Renderer",
	"videoMastheadAdV2Renderer",
	"actionCompanionAdRenderer",
	"imageCompanionAdRenderer",
	"videoDisplayFullButtonedAdRenderer",
	"adsFeedRenderer",
	"promotedItemRenderer",
	"compactPromotedItemRenderer",
	"shortsAdCardRenderer",
	"adDivergentRenderer",
	"featuredPromoRenderer",
}

// walkRemoveRenderers drops array entries whose sole content is an ad
// renderer. Removing the entry rather than blanking it is what makes the
// surrounding list close up instead of showing an empty card.
func walkRemoveRenderers(node any, depth int) int {
	if depth > 40 {
		return 0
	}
	removed := 0
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if arr, ok := child.([]any); ok {
				kept := compactAdItems(arr, &removed)
				v[key] = kept
				// Recurse over what survived, not over the slice we just
				// compacted in place: its tail still aliases entries that
				// were removed, and walking those counts them twice and
				// re-walks subtrees that are no longer in the document.
				removed += walkRemoveRenderers(kept, depth+1)
				continue
			}
			removed += walkRemoveRenderers(child, depth+1)
		}
	case []any:
		for _, child := range v {
			removed += walkRemoveRenderers(child, depth+1)
		}
	}
	return removed
}

// compactAdItems returns arr without its ad entries, compacting in place.
func compactAdItems(arr []any, removed *int) []any {
	kept := arr[:0]
	for _, item := range arr {
		if isAdItem(item) {
			*removed++
			continue
		}
		kept = append(kept, item)
	}
	// Clear the tail so the removed entries are not kept alive by the
	// backing array for as long as the document is.
	for i := len(kept); i < len(arr); i++ {
		arr[i] = nil
	}
	return kept
}

func isAdItem(item any) bool {
	m, ok := item.(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	// Only treat an entry as an ad when every key it has is an ad renderer;
	// a mixed object is content that happens to carry a promotion, and
	// deleting it would remove real results from the page.
	for k := range m {
		matched := false
		for _, r := range adRenderers {
			if k == r {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
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

// inlinePayloads are the assignments a YouTube HTML document embeds its own
// data in. The client reads the first video's player response from the page
// rather than calling the API, so a filter that only knows the API endpoint
// lets the first ad of every session through. The exact spelling varies by
// surface and has changed more than once — desktop, mobile web and the TV
// page each write it differently — so all of the known forms are tried.
var inlinePayloads = []string{
	"var ytInitialPlayerResponse = ",
	"var ytInitialPlayerResponse=",
	"ytInitialPlayerResponse = ",
	"ytInitialPlayerResponse=",
	`window["ytInitialPlayerResponse"] = `,
	`window["ytInitialPlayerResponse"]=`,
	"var ytInitialData = ",
	"var ytInitialData=",
	`window["ytInitialData"] = `,
	`window["ytInitialData"]=`,
}

// stripYouTubeInlineAds rewrites every embedded payload in a watch or feed
// page. It rebuilds the document once at the end so a page carrying both a
// player response and a feed payload is filtered in a single pass.
func stripYouTubeInlineAds(body []byte) ([]byte, int) {
	var spans []inlineSpan
	total := 0

	for _, marker := range inlinePayloads {
		off := 0
		for {
			idx := bytes.Index(body[off:], []byte(marker))
			if idx < 0 {
				break
			}
			start := off + idx + len(marker)
			off = start
			end := matchJSONObject(body, start)
			if end <= start {
				continue
			}
			// A shorter marker can match inside a longer one already handled
			// (`ytInitialPlayerResponse=` inside `var ytInitialPlayerResponse=`),
			// which would rewrite the same object twice and corrupt the page.
			if overlapsAny(spans, start, end) {
				off = end
				continue
			}
			rewritten, n := stripYouTubeAds(body[start:end])
			if n > 0 {
				spans = append(spans, inlineSpan{start, end, rewritten})
				total += n
			}
			off = end
		}
	}
	if total == 0 {
		return body, 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	out := make([]byte, 0, len(body))
	prev := 0
	for _, s := range spans {
		out = append(out, body[prev:s.start]...)
		out = append(out, s.repl...)
		prev = s.end
	}
	out = append(out, body[prev:]...)
	return out, total
}

// inlineSpan is one embedded payload and the bytes that replace it.
type inlineSpan struct {
	start, end int
	repl       []byte
}

func overlapsAny(spans []inlineSpan, start, end int) bool {
	for _, s := range spans {
		if start < s.end && s.start < end {
			return true
		}
	}
	return false
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
