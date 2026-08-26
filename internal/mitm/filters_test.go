package mitm

import (
	"encoding/json"
	"strings"
	"testing"
)

// A trimmed but structurally faithful InnerTube player response: the ad keys
// sit alongside the streaming data that must survive.
const playerResponse = `{
  "responseContext": {"visitorData": "abc"},
  "playabilityStatus": {"status": "OK"},
  "streamingData": {
    "expiresInSeconds": "21540",
    "formats": [{"itag": 18, "url": "https://rr1.googlevideo.com/videoplayback?x=1"}],
    "adaptiveFormats": [
      {"itag": 137, "url": "https://rr1.googlevideo.com/videoplayback?x=2"},
      {"itag": 999, "isAdFormat": true, "url": "https://ad.example/creative"}
    ]
  },
  "adPlacements": [
    {"adPlacementRenderer": {"config": {"adPlacementConfig": {"kind": "AD_PLACEMENT_KIND_START"}}}},
    {"adPlacementRenderer": {"config": {"adPlacementConfig": {"kind": "AD_PLACEMENT_KIND_MILLISECONDS"}}}}
  ],
  "playerAds": [{"playerLegacyDesktopWatchAdsRenderer": {"playerAdParams": {"showContentThumbnail": true}}}],
  "adSlots": [{"adSlotRenderer": {"adSlotMetadata": {"slotId": "0"}}}],
  "adBreakHeartbeatParams": "Q0FF",
  "videoDetails": {"videoId": "dQw4w9WgXcQ", "title": "A video", "lengthSeconds": "212"},
  "playerConfig": {"audioConfig": {"loudnessDb": 1.5}, "adConfig": {"enableAds": true}}
}`

func TestStripYouTubeAdsRemovesAdsAndKeepsContent(t *testing.T) {
	out, removed := stripYouTubeAds([]byte(playerResponse))
	if removed == 0 {
		t.Fatal("no ad structures were removed")
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, key := range []string{"adPlacements", "playerAds", "adSlots", "adBreakHeartbeatParams"} {
		if _, present := doc[key]; present {
			t.Errorf("%q survived the filter", key)
		}
	}

	// The content side has to be intact, or the video will not play at all —
	// which is a far worse outcome than seeing an ad.
	vd, ok := doc["videoDetails"].(map[string]any)
	if !ok || vd["videoId"] != "dQw4w9WgXcQ" {
		t.Error("videoDetails was damaged")
	}
	sd, ok := doc["streamingData"].(map[string]any)
	if !ok {
		t.Fatal("streamingData was removed")
	}
	formats, _ := sd["adaptiveFormats"].([]any)
	if len(formats) != 1 {
		t.Errorf("adaptiveFormats has %d entries, want 1 (the ad-only format removed, the real one kept)", len(formats))
	}
	if len(formats) == 1 {
		f := formats[0].(map[string]any)
		if f["itag"].(float64) != 137 {
			t.Error("the wrong format survived")
		}
	}
	if pc, ok := doc["playerConfig"].(map[string]any); ok {
		if _, present := pc["adConfig"]; present {
			t.Error("playerConfig.adConfig survived")
		}
		if _, present := pc["audioConfig"]; !present {
			t.Error("playerConfig.audioConfig was removed — only the ad key should go")
		}
	}
}

func TestStripYouTubeAdsIgnoresUnrelatedJSON(t *testing.T) {
	input := []byte(`{"items":[{"id":"1"}],"nextPageToken":"abc"}`)
	out, removed := stripYouTubeAds(input)
	if removed != 0 {
		t.Errorf("removed %d keys from a response with no ads", removed)
	}
	if string(out) != string(input) {
		t.Error("an untouched response should be returned byte-identical, not re-serialised")
	}
}

func TestStripYouTubeAdsSurvivesMalformedInput(t *testing.T) {
	// A truncated body must be passed through unchanged rather than
	// replaced with something the client cannot parse.
	broken := []byte(`{"adPlacements": [ {"unclosed": `)
	out, removed := stripYouTubeAds(broken)
	if removed != 0 || string(out) != string(broken) {
		t.Error("malformed JSON should be returned untouched")
	}
}

func TestStripYouTubeInlineAds(t *testing.T) {
	html := `<!doctype html><html><head><script>var ytInitialPlayerResponse = ` +
		playerResponse + `;var other = 1;</script></head><body>hi</body></html>`
	out, removed := stripYouTubeInlineAds([]byte(html))
	if removed == 0 {
		t.Fatal("inline player response was not filtered")
	}
	s := string(out)
	if strings.Contains(s, "adPlacements") {
		t.Error("adPlacements survived in the inline response")
	}
	// The surrounding document has to stay intact or the page breaks.
	if !strings.HasPrefix(s, "<!doctype html>") || !strings.HasSuffix(s, "</html>") {
		t.Error("the surrounding HTML was damaged")
	}
	if !strings.Contains(s, "var other = 1;") {
		t.Error("script content after the player response was lost")
	}
	if !strings.Contains(s, "dQw4w9WgXcQ") {
		t.Error("the video id was lost")
	}
}

func TestMatchJSONObjectRespectsStringsAndEscapes(t *testing.T) {
	// A brace inside a video title must not terminate the scan early.
	input := []byte(`{"title":"a } brace and a \" quote","x":{"y":1}} trailing`)
	end := matchJSONObject(input, 0)
	if end <= 0 {
		t.Fatal("no object end found")
	}
	var doc map[string]any
	if err := json.Unmarshal(input[:end], &doc); err != nil {
		t.Fatalf("the extracted slice is not valid JSON: %v", err)
	}
	if doc["title"] != `a } brace and a " quote` {
		t.Errorf("title = %v", doc["title"])
	}
}

func TestStripGenericJSONAdsRecurses(t *testing.T) {
	input := []byte(`{"feed":{"sections":[{"items":[1,2],"ads":[{"id":"x"}]},{"promoted_items":["y"]}]}}`)
	out, removed := stripGenericJSONAds(input)
	if removed != 2 {
		t.Errorf("removed %d ad keys, want 2", removed)
	}
	if strings.Contains(string(out), `"ads"`) || strings.Contains(string(out), `"promoted_items"`) {
		t.Error("ad keys survived")
	}
	if !strings.Contains(string(out), `"items"`) {
		t.Error("real content was removed")
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"www.youtube.com", "*.youtube.com", true},
		{"youtube.com", "*.youtube.com", true},
		{"notyoutube.com", "*.youtube.com", false},
		{"evil-youtube.com.attacker.test", "*.youtube.com", false},
		{"chase.com", "*.chase.com", true},
		{"anything.test", "*", true},
		{"mybank.co", "*.bank*", false},
		{"exact.example", "exact.example", true},
	}
	for _, c := range cases {
		if got := hostMatches(c.host, c.pattern); got != c.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestInjectCosmeticCSSIsIdempotent(t *testing.T) {
	html := []byte("<html><head><title>x</title></head><body></body></html>")
	once, ok := injectCosmeticCSS(html)
	if !ok {
		t.Fatal("CSS was not injected")
	}
	if _, ok := injectCosmeticCSS(once); ok {
		t.Error("CSS was injected twice into the same document")
	}
	if _, ok := injectCosmeticCSS([]byte("no head element here")); ok {
		t.Error("injected into a document with no head")
	}
}

// The watch page and Shorts carry ads in containers the player-response keys
// do not cover. A filter that only knows one layout stops working the week
// YouTube changes it, which is exactly what "it still shows ads sometimes"
// looks like from the outside.
func TestStripYouTubeAdsHandlesFeedRenderers(t *testing.T) {
	next := `{
	  "contents": {
	    "twoColumnWatchNextResults": {
	      "secondaryResults": {
	        "secondaryResults": {
	          "results": [
	            {"compactVideoRenderer": {"videoId": "real1"}},
	            {"adSlotRenderer": {"adSlotMetadata": {"slotId": "1"}}},
	            {"compactVideoRenderer": {"videoId": "real2"}},
	            {"promotedSparklesWebRenderer": {"impressionUrl": "https://ad"}},
	            {"compactPromotedVideoRenderer": {"videoId": "ad1"}}
	          ]
	        }
	      }
	    }
	  }
	}`
	out, removed := stripYouTubeAds([]byte(next))
	if removed == 0 {
		t.Fatal("no ad renderers were removed from the watch-page response")
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	results := doc["contents"].(map[string]any)["twoColumnWatchNextResults"].(map[string]any)["secondaryResults"].(map[string]any)["secondaryResults"].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results has %d entries, want the 2 real videos", len(results))
	}
	// The surrounding list has to close up, not leave empty cards behind.
	for _, r := range results {
		if _, isAd := r.(map[string]any)["adSlotRenderer"]; isAd {
			t.Error("an ad renderer survived")
		}
	}
	if !strings.Contains(string(out), "real1") || !strings.Contains(string(out), "real2") {
		t.Error("real content was removed alongside the ads")
	}
}

func TestAdRemovalKeepsMixedObjects(t *testing.T) {
	// An entry that carries both content and a promotion is content. Removing
	// it would delete real search results, which is far worse than showing
	// one promoted item.
	if isAdItem(map[string]any{"videoRenderer": map[string]any{}, "adSlotRenderer": map[string]any{}}) {
		t.Error("a mixed object was treated as an ad and would be deleted whole")
	}
	if !isAdItem(map[string]any{"adSlotRenderer": map[string]any{}}) {
		t.Error("a pure ad entry was not recognised")
	}
	if isAdItem(map[string]any{}) {
		t.Error("an empty object was treated as an ad")
	}
	if isAdItem("not an object") {
		t.Error("a non-object was treated as an ad")
	}
}

func TestNestedAdKeysAreRemovedAtAnyDepth(t *testing.T) {
	// YouTube relocates these between response shapes; a top-level-only
	// filter silently stops working when it does.
	body := `{"a":{"b":{"c":{"playerAds":[{"x":1}],"keep":"yes"}}},"adBreakParams":{"y":2}}`
	out, removed := stripYouTubeAds([]byte(body))
	if removed < 2 {
		t.Errorf("removed %d keys, want both the nested and the top-level one", removed)
	}
	if strings.Contains(string(out), "playerAds") || strings.Contains(string(out), "adBreakParams") {
		t.Error("an ad key survived")
	}
	if !strings.Contains(string(out), `"keep":"yes"`) {
		t.Error("a sibling key was removed alongside the ad key")
	}
}

func TestWantsYouTubeFilterSkipsBulkContent(t *testing.T) {
	// Buffering a video segment to look for ad JSON would be pointless and
	// would add latency to the thing people actually came to watch.
	for _, p := range []string{"/youtubei/v1/player", "/youtubei/v1/next", "/watch?v=abc", "/shorts/xyz"} {
		if !wantsYouTubeFilter(p) {
			t.Errorf("%q should be filtered", p)
		}
	}
	for _, p := range []string{"/videoplayback?range=0-100", "/vi/abc/hqdefault.jpg", "/s/player/base.js"} {
		if wantsYouTubeFilter(p) {
			t.Errorf("%q should pass through untouched", p)
		}
	}
}

func TestPrefilterCoversEveryRemovedKey(t *testing.T) {
	// If the walker can remove a key the prefilter does not probe for, a
	// response carrying only that key is skipped entirely — the exact bug
	// that lets ads through after a YouTube rename.
	for _, k := range youtubeAdKeys {
		body := []byte(`{"` + k + `":[1]}`)
		if _, removed := stripYouTubeAds(body); removed == 0 {
			t.Errorf("key %q is removed by the walker but missed by the prefilter", k)
		}
	}
}
