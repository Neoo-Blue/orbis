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
