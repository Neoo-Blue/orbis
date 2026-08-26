package lounge

import (
	"strings"
	"testing"
)

func TestParseFrame(t *testing.T) {
	// A realistic bind response: the "c" (SID), "S" (gsessionid), and a
	// nowPlaying event, as a single JSON frame.
	frame := `[[0,["c","SID12345","",8]],[1,["S","gsess-abc"]],[2,["nowPlaying",{"videoId":"dQw4w9WgXcQ","currentTime":"12.5","state":"1"}]]]`
	evs := parseFrame([]byte(frame))
	if len(evs) != 3 {
		t.Fatalf("want 3 events, got %d", len(evs))
	}
	if evs[0].typ != "c" || evs[0].firstString(0) != "SID12345" {
		t.Fatalf("bad c event: %+v", evs[0])
	}
	if evs[1].typ != "S" || evs[1].firstString(0) != "gsess-abc" {
		t.Fatalf("bad S event: %+v", evs[1])
	}
	if evs[2].typ != "nowPlaying" {
		t.Fatalf("bad nowPlaying event: %+v", evs[2])
	}
	obj := evs[2].object()
	if obj["videoId"] != "dQw4w9WgXcQ" {
		t.Fatalf("videoId not parsed: %+v", obj)
	}
	if f, ok := asFloat(obj["currentTime"]); !ok || f != 12.5 {
		t.Fatalf("currentTime not coerced: %v %v", f, ok)
	}
}

func TestParseFrameSkipsMalformed(t *testing.T) {
	// A missing body and a non-array entry must not abort the whole frame.
	frame := `[[0,["onStateChange",{"state":"2"}]],[1],"garbage",[2,["nowPlaying",{"videoId":"abc"}]]]`
	evs := parseFrame([]byte(frame))
	if len(evs) != 2 {
		t.Fatalf("want 2 usable events, got %d: %+v", len(evs), evs)
	}
	if evs[0].typ != "onStateChange" || evs[1].typ != "nowPlaying" {
		t.Fatalf("wrong events survived: %+v", evs)
	}
}

func TestReadStreamRuneFraming(t *testing.T) {
	// Two frames; the first title contains a multibyte rune so the length is a
	// rune count, not a byte count. If framing used bytes it would desync.
	body := `[[0,["nowPlaying",{"videoId":"a","title":"café"}]]]`
	runeLen := len([]rune(body))
	stream := itoa(runeLen) + "\n" + body
	// Second frame.
	body2 := `[[1,["onStateChange",{"state":"1","currentTime":"3"}]]]`
	stream += itoa(len([]rune(body2))) + "\n" + body2

	var got []string
	err := readStream(strings.NewReader(stream), func(ev event) {
		got = append(got, ev.typ)
	})
	if err != nil {
		t.Fatalf("readStream error: %v", err)
	}
	if len(got) != 2 || got[0] != "nowPlaying" || got[1] != "onStateChange" {
		t.Fatalf("framing desynced, got %v", got)
	}
}

func TestSegmentAtAndSelection(t *testing.T) {
	segs := []Segment{
		{Category: "sponsor", Start: 10, End: 30},
		{Category: "intro", Start: 60, End: 75},
	}
	if s := SegmentAt(segs, 5); s != nil {
		t.Fatalf("5s should be outside all segments")
	}
	if s := SegmentAt(segs, 15); s == nil || s.Category != "sponsor" {
		t.Fatalf("15s should be inside the sponsor segment, got %+v", s)
	}
	// Right at the tail (within 1s of end) we should NOT still be skipping,
	// so we do not fight the player as it naturally exits the segment.
	if s := SegmentAt(segs, 29.5); s != nil {
		t.Fatalf("29.5s is within 1s of end; should not match")
	}
	// A hair before the start still fires thanks to the lead tolerance.
	if s := SegmentAt(segs, 9.7); s == nil {
		t.Fatalf("9.7s should match via lead tolerance")
	}
}

// itoa avoids importing strconv into the test just for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
