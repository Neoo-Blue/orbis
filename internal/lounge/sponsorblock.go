package lounge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SponsorBlock is a thin client for the crowd-sourced segment database. It is
// used only to skip in-video segments (sponsor read-outs, intros, self-promo);
// Google's own ads are handled by the Lounge ad events, not by this.
//
// Queries use the privacy-preserving hash-prefix endpoint: the client sends
// only the first four hex characters of sha256(videoID), receives every video
// sharing that prefix, and filters locally. The server never learns which
// video was actually watched.
type SponsorBlock struct {
	base string
	hc   *http.Client
}

// Segment is one skippable region, in seconds.
type Segment struct {
	Category string  `json:"category"`
	Action   string  `json:"actionType"`
	Start    float64 `json:"-"`
	End      float64 `json:"-"`
}

func NewSponsorBlock(base string) *SponsorBlock {
	if base == "" {
		base = "https://sponsor.ajay.app/api/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &SponsorBlock{
		base: base,
		hc:   &http.Client{Timeout: 15 * time.Second},
	}
}

// wire mirrors the SponsorBlock response shape for one video.
type sbVideo struct {
	VideoID  string `json:"videoID"`
	Segments []struct {
		Category string    `json:"category"`
		Action   string    `json:"actionType"`
		Segment  []float64 `json:"segment"`
	} `json:"segments"`
}

// Segments returns the skip segments for videoID limited to the given
// categories, sorted by start time and filtered to plain "skip" actions
// (muting or full-video categories are ignored: seeking past them is the only
// action a TV remote can take).
func (s *SponsorBlock) Segments(ctx context.Context, videoID string, categories []string) ([]Segment, error) {
	if videoID == "" || len(categories) == 0 {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(videoID))
	prefix := hex.EncodeToString(sum[:])[:4]

	catJSON, _ := json.Marshal(categories)
	u := fmt.Sprintf("%sskipSegments/%s?categories=%s", s.base, prefix, url.QueryEscape(string(catJSON)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no segments for this prefix
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sponsorblock: http %d", resp.StatusCode)
	}
	var videos []sbVideo
	if err := json.NewDecoder(resp.Body).Decode(&videos); err != nil {
		return nil, err
	}

	want := make(map[string]bool, len(categories))
	for _, c := range categories {
		want[c] = true
	}
	var out []Segment
	for _, v := range videos {
		if v.VideoID != videoID {
			continue
		}
		for _, seg := range v.Segments {
			if !want[seg.Category] {
				continue
			}
			// "skip" is the only action a seek can perform; "mute"/"poi"/
			// "full" are not something we can honour on a cast player.
			if seg.Action != "" && seg.Action != "skip" {
				continue
			}
			if len(seg.Segment) != 2 || seg.Segment[1] <= seg.Segment[0] {
				continue
			}
			out = append(out, Segment{
				Category: seg.Category,
				Action:   "skip",
				Start:    seg.Segment[0],
				End:      seg.Segment[1],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// SegmentAt returns the segment covering t (with a small tolerance so a report
// that lands a hair before the start still fires), or nil.
func SegmentAt(segs []Segment, t float64) *Segment {
	const lead = 0.5
	for i := range segs {
		s := &segs[i]
		if t >= s.Start-lead && t < s.End-1.0 {
			return s
		}
	}
	return nil
}
