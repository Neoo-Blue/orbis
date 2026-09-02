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
	"sync"
	"time"
)

// Segment actions. A skip segment moves the playhead past itself; a mute
// segment leaves the picture alone and silences the audio for its duration,
// which is what SponsorBlock uses for segments where skipping would cut
// something the viewer needs to see (a sponsor read over on-screen content).
const (
	ActionSkip = "skip"
	ActionMute = "mute"
)

// SponsorBlock is a thin client for the crowd-sourced segment database. It is
// used only to skip in-video segments (sponsor read-outs, intros, self-promo);
// Google's own ads are handled by the Lounge ad events, not by this.
//
// Queries use the privacy-preserving hash-prefix endpoint: the client sends
// only the first four hex characters of sha256(videoID), receives every video
// sharing that prefix, and filters locally. The server never learns which
// video was actually watched.
//
// Results are cached briefly so a page that reloads, a TV that buffers and
// re-reports, or the in-page engine and the Lounge engine looking at the same
// video do not each cost a round trip to the public API.
type SponsorBlock struct {
	base string
	hc   *http.Client

	mu    sync.Mutex
	cache map[string]sbCached
}

type sbCached struct {
	at   time.Time
	ttl  time.Duration
	segs []Segment
	err  error
}

const (
	sbCacheTTL = 10 * time.Minute
	// sbErrorTTL is how long a failed lookup is remembered. Without it a
	// SponsorBlock outage costs a full timeout per new video, per engine,
	// per page load.
	sbErrorTTL = time.Minute
	sbCacheMax = 512
)

// Segment is one skippable or mutable region, in seconds.
type Segment struct {
	Category string  `json:"category"`
	Action   string  `json:"action"`
	Start    float64 `json:"start"`
	End      float64 `json:"end"`
}

func NewSponsorBlock(base string) *SponsorBlock {
	if base == "" {
		base = "https://sponsor.ajay.app/api/"
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &SponsorBlock{
		base:  base,
		hc:    &http.Client{Timeout: 15 * time.Second},
		cache: map[string]sbCached{},
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

// Segments returns the segments for videoID limited to the given categories,
// sorted by start time. Only skip and mute actions are returned: a
// point-of-interest or full-video label is information, not something a
// player can act on.
func (s *SponsorBlock) Segments(ctx context.Context, videoID string, categories []string) ([]Segment, error) {
	if videoID == "" || len(categories) == 0 {
		return nil, nil
	}
	key := videoID + "|" + strings.Join(categories, ",")
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && time.Since(c.at) < c.ttl {
		s.mu.Unlock()
		if c.err != nil {
			return nil, c.err
		}
		return append([]Segment(nil), c.segs...), nil
	}
	s.mu.Unlock()

	sum := sha256.Sum256([]byte(videoID))
	prefix := hex.EncodeToString(sum[:])[:4]

	catJSON, _ := json.Marshal(categories)
	u := fmt.Sprintf("%sskipSegments/%s?categories=%s&actionTypes=%s", s.base, prefix,
		url.QueryEscape(string(catJSON)), url.QueryEscape(`["skip","mute"]`))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		s.rememberError(key, err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		s.remember(key, nil)
		return nil, nil // no segments for this prefix
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("sponsorblock: http %d", resp.StatusCode)
		s.rememberError(key, err)
		return nil, err
	}
	var videos []sbVideo
	if err := json.NewDecoder(resp.Body).Decode(&videos); err != nil {
		s.rememberError(key, err)
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
			action := seg.Action
			if action == "" {
				action = ActionSkip
			}
			if action != ActionSkip && action != ActionMute {
				continue
			}
			if len(seg.Segment) != 2 || seg.Segment[1] <= seg.Segment[0] {
				continue
			}
			out = append(out, Segment{
				Category: seg.Category,
				Action:   action,
				Start:    seg.Segment[0],
				End:      seg.Segment[1],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	s.remember(key, out)
	return out, nil
}

func (s *SponsorBlock) remember(key string, segs []Segment) {
	s.store(key, sbCached{at: time.Now(), ttl: sbCacheTTL, segs: segs})
}

func (s *SponsorBlock) rememberError(key string, err error) {
	s.store(key, sbCached{at: time.Now(), ttl: sbErrorTTL, err: err})
}

func (s *SponsorBlock) store(key string, entry sbCached) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= sbCacheMax {
		// Drop the oldest half rather than one entry at a time; the cache is
		// small and this keeps the eviction cost negligible.
		type kv struct {
			k  string
			at time.Time
		}
		all := make([]kv, 0, len(s.cache))
		for k, v := range s.cache {
			all = append(all, kv{k, v.at})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
		for _, e := range all[:len(all)/2] {
			delete(s.cache, e.k)
		}
	}
	s.cache[key] = entry
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
