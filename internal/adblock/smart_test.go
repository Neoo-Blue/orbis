package adblock

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

type countingJudge struct {
	asked []string
}

func (j *countingJudge) JudgeDomains(_ context.Context, batch []DomainEvidence) ([]DomainVerdict, error) {
	var out []DomainVerdict
	for _, e := range batch {
		j.asked = append(j.asked, e.Domain)
		out = append(out, DomainVerdict{Domain: e.Domain, IsAdTech: e.Domain == "ads.example", Confidence: 0.97})
	}
	return out, nil
}

// A host seen only in DNS scores zero on the heuristics for lack of evidence.
// It must still reach the model once, its verdict must stand on its own
// rather than be blended with that zero, and a name-only verdict queues for
// a person instead of blocking.
func TestSmartCaptureDNSOnlyEscalation(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	cfg.AdBlock.SmartCapture.Enabled = true
	cfg.AdBlock.SmartCapture.UseAI = true
	for _, d := range []string{"ads.example", "cdn.example", "static.example"} {
		if err := st.ObserveCandidate(d, 50, 2, 0); err != nil {
			t.Fatal(err)
		}
	}
	// static.example was seen over HTTP on an earlier pass and is quiet in
	// this one: it is not a name-only case and must not be asked as one.
	if err := st.ScoreCandidate("static.example", 0.42, nil, "", 0.42, map[string]any{
		"referrers": []string{"a.com", "b.com"}, "third_party_ratio": 1.0, "avg_bytes": 43,
	}); err != nil {
		t.Fatal(err)
	}

	j := &countingJudge{}
	s := NewSmartCapture(st, cfg, nil, nil, nil)
	s.SetJudge(j)
	if err := s.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(j.asked) != 2 {
		t.Fatalf("judge asked about %v, want the two DNS-only candidates", j.asked)
	}
	if c, _ := st.Candidates(store.CandidateNew, 0, 10); len(c) != 1 || c[0].HeuristicScore < 0.4 {
		t.Errorf("static.example lost its HTTP evidence in a quiet pass: %+v", c)
	}
	review, _ := st.Candidates(store.CandidateReview, 0, 10)
	if len(review) != 1 || review[0].Domain != "ads.example" {
		t.Fatalf("review = %+v, want ads.example", review)
	}
	if f := review[0].FinalScore; f < 0.9 || f >= cfg.AdBlock.SmartCapture.AutoBlockScore {
		t.Errorf("final score %.2f: want the model's score, capped below auto-block", f)
	}
	if d, _ := st.Candidates(store.CandidateDismissed, 0, 10); len(d) != 1 {
		t.Errorf("dismissed = %+v, want cdn.example", d)
	}

	// The next pass leaves the queued verdict for a person: no second
	// question, and the model's reason is still there to read.
	j.asked = nil
	if err := s.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(j.asked) != 0 {
		t.Errorf("re-asked about %v", j.asked)
	}
	review, _ = st.Candidates(store.CandidateReview, 0, 10)
	if len(review) != 1 || review[0].AIScore == nil {
		t.Errorf("review verdict lost: %+v", review)
	}
}
