package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestJobsRunOnceAndHandBackOnce(t *testing.T) {
	var j jobs
	calls := 0
	fn := func(ctx context.Context) (any, error) {
		calls++
		time.Sleep(50 * time.Millisecond)
		return "answer", nil
	}
	if st := j.get("k", time.Second, fn); !st.Running {
		t.Fatal("first call must start the job and report running")
	}
	if st := j.get("k", time.Second, fn); !st.Running {
		t.Fatal("a second call while running must not start another")
	}
	time.Sleep(120 * time.Millisecond)
	st := j.get("k", time.Second, fn)
	if st.Running || st.Result != "answer" || st.Err != nil {
		t.Fatalf("finished job not handed back: %+v", st)
	}
	if calls != 1 {
		t.Fatalf("fn ran %d times, want 1", calls)
	}
	if st := j.get("k", time.Second, fn); !st.Running {
		t.Fatal("after collection the next call must start a fresh job")
	}
	time.Sleep(120 * time.Millisecond)
	failing := func(ctx context.Context) (any, error) { return nil, errors.New("boom") }
	j.get("f", time.Second, failing)
	time.Sleep(20 * time.Millisecond)
	if st := j.get("f", time.Second, failing); st.Running || st.Err == nil {
		t.Fatalf("error not handed back: %+v", st)
	}
}
