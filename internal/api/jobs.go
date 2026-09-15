package api

import (
	"context"
	"sync"
	"time"
)

// jobs runs slow operator actions (a model explanation, a review, a brief,
// an assessment) off the request. Through the Cloudflare tunnel a request
// that takes longer than the edge waits comes back as a 502 no matter what
// the daemon eventually answers, and free models can take two minutes to
// walk their fallback chain. A handler asks for the job: if it is finished
// the answer is returned and forgotten; if it is running the caller gets
// "still running" and asks again; otherwise it starts, detached from the
// request's context so a client that gives up does not cancel the work.
type jobs struct {
	mu   sync.Mutex
	runs map[string]*job
}

type job struct {
	started time.Time
	done    bool
	result  any
	err     error
}

type jobState struct {
	Running bool
	Started time.Time
	Result  any
	Err     error
}

// get returns the job's state, starting it when nothing is known. A finished
// job is handed back once and then cleared, so the next request starts anew.
func (j *jobs) get(key string, timeout time.Duration, fn func(ctx context.Context) (any, error)) jobState {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.runs == nil {
		j.runs = map[string]*job{}
	}
	if r, ok := j.runs[key]; ok {
		if !r.done {
			return jobState{Running: true, Started: r.started}
		}
		delete(j.runs, key)
		return jobState{Result: r.result, Err: r.err, Started: r.started}
	}
	r := &job{started: time.Now()}
	j.runs[key] = r
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res, err := fn(ctx)
		j.mu.Lock()
		r.result, r.err, r.done = res, err, true
		j.mu.Unlock()
	}()
	// Finished jobs nobody collected must not pile up.
	for k, r := range j.runs {
		if r.done && time.Since(r.started) > 30*time.Minute {
			delete(j.runs, k)
		}
	}
	return jobState{Running: true, Started: r.started}
}
