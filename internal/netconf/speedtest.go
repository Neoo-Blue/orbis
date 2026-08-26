package netconf

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Speed test. This measures the node's own throughput against a public
// endpoint, which is what UniFi and Meraki report too. It is not a substitute
// for a client-side test: it says what this box can reach, not what the sofa
// gets over WiFi.

// SpeedResult is one measurement.
type SpeedResult struct {
	DownloadMbps float64   `json:"download_mbps"`
	UploadMbps   float64   `json:"upload_mbps"`
	LatencyMS    float64   `json:"latency_ms"`
	JitterMS     float64   `json:"jitter_ms"`
	Server       string    `json:"server"`
	RanAt        time.Time `json:"ran_at"`
	Note         string    `json:"note,omitempty"`
}

// Cloudflare's speed endpoints are used because they are anycast, unmetered,
// need no API key, and accept both a download size and an upload body.
const (
	dlURL = "https://speed.cloudflare.com/__down?bytes=%d"
	ulURL = "https://speed.cloudflare.com/__up"
	// A latency probe with a tiny body isolates round-trip time from transfer.
	pingURL = "https://speed.cloudflare.com/__down?bytes=0"
)

// RunSpeedTest measures latency, download and upload in that order.
func RunSpeedTest(ctx context.Context) (*SpeedResult, error) {
	res := &SpeedResult{Server: "speed.cloudflare.com", RanAt: time.Now()}
	hc := &http.Client{Timeout: 60 * time.Second}

	// Latency and jitter from a handful of small requests.
	var samples []float64
	for i := 0; i < 5; i++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("latency probe: %w", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
	}
	res.LatencyMS, res.JitterMS = meanJitter(samples)

	// Download. 25 MB is enough to saturate a domestic link without turning a
	// speed test into a meaningful chunk of a metered allowance.
	const dlBytes = 25 << 20
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(dlURL, dlBytes), nil)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if elapsed > 0 {
		res.DownloadMbps = float64(n) * 8 / elapsed / 1e6
	}

	// Upload. Random bytes so no intermediary can compress the stream and
	// report a throughput the link cannot really deliver.
	const ulBytes = 10 << 20
	payload := make([]byte, ulBytes)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ulURL, newRepeatReader(payload))
	if err != nil {
		return nil, err
	}
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upReq.ContentLength = ulBytes
	start = time.Now()
	upResp, err := hc.Do(upReq)
	if err != nil {
		res.Note = "upload measurement failed: " + err.Error()
		return res, nil // a download-only result is still useful
	}
	_, _ = io.Copy(io.Discard, upResp.Body)
	upResp.Body.Close()
	elapsed = time.Since(start).Seconds()
	if elapsed > 0 {
		res.UploadMbps = float64(ulBytes) * 8 / elapsed / 1e6
	}
	return res, nil
}

func meanJitter(samples []float64) (mean, jitter float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	mean = sum / float64(len(samples))
	// Jitter as mean absolute deviation, which is what a user perceives as
	// inconsistency better than standard deviation does.
	var dev float64
	for _, s := range samples {
		d := s - mean
		if d < 0 {
			d = -d
		}
		dev += d
	}
	jitter = dev / float64(len(samples))
	return mean, jitter
}

// repeatReader streams a fixed buffer without holding a second copy.
type repeatReader struct {
	buf []byte
	pos int
}

func newRepeatReader(b []byte) *repeatReader { return &repeatReader{buf: b} }

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}
