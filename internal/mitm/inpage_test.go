package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestInjectPlayerEngineGoesAfterCharsetAndReusesNonce(t *testing.T) {
	page := []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>x</title>` +
		`<script nonce="abcDEF123">var a=1;</script></head><body></body></html>`)
	out, ok := injectPlayerEngine(page, InPageOptions{SponsorBlock: true, Offset: 0.5})
	if !ok {
		t.Fatal("expected injection")
	}
	s := string(out)
	charset := strings.Index(s, `<meta charset="utf-8">`)
	engine := strings.Index(s, engineMarker)
	if charset < 0 || engine < charset {
		t.Fatalf("engine must come after the charset meta:\n%s", s[:200])
	}
	if !strings.Contains(s, `<script nonce="abcDEF123">window.__orbisYTcfg={sb:true,offset:0.5};`) {
		t.Fatalf("engine should reuse the page nonce and carry its config:\n%s", s[:400])
	}
	if !strings.Contains(s, InPageReportPath) || !strings.Contains(s, InPageSegmentsPath) {
		t.Fatal("engine should reference both same-origin endpoints")
	}
	// Idempotent: a second pass leaves the document alone.
	if _, again := injectPlayerEngine(out, InPageOptions{}); again {
		t.Fatal("second injection should be a no-op")
	}
}

func TestInjectPlayerEngineNeedsAHead(t *testing.T) {
	if _, ok := injectPlayerEngine([]byte(`{"not":"html"}`), InPageOptions{}); ok {
		t.Fatal("no <head>, no injection")
	}
}

func TestPlayerEngineIsES5Safe(t *testing.T) {
	// Template literals and arrow functions would break the oldest TV
	// browsers, and a backtick would also terminate the Go raw string.
	if strings.Contains(playerEngineJS, "`") || strings.Contains(playerEngineJS, "=>") {
		t.Fatal("engine must stay ES5: no template literals or arrow functions")
	}
	if strings.Contains(playerEngineJS, "const ") || strings.Contains(playerEngineJS, "let ") {
		t.Fatal("engine must stay ES5: no const/let")
	}
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

func TestTakeBodyDecodesGzipAndSetPlainBodyFixesHeaders(t *testing.T) {
	plain := []byte(`{"hello":"world"}`)
	enc := gzipBytes(t, plain)
	resp := &http.Response{
		Header:        http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"999"}},
		Body:          io.NopCloser(bytes.NewReader(enc)),
		ContentLength: int64(len(enc)),
	}
	body, ok := takeBody(resp)
	if !ok || !bytes.Equal(body, plain) {
		t.Fatalf("gzip body should decode: ok=%v body=%q", ok, body)
	}
	setPlainBody(resp, body)
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "17" || resp.ContentLength != 17 {
		t.Fatalf("headers not normalised: %+v len=%d", resp.Header, resp.ContentLength)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, plain) {
		t.Fatalf("body mismatch: %q", got)
	}
}

func TestTakeBodyRestoresUnsupportedEncodingUntouched(t *testing.T) {
	raw := []byte("\x1b\x02brotli-ish-bytes")
	resp := &http.Response{
		Header: http.Header{"Content-Encoding": {"br"}},
		Body:   io.NopCloser(bytes.NewReader(raw)),
	}
	body, ok := takeBody(resp)
	if ok || body != nil {
		t.Fatal("an encoding we cannot decode must not be rewritten")
	}
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Fatal("Content-Encoding must survive so the client can decode it")
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, raw) {
		t.Fatalf("original bytes must stream through unchanged, got %q", got)
	}
}

func TestTakeBodyOverBudgetStreamsWholeBody(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxRewriteBody+10)
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewReader(big)),
	}
	body, ok := takeBody(resp)
	if ok || body != nil {
		t.Fatal("over-budget body must not be buffered for rewrite")
	}
	got, _ := io.ReadAll(resp.Body)
	if len(got) != len(big) {
		t.Fatalf("over-budget body truncated: %d of %d", len(got), len(big))
	}
}

// readBack parses what writeResponse put on the wire, using the standard
// library's reader as the arbiter of whether the framing was legal.
func readBack(t *testing.T, resp *http.Response, req *http.Request) (*http.Response, bool) {
	t.Helper()
	client, server := net.Pipe()
	var keep bool
	done := make(chan struct{})
	go func() {
		keep = writeResponse(server, resp, req)
		server.Close()
		close(done)
	}()
	got, err := http.ReadResponse(newBufReader(client), req)
	if err != nil {
		t.Fatalf("wire response unreadable: %v", err)
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatalf("body unreadable: %v", err)
	}
	got.Body = io.NopCloser(bytes.NewReader(body))
	<-done
	return got, keep
}

func TestWriteResponseUsesChunkedForUnknownLength(t *testing.T) {
	req := httptest.NewRequest("GET", "https://www.youtube.com/watch", nil)
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"video/mp4"}},
		Body:          io.NopCloser(strings.NewReader("segment-bytes")),
		ContentLength: -1,
	}
	got, keep := readBack(t, resp, req)
	if !keep {
		t.Fatal("HTTP/1.1 with chunked framing should keep the connection alive")
	}
	if len(got.TransferEncoding) == 0 || got.TransferEncoding[0] != "chunked" {
		t.Fatalf("expected chunked, got %+v", got.TransferEncoding)
	}
	b, _ := io.ReadAll(got.Body)
	if string(b) != "segment-bytes" {
		t.Fatalf("body mismatch: %q", b)
	}
}

func TestWriteResponseKeepsKnownLengthAndEncoding(t *testing.T) {
	req := httptest.NewRequest("GET", "https://www.youtube.com/x", nil)
	enc := gzipBytes(t, []byte("still compressed"))
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Encoding": {"gzip"}, "Content-Type": {"text/plain"}},
		Body:          io.NopCloser(bytes.NewReader(enc)),
		ContentLength: int64(len(enc)),
	}
	got, _ := readBack(t, resp, req)
	if got.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("a body the filter did not decode must keep its Content-Encoding")
	}
	if got.ContentLength != int64(len(enc)) {
		t.Fatalf("Content-Length should be preserved: %d vs %d", got.ContentLength, len(enc))
	}
	b, _ := io.ReadAll(got.Body)
	if !bytes.Equal(b, enc) {
		t.Fatal("compressed bytes altered in transit")
	}
}

func TestWriteResponseHeadHasNoBody(t *testing.T) {
	req := httptest.NewRequest("HEAD", "https://www.youtube.com/x", nil)
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader("should-not-be-sent")),
		ContentLength: 18,
	}
	got, _ := readBack(t, resp, req)
	b, _ := io.ReadAll(got.Body)
	if len(b) != 0 {
		t.Fatalf("HEAD response carried a body: %q", b)
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	c := config.Default()
	c.MITM.Enabled = true
	return c
}

func TestFilterRequestAnswersInPageReportLocally(t *testing.T) {
	f := NewFilterChain(testConfig(t))
	req := httptest.NewRequest("POST", "https://www.youtube.com"+InPageReportPath, strings.NewReader(`{"stripped":3}`))
	v := f.FilterRequest("www.youtube.com", InPageReportPath, req)
	if !v.Drop || v.Reason != "orbis-inpage-report" || v.Status != http.StatusNoContent {
		t.Fatalf("report endpoint should be answered locally: %+v", v)
	}
	// The same path on another host is not ours to answer.
	v = f.FilterRequest("example.com", InPageReportPath, req)
	if v.Drop {
		t.Fatal("report path on a non-YouTube host must be forwarded")
	}
}

func TestRecordInPageReportCapsAndSums(t *testing.T) {
	p := New(testConfig(t), nil, nil)
	mk := func(body string) *http.Request {
		return httptest.NewRequest("POST", "https://www.youtube.com"+InPageReportPath, strings.NewReader(body))
	}
	p.recordInPageReport(mk(`{"stripped":2,"burned":1,"skips":1,"segments":4}`))
	p.recordInPageReport(mk(`{"stripped":999999}`))
	p.recordInPageReport(mk(`not json`))
	st := p.Stats()
	if st["inpage_stripped"] != int64(1002) || st["inpage_skipped"] != int64(2) || st["inpage_segments"] != int64(4) {
		t.Fatalf("unexpected counters: %+v", st)
	}
}

func TestSponsorResponseValidatesAndSerialises(t *testing.T) {
	p := New(testConfig(t), nil, nil)
	p.SponsorSegments = func(_ context.Context, vid string) (any, error) {
		return map[string]any{"video_id": vid, "segments": []map[string]any{{"category": "sponsor", "action": "skip", "start": 1.0, "end": 9.5}}}, nil
	}
	mk := func(q string) *http.Request {
		u := &url.URL{Scheme: "https", Host: "www.youtube.com", Path: InPageSegmentsPath, RawQuery: q}
		return &http.Request{Method: "GET", URL: u, Header: http.Header{}}
	}
	resp := p.sponsorResponse(context.Background(), mk("v=dQw4w9WgXcQ"))
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"start":1`) || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("bad segment response: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	// A malformed id never reaches the lookup.
	called := false
	p.SponsorSegments = func(context.Context, string) (any, error) { called = true; return nil, nil }
	resp = p.sponsorResponse(context.Background(), mk("v=../../etc/passwd"))
	b, _ = io.ReadAll(resp.Body)
	if called || !strings.Contains(string(b), `"segments":[]`) {
		t.Fatalf("invalid id should get the empty answer without a lookup: called=%v body=%s", called, b)
	}
	// Disabled in config: same empty answer.
	cfg := testConfig(t)
	cfg.MITM.Filters.YouTubeSponsorBlock = false
	p2 := New(cfg, nil, nil)
	p2.SponsorSegments = func(context.Context, string) (any, error) { t.Fatal("must not be called"); return nil, nil }
	resp = p2.sponsorResponse(context.Background(), mk("v=dQw4w9WgXcQ"))
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"segments":[]`) {
		t.Fatalf("disabled endpoint should answer empty: %s", b)
	}
	_ = time.Second
}
