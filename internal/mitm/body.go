package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Response bodies are only ever buffered when there is a realistic chance of
// rewriting them. Everything else streams straight through, because a proxy
// that buffers a video segment is a proxy that breaks video.
const (
	// maxRewriteBody is the largest *encoded* body worth pulling into memory.
	maxRewriteBody = 24 << 20
	// maxInflated bounds the decompressed size, so a compression bomb cannot
	// turn a 2 MB response into gigabytes of resident memory.
	maxInflated = 96 << 20
)

type stringError string

func (e stringError) Error() string { return string(e) }

const errUnsupportedEncoding = stringError("unsupported content-encoding")

// takeBody reads and decodes a response body for rewriting. It returns
// ok=false when the body cannot or should not be rewritten — too large, or in
// an encoding this build cannot decode — and in that case it restores
// resp.Body so the response still streams through byte-for-byte with its
// original framing and Content-Encoding intact.
//
// The restore path is the whole point of the function. Decoding a body and
// discovering afterwards that it is unusable used to leave the response
// holding a truncated copy of itself, which is how a 30 MB page became 24 MB
// of broken HTML.
func takeBody(resp *http.Response) ([]byte, bool) {
	if resp.Body == nil {
		return nil, false
	}
	// Read one byte past the budget so "exactly at the limit" is
	// distinguishable from "longer than the limit".
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBody+1))
	if err != nil {
		// The origin cut off mid-body. What was read is forwarded, but the
		// declared length is left as the origin stated it and the
		// connection is marked to close, so the client sees a short read
		// rather than a well-framed, complete-looking, broken document.
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.Close = true
		resp.Header.Set("X-Orbis-Truncated", "1")
		return nil, false
	}
	if len(raw) > maxRewriteBody {
		// Over budget: hand the buffered bytes back, still encoded, and let
		// the remainder stream from the socket behind them.
		resp.Body = &replayCloser{
			Reader: io.MultiReader(bytes.NewReader(raw), resp.Body),
			Closer: resp.Body,
		}
		return nil, false
	}
	resp.Body.Close()

	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	plain, err := decodeBody(raw, enc)
	if err != nil {
		// Mislabelled or unsupported encoding. Replay the original bytes
		// untouched rather than serving something we did not understand.
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		return nil, false
	}
	return plain, true
}

// decodeBody inflates raw according to a Content-Encoding value. An empty or
// "identity" encoding returns the bytes unchanged.
func decodeBody(raw []byte, enc string) ([]byte, error) {
	switch enc {
	case "", "identity":
		return raw, nil
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return readLimited(gz)
	case "deflate":
		// "deflate" is served both as a raw deflate stream and as a
		// zlib-wrapped one. Both are in the wild; try the wrapped form first
		// because its header makes a wrong guess detectable.
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			defer zr.Close()
			if out, err := readLimited(zr); err == nil {
				return out, nil
			}
		}
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		return readLimited(fr)
	default:
		// br, zstd, or something newer. We advertise gzip only, so reaching
		// here means an origin ignored the negotiation: pass it through.
		return nil, errUnsupportedEncoding
	}
}

func readLimited(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxInflated+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflated {
		return nil, stringError("decompressed body exceeds the rewrite budget")
	}
	return out, nil
}

// replayCloser streams already-read bytes ahead of the rest of a live body
// while still closing the underlying socket-backed reader.
type replayCloser struct {
	io.Reader
	io.Closer
}

// setPlainBody installs a decoded (and possibly rewritten) body and fixes every
// header that described the old one. Getting this wrong is worse than not
// filtering at all: a body still labelled gzip that is no longer gzip is
// unreadable to the client, and that failure looks like the site being down.
func setPlainBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Range")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.TransferEncoding = nil
	resp.Uncompressed = true
}
