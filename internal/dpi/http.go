package dpi

import (
	"bytes"
	"strings"
)

// HTTPRequest is the handful of cleartext HTTP fields worth recording: the
// Host tells us the destination identity, the Referer tells us which page
// pulled in a third-party request (the key signal for ad detection), and the
// User-Agent feeds device fingerprinting.
type HTTPRequest struct {
	Method    string
	Path      string
	Host      string
	UserAgent string
	Referer   string
	Origin    string
	Accept    string
	IsRequest bool
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

// ParseHTTPRequest reads request-line + headers out of a TCP payload. It
// deliberately stops at the header terminator and never buffers a body.
func ParseHTTPRequest(payload []byte) (*HTTPRequest, bool) {
	if len(payload) < 16 {
		return nil, false
	}
	matched := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, m) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, false
	}
	// Cap the scan: headers past 8 KiB are not worth chasing across segments.
	limit := len(payload)
	if limit > 8192 {
		limit = 8192
	}
	head := payload[:limit]
	if idx := bytes.Index(head, []byte("\r\n\r\n")); idx >= 0 {
		head = head[:idx]
	}

	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 {
		return nil, false
	}
	req := &HTTPRequest{IsRequest: true}
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		req.Method = parts[0]
		req.Path = parts[1]
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "host":
			// Strip any :port so it matches DNS-derived names.
			if h, _, found := strings.Cut(v, ":"); found {
				req.Host = strings.ToLower(h)
			} else {
				req.Host = strings.ToLower(v)
			}
		case "user-agent":
			req.UserAgent = v
		case "referer", "referrer":
			req.Referer = v
		case "origin":
			req.Origin = v
		case "accept":
			req.Accept = v
		}
	}
	if req.Host == "" && req.Method == "" {
		return nil, false
	}
	return req, true
}

// RefererHost pulls the bare hostname out of a Referer/Origin URL.
func RefererHost(ref string) string {
	if ref == "" {
		return ""
	}
	s := ref
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, found := strings.Cut(s, ":"); found {
		s = h
	}
	return strings.ToLower(s)
}

// ClassifyApp maps an observed hostname to a friendly application name so
// the UI can group "37 connections to googlevideo" as "YouTube". Empty when
// the name is not in the catalogue; see Classify for the category and the
// registrable-domain fallback.
func ClassifyApp(host string) string {
	if svc, ok := Classify(host); ok {
		return svc.Name
	}
	return ""
}

// The list is intentionally short and high-signal; anything unmatched shows
// its raw hostname, which is more honest than a bad guess.
