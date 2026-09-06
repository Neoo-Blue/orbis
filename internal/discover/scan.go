package discover

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// scanPorts knocks on every port of every host with a small worker pool and
// a short timeout. Gentle on purpose: a scan should not look like an attack
// to anything watching, and a closed port answers in a millisecond anyway.
func scanPorts(ctx context.Context, hosts []string, ports []int, concurrency int, timeout time.Duration) map[string][]int {
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := map[string][]int{}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.ip, strconv.Itoa(j.port)))
				if err != nil {
					continue
				}
				conn.Close()
				mu.Lock()
				found[j.ip] = append(found[j.ip], j.port)
				mu.Unlock()
			}
		}()
	}
	for _, ip := range hosts {
		for _, p := range ports {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return found
			case jobs <- job{ip, p}:
			}
		}
	}
	close(jobs)
	wg.Wait()
	for _, ps := range found {
		sort.Ints(ps)
	}
	return found
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var fpClient = &http.Client{
	Timeout: 4 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // identifying our own devices, not trusting them
		ResponseHeaderTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Follow a few redirects, but only within the same host: a login page
		// that bounces to the vendor's cloud is not the service.
		if len(via) >= 3 || req.URL.Hostname() != via[0].URL.Hostname() {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// fingerprint fetches the front page of a port over http or https, whichever
// answers, and returns what it learned. nil means nothing spoke HTTP.
func fingerprint(ctx context.Context, host string, port int, tlsFirst bool) *Fingerprint {
	schemes := []string{"http", "https"}
	if tlsFirst || port == 443 {
		schemes = []string{"https", "http"}
	}
	for _, scheme := range schemes {
		fp := fetch(ctx, scheme, host, port)
		if fp == nil {
			continue
		}
		// A TLS port answering plain HTTP with 400 and a "plain HTTP request
		// was sent to HTTPS port" body is the other scheme's problem.
		if scheme == "http" && fp.Status == 400 && strings.Contains(strings.ToLower(fp.Body), "https port") {
			continue
		}
		return fp
	}
	return nil
}

func fetch(ctx context.Context, scheme, host string, port int) *Fingerprint {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(host, strconv.Itoa(port))+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "orbis-discover/1.0 (+https://github.com/Neoo-Blue/orbis)")
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.5")
	resp, err := fpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	fp := &Fingerprint{Scheme: scheme, Status: resp.StatusCode, Server: resp.Header.Get("Server"), Location: resp.Header.Get("Location")}
	if wa := resp.Header.Get("WWW-Authenticate"); wa != "" {
		if i := strings.Index(strings.ToLower(wa), "realm="); i >= 0 {
			fp.Realm = strings.Trim(wa[i+6:], `" `)
		}
	}
	text := string(body)
	if m := titleRe.FindStringSubmatch(text); len(m) > 1 {
		t := strings.TrimSpace(html.UnescapeString(strings.Join(strings.Fields(m[1]), " ")))
		if len(t) > 80 {
			t = t[:80]
		}
		fp.Title = t
	}
	// Keep a short slice of the body for signature matching; login pages
	// name the product in a meta tag or a script path more often than in
	// the title.
	if len(text) > 8192 {
		text = text[:8192]
	}
	fp.Body = text
	return fp
}
