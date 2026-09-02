// Package lounge speaks YouTube's Lounge API — the same protocol a phone uses
// to cast to and control a TV. It lets Orbis attach to any YouTube "screen" on
// the network (a TV, an Apple TV, a console) as a remote control, watch what is
// playing, and skip or mute ads and sponsor segments. It needs no certificate,
// nothing installed on the device, and works precisely because it never touches
// the encrypted video stream: it drives the player instead of rewriting bytes.
package lounge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	apiBase   = "https://www.youtube.com/api/lounge"
	bindURL   = apiBase + "/bc/bind"
	tokenURL  = apiBase + "/pairing/get_lounge_token_batch"
	screenURL = apiBase + "/pairing/get_screen"
	origin    = "https://www.youtube.com"
	// userAgent is a plausible desktop UA. The Lounge endpoint rejects some
	// obviously-bot agents; a normal browser string is the safe choice.
	userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

// zxCounter feeds the "zx" cache-buster parameter. Google's browser channel
// wants it unique per request; a monotonic counter is sufficient and keeps the
// package free of the forbidden time/rand calls at construction.
var zxCounter struct {
	sync.Mutex
	n uint64
}

func nextZx() string {
	zxCounter.Lock()
	zxCounter.n++
	n := zxCounter.n
	zxCounter.Unlock()
	return strconv.FormatUint(n, 36) + "zxorbis"
}

// event is one decoded entry from the browser-channel stream:
// [aid, [type, arg0, arg1, ...]].
type event struct {
	aid  int
	typ  string
	args []json.RawMessage
}

// firstString decodes args[i] as a string, or "" if absent/not a string.
func (e event) firstString(i int) string {
	if i >= len(e.args) {
		return ""
	}
	var s string
	_ = json.Unmarshal(e.args[i], &s)
	return s
}

// object decodes args[0] as a map, or nil.
func (e event) object() map[string]any {
	if len(e.args) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(e.args[0], &m) != nil {
		return nil
	}
	return m
}

// GetLoungeToken exchanges a durable screen id for a short-lived lounge token,
// which every subsequent request authenticates with.
func GetLoungeToken(ctx context.Context, hc *http.Client, screenID string) (string, error) {
	form := url.Values{"screen_ids": {screenID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	setHeaders(req)
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("lounge token: http %d", resp.StatusCode)
	}
	var body struct {
		Screens []struct {
			ScreenID    string `json:"screenId"`
			LoungeToken string `json:"loungeToken"`
		} `json:"screens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	for _, s := range body.Screens {
		if s.LoungeToken != "" {
			return s.LoungeToken, nil
		}
	}
	return "", fmt.Errorf("lounge token: screen %q not registered (re-pair the device)", screenID)
}

// PairWithCode turns the 12-digit "Link with TV code" into a durable screen id
// and a friendly name. This is the manual-pairing fallback for devices Orbis
// cannot auto-discover over DIAL.
func PairWithCode(ctx context.Context, hc *http.Client, code string) (screenID, name string, err error) {
	// Normalise: the UI shows the code with spaces; only the digits matter.
	var b strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	form := url.Values{"pairing_code": {b.String()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, screenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	setHeaders(req)
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("pair: http %d (code expired? get a fresh one)", resp.StatusCode)
	}
	var body struct {
		Screen struct {
			ScreenID string `json:"screenId"`
			Name     string `json:"name"`
		} `json:"screen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", "", err
	}
	if body.Screen.ScreenID == "" {
		return "", "", fmt.Errorf("pair: no screen returned for that code")
	}
	return body.Screen.ScreenID, body.Screen.Name, nil
}

func setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", userAgent)
}

// Session is a live control connection to one screen. It is not safe for
// concurrent command sends from multiple goroutines; the controller serialises
// them through the command channel.
type Session struct {
	screenID string
	name     string
	deviceID string
	token    string

	hc *http.Client

	mu   sync.Mutex
	sid  string
	gsid string
	aid  int
	rid  int
	ofs  int

	onEvent func(event)
}

func newSession(screenID, deviceID, name string, hc *http.Client) *Session {
	return &Session{
		screenID: screenID,
		deviceID: deviceID,
		name:     name,
		hc:       hc,
		rid:      1,
	}
}

func (s *Session) baseParams() url.Values {
	v := url.Values{}
	v.Set("device", "REMOTE_CONTROL")
	v.Set("app", "youtube-desktop")
	v.Set("id", s.deviceID)
	v.Set("name", s.name)
	v.Set("loungeIdToken", s.token)
	v.Set("VER", "8")
	v.Set("v", "2")
	v.Set("t", "1")
	v.Set("zx", nextZx())
	return v
}

// connect performs the initial bind and returns once SID/gsessionid are known.
// Any events carried in the bind response are dispatched.
func (s *Session) connect(ctx context.Context) error {
	tok, err := GetLoungeToken(ctx, s.hc, s.screenID)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.token = tok
	s.aid = 0
	s.ofs = 0
	p := s.baseParams()
	p.Set("RID", strconv.Itoa(s.rid))
	s.rid++
	s.mu.Unlock()
	p.Set("CVER", "1")
	p.Set("CI", "0")
	p.Set("auth_failure_option", "send_error")
	p.Set("mdx-version", "3")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bindURL+"?"+p.Encode(), strings.NewReader("count=0"))
	if err != nil {
		return err
	}
	setHeaders(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("bind: http %d", resp.StatusCode)
	}

	var gotSID, gotGSID bool
	err = readStream(resp.Body, func(ev event) {
		switch ev.typ {
		case "c":
			s.mu.Lock()
			s.sid = ev.firstString(0)
			s.mu.Unlock()
			gotSID = true
		case "S":
			s.mu.Lock()
			s.gsid = ev.firstString(0)
			s.mu.Unlock()
			gotGSID = true
		}
		s.noteAID(ev.aid)
		if s.onEvent != nil {
			s.onEvent(ev)
		}
	})
	if err != nil && err != io.EOF {
		return err
	}
	if !gotSID || !gotGSID {
		return fmt.Errorf("bind: session not established (screen offline?)")
	}
	return nil
}

// poll runs one long-poll GET, dispatching events until the server closes the
// stream. It returns nil on a clean close (reconnect) or an error.
func (s *Session) poll(ctx context.Context) error {
	s.mu.Lock()
	p := s.baseParams()
	p.Set("SID", s.sid)
	p.Set("gsessionid", s.gsid)
	p.Set("RID", "rpc")
	p.Set("CI", "0")
	p.Set("TYPE", "xmlhttp")
	p.Set("AID", strconv.Itoa(s.aid))
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bindURL+"?"+p.Encode(), nil)
	if err != nil {
		return err
	}
	setHeaders(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
		// Session expired; caller should re-bind.
		return errSessionExpired
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("poll: http %d", resp.StatusCode)
	}
	return readStream(resp.Body, func(ev event) {
		s.noteAID(ev.aid)
		if s.onEvent != nil {
			s.onEvent(ev)
		}
	})
}

var errSessionExpired = fmt.Errorf("lounge session expired")

func (s *Session) noteAID(aid int) {
	s.mu.Lock()
	if aid > s.aid {
		s.aid = aid
	}
	s.mu.Unlock()
}

// sendCommand issues one player command (seekTo, setVolume, skipAd, ...).
func (s *Session) sendCommand(ctx context.Context, command string, args map[string]string) error {
	s.mu.Lock()
	p := s.baseParams()
	p.Set("SID", s.sid)
	p.Set("gsessionid", s.gsid)
	p.Set("RID", strconv.Itoa(s.rid))
	s.rid++
	ofs := s.ofs
	s.ofs++
	s.mu.Unlock()

	body := url.Values{}
	body.Set("count", "1")
	body.Set("ofs", strconv.Itoa(ofs))
	body.Set("req0__sc", command)
	for k, v := range args {
		body.Set("req0_"+k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bindURL+"?"+p.Encode(), strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	setHeaders(req)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("command %s: http %d", command, resp.StatusCode)
	}
	return nil
}

// maxFrameRunes bounds one frame so a corrupt or hostile length prefix cannot
// make the session allocate without limit. Real frames are a few kilobytes;
// the largest legitimate one carries a whole playlist.
const maxFrameRunes = 4 << 20

// readStream parses the Google browser-channel wire format: a sequence of
// "<length>\n<json>" frames, where the JSON is an array of [aid, [type,
// args...]] entries.
//
// The length prefix is the only tricky part. The server measures it the way
// JavaScript measures a string — in UTF-16 code units — so a single emoji in a
// video title counts as two while being one code point. Reading code points
// instead falls one short on that frame, and because the frames are packed
// back to back with no delimiter, every frame after it is misread too: the
// session goes quiet and ads stop being skipped, with nothing in the log to
// say why.
//
// So the count is read as UTF-16 units, and then treated as a hint rather than
// gospel: the frame ends where its JSON actually closes. That is correct under
// either convention, and self-corrects if the server ever changes its mind.
func readStream(r io.Reader, dispatch func(event)) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(line))
		if convErr != nil || n <= 0 {
			continue // keep-alive / blank frame
		}
		if n > maxFrameRunes {
			return fmt.Errorf("browser channel: implausible frame length %d", n)
		}
		frame, readErr := readFrame(br, n)
		if len(frame) > 0 {
			for _, ev := range parseFrame(frame) {
				dispatch(ev)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

// readFrame reads one frame, stopping at whichever comes first: the declared
// length in UTF-16 code units, or the close of the JSON value. If the declared
// length runs out mid-value it keeps reading until the value closes.
func readFrame(br *bufio.Reader, n int) ([]byte, error) {
	var buf []rune
	var sc frameScanner
	units := 0
	for units < n && !sc.complete() {
		ru, _, err := br.ReadRune()
		if err != nil {
			return []byte(string(buf)), err
		}
		buf = append(buf, ru)
		sc.feed(ru)
		units += utf16Len(ru)
	}
	for !sc.complete() && len(buf) < maxFrameRunes {
		ru, _, err := br.ReadRune()
		if err != nil {
			return []byte(string(buf)), err
		}
		buf = append(buf, ru)
		sc.feed(ru)
	}
	return []byte(string(buf)), nil
}

// frameScanner tracks JSON nesting one rune at a time, so the end of a frame
// can be found without rescanning everything read so far.
type frameScanner struct {
	depth   int
	inStr   bool
	escaped bool
	started bool
}

func (s *frameScanner) feed(r rune) {
	if s.inStr {
		switch {
		case s.escaped:
			s.escaped = false
		case r == '\\':
			s.escaped = true
		case r == '"':
			s.inStr = false
		}
		return
	}
	switch r {
	case '"':
		s.inStr = true
	case '[', '{':
		s.depth++
		s.started = true
	case ']', '}':
		s.depth--
	}
}

func (s *frameScanner) complete() bool { return s.started && s.depth <= 0 && !s.inStr }

// utf16Len is how many UTF-16 code units a rune occupies, which is how the
// server counted it.
func utf16Len(r rune) int {
	if r > 0xFFFF {
		return 2
	}
	return 1
}

// parseFrame decodes one JSON frame into events. Malformed entries are skipped
// rather than aborting the whole frame.
func parseFrame(data []byte) []event {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil
	}
	out := make([]event, 0, len(entries))
	for _, raw := range entries {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil || len(pair) < 2 {
			continue
		}
		var aid int
		_ = json.Unmarshal(pair[0], &aid)
		var body []json.RawMessage
		if err := json.Unmarshal(pair[1], &body); err != nil || len(body) == 0 {
			continue
		}
		var typ string
		if err := json.Unmarshal(body[0], &typ); err != nil {
			continue
		}
		out = append(out, event{aid: aid, typ: typ, args: body[1:]})
	}
	return out
}

// asFloat coerces a JSON value (number or numeric string) to float64.
func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// asString coerces a JSON value to string.
func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	}
	return ""
}
