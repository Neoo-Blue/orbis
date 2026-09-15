package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	tok, err := newSession("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if !validSession("test-key", tok) {
		t.Fatal("a freshly minted session was rejected")
	}
	if validSession("other-key", tok) {
		t.Fatal("a session signed with a different key was accepted")
	}
	if validSession("", tok) {
		t.Fatal("an empty key accepted a session")
	}
	if validSession("test-key", "") {
		t.Fatal("an empty token was accepted")
	}
	if validSession("test-key", "not-a-token") {
		t.Fatal("a malformed token was accepted")
	}
}

func TestSessionRejectsTamperedPayload(t *testing.T) {
	tok, err := newSession("test-key")
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(tok)
	if b[0] == '1' {
		b[0] = '2'
	} else {
		b[0] = '1'
	}
	if validSession("test-key", string(b)) {
		t.Fatal("a tampered session was accepted")
	}
}

func TestRotatingTheKeyInvalidatesSessions(t *testing.T) {
	tok, err := newSession("old-key")
	if err != nil {
		t.Fatal(err)
	}
	if !validSession("old-key", tok) {
		t.Fatal("setup")
	}
	if validSession("new-key", tok) {
		t.Fatal("a session survived a signing-key rotation")
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	payload := "1.deadbeef"
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write([]byte(payload))
	tok := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if validSession("test-key", tok) {
		t.Fatal("an expired session was accepted")
	}
}

func TestLongLivedPathsSkipTheRequestTimeout(t *testing.T) {
	if !longLivedPath("/api/stream") {
		t.Error("the live event stream must not be cut by the request timeout")
	}
	if !longLivedPath("/api/chat/ask") {
		t.Error("the assistant SSE turn must not be cut by the request timeout")
	}
	if longLivedPath("/api/status") {
		t.Error("ordinary API calls should still time out")
	}
	if longLivedPath("/api/auth/login") {
		t.Error("login should still time out")
	}
}
