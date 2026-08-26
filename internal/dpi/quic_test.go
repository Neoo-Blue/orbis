package dpi

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestReadVarint uses the worked examples from RFC 9000 Appendix A.1, which
// is the only way to be sure a hand-written varint decoder is right.
func TestReadVarint(t *testing.T) {
	cases := []struct {
		bytes []byte
		want  uint64
		n     int
	}{
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4},
		{[]byte{0x7b, 0xbd}, 15293, 2},
		{[]byte{0x25}, 37, 1},
		{[]byte{0x40, 0x25}, 37, 2}, // the same value in a longer encoding
	}
	for _, c := range cases {
		got, n := readVarint(c.bytes)
		if got != c.want || n != c.n {
			t.Errorf("readVarint(%x) = (%d, %d), want (%d, %d)", c.bytes, got, n, c.want, c.n)
		}
	}
	// A truncated encoding must report failure rather than a wrong value.
	if _, n := readVarint([]byte{0xc2, 0x19}); n != 0 {
		t.Error("a truncated 8-byte varint should fail")
	}
	if _, n := readVarint(nil); n != 0 {
		t.Error("an empty slice should fail")
	}
}

func TestCollectCryptoFramesReassembles(t *testing.T) {
	// Two CRYPTO frames delivered out of order, with PADDING and an ACK
	// mixed in — exactly what a real Initial datagram looks like.
	var payload []byte
	payload = append(payload, 0x00, 0x00, 0x00) // PADDING run

	// CRYPTO at offset 4, carrying "efgh"
	payload = append(payload, 0x06, 0x04, 0x04, 'e', 'f', 'g', 'h')
	// ACK frame: largest, delay, range count, first range
	payload = append(payload, 0x02, 0x00, 0x00, 0x00, 0x00)
	// CRYPTO at offset 0, carrying "abcd"
	payload = append(payload, 0x06, 0x00, 0x04, 'a', 'b', 'c', 'd')
	payload = append(payload, 0x00, 0x00) // trailing PADDING

	got := collectCryptoFrames(payload)
	if string(got) != "abcdefgh" {
		t.Errorf("reassembled %q, want abcdefgh", got)
	}
}

func TestCollectCryptoFramesStopsOnUnknownFrame(t *testing.T) {
	// An unrecognised frame type means the boundary is lost; returning what
	// was collected so far beats guessing and producing nonsense.
	payload := []byte{0x06, 0x00, 0x02, 'h', 'i', 0x1e /* HANDSHAKE_DONE */, 0xff, 0xff}
	got := collectCryptoFrames(payload)
	if string(got) != "hi" {
		t.Errorf("got %q, want the frames collected before the unknown type", got)
	}
}

func TestParseQUICInitialRejectsNonQUIC(t *testing.T) {
	cases := map[string][]byte{
		"empty":         {},
		"too short":     {0x80, 0x00},
		"short header":  {0x40, 0x01, 0x02, 0x03, 0x04, 0x05},
		"unknown version": append([]byte{0xc0}, encodeU32(0xdeadbeef)...),
		"stun":          {0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42},
	}
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseQUICInitial(pkt); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// TestParseQUICInitialNeverPanics throws structured-but-wrong input at the
// parser. This code runs on every UDP/443 packet from an untrusted network,
// so a panic here is a remote denial of service on the capture goroutine.
func TestParseQUICInitialNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 3000; i++ {
		size := 8 + rng.Intn(400)
		pkt := make([]byte, size)
		rng.Read(pkt)
		// Force a plausible long header with a real version so the parser
		// commits to the Initial path instead of bailing immediately.
		pkt[0] = 0xc0 | byte(rng.Intn(16))
		binary.BigEndian.PutUint32(pkt[1:5], 0x00000001)
		if size > 6 {
			pkt[5] = byte(rng.Intn(25)) // DCID length, sometimes over the max
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %x: %v", pkt, r)
				}
			}()
			_, _ = ParseQUICInitial(pkt)
		}()
	}
}

func TestIsQUIC(t *testing.T) {
	v1 := append([]byte{0xc0}, encodeU32(0x00000001)...)
	if !IsQUIC(v1, 443) {
		t.Error("a QUIC v1 long header was not recognised")
	}
	v2 := append([]byte{0xc0}, encodeU32(0x6b3343cf)...)
	if !IsQUIC(v2, 443) {
		t.Error("a QUIC v2 long header was not recognised")
	}
	// A short header is only assumed to be QUIC on the HTTP/3 ports; on a
	// random port it is far more likely to be something else entirely.
	short := []byte{0x40, 1, 2, 3, 4, 5}
	if !IsQUIC(short, 443) {
		t.Error("a short header on 443 should be treated as QUIC")
	}
	if IsQUIC(short, 12345) {
		t.Error("a short header on an arbitrary port should not be assumed to be QUIC")
	}
}

func TestHKDFExpandLabelLength(t *testing.T) {
	// The derivation itself is exercised end-to-end by the decryption path;
	// what is worth pinning here is that it honours the requested length,
	// since a wrong key size fails in a very confusing way downstream.
	secret := make([]byte, 32)
	for _, n := range []int{12, 16, 32} {
		out, err := hkdfExpandLabel(secret, "quic key", n)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != n {
			t.Errorf("hkdfExpandLabel returned %d bytes, want %d", len(out), n)
		}
	}
}

func encodeU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
