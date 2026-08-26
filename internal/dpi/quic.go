package dpi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// QUIC Initial packets are encrypted, but with keys derived from a salt that
// is fixed by the RFC and the connection ID that travels in the clear. That
// makes them decryptable by any on-path observer, which is exactly what we
// need to read the SNI out of an HTTP/3 handshake and apply the same block
// policy we apply to TLS-over-TCP. Without this, a client that speaks QUIC
// simply bypasses SNI filtering.
var (
	// RFC 9001 §5.2 initial salt for QUIC v1.
	quicV1Salt = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	// draft-29 salt, still emitted by some older stacks.
	quicD29Salt = []byte{
		0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
	}
	// RFC 9369 QUIC v2 salt.
	quicV2Salt = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}

	ErrNotQUICInitial = errors.New("dpi: not a QUIC Initial packet")
	ErrQUICDecrypt    = errors.New("dpi: QUIC Initial decryption failed")
)

// ParseQUICInitial extracts the ClientHello from a UDP payload carrying a
// QUIC Initial packet. Returns ErrNotQUICInitial for anything else, which is
// the common case (1-RTT packets, STUN, DNS, plain UDP).
func ParseQUICInitial(pkt []byte) (*ClientHello, error) {
	if len(pkt) < 7 {
		return nil, ErrNotQUICInitial
	}
	// Long header form: high bit set, fixed bit set.
	if pkt[0]&0x80 == 0 {
		return nil, ErrNotQUICInitial
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	var salt []byte
	var isV2 bool
	switch version {
	case 0x00000001:
		salt = quicV1Salt
	case 0xff00001d:
		salt = quicD29Salt
	case 0x6b3343cf:
		salt = quicV2Salt
		isV2 = true
	default:
		return nil, ErrNotQUICInitial
	}
	// Packet type lives in bits 4-5. In v1 Initial == 0; v2 renumbered it to 1.
	ptype := (pkt[0] & 0x30) >> 4
	if (!isV2 && ptype != 0) || (isV2 && ptype != 1) {
		return nil, ErrNotQUICInitial
	}

	pos := 5
	dcidLen := int(pkt[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	dcid := pkt[pos : pos+dcidLen]
	pos += dcidLen
	if pos >= len(pkt) {
		return nil, ErrNotQUICInitial
	}
	scidLen := int(pkt[pos])
	pos++
	if scidLen > 20 || pos+scidLen > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	pos += scidLen

	// Token (Initial only).
	tokenLen, n := readVarint(pkt[pos:])
	if n == 0 {
		return nil, ErrNotQUICInitial
	}
	pos += n
	if pos+int(tokenLen) > len(pkt) {
		return nil, ErrNotQUICInitial
	}
	pos += int(tokenLen)

	// Length field covers packet number + payload.
	length, n := readVarint(pkt[pos:])
	if n == 0 {
		return nil, ErrNotQUICInitial
	}
	pos += n
	pnOffset := pos
	if pnOffset+int(length) > len(pkt) {
		// Truncated capture: work with what is present.
		length = uint64(len(pkt) - pnOffset)
	}
	if length < 20 {
		return nil, ErrNotQUICInitial
	}

	clientSecret, err := deriveInitialSecret(salt, dcid)
	if err != nil {
		return nil, err
	}
	labelKey, labelIV, labelHP := "quic key", "quic iv", "quic hp"
	if isV2 {
		labelKey, labelIV, labelHP = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	key, err := hkdfExpandLabel(clientSecret, labelKey, 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(clientSecret, labelIV, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := hkdfExpandLabel(clientSecret, labelHP, 16)
	if err != nil {
		return nil, err
	}

	// Header protection: sample 16 bytes starting 4 after the PN offset.
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(pkt) {
		return nil, ErrQUICDecrypt
	}
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, pkt[sampleOffset:sampleOffset+16])

	// Copy so we never mutate the caller's buffer (it may be a ring slice).
	hdr := make([]byte, pnOffset+4)
	copy(hdr, pkt[:pnOffset+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(hdr[pnOffset+i])
	}

	payloadStart := pnOffset + pnLen
	payloadEnd := pnOffset + int(length)
	if payloadEnd > len(pkt) {
		payloadEnd = len(pkt)
	}
	if payloadStart >= payloadEnd {
		return nil, ErrQUICDecrypt
	}

	// Nonce = IV XOR left-padded packet number.
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	aad := hdr[:payloadStart]
	plain, err := aead.Open(nil, nonce, pkt[payloadStart:payloadEnd], aad)
	if err != nil {
		return nil, ErrQUICDecrypt
	}
	cryptoData := collectCryptoFrames(plain)
	if len(cryptoData) == 0 {
		return nil, ErrQUICDecrypt
	}
	ch, err := ParseClientHello(cryptoData)
	if ch != nil {
		return ch, err
	}
	return nil, err
}

// collectCryptoFrames walks the decrypted payload and concatenates CRYPTO
// frame data in offset order. A ClientHello larger than one datagram is
// fragmented, and Chrome routinely sends PADDING before the real frames.
func collectCryptoFrames(payload []byte) []byte {
	var frags []cryptoFrag
	var maxEnd uint64
	pos := 0
	for pos < len(payload) {
		ft := payload[pos]
		switch {
		case ft == 0x00: // PADDING; runs can be long, skip them all at once
			for pos < len(payload) && payload[pos] == 0x00 {
				pos++
			}
			continue
		case ft == 0x01: // PING
			pos++
			continue
		case ft == 0x06: // CRYPTO
			pos++
			off, n := readVarint(payload[pos:])
			if n == 0 {
				return assemble(frags, maxEnd)
			}
			pos += n
			l, n2 := readVarint(payload[pos:])
			if n2 == 0 {
				return assemble(frags, maxEnd)
			}
			pos += n2
			if pos+int(l) > len(payload) {
				l = uint64(len(payload) - pos)
			}
			frags = append(frags, cryptoFrag{off: off, data: payload[pos : pos+int(l)]})
			if off+l > maxEnd {
				maxEnd = off + l
			}
			pos += int(l)
		case ft == 0x02 || ft == 0x03: // ACK
			pos++
			for i := 0; i < 4; i++ {
				_, n := readVarint(payload[pos:])
				if n == 0 {
					return assemble(frags, maxEnd)
				}
				pos += n
			}
			if ft == 0x03 { // ECN counts
				for i := 0; i < 3; i++ {
					_, n := readVarint(payload[pos:])
					if n == 0 {
						return assemble(frags, maxEnd)
					}
					pos += n
				}
			}
		default:
			// Anything else in an Initial means we have lost the frame
			// boundary; return what we have rather than guessing.
			return assemble(frags, maxEnd)
		}
	}
	return assemble(frags, maxEnd)
}

// cryptoFrag is one CRYPTO frame's slice of the handshake byte stream.
type cryptoFrag struct {
	off  uint64
	data []byte
}

func assemble(frags []cryptoFrag, size uint64) []byte {
	if len(frags) == 0 || size == 0 || size > 1<<20 {
		return nil
	}
	out := make([]byte, size)
	for _, f := range frags {
		if f.off+uint64(len(f.data)) <= size {
			copy(out[f.off:], f.data)
		}
	}
	return out
}

func deriveInitialSecret(salt, dcid []byte) ([]byte, error) {
	initial := hkdf.Extract(sha256.New, dcid, salt)
	return hkdfExpandLabelWith(initial, "client in", 32)
}

// hkdfExpandLabel is the TLS 1.3 HKDF-Expand-Label with the "tls13 " prefix,
// which QUIC reuses verbatim.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	return hkdfExpandLabelWith(secret, label, length)
}

func hkdfExpandLabelWith(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // empty context
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// readVarint decodes a QUIC variable-length integer, returning the value and
// the number of bytes consumed (0 on failure).
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length
}

// IsQUIC reports whether a UDP payload plausibly carries QUIC, used to tag
// flows even when the Initial cannot be decrypted.
func IsQUIC(pkt []byte, dstPort int) bool {
	if len(pkt) < 5 {
		return false
	}
	if pkt[0]&0x80 != 0 {
		v := binary.BigEndian.Uint32(pkt[1:5])
		return v == 0x00000001 || v == 0x6b3343cf || (v&0xff000000) == 0xff000000 || v == 0
	}
	// Short header: only trust it on the standard HTTP/3 ports.
	return dstPort == 443 || dstPort == 80
}
