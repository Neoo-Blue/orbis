// Package dpi extracts application-layer identity from the first packets of
// a connection: the SNI from a TLS ClientHello, the SNI from a QUIC Initial,
// the Host header from cleartext HTTP, plus a JA4-style client fingerprint.
//
// Everything here is read-only parsing of untrusted input, so every accessor
// is bounds-checked and the parsers return an error rather than panicking on
// a truncated or hostile record.
package dpi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrNotHandshake   = errors.New("dpi: not a TLS handshake record")
	ErrIncomplete     = errors.New("dpi: incomplete record")
	ErrNoSNI          = errors.New("dpi: no server_name extension")
	ErrNotClientHello = errors.New("dpi: not a ClientHello")
)

// ClientHello is the subset of a TLS ClientHello worth keeping.
type ClientHello struct {
	SNI          string
	ALPN         []string
	Versions     []uint16
	CipherSuites []uint16
	Extensions   []uint16
	Groups       []uint16
	SigAlgs      []uint16
	JA4          string
	// SNIOffset is the byte offset of the SNI string within the input,
	// which lets the MITM path rewrite or the block path target it.
	SNIOffset int
}

// reader is a bounds-checked cursor over a byte slice.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) u8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, ErrIncomplete
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, ErrIncomplete
	}
	v := uint16(r.b[r.pos])<<8 | uint16(r.b[r.pos+1])
	r.pos += 2
	return v, nil
}

func (r *reader) u24() (uint32, error) {
	if r.remaining() < 3 {
		return 0, ErrIncomplete
	}
	v := uint32(r.b[r.pos])<<16 | uint32(r.b[r.pos+1])<<8 | uint32(r.b[r.pos+2])
	r.pos += 3
	return v, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, ErrIncomplete
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

// ParseTLSRecord takes raw TCP payload starting at a TLS record header and
// returns the ClientHello it contains.
func ParseTLSRecord(payload []byte) (*ClientHello, error) {
	if len(payload) < 5 {
		return nil, ErrIncomplete
	}
	// 0x16 = handshake. Version in the record header is deliberately ignored:
	// modern clients pin it to 0x0301 regardless of the real version.
	if payload[0] != 0x16 {
		return nil, ErrNotHandshake
	}
	recLen := int(payload[3])<<8 | int(payload[4])
	end := 5 + recLen
	if end > len(payload) {
		// A ClientHello can span records when it carries a large key share
		// or ECH. Parse what we have; the SNI is almost always in the first.
		end = len(payload)
	}
	return ParseClientHello(payload[5:end])
}

// ParseClientHello parses the handshake message body (starting at the
// handshake type byte).
func ParseClientHello(b []byte) (*ClientHello, error) {
	r := &reader{b: b}
	htype, err := r.u8()
	if err != nil {
		return nil, err
	}
	if htype != 0x01 {
		return nil, ErrNotClientHello
	}
	if _, err := r.u24(); err != nil { // handshake length
		return nil, err
	}
	ch := &ClientHello{}
	legacyVersion, err := r.u16()
	if err != nil {
		return nil, err
	}
	if _, err := r.bytes(32); err != nil { // random
		return nil, err
	}
	sidLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.bytes(int(sidLen)); err != nil {
		return nil, err
	}
	csLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	csBytes, err := r.bytes(int(csLen))
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(csBytes); i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, uint16(csBytes[i])<<8|uint16(csBytes[i+1]))
	}
	compLen, err := r.u8()
	if err != nil {
		return nil, err
	}
	if _, err := r.bytes(int(compLen)); err != nil {
		return nil, err
	}

	// Extensions are optional in TLS 1.0/1.1; a hello without them has no SNI.
	if r.remaining() < 2 {
		ch.Versions = []uint16{legacyVersion}
		ch.JA4 = computeJA4(ch, legacyVersion)
		return ch, nil
	}
	extTotal, err := r.u16()
	if err != nil {
		return nil, err
	}
	extEnd := r.pos + int(extTotal)
	if extEnd > len(b) {
		extEnd = len(b)
	}
	for r.pos+4 <= extEnd {
		extType, err := r.u16()
		if err != nil {
			break
		}
		extLen, err := r.u16()
		if err != nil {
			break
		}
		body, err := r.bytes(int(extLen))
		if err != nil {
			break
		}
		bodyStart := r.pos - int(extLen)
		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case 0x0000: // server_name
			if name, off, ok := parseSNIExtension(body); ok {
				ch.SNI = name
				ch.SNIOffset = bodyStart + off
			}
		case 0x0010: // ALPN
			ch.ALPN = parseALPN(body)
		case 0x002b: // supported_versions
			ch.Versions = parseSupportedVersions(body)
		case 0x000a: // supported_groups
			ch.Groups = parseU16List(body)
		case 0x000d: // signature_algorithms
			ch.SigAlgs = parseU16List(body)
		}
	}
	if len(ch.Versions) == 0 {
		ch.Versions = []uint16{legacyVersion}
	}
	ch.JA4 = computeJA4(ch, legacyVersion)
	if ch.SNI == "" {
		return ch, ErrNoSNI
	}
	return ch, nil
}

func parseSNIExtension(b []byte) (string, int, bool) {
	r := &reader{b: b}
	listLen, err := r.u16()
	if err != nil {
		return "", 0, false
	}
	limit := r.pos + int(listLen)
	if limit > len(b) {
		limit = len(b)
	}
	for r.pos+3 <= limit {
		nameType, err := r.u8()
		if err != nil {
			return "", 0, false
		}
		nameLen, err := r.u16()
		if err != nil {
			return "", 0, false
		}
		off := r.pos
		name, err := r.bytes(int(nameLen))
		if err != nil {
			return "", 0, false
		}
		if nameType == 0 { // host_name
			return strings.ToLower(strings.TrimSuffix(string(name), ".")), off, true
		}
	}
	return "", 0, false
}

func parseALPN(b []byte) []string {
	r := &reader{b: b}
	listLen, err := r.u16()
	if err != nil {
		return nil
	}
	limit := r.pos + int(listLen)
	if limit > len(b) {
		limit = len(b)
	}
	var out []string
	for r.pos < limit {
		l, err := r.u8()
		if err != nil {
			break
		}
		p, err := r.bytes(int(l))
		if err != nil {
			break
		}
		out = append(out, string(p))
	}
	return out
}

func parseSupportedVersions(b []byte) []uint16 {
	if len(b) < 1 {
		return nil
	}
	// In a ClientHello this is a length-prefixed list.
	n := int(b[0])
	if n+1 > len(b) {
		return nil
	}
	return parseU16Raw(b[1 : 1+n])
}

func parseU16List(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	n := int(b[0])<<8 | int(b[1])
	if n+2 > len(b) {
		n = len(b) - 2
	}
	return parseU16Raw(b[2 : 2+n])
}

func parseU16Raw(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

// GREASE values (RFC 8701) are random padding and must be excluded from any
// fingerprint, otherwise the same client hashes differently every session.
func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// computeJA4 builds a JA4-style TLS client fingerprint:
//
//	<proto><version><sni?><#ciphers><#exts><alpn>_<hash(ciphers)>_<hash(exts+sigalgs)>
//
// The truncated-SHA256 form matches the published JA4 spec closely enough to
// be comparable across tools while remaining self-contained here.
func computeJA4(ch *ClientHello, legacy uint16) string {
	version := legacy
	for _, v := range ch.Versions {
		if isGREASE(v) {
			continue
		}
		if v > version || version == 0 {
			version = v
		}
	}
	verStr := map[uint16]string{
		0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0xfeff: "d1", 0xfefd: "d2",
	}[version]
	if verStr == "" {
		verStr = "00"
	}
	sniFlag := "i" // ip (no SNI)
	if ch.SNI != "" {
		sniFlag = "d" // domain
	}
	proto := "t" // tcp
	alpn := "00"
	if len(ch.ALPN) > 0 && len(ch.ALPN[0]) > 0 {
		a := ch.ALPN[0]
		if len(a) == 1 {
			alpn = string(a[0]) + string(a[0])
		} else {
			alpn = string(a[0]) + string(a[len(a)-1])
		}
	}

	ciphers := filterGREASE(ch.CipherSuites)
	// SNI (0x0000) and ALPN (0x0010) are excluded from the extension hash by
	// the JA4 spec because they vary per destination, not per client.
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if isGREASE(e) || e == 0x0000 || e == 0x0010 {
			continue
		}
		exts = append(exts, e)
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, verStr, sniFlag,
		minInt(len(ciphers), 99), minInt(len(exts), 99), alpn)
	b := truncHash(hexList(ciphers))
	sigs := filterGREASE(ch.SigAlgs)
	c := truncHash(hexList(exts) + "_" + hexList(sigs))
	return a + "_" + b + "_" + c
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func hexList(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

func truncHash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
