package mitm

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
)

// MobileConfig renders an Apple Configuration Profile that installs the CA as
// a trusted root. It is the sanctioned way to get a certificate onto an iPhone
// or iPad: a raw .crt there installs but cannot be trusted, whereas a profile
// walks the user straight to the trust step. On macOS a profile installs to
// the system store in one action.
//
// The profile carries the CA in DER, base64-encoded. The UUIDs are derived
// from the certificate so re-downloading after a CA change replaces the old
// profile rather than stacking a second one.
func (c *CA) MobileConfig() []byte {
	der := c.cert.Raw
	b64 := base64.StdEncoding.EncodeToString(der)

	// 60-column wrapping keeps the <data> block readable and matches how
	// Apple's own tooling emits profiles.
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 60 {
		end := i + 60
		if end > len(b64) {
			end = len(b64)
		}
		wrapped.WriteString("\t\t\t")
		wrapped.WriteString(b64[i:end])
		wrapped.WriteByte('\n')
	}

	sum := sha1.Sum(c.cert.Raw)
	rootUUID := uuidFrom(sum[:], "root")
	topUUID := uuidFrom(sum[:], "profile")
	name := c.cert.Subject.CommonName
	if name == "" {
		name = "Orbis Filter CA"
	}

	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>orbis-ca.crt</string>
			<key>PayloadContent</key>
			<data>
` + wrapped.String() + `			</data>
			<key>PayloadDescription</key>
			<string>Adds the Orbis Filter certificate authority so Orbis can remove ads on this device.</string>
			<key>PayloadDisplayName</key>
			<string>` + xmlEscape(name) + `</string>
			<key>PayloadIdentifier</key>
			<string>ai.cooli.orbis.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>` + rootUUID + `</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>After installing, enable full trust for "` + xmlEscape(name) + `" under Settings, General, About, Certificate Trust Settings.</string>
	<key>PayloadDisplayName</key>
	<string>Orbis Filter</string>
	<key>PayloadIdentifier</key>
	<string>ai.cooli.orbis</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + topUUID + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`)
}

// uuidFrom derives a stable RFC-4122-shaped UUID from the certificate hash and
// a role tag, so the same CA always produces the same profile identity.
func uuidFrom(sum []byte, role string) string {
	h := sha1.Sum(append(append([]byte(nil), sum...), role...))
	// Shape the first 16 bytes as a version-5-style UUID string.
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}
