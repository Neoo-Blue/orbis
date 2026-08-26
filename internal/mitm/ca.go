// Package mitm is the TLS-intercepting filter proxy.
//
// It exists because DNS and SNI blocking have a hard ceiling: when ads and
// content are served from the same hostname over the same connection — which
// is exactly how YouTube, Twitch and most in-app advertising work — there is
// no name to block. The only place left to act is inside the stream, which
// means terminating TLS with a certificate the client trusts.
//
// That is a real trade-off and the code treats it as one: interception is off
// by default, applies only to an explicit host allowlist, and never touches
// pinned or sensitive hosts.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CA issues the leaf certificates presented to intercepted clients.
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
	// order is a FIFO of cache keys so a host-scanning client cannot grow
	// the cache without bound.
	order []string
	max   int

	dir string
}

// LoadOrCreateCA reads the root from disk, generating it on first run. The
// key never leaves the node; only the certificate is downloadable.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "orbis-ca.crt")
	keyPath := filepath.Join(dir, "orbis-ca.key")

	ca := &CA{cache: make(map[string]*tls.Certificate), max: 512, dir: dir}

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("ca cert is not valid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ca cert: %w", err)
		}
		kb, _ := pem.Decode(keyPEM)
		if kb == nil {
			return nil, fmt.Errorf("ca key is not valid PEM")
		}
		key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			parsed, err2 := x509.ParsePKCS8PrivateKey(kb.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("parse ca key: %w", err)
			}
			rk, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("ca key is not RSA")
			}
			key = rk
		}
		// An expired root produces baffling client errors; regenerate early
		// rather than letting it lapse.
		if time.Now().After(cert.NotAfter.Add(-30 * 24 * time.Hour)) {
			return generateCA(dir, ca)
		}
		ca.cert, ca.key, ca.certPEM = cert, key, certPEM
		return ca, nil
	}
	return generateCA(dir, ca)
}

func generateCA(dir string, ca *CA) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "orbis"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Orbis Filter CA (" + host + ")",
			Organization: []string{"Orbis"},
			OrganizationalUnit: []string{
				// Spelling out what this key can do in the subject means an
				// operator who finds it in a trust store knows immediately.
				"Local network content filter — installed by the network owner",
			},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(filepath.Join(dir, "orbis-ca.crt"), certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "orbis-ca.key"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	ca.cert, ca.key, ca.certPEM = cert, key, certPEM
	return ca, nil
}

func (c *CA) CertPEM() []byte { return c.certPEM }

// Fingerprint is shown in the UI next to the download link so an operator can
// verify what they installed on a device matches what the node is using.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (c *CA) Info() map[string]any {
	return map[string]any{
		"subject":         c.cert.Subject.CommonName,
		"not_before":      c.cert.NotBefore,
		"not_after":       c.cert.NotAfter,
		"fingerprint":     c.Fingerprint(),
		"expires_in_days": int(time.Until(c.cert.NotAfter).Hours() / 24),
	}
}

// Leaf mints (and caches) a certificate for a hostname. Leaves use ECDSA
// P-256: it is universally supported, far cheaper to generate than RSA, and
// the whole point here is generating them on demand at connection time.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	key := certCacheKey(host)

	c.mu.RLock()
	if cert, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Orbis Filtered"}},
		NotBefore:    time.Now().Add(-time.Hour),
		// Short-lived leaves limit the damage if one is ever extracted, and
		// they are free to reissue.
		NotAfter:    time.Now().AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
		// A wildcard sibling covers the shard hostnames a CDN rotates
		// through without minting a certificate per shard.
		if parts := strings.SplitN(host, ".", 2); len(parts) == 2 && strings.Count(parts[1], ".") >= 1 {
			tmpl.DNSNames = append(tmpl.DNSNames, "*."+parts[1])
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &priv.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  priv,
	}

	c.mu.Lock()
	if len(c.order) >= c.max {
		delete(c.cache, c.order[0])
		c.order = c.order[1:]
	}
	c.cache[key] = cert
	c.order = append(c.order, key)
	c.mu.Unlock()
	return cert, nil
}

func certCacheKey(host string) string {
	return host
}

// ExportPKCS12 is not implemented on purpose: shipping a bundle that includes
// the private key invites installing the CA on a device the operator does not
// control. Only the public certificate is exportable.

// TrustInstructions returns per-platform steps for the UI. Getting a CA into
// a trust store is the single hardest step of enabling interception, and
// vague instructions here produce support burden.
func TrustInstructions() []map[string]string {
	return []map[string]string{
		{
			"platform": "iOS / iPadOS",
			"steps": "Open the .crt link in Safari (not Chrome) → Allow → Settings → Profile Downloaded → Install. " +
				"Then Settings → General → About → Certificate Trust Settings → enable full trust for “Orbis Filter CA”. " +
				"The second step is mandatory; without it every intercepted site fails.",
		},
		{
			"platform": "macOS",
			"steps": "Download the .crt → double-click → add to the System keychain → open it in Keychain Access → " +
				"Trust → “When using this certificate: Always Trust”.",
		},
		{
			"platform": "Windows",
			"steps": "Download the .crt → right-click → Install Certificate → Local Machine → " +
				"“Place all certificates in the following store” → Trusted Root Certification Authorities.",
		},
		{
			"platform": "Android",
			"steps": "Settings → Security → Encryption & credentials → Install a certificate → CA certificate. " +
				"Note: since Android 7 apps do not trust user-installed CAs by default, so this affects browsers " +
				"but not most native apps unless the device is rooted.",
		},
		{
			"platform": "Linux",
			"steps": "sudo cp orbis-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates. " +
				"Firefox and Chrome keep their own stores; import there separately.",
		},
	}
}

// SortedHosts is a helper for stable UI output of the intercept list.
func SortedHosts(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

var _ = binary.BigEndian
