package vpn

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseWGQuick reads a standard wg-quick configuration — the file every
// WireGuard provider hands you. Supporting it directly matters: the
// alternative is asking someone to retype a 44-character base64 key and four
// other fields into a form, which they will get wrong.
//
// PostUp/PostDown hooks are deliberately ignored rather than executed. They
// are arbitrary shell from a third party, and everything they usually do
// (NAT, kill switch, DNS) Orbis does itself in a way it can reason about.
func ParseWGQuick(text string) (*WGTunnel, error) {
	t := &WGTunnel{Keepalive: 25, MTU: 1420}
	section := ""
	var ignored []string
	peerCount := 0

	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				peerCount++
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value, got %q", lineNo+1, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		// A base64 key contains '=' padding, so only split on the first one.
		value = strings.TrimSpace(value)
		if i := strings.IndexByte(value, '#'); i >= 0 && !strings.Contains(key, "key") {
			value = strings.TrimSpace(value[:i])
		}

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				t.PrivateKey = value
			case "address":
				t.Addresses = splitList(value)
			case "dns":
				t.DNS = splitList(value)
			case "mtu":
				if n, err := strconv.Atoi(value); err == nil {
					t.MTU = n
				}
			case "fwmark", "table":
				// Orbis manages routing itself; honouring a provider's table
				// choice would collide with the per-device policy rules.
				ignored = append(ignored, key)
			case "postup", "postdown", "preup", "predown", "saveconfig":
				ignored = append(ignored, key)
			}
		case "peer":
			// Multiple peers in one file is a mesh config, not a provider
			// tunnel, and silently using only the first would be worse than
			// refusing.
			if peerCount > 1 {
				return nil, fmt.Errorf("this config has %d peers; Orbis routes through a single upstream tunnel", peerCount)
			}
			switch key {
			case "publickey":
				t.PeerPublicKey = value
			case "presharedkey":
				t.PresharedKey = value
			case "endpoint":
				t.Endpoint = value
			case "allowedips":
				t.AllowedIPs = splitList(value)
			case "persistentkeepalive":
				if n, err := strconv.Atoi(value); err == nil {
					t.Keepalive = n
				}
			}
		}
	}

	if t.PrivateKey == "" {
		return nil, fmt.Errorf("no PrivateKey in the [Interface] section")
	}
	if t.PeerPublicKey == "" {
		return nil, fmt.Errorf("no PublicKey in the [Peer] section")
	}
	if t.Endpoint == "" {
		return nil, fmt.Errorf("no Endpoint in the [Peer] section — Orbis would not know where to connect")
	}
	if len(t.Addresses) == 0 {
		return nil, fmt.Errorf("no Address in the [Interface] section")
	}
	if len(t.AllowedIPs) == 0 {
		// A provider config almost always says 0.0.0.0/0; defaulting to it
		// matches the intent of "route my traffic through this".
		t.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	// Validate the key material now rather than letting `wg setconf` fail
	// with a message the operator cannot act on.
	if _, err := publicFromPrivate(t.PrivateKey); err != nil {
		return nil, fmt.Errorf("the PrivateKey is not a valid WireGuard key")
	}
	t.Ignored = ignored
	return t, nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// RenderWGQuick produces the config Orbis actually applies, so an operator can
// see exactly what was taken from their file.
func (t *WGTunnel) RenderWGQuick(maskSecrets bool) string {
	priv, psk := t.PrivateKey, t.PresharedKey
	if maskSecrets {
		if priv != "" {
			priv = "••••••••"
		}
		if psk != "" {
			psk = "••••••••"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", priv, strings.Join(t.Addresses, ", "))
	if len(t.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(t.DNS, ", "))
	}
	if t.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", t.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", t.PeerPublicKey)
	if psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\nEndpoint = %s\n", strings.Join(t.AllowedIPs, ", "), t.Endpoint)
	if t.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", t.Keepalive)
	}
	return b.String()
}
