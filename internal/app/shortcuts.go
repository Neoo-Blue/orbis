package app

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// Shortcuts: a name for something that lives on a port. DNS answers the name
// with this node's own address; the HTTP side (api/shortcuts.go) sends the
// browser on to the target.

// NormalizeShortcutTarget accepts what people type ("192.168.50.223:8080",
// "nas.lan", "https://nas.lan:5001/") and returns a clean URL.
func NormalizeShortcutTarget(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", fmt.Errorf("target is required")
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("target must be a host, a host:port or a URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target must be http or https")
	}
	u.Fragment = ""
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String(), nil
}

// ValidateShortcut checks a shortcut before it is saved.
func ValidateShortcut(sc *config.DNSShortcut) error {
	sc.Name = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(sc.Name, ".")))
	if sc.Name == "" || strings.ContainsAny(sc.Name, " /:") {
		return fmt.Errorf("name must be a hostname such as deep.seek or nas.lan")
	}
	target, err := NormalizeShortcutTarget(sc.Target)
	if err != nil {
		return err
	}
	sc.Target = target
	switch sc.Mode {
	case "", "redirect":
		sc.Mode = "redirect"
	case "proxy":
	default:
		return fmt.Errorf("mode must be redirect or proxy")
	}
	return nil
}

// ShortcutFor returns the shortcut whose name matches a request's Host.
func (a *App) ShortcutFor(host string) *config.DNSShortcut {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	for _, sc := range a.Cfg.Snapshot().DNS.Shortcuts {
		if strings.EqualFold(sc.Name, h) {
			c := sc
			return &c
		}
	}
	return nil
}

func (a *App) Shortcuts() []config.DNSShortcut {
	out := a.Cfg.Snapshot().DNS.Shortcuts
	if out == nil {
		out = []config.DNSShortcut{}
	}
	return out
}

// SaveShortcut adds or replaces a shortcut by name and republishes the
// local records so the name resolves at once.
func (a *App) SaveShortcut(sc config.DNSShortcut, actor string) (config.DNSShortcut, error) {
	if err := ValidateShortcut(&sc); err != nil {
		return sc, err
	}
	err := a.Cfg.Update(func(c *config.Config) {
		// Drop address records for the same name: the shortcut answers it now.
		kept := c.DNS.Records[:0]
		for _, r := range c.DNS.Records {
			t := strings.ToUpper(r.Type)
			if (t == "A" || t == "AAAA") && strings.EqualFold(strings.TrimSuffix(r.Name, "."), sc.Name) {
				continue
			}
			kept = append(kept, r)
		}
		c.DNS.Records = kept
		for i := range c.DNS.Shortcuts {
			if strings.EqualFold(c.DNS.Shortcuts[i].Name, sc.Name) {
				c.DNS.Shortcuts[i] = sc
				return
			}
		}
		c.DNS.Shortcuts = append(c.DNS.Shortcuts, sc)
	})
	if err != nil {
		return sc, err
	}
	a.ReloadRecords()
	a.FlushDNSCache(sc.Name)
	a.Store.Audit(actor, "shortcut.save", sc.Name, "", sc.Target, "ok")
	return sc, nil
}

func (a *App) DeleteShortcut(name, actor string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	found := false
	err := a.Cfg.Update(func(c *config.Config) {
		out := c.DNS.Shortcuts[:0]
		for _, sc := range c.DNS.Shortcuts {
			if strings.EqualFold(sc.Name, name) {
				found = true
				continue
			}
			out = append(out, sc)
		}
		c.DNS.Shortcuts = out
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no shortcut named %s", name)
	}
	a.ReloadRecords()
	a.FlushDNSCache(name)
	a.Store.Audit(actor, "shortcut.delete", name, "", "", "ok")
	return nil
}

// nodeLANAddr is the IPv4 address this node would use to reach the internet,
// which on a home network is its LAN address: what a shortcut should resolve
// to. No packet is sent; the kernel only picks a source.
func nodeLANAddr() string {
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return ""
}
