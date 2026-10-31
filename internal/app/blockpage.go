package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/blockpage"
)

// ClaimsBlockedHost reports whether a request reached this node because the
// resolver answered a blocked name with it, as opposed to someone opening
// Orbis itself. Anything else falls through to the interface.
func (a *App) ClaimsBlockedHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return a.BlockGuard.Pointed(host, time.Now())
}

// SyncBlockPage starts or stops the HTTPS listener to match the setting.
func (a *App) SyncBlockPage() {
	want := a.Cfg.Snapshot().DNS.BlockPage && a.BlockPage.Leaf != nil
	if want == a.BlockPage.Listening() {
		return
	}
	if !want {
		a.BlockPage.Close()
		return
	}
	if err := a.BlockPage.ListenTLS(":443"); err != nil {
		a.log("blockpage: https block page unavailable: %v", err)
	}
}

// explainBlock turns the same trace the domain tester and the assistant use
// into what a person sees, so the three can never disagree.
func (a *App) explainBlock(ctx context.Context, host string, client netip.Addr) blockpage.Page {
	now := time.Now()
	page := blockpage.Page{Host: host, When: now.Format("3:04 PM, Jan 2")}
	clientID, _ := a.clientForAddr(client)
	if c := a.Registry.ByIP(client); c != nil {
		page.Device = firstNonEmpty(c.Label, c.Hostname, c.IP)
	}
	page.DeviceAddress = net.ParseIP(page.Device) != nil
	if addr, ok := a.BlockGuard.AddrFor(client, host, now); ok {
		port := ""
		if _, p, err := net.SplitHostPort(a.Cfg.Snapshot().API.Listen); err == nil && p != "80" {
			port = ":" + p
		}
		page.AdminURL = fmt.Sprintf("http://%s%s/#/dnstools/%s", addr, port, host)
	}

	out, err := a.DiagnoseDomain(ctx, host, clientID, false)
	if err != nil {
		return page
	}
	steps, _ := out["steps"].([]DiagnoseStep)
	page.Blocked = out["verdict"] == "block"
	if !page.Blocked {
		return page
	}

	page.Stations = []blockpage.Station{
		{Title: "Your device", Detail: page.Device, Class: "clear", Address: page.DeviceAddress},
		{Title: "Orbis", Detail: "Received the lookup for " + host, Class: "clear"},
	}
	for _, s := range steps {
		st := blockpage.Station{Title: s.Stage, Detail: s.Detail}
		if s.Verdict == "block" {
			st.Class = "decided"
			page.Rule, page.Source = s.Rule, plainSource(s.Source)
		}
		page.Stations = append(page.Stations, st)
		if s.Verdict == "block" {
			page.Why = a.whyBlocked(host, s)
			break
		}
	}
	if match := a.Matcher.Lookup(host); match.Category != "" {
		page.Category = blockpage.Sentence(match.Category)
	}
	page.Stations = append(page.Stations, blockpage.Station{Title: "The site", Detail: "Never contacted", Class: "unreached"})
	page.Copy = strings.TrimSpace(fmt.Sprintf("%s blocked by %s, rule %s, on %s, %s", host, page.Source, page.Rule, page.Device, page.When))
	return page
}

// whyBlocked says it in one sentence, for someone who does not know what a
// resolver is.
func (a *App) whyBlocked(host string, s DiagnoseStep) string {
	switch {
	case s.Stage == "Blocked service":
		return fmt.Sprintf("%s is switched off for this device.", s.Rule)
	case s.Stage == "DoH bypass":
		return "This is a public encrypted DNS service, which this device's profile does not allow because it would get around this network's filtering."
	case strings.HasPrefix(s.Source, "local:"), s.Source == "config":
		return "It was blocked by a rule on this network."
	case s.Source == "builtin:doh-bypass":
		return "This is a public encrypted DNS service. Using one would get around this network's filtering, so Orbis blocks it."
	case s.Source == "builtin:streaming-ads":
		return "This host serves ads to smart TVs and streaming boxes."
	}
	if what := blockpage.Sentence(a.Matcher.Lookup(host).Category); what != "" {
		return fmt.Sprintf("It is on %s, a list this network uses to block %s.", plainSource(s.Source), what)
	}
	return fmt.Sprintf("It is on %s, a list this network uses.", plainSource(s.Source))
}

func plainSource(src string) string {
	switch {
	case strings.HasPrefix(src, "local:"), src == "config":
		return "A rule on this network"
	case src == "builtin:doh-bypass":
		return "Orbis built-in DNS bypass list"
	case src == "builtin:streaming-ads":
		return "Orbis built-in streaming ads list"
	case strings.HasPrefix(src, "policy:"):
		return strings.TrimPrefix(src, "policy:") + " profile"
	}
	return src
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
