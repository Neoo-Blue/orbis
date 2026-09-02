package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Prometheus exposition without the client library. Orbis exports a few dozen
// gauges and counters, all already computed elsewhere; pulling in a dependency
// and a registry to format them would be more machinery than the job needs.

// metricWriter accumulates exposition-format lines.
type metricWriter struct {
	b strings.Builder
}

func (m *metricWriter) gauge(name, help string, value float64, labels ...string) {
	m.emit("gauge", name, help, value, labels...)
}

func (m *metricWriter) counter(name, help string, value float64, labels ...string) {
	m.emit("counter", name, help, value, labels...)
}

// emit writes one sample. Labels arrive as alternating key/value pairs; an odd
// trailing element is dropped rather than producing malformed output that a
// scraper would reject wholesale.
func (m *metricWriter) emit(kind, name, help string, value float64, labels ...string) {
	if help != "" {
		fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	m.b.WriteString(name)
	if len(labels) >= 2 {
		parts := make([]string, 0, len(labels)/2)
		for i := 0; i+1 < len(labels); i += 2 {
			parts = append(parts, fmt.Sprintf("%s=%q", labels[i], escapeLabel(labels[i+1])))
		}
		m.b.WriteString("{" + strings.Join(parts, ",") + "}")
	}
	fmt.Fprintf(&m.b, " %g\n", value)
}

func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// handleMetrics serves the Prometheus endpoint. It is mounted outside the
// session-auth wrapper but behind a bearer token when one is configured,
// because a scraper cannot log in and the data is operational, not secret.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	if tok := cfg.API.MetricsToken; tok != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got != tok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	m := &metricWriter{}
	app := s.app

	m.gauge("orbis_up", "1 when the daemon is serving.", 1)
	m.gauge("orbis_uptime_seconds", "Seconds since the daemon started.", app.Uptime().Seconds())
	m.gauge("orbis_mode", "1 when inline, 0 when observing.", b2f(cfg.Mode == "inline"))

	// DNS.
	if app.DNS != nil {
		d := app.DNS.Stats()
		for _, k := range sortedKeys(d) {
			v, ok := toFloat(d[k])
			if !ok {
				continue
			}
			switch k {
			case "queries", "blocked", "cached", "errors", "collapsed", "local",
				"rate_limited", "rebind_blocked", "rewritten":
				m.counter("orbis_dns_"+k+"_total", "DNS "+strings.ReplaceAll(k, "_", " ")+".", v)
			default:
				m.gauge("orbis_dns_"+k, "", v)
			}
		}
		m.gauge("orbis_dns_running", "1 when the resolver is listening.", b2f(app.DNS.Running()))
	}
	if app.DNSCrypt != nil {
		m.gauge("orbis_dns_encrypted_running", "1 when DoT/DoH are listening.", b2f(app.DNSCrypt.Running()))
	}

	// Ad blocking.
	if app.Matcher != nil {
		m.gauge("orbis_adblock_rules", "Blocklist entries currently indexed.", float64(app.Matcher.Count()))
		hits, misses := app.Matcher.Stats()
		m.counter("orbis_adblock_hits_total", "Lookups that matched a rule.", float64(hits))
		m.counter("orbis_adblock_misses_total", "Lookups that matched nothing.", float64(misses))
	}

	// Flows.
	if app.Tracker != nil {
		t := app.Tracker.Stats()
		m.gauge("orbis_flows_active", "Flows currently tracked.", float64(t.Active))
		m.counter("orbis_flows_total", "Flows observed since start.", float64(t.Total))
		m.counter("orbis_flows_dropped_total", "Flows dropped at the capacity cap.", float64(t.Dropped))
		m.counter("orbis_sni_extracted_total", "TLS ClientHellos parsed.", float64(t.SNIExtracted))
		m.counter("orbis_quic_decrypted_total", "QUIC Initials decrypted.", float64(t.QUICDecrypted))
	}

	// Devices. Online is defined the same way the dashboard defines it, so the
	// scraped number and the displayed number cannot disagree.
	if app.Registry != nil {
		all := app.Registry.All()
		online := 0
		cutoff := time.Now().Add(-5 * time.Minute)
		for _, c := range all {
			if c.LastSeen.After(cutoff) {
				online++
			}
		}
		m.gauge("orbis_clients_total", "Known devices.", float64(len(all)))
		m.gauge("orbis_clients_online", "Devices seen in the last 5 minutes.", float64(online))
	}

	// Filter proxy.
	if app.MITM != nil {
		st := app.MITM.Stats()
		for _, k := range sortedKeys(st) {
			if v, ok := toFloat(st[k]); ok {
				m.counter("orbis_proxy_"+k+"_total", "", v)
			}
		}
	}

	// YouTube Lounge engine.
	if app.Lounge != nil {
		lst := app.Lounge.Status()
		connected, online, ads, skipped, lost, segs, reloads := 0, 0, 0, 0, 0, 0, 0
		saved := 0.0
		for _, d := range lst.Devices {
			if d.Connected {
				connected++
			}
			if d.Online {
				online++
			}
			ads += d.AdsHandled
			skipped += d.AdsSkipped
			lost += d.AdsLost
			reloads += d.Reloads
			segs += d.SegmentsSkipped + d.SegmentsMuted
			saved += d.SecondsSaved
		}
		m.gauge("orbis_lounge_devices", "Paired YouTube screens.", float64(len(lst.Devices)))
		m.gauge("orbis_lounge_connected", "Screens with a live session.", float64(connected))
		m.gauge("orbis_lounge_online", "Screens currently present in the lounge.", float64(online))
		m.counter("orbis_lounge_ads_total", "Ads seen on paired screens.", float64(ads))
		m.counter("orbis_lounge_ads_skipped_total", "Ads cut short by Orbis.", float64(skipped))
		m.counter("orbis_lounge_ads_lost_total", "Ads whose end the player never reported.", float64(lost))
		m.counter("orbis_lounge_reloads_total", "Unskippable mid-rolls reloaded past.", float64(reloads))
		m.counter("orbis_lounge_segments_total", "SponsorBlock segments skipped or muted.", float64(segs))
		m.counter("orbis_lounge_seconds_saved_total", "Seconds of ads and segments not watched.", saved)
	}

	// Firewall counters, one series per named rule. A failure to read them is
	// not fatal to the scrape: the rest of the metrics are still useful.
	if app.Firewall != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		if counters, err := app.Firewall.Counters(ctx); err == nil {
			for name, pb := range counters {
				m.emit("counter", "orbis_firewall_rule_packets_total", "", float64(pb[0]), "rule", name)
				m.emit("counter", "orbis_firewall_rule_bytes_total", "", float64(pb[1]), "rule", name)
			}
		}
		cancel()
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(m.b.String()))
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case bool:
		return b2f(n), true
	}
	return 0, false
}
