// Package report builds the network summary an operator wants to receive on a
// schedule or download: what talked most, what got blocked, what joined, and
// how much moved. It renders to JSON for the UI, CSV for a spreadsheet, and a
// self-contained HTML page that prints cleanly to PDF, which is the pragmatic
// answer to "PDF export" without carrying a PDF engine in the binary.
package report

import (
	"encoding/csv"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"
)

// Report is the structured summary.
type Report struct {
	Node        string       `json:"node"`
	GeneratedAt time.Time    `json:"generated_at"`
	Since       time.Time    `json:"since"`
	Window      string       `json:"window"`
	DNSQueries  int64        `json:"dns_queries"`
	DNSBlocked  int64        `json:"dns_blocked"`
	BlockRate   float64      `json:"block_rate"`
	Devices     int          `json:"devices"`
	NewDevices  []string     `json:"new_devices"`
	BytesIn     int64        `json:"bytes_in"`
	BytesOut    int64        `json:"bytes_out"`
	TopTalkers  []Row        `json:"top_talkers"`
	TopBlocked  []Row        `json:"top_blocked"`
	TopCountries []Row       `json:"top_countries"`
	Events      int          `json:"events"`
}

// Row is one ranked line: a label and a number.
type Row struct {
	Label string `json:"label"`
	Value int64  `json:"value"`
	Extra string `json:"extra,omitempty"`
}

// WriteCSV emits the ranked sections as a single flat CSV, which is what a
// spreadsheet wants: a section column so every row is self-describing.
func (r *Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"section", "label", "value", "extra"})
	rows := func(section string, list []Row) {
		for _, row := range list {
			_ = cw.Write([]string{section, row.Label, fmt.Sprint(row.Value), row.Extra})
		}
	}
	_ = cw.Write([]string{"summary", "dns_queries", fmt.Sprint(r.DNSQueries), ""})
	_ = cw.Write([]string{"summary", "dns_blocked", fmt.Sprint(r.DNSBlocked), fmt.Sprintf("%.1f%%", r.BlockRate)})
	_ = cw.Write([]string{"summary", "bytes_in", fmt.Sprint(r.BytesIn), ""})
	_ = cw.Write([]string{"summary", "bytes_out", fmt.Sprint(r.BytesOut), ""})
	_ = cw.Write([]string{"summary", "devices", fmt.Sprint(r.Devices), ""})
	rows("top_talker", r.TopTalkers)
	rows("top_blocked", r.TopBlocked)
	rows("top_country", r.TopCountries)
	for _, d := range r.NewDevices {
		_ = cw.Write([]string{"new_device", d, "", ""})
	}
	return cw.Error()
}

// WriteHTML emits a standalone, styled page. No external assets, so it renders
// and prints anywhere, including from an email client.
func (r *Report) WriteHTML(w io.Writer) error {
	var b strings.Builder
	esc := html.EscapeString
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<title>Orbis report</title><style>`)
	b.WriteString(`body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#111;max-width:760px;margin:32px auto;padding:0 20px}`)
	b.WriteString(`h1{font-size:20px;margin:0 0 2px}.sub{color:#666;font-size:12px;margin-bottom:24px}`)
	b.WriteString(`h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#888;margin:26px 0 8px;border-bottom:1px solid #eee;padding-bottom:4px}`)
	b.WriteString(`.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:12px 0}`)
	b.WriteString(`.stat{border:1px solid #eee;border-radius:8px;padding:10px 12px}.stat .n{font-size:22px;font-weight:600}.stat .l{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.05em}`)
	b.WriteString(`table{width:100%;border-collapse:collapse;font-size:13px}td{padding:5px 4px;border-bottom:1px solid #f2f2f2}td.n{text-align:right;color:#555;font-variant-numeric:tabular-nums}`)
	b.WriteString(`</style></head><body>`)
	fmt.Fprintf(&b, `<h1>Orbis network report</h1><div class="sub">%s · %s window · generated %s</div>`,
		esc(r.Node), esc(r.Window), r.GeneratedAt.Format("2006-01-02 15:04 MST"))

	fmt.Fprintf(&b, `<div class="grid">`+
		`<div class="stat"><div class="n">%s</div><div class="l">DNS queries</div></div>`+
		`<div class="stat"><div class="n">%.1f%%</div><div class="l">Blocked</div></div>`+
		`<div class="stat"><div class="n">%s</div><div class="l">Downloaded</div></div>`+
		`<div class="stat"><div class="n">%s</div><div class="l">Uploaded</div></div></div>`,
		humanCount(r.DNSQueries), r.BlockRate, humanBytes(r.BytesIn), humanBytes(r.BytesOut))

	section := func(title string, rows []Row, human func(int64) string) {
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, `<h2>%s</h2><table>`, esc(title))
		for _, row := range rows {
			fmt.Fprintf(&b, `<tr><td>%s</td><td class="n">%s</td></tr>`,
				esc(row.Label), esc(human(row.Value)))
		}
		b.WriteString(`</table>`)
	}
	section("Top talkers", r.TopTalkers, humanBytes)
	section("Most blocked", r.TopBlocked, humanCount)
	section("Top countries", r.TopCountries, humanCount)
	if len(r.NewDevices) > 0 {
		b.WriteString(`<h2>New devices</h2><table>`)
		for _, d := range r.NewDevices {
			fmt.Fprintf(&b, `<tr><td>%s</td></tr>`, esc(d))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</body></html>`)
	_, err := io.WriteString(w, b.String())
	return err
}

// TextSummary is the compact form emailed on a schedule, when a full HTML body
// is more than the moment calls for.
func (r *Report) TextSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Orbis report — %s (%s)\n\n", r.Node, r.Window)
	fmt.Fprintf(&b, "DNS: %s queries, %s blocked (%.1f%%)\n",
		humanCount(r.DNSQueries), humanCount(r.DNSBlocked), r.BlockRate)
	fmt.Fprintf(&b, "Traffic: %s down, %s up across %d devices\n",
		humanBytes(r.BytesIn), humanBytes(r.BytesOut), r.Devices)
	if len(r.NewDevices) > 0 {
		fmt.Fprintf(&b, "New devices: %s\n", strings.Join(r.NewDevices, ", "))
	}
	if len(r.TopTalkers) > 0 {
		b.WriteString("\nTop talkers:\n")
		for i, row := range r.TopTalkers {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "  %s — %s\n", row.Label, humanBytes(row.Value))
		}
	}
	return b.String()
}

// SortRows ranks a slice descending, keeping the top n.
func SortRows(rows []Row, n int) []Row {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Value > rows[j].Value })
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

func humanBytes(b int64) string {
	f := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%d B", b)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%d B", b)
}

func humanCount(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}
