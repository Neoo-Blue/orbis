package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func sample() *Report {
	return &Report{
		Node: "orbis", GeneratedAt: time.Unix(1700000000, 0), Window: "weekly",
		DNSQueries: 120345, DNSBlocked: 20456, BlockRate: 17.0, Devices: 24,
		NewDevices: []string{"new-laptop"},
		BytesIn:    9_800_000_000, BytesOut: 1_200_000_000,
		TopTalkers: []Row{{Label: "nas", Value: 5_000_000_000}, {Label: "tv", Value: 2_000_000_000}},
		TopBlocked: []Row{{Label: "doubleclick.net", Value: 8000}},
		TopCountries: []Row{{Label: "US", Value: 30000}, {Label: "CA", Value: 2000}},
	}
}

func TestCSVIsWellFormed(t *testing.T) {
	var b bytes.Buffer
	if err := sample().WriteCSV(&b); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatalf("produced CSV that does not parse: %v", err)
	}
	if len(rows) < 6 {
		t.Fatalf("expected header plus data rows, got %d", len(rows))
	}
	if rows[0][0] != "section" {
		t.Fatalf("first column should be section, got %q", rows[0][0])
	}
	// Every data row must have the section-label-value-extra shape.
	for i, r := range rows {
		if len(r) != 4 {
			t.Fatalf("row %d has %d columns, want 4", i, len(r))
		}
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	var b bytes.Buffer
	if err := sample().WriteHTML(&b); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "<!doctype html>") || !strings.Contains(s, "</html>") {
		t.Fatal("not a complete HTML document")
	}
	// No external asset references: it has to render from an email or a file.
	for _, bad := range []string{"http://", "https://", "src=", "<script"} {
		if strings.Contains(s, bad) {
			t.Fatalf("HTML report must be self-contained, found %q", bad)
		}
	}
	if !strings.Contains(s, "doubleclick.net") {
		t.Fatal("report content missing")
	}
}

func TestHTMLEscapesContent(t *testing.T) {
	r := sample()
	r.TopBlocked = []Row{{Label: `<script>alert(1)</script>`, Value: 1}}
	var b bytes.Buffer
	_ = r.WriteHTML(&b)
	if strings.Contains(b.String(), "<script>alert(1)") {
		t.Fatal("a domain label must be HTML-escaped, or a report is an injection vector")
	}
}

func TestTextSummaryHasNumbers(t *testing.T) {
	s := sample().TextSummary()
	for _, want := range []string{"orbis", "weekly", "new-laptop", "nas"} {
		if !strings.Contains(s, want) {
			t.Fatalf("text summary missing %q", want)
		}
	}
}
