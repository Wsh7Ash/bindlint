// Package render formats lint reports and parse dumps for humans and machines.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Wsh7Ash/bindlint/internal/lint"
	"github.com/Wsh7Ash/bindlint/internal/zone"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r lint.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes the human-readable report: one block per finding with code,
// line, message, explanation and suggestion, followed by a summary line.
func Text(w io.Writer, r lint.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "bindlint %s — lint %s\n", r.Version, r.File)
	if r.Origin != "" {
		fmt.Fprintf(&b, "zone origin: %s\n", r.Origin)
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "clean: no findings in %s (%d records parsed)\n", r.File, r.Summary.Records)
		_, err := io.WriteString(w, b.String())
		return err
	}

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%-7s %s (line %d): %s\n", strings.ToUpper(f.Severity.String()), f.Code, f.Line, f.Message)
		if f.Owner != "" {
			fmt.Fprintf(&b, "  owner: %s\n", f.Owner)
		}
		if f.Explanation != "" {
			fmt.Fprintf(&b, "  why:   %s\n", f.Explanation)
		}
		if f.Suggestion != "" {
			fmt.Fprintf(&b, "  fix:   %s\n", f.Suggestion)
		}
		b.WriteString("\n")
	}

	s := r.Summary
	fmt.Fprintf(&b, "summary: %s — %d records parsed, %d findings\n",
		plural(s.Errors, s.Warnings, s.Infos), s.Records, s.Total)

	_, err := io.WriteString(w, b.String())
	return err
}

func plural(errors, warnings, infos int) string {
	parts := []string{}
	if errors > 0 {
		parts = append(parts, fmt.Sprintf("%d error%s", errors, pluralS(errors)))
	}
	if warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warning%s", warnings, pluralS(warnings)))
	}
	if infos > 0 {
		parts = append(parts, fmt.Sprintf("%d info", infos))
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ParseDump is the machine-readable output of the `bindlint parse` command.
type ParseDump struct {
	File     string         `json:"file"`
	Origin   string         `json:"origin,omitempty"`
	Records  []*zone.Record `json:"records"`
	Findings []zone.Finding `json:"findings"`
}

// DumpJSON writes the parsed records (and any parser findings) as JSON.
func DumpJSON(w io.Writer, z *zone.Zone) error {
	d := ParseDump{File: z.File, Origin: z.Origin, Records: z.Records, Findings: z.Findings}
	if d.Records == nil {
		d.Records = []*zone.Record{}
	}
	if d.Findings == nil {
		d.Findings = []zone.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}

// DumpText writes the parsed records as an aligned table.
func DumpText(w io.Writer, z *zone.Zone) error {
	var b strings.Builder
	fmt.Fprintf(&b, "bindlint parse %s\n", z.File)
	if z.OriginKnown {
		fmt.Fprintf(&b, "origin: %s\n", z.Origin)
	} else {
		b.WriteString("origin: (unknown)\n")
	}
	fmt.Fprintf(&b, "%-6s %-30s %-8s %-6s %-8s %s\n", "LINE", "OWNER", "TTL", "CLASS", "TYPE", "RDATA")
	for _, r := range z.Records {
		fmt.Fprintf(&b, "%-6d %-30s %-8d %-6s %-8s %s\n", r.Line, r.Owner, r.TTL, r.Class, r.Type, r.RDataText)
	}
	fmt.Fprintf(&b, "%d record(s), %d parser finding(s)\n", len(z.Records), len(z.Findings))
	for _, f := range z.Findings {
		fmt.Fprintf(&b, "%s (line %d): %s\n", f.Code, f.Line, f.Message)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
