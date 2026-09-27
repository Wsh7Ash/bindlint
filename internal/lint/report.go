package lint

import (
	"sort"

	"github.com/Wsh7Ash/bindlint/internal/zone"
)

// Summary counts findings by severity.
type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
	Total    int `json:"total"`
	Records  int `json:"records"`
}

// Report is the machine-readable result of linting one file.
type Report struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	File     string         `json:"file"`
	Origin   string         `json:"origin,omitempty"`
	Findings []zone.Finding `json:"findings"`
	Summary  Summary        `json:"summary"`
}

// Build lints a zone and packages the findings into a Report.
func Build(file, version string, z *zone.Zone, cfg Config) Report {
	findings := Lint(z, cfg)

	r := Report{
		Tool:     "bindlint",
		Version:  version,
		File:     file,
		Findings: findings,
		Summary:  Summarize(findings, len(z.Records)),
	}
	if z.OriginKnown {
		r.Origin = z.Origin
	}
	if r.Findings == nil {
		r.Findings = []zone.Finding{}
	}
	return r
}

// Summarize counts findings by severity.
func Summarize(findings []zone.Finding, records int) Summary {
	s := Summary{Records: records}
	for _, f := range findings {
		switch f.Severity {
		case zone.SeverityError:
			s.Errors++
		case zone.SeverityWarning:
			s.Warnings++
		default:
			s.Infos++
		}
	}
	s.Total = len(findings)
	return s
}

// MeetsThreshold reports whether the report reaches the --fail-on level.
// Valid thresholds are "error", "warning" and "never".
func (r Report) MeetsThreshold(failOn string) bool {
	switch failOn {
	case "error":
		return r.Summary.Errors > 0
	case "warning":
		return r.Summary.Errors > 0 || r.Summary.Warnings > 0
	case "never":
		return false
	default:
		return r.Summary.Errors > 0
	}
}

// WorstSeverity returns the highest severity present in the report.
func (r Report) WorstSeverity() (zone.Severity, bool) {
	worst := zone.SeverityInfo
	found := false
	for _, f := range r.Findings {
		if !found || f.Severity > worst {
			worst = f.Severity
			found = true
		}
	}
	return worst, found
}

// SortFindings orders findings by line then rule code.
func SortFindings(findings []zone.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Code < findings[j].Code
	})
}
