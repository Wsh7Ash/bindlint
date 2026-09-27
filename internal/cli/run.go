// Package cli implements the bindlint command line interface. Run is the
// single entry point so exit codes are testable without a subprocess.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Wsh7Ash/bindlint/internal/lint"
	"github.com/Wsh7Ash/bindlint/internal/render"
	"github.com/Wsh7Ash/bindlint/internal/zone"
)

// Version is the released bindlint version.
const Version = "1.0.0"

const mainUsage = `bindlint — offline DNS zone-file parser and RFC-aware linter

Usage:
  bindlint lint  <file> [flags]   lint a zone file and report findings
  bindlint parse <file> [flags]   dump parsed records (debugging aid)
  bindlint rules [flags]          list all lint rules
  bindlint --version              print the version
  bindlint --help                 show this help

Exit codes:
  0  no findings at or above the --fail-on threshold
  1  findings at or above the --fail-on threshold
  2  usage error, unreadable file or unrecoverable parse error

Run 'bindlint <command> --help' for command flags.
`

const lintUsage = `Usage: bindlint lint <file> [flags]

Parses the zone file offline (no network, no BIND) and reports RFC-aware
findings with severity, explanation and suggestion.

Flags:
  --format text|json     output format (default "text")
  --fail-on error|warning|never
                         minimum severity that fails the run (default "error")
  --origin <name>        zone origin to assume when the file has no $ORIGIN
  --max-ttl <seconds>    TTL ceiling for rule ZS016 (default 68400)
`

const parseUsage = `Usage: bindlint parse <file> [flags]

Dumps the parsed records as a debugging aid.

Flags:
  --format json|text     output format (default "json")
  --origin <name>        zone origin to assume when the file has no $ORIGIN
`

const rulesUsage = `Usage: bindlint rules [flags]

Lists every lint rule with its id, severity and description.

Flags:
  --format text|json     output format (default "text")
`

// Run executes bindlint with the given arguments (excluding the program
// name) and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		io.WriteString(stderr, mainUsage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		io.WriteString(stdout, mainUsage)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "bindlint %s\n", Version)
		return 0
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "parse":
		return runParse(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "bindlint: unknown command %q\n\n", args[0])
		io.WriteString(stderr, mainUsage)
		return 2
	}
}

// reorderArgs moves flags (and their values) ahead of positional arguments
// so that `bindlint lint zonefile --format json` works even though Go's flag
// package stops parsing at the first non-flag argument.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				flags = append(flags, a)
				continue
			}
			flags = append(flags, a)
			f := fs.Lookup(name)
			if f == nil {
				continue // unknown flag: let flag.Parse report it
			}
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

// parseFlags parses reordered args so flags may follow positional arguments.
// It returns flag.ErrHelp untouched so callers can treat --help as exit 0.
func parseFlags(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorderArgs(fs, args))
}

func runLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", `output format: "text" or "json"`)
	failOn := fs.String("fail-on", "error", `threshold: "error", "warning" or "never"`)
	origin := fs.String("origin", "", "zone origin to assume when the file has no $ORIGIN")
	maxTTL := fs.Uint("max-ttl", lint.DefaultMaxTTL, "TTL ceiling in seconds for rule ZS016")
	fs.Usage = func() { io.WriteString(stderr, lintUsage) }
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "bindlint lint: expected exactly one zone file argument")
		fs.Usage()
		return 2
	}
	switch *format {
	case "text", "json":
	default:
		fmt.Fprintf(stderr, "bindlint lint: invalid --format %q (want \"text\" or \"json\")\n", *format)
		return 2
	}
	switch *failOn {
	case "error", "warning", "never":
	default:
		fmt.Fprintf(stderr, "bindlint lint: invalid --fail-on %q (want \"error\", \"warning\" or \"never\")\n", *failOn)
		return 2
	}

	file := fs.Arg(0)
	z, err := zone.ParseFile(file, zone.Options{Origin: *origin})
	if err != nil {
		fmt.Fprintf(stderr, "bindlint: %v\n", err)
		return 2
	}

	report := lint.Build(file, Version, z, lint.Config{MaxTTL: uint32(*maxTTL)})
	if *format == "json" {
		err = render.JSON(stdout, report)
	} else {
		err = render.Text(stdout, report)
	}
	if err != nil {
		fmt.Fprintf(stderr, "bindlint: writing report: %v\n", err)
		return 2
	}

	if report.MeetsThreshold(*failOn) {
		return 1
	}
	return 0
}

func runParse(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "json", `output format: "json" or "text"`)
	origin := fs.String("origin", "", "zone origin to assume when the file has no $ORIGIN")
	fs.Usage = func() { io.WriteString(stderr, parseUsage) }
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "bindlint parse: expected exactly one zone file argument")
		fs.Usage()
		return 2
	}
	switch *format {
	case "json", "text":
	default:
		fmt.Fprintf(stderr, "bindlint parse: invalid --format %q (want \"json\" or \"text\")\n", *format)
		return 2
	}

	file := fs.Arg(0)
	z, err := zone.ParseFile(file, zone.Options{Origin: *origin})
	if err != nil {
		fmt.Fprintf(stderr, "bindlint: %v\n", err)
		return 2
	}

	if *format == "text" {
		err = render.DumpText(stdout, z)
	} else {
		err = render.DumpJSON(stdout, z)
	}
	if err != nil {
		fmt.Fprintf(stderr, "bindlint: writing dump: %v\n", err)
		return 2
	}
	return 0
}

func runRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", `output format: "text" or "json"`)
	fs.Usage = func() { io.WriteString(stderr, rulesUsage) }
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "bindlint rules: takes no arguments")
		fs.Usage()
		return 2
	}
	switch *format {
	case "text", "json":
	default:
		fmt.Fprintf(stderr, "bindlint rules: invalid --format %q (want \"text\" or \"json\")\n", *format)
		return 2
	}

	if *format == "json" {
		type ruleOut struct {
			Code        string        `json:"code"`
			Severity    zone.Severity `json:"severity"`
			Description string        `json:"description"`
			Explanation string        `json:"explanation"`
			Suggestion  string        `json:"suggestion"`
		}
		out := make([]ruleOut, 0, len(lint.Rules))
		for _, r := range lint.Rules {
			out = append(out, ruleOut{r.Code, r.Severity, r.Description, r.Explanation, r.Suggestion})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "bindlint: %v\n", err)
			return 2
		}
		return 0
	}

	var b strings.Builder
	b.WriteString("CODE    SEVERITY  DESCRIPTION\n")
	for _, r := range lint.Rules {
		fmt.Fprintf(&b, "%-7s %-9s %s\n", r.Code, r.Severity.String(), r.Description)
	}
	fmt.Fprintf(&b, "\n%d rules (errors: %d, warnings: %d, info: %d)\n",
		len(lint.Rules), countSeverity(zone.SeverityError), countSeverity(zone.SeverityWarning), countSeverity(zone.SeverityInfo))
	io.WriteString(stdout, b.String())
	return 0
}

func countSeverity(s zone.Severity) int {
	n := 0
	for _, r := range lint.Rules {
		if r.Severity == s {
			n++
		}
	}
	return n
}
