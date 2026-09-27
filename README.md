# bindlint

**Offline linter for DNS zone files (RFC 1035 master-file syntax)** — parse
`example.com.zone` the way BIND would, then report 19 classes of mistakes with
a why/fix explanation per finding and CI-friendly exit codes.

## The problem

Zone files are still hand-edited: a missing SOA field, a CNAME pointed at an
IP, or a trailing space before `(` breaks delegation at 3 a.m. Generic text
linters do not understand master-file syntax; spinning up a DNS server to
validate a file is heavy. bindlint parses the file offline and answers: *would
this zone load, and is it sane?*

## Key features

- **RFC 1035 syntax engine** — comments, parenthesised multi-line records,
  quoted strings, `$ORIGIN`/`$TTL` directives, blank-owner inheritance
  (leading whitespace), relative-name resolution, TTL units (`1h30m`).
- **19 lint rules (ZS001–ZS019)** — SOA/serial sanity, MX/SRV/CNAME/PTR
  field checks, label length and character validation, apex-address and
  SPF/DMARC presence, `$INCLUDE` awareness. Every finding prints a `why` and
  a `fix`.
- **Line-accurate recovery** — one bad record becomes one finding; the rest
  of the zone is still parsed and linted.
- **Threshold gates for CI** — `--fail-on error|warning|never` maps findings
  to exit codes 0/1.
- **JSON parse dump** — `bindlint parse` emits records for tooling.
- **Zero dependencies** — pure Go standard library.

## Example

```console
$ bindlint lint testdata/broken.zone
bindlint 1.0.0 — lint testdata/broken.zone
zone origin: example.com.

ERROR   ZS001 (line 5): zone has no SOA record
  why:   Every zone needs exactly one SOA record at its apex; without it
         secondaries cannot transfer the zone and resolvers reject it.
  fix:   Add an SOA record, e.g.
         `@ IN SOA ns1.example.com. hostmaster.example.com. 2026092701 1h 15m 1w 5m`

WARNING ZS012 (line 1): zone apex "example.com." has no A or AAAA record
  ...
summary: 7 errors, 6 warnings, 2 info — 19 records parsed, 15 findings
```

## Architecture summary

```
cmd/bindlint        CLI wiring, flags, exit codes
internal/zone       lexer → parser → typed record tree (lexer/parser tested)
internal/lint       19 rules over the parsed zone
internal/render     text + JSON finding renderer
```

The parser is deliberately tolerant: malformed records become findings
(`ZS007`) instead of aborting, so one typo never hides the rest of the file.

## Requirements

- Go 1.22+ (developed and tested with Go 1.27)

## Installation

```console
$ git clone https://github.com/Wsh7Ash/bindlint
$ cd bindlint
$ go build ./cmd/bindlint
```

## Quick start

```console
$ bindlint lint db.example.com.zone
$ bindlint lint db.example.com.zone --fail-on warning   # gate on warnings too
$ bindlint parse db.example.com.zone                    # JSON record dump
$ bindlint rules                                        # list all 19 rules
```

## Usage examples

Lint with warnings as the CI threshold:

```console
$ bindlint lint testdata/broken.zone --fail-on warning
summary: 7 errors, 6 warnings, 2 info — 19 records parsed, 15 findings
$ echo $?
1
```

Dump parsed records for other tooling:

```console
$ bindlint parse testdata/clean.zone | jq '.records | length'
10
```

## Configuration

No configuration files. Flags: `--fail-on`, `--origin` (seed the origin when
the file has no `$ORIGIN`), `--version`.

## Testing

```console
$ go test ./...
$ go vet ./...
```

The `internal/zone` package carries table-driven lexer and parser tests;
`testdata/` holds one crafted zone file per lint rule plus clean/broken
end-to-end fixtures.

## Project structure

```text
bindlint/
├─ cmd/bindlint/        # CLI entry point
├─ internal/zone/       # lexer, parser, TTL grammar, types (+ tests)
├─ internal/lint/       # rule registry and checks
├─ internal/render/     # text/JSON renderers
├─ internal/cli/        # command plumbing
├─ testdata/            # clean/broken zones + per-rule fixtures
├─ results/             # generated demo artifacts
└─ docs/                # architecture, usage, spec
```

## Limitations

- Lint scope only: no zone *serving*, no DNSSEC chain validation.
- Supported typed rdata: SOA, NS, A, AAAA, CNAME, MX, TXT, PTR, SRV, CAA;
  other types are preserved opaquely and structurally linted.
- `$INCLUDE` files are reported (ZS019) but not followed.

## Roadmap

- `--format sarif` for GitHub code scanning
- CAA tag validation and DMARC policy strength checks
- Cross-record consistency rules (glue records for in-zone NS targets)

## Security notes

Fully offline; reads only the files you pass. No network, no execution of
zone content. Safe to run on untrusted zone text in a low-risk environment.

## License

MIT — see `LICENSE`.
