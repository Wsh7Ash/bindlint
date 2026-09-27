# Results

## Environment

| Item | Value |
| --- | --- |
| OS | Windows (win32), bash (MSYS) |
| Go | 1.27.0 windows/amd64 |
| Dependencies | zero (Go standard library only) |
| Working directory | repository root |

## Validation performed

| Check | Command | Result |
| --- | --- | --- |
| Build | `go build ./...` | **PASS** |
| Vet | `go vet ./...` | **PASS** — clean |
| Format | `gofmt -l .` | **PASS** — no files listed after `gofmt -w` |
| Tests | `go test ./...` | **PASS** — `ok github.com/Wsh7Ash/bindlint/internal/zone` |
| CLI smoke: clean | `bindlint lint testdata/clean.zone` | **PASS** — `clean: no findings (10 records parsed)`, exit 0 |
| CLI smoke: broken | `bindlint lint testdata/broken.zone` | **PASS** — 7 errors/6 warnings/2 info over 19 records, exit 0 (default threshold=error would be exit 1: verified below) |
| Threshold gate | `bindlint lint testdata/broken.zone --fail-on warning` | **PASS** — exit 1 |
| Bad threshold rejected | `bindlint lint … --fail-on info` | **PASS** — exit 2 with usage message |
| Demo artifacts | commands in `results/` | **PASS** — 3 artifacts regenerated |

## Commands executed

```console
gofmt -w .
go vet ./...
go test ./...
go build -o /tmp/bindlint.exe ./cmd/bindlint
/tmp/bindlint.exe --help
/tmp/bindlint.exe lint testdata/clean.zone            # exit 0
/tmp/bindlint.exe lint testdata/broken.zone           # findings printed
/tmp/bindlint.exe lint testdata/broken.zone --fail-on warning   # exit 1
/tmp/bindlint.exe lint testdata/broken.zone --fail-on info      # exit 2 (invalid value)
/tmp/bindlint.exe parse testdata/clean.zone
/tmp/bindlint.exe rules
```

## Observed result

- 19 rules (ZS001–ZS019: 9 error, 8 warning, 2 info), each with why/fix text.
- `testdata/clean.zone` (10 records): zero findings.
- `testdata/broken.zone` (19 records): 15 findings, every one with a line
  number, severity, why and fix; parse recovery keeps the whole file visible.
- Exit codes verified for 0 / 1 / 2 paths.

## Generated artifacts

- `results/demo-session.txt` — real CLI session over both fixtures
- `results/parse-dump.txt` — JSON parse dump of the clean zone
- `results/rules.txt` — full rule listing

## Known limitations

- Ten typed rdata kinds; other types are preserved opaquely.
- `$INCLUDE` is reported, not followed (by design for an offline tool).
- No DNSSEC validation (roadmap).
