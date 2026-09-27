# Usage

Build once, then:

```console
$ go build ./cmd/bindlint
```

## Commands

| Command | Purpose |
| --- | --- |
| `bindlint lint <file>` | lint a zone file, print findings |
| `bindlint parse <file>` | dump parsed records as JSON |
| `bindlint rules` | list all rules with severity, why, fix |
| `bindlint --version` | print version |

## Flags

- `--fail-on error|warning|never` — exit-code threshold (default `error`).
- `--origin example.com` — seed the origin when the file has no `$ORIGIN`
  (suppresses ZS017 for relative names).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | no findings at or above the threshold |
| 1 | findings at or above the threshold |
| 2 | usage error / unreadable file |

## CI usage

```yaml
- run: go build ./cmd/bindlint
- run: ./bindlint lint zones/db.example.com --fail-on warning
```

## Interpreting findings

Each finding prints:

```text
SEVERITY CODE (line N): message
  owner: <owner name, when known>
  why:   the operational reason the rule exists
  fix:   a concrete remediation
```

Errors (ZS001–ZS009) mean the zone is broken or dangerous. Warnings
(ZS010–ZS017) mean it will load but something is probably wrong. Info
(ZS018–ZS019) means awareness-level hygiene (mail authentication,
`$INCLUDE` skipping).
