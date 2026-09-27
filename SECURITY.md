# Security Policy

## Scope

bindlint is an offline, read-only linter for DNS zone files. It makes no
network connections, executes no zone content, and writes nothing except
what you redirect. The attack surface is limited to malformed input files
(parsed by a hand-rolled lexer/parser) — crashes or hangs on hostile input
are treated as bugs.

## Safe use

- Running bindlint on untrusted zone text is safe by design; if you find a
  panic, hang, or unbounded memory growth from a crafted file, please
  report it.
- The `parse` command emits JSON of file content — do not point it at
  files whose content is confidential if you plan to share the output.

## Reporting

Open a GitHub issue with the minimal offending zone file and the observed
behavior. For anything that looks exploitable in a pipeline context
(e.g. JSON rendering of hostile content), describe the mechanism privately
first.

## Supported versions

Only the latest published release receives security fixes.
