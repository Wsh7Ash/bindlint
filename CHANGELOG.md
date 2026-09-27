# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-09-27

### Added

- RFC 1035 master-file lexer: comments, parenthesised continuations, quoted
  strings, leading-space blank-owner inheritance.
- Tolerant parser: `$ORIGIN`/`$TTL`/`$INCLUDE` directives, TTL unit grammar,
  typed rdata for SOA/NS/A/AAAA/CNAME/MX/TXT/PTR/SRV/CAA, opaque preservation
  of unknown types, line-accurate `ZS007` recovery.
- 19 lint rules (ZS001–ZS019) with why/fix explanations.
- CLI: `lint`, `parse` (JSON dump), `rules`, `--fail-on error|warning|never`,
  `--origin`, exit codes 0/1/2.
- Table-driven lexer/parser tests and per-rule `testdata/` fixtures.
