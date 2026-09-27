# Architecture

## Pipeline

```text
zone file ──▶ Lex ──▶ []Entry ──▶ Parse ──▶ Zone{Records, Findings}
                                             │
                        lint.Rules ──────────┤
                                             ▼
                                     render (text | JSON) ──▶ exit code
```

## Components

### internal/zone — the syntax layer

- **lexer.go** — splits source into logical entries: strips `;` comments
  (quote-aware), joins parenthesised continuations, normalises whitespace,
  and records `LeadingSpace` because that is how RFC 1035 expresses a blank
  (inherited) owner. Unbalanced parens/quotes are fatal `*ParseError`s.
- **parser.go** — directives (`$ORIGIN`, `$TTL`, `$INCLUDE`), owner
  resolution (`@`, absolute/relative names, inheritance), TTL grammar
  (`ParseTTL`: `30`, `1h30m`, unit validation, 32-bit range), and typed
  rdata builders for SOA/NS/A/AAAA/CNAME/MX/TXT/PTR/SRV/CAA. Unknown types
  are kept as `OpaqueData` so structural rules still apply.
- **Recovery model** — bad records emit `ZS007` findings and are skipped;
  parsing always continues. `parseSRV` keeps malformed SRV data with an
  `Err` field so rule ZS009 can point at the exact line.

### internal/lint — the semantic layer

19 rules over the parsed `Zone`. Rules never re-parse text; they inspect
`Records`/`Findings`. Each rule reports code, severity, line, owner, message,
`why`, and `fix`.

### internal/cli + internal/render

Flag parsing and threshold mapping (`--fail-on error|warning|never` → exit
0/1); text and JSON renderers share the finding model.

## Design decisions

- **Blank owner requires leading whitespace.** A token that merely looks
  like a type (`a`, `ptr`) is an owner unless the line starts with
  whitespace; `a IN A …` keeps owner `a`. A bare type token (`A 1.2.3.4`)
  still starts an inherited record.
- **Keep bad-TTL records** with the default TTL (`TTLSet=false`) so line
  numbers and neighbors survive for later rules.
- **First `$ORIGIN` wins for `Zone.Apex`**; `$ORIGIN` redefinitions affect
  only records after them (`Zone.Origin` tracks the current value).
- **No third-party dependencies** — the lexer/parser is hand-rolled and
  table-tested; `golang.org/x/net/dns/dnsmessage` was rejected because its
  parser is binary-oriented and aborts on the first error.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | no findings at or above the threshold |
| 1 | findings at or above the threshold |
| 2 | usage error or unreadable file |
