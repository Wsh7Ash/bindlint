# Contributing

Thanks for considering a contribution to bindlint.

## Ground rules

- Go standard library only — no third-party dependencies.
- Every new rule needs: a `ZSxxx` code, a severity, a check in
  `internal/lint`, a fixture in `testdata/`, and why/fix text written for
  the operator reading it at 3 a.m.
- Parser changes must keep the recovery model: a bad record is a finding,
  never an abort.
- `gofmt`, `go vet ./...` and `go test ./...` must stay clean.

## Workflow

1. Fork/branch.
2. Add or extend tests first for rule behavior.
3. Update `docs/` and `CHANGELOG.md` for user-visible changes.
4. Open a pull request describing the failure mode the rule catches.

## Code style

- Table-driven tests; fixtures as real zone files under `testdata/`.
- Explanatory text (`why`/`fix`) is part of the product, not a comment.
