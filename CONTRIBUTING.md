# Contributing to StackGuard

Thanks for helping! Most contributions are new rules, and those need no Go code.

## Setup

You need Go 1.24 or newer. Optionally install
[golangci-lint](https://golangci-lint.run/) and
[GoReleaser](https://goreleaser.com/).

```bash
git clone https://github.com/nexutils/StackGuard
cd StackGuard
make build test
```

## Adding a rule

1. Create `rules/<target>/<ID>.yaml`. See [docs/rule-authoring.md](docs/rule-authoring.md).
2. Add a failing fixture under `testdata/rules/<ID>/fail/`, and optionally a
   passing one under `testdata/rules/<ID>/pass/`.
3. Run `make test docs` and commit the regenerated `docs/rules`.

The test suite enforces these conventions for every built-in rule:

- the ID prefix matches the target and the ID's middle segment matches the category
- the file is named after the ID and sits in its target's directory
- `description`, `remediation` and `pass_message` are set
- the `fail` fixture triggers the rule and the `pass` fixture does not
- the clean project for the target, `testdata/rules/_clean/<target>/`, has no findings

## Adding a parser

1. Create `internal/parser/<target>/`, implement `parser.Parser`, and document
   the resource types and properties in the package comment.
2. Register it in `internal/parser/all/all.go` with an appropriate priority.
3. Add inputs under `testdata/parsers/<target>/` and run `make golden`. Review
   the generated `*.golden.json` carefully, because it becomes the contract.
4. Add a clean project under `testdata/rules/_clean/<target>/` and at least one rule.
5. Document the properties in `docs/rule-authoring.md`.

## Pull requests

- Run `make fmt lint test` before pushing.
- Golden files change only when output changes on purpose. Regenerate them
  with `make golden` and say why in the PR description.
- Keep commits focused. The first line of each message should say what changed.

## Reporting security issues

Please don't open a public issue for a vulnerability in StackGuard itself.
Use GitHub's private vulnerability reporting on the repository instead.
