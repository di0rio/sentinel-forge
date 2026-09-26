# Contributing

Thanks for helping. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Setup

Requirements: Go (version in [`go.mod`](go.mod)) and [golangci-lint](https://golangci-lint.run/) v2.

```bash
git clone https://github.com/di0rio/sentinel-forge.git
cd sentinel-forge
go test ./...
go run ./cmd/sentinelforge replay fixtures/authentication/brute-force.json
```

## Before opening a pull request

These are the same checks CI runs; a PR is merged only when all pass.

```bash
go vet ./...
go test -race ./...
golangci-lint run
go run ./cmd/sentinelforge rules validate
```

## Adding a detection rule

A rule is not done until it is tested.

1. Add the rule to `rules/<category>/<ID>.yml`. IDs follow `CATEGORY-NNN` (e.g. `AUTH-002`) and are never reused.
2. Add a fixture under `fixtures/<category>/` with **artificial** events that trigger it. Never commit real user data, real IPs from production, or credentials.
3. Add tests covering at least: the threshold being reached, one event below the threshold, and events outside the window.
4. Map the rule to MITRE ATT&CK (`attack.tactic`, `attack.technique`) when applicable, and list sources in `references`.
5. If the rule is derived from external work (e.g. Sigma), note the origin and make sure its license allows redistribution.

When changing an existing rule, bump `version`. Old alerts must remain explainable by the version that produced them.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(engine): add sequence detection
fix(rule): reject negative threshold count
docs: explain rule versioning
```

## Pull requests must not include

- secrets, tokens, private keys or credentials, even fake-looking ones;
- real personal or customer data;
- new dependencies without a stated reason and a license compatible with Apache-2.0;
- code that executes content from rules or events (`exec`, templates, plugins loaded from rule files).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
