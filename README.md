# SentinelForge

[![CI](https://github.com/di0rio/sentinel-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/di0rio/sentinel-forge/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Open-source **Detection-as-Code** engine that turns security events into explainable, testable and reproducible detections.

> **Status:** early development (pre-1.0). The detection core works end to end; APIs and rule format may still change.

## Why

Most detection logic lives in dashboards and ad-hoc queries: hard to review, hard to test, and impossible to reproduce months later. SentinelForge treats detections like code:

- **Rules are versioned YAML**, reviewed in pull requests and validated before they run.
- **Every rule is tested** against artificial fixtures, so a change can't silently break a detection.
- **Every detection explains itself**: which rule and version, which events, which threshold, when.
- **Deterministic**: windows use event time, so replaying the same events always yields the same result.

## Demo

```text
$ sentinelforge replay fixtures/authentication/brute-force.json

SentinelForge Detection Engine

✓ 24 events processed
✓ 2 rules evaluated

────────────────────────────────────────

🚨 Detection triggered

AUTH-001 v1
Brute Force Authentication

Severity:      HIGH
Group:         network.sourceIp=10.0.0.15
Matched:       17 events
Window:        43s (14:32:11 → 14:32:54)
Threshold:     10 events / 60s
MITRE ATT&CK:  T1110 (credential-access)

Reason:
17 events matched type=authentication_failure, reaching the threshold of 10 within 60s.
```

The same rule fires on a raw sshd `auth.log` (classic syslog timestamps carry no year, hence `--year`):

```text
$ sentinelforge replay --format sshd --year 2026 fixtures/authentication/auth.log

SentinelForge Detection Engine

✓ 25 events processed
· 10 lines skipped (not security events)
✓ 2 rules evaluated

────────────────────────────────────────

🚨 Detection triggered

AUTH-001 v1
Brute Force Authentication

Severity:      HIGH
Group:         network.sourceIp=203.0.113.45
Matched:       14 events
Window:        42s (14:32:12 → 14:32:54)
Threshold:     10 events / 60s
MITRE ATT&CK:  T1110 (credential-access)

Reason:
14 events matched type=authentication_failure, reaching the threshold of 10 within 60s.
```

## Quick start

Requires Go (see [`go.mod`](go.mod) for the version).

```bash
go install github.com/di0rio/sentinel-forge/cmd/sentinelforge@latest

git clone https://github.com/di0rio/sentinel-forge.git
cd sentinel-forge
sentinelforge rules validate
sentinelforge replay fixtures/authentication/brute-force.json
sentinelforge replay --format sshd --year 2026 fixtures/authentication/auth.log
sentinelforge replay --format nginx fixtures/web/scan.log
```

## Replaying logs

`replay` reads a JSON array of events by default. `--format` selects a log parser instead:

| `--format` | Input | Event type |
| --- | --- | --- |
| `json` (default) | JSON array of events | as given |
| `sshd` | OpenSSH `auth.log`, classic or ISO 8601 timestamps | `authentication_failure`, `authentication_success`, `invalid_user` (logged before the failure of the same attempt, so it's a separate type) |
| `nginx` | nginx access log, default `combined` format | `http_request` (`metadata.status` is a string, e.g. `"404"`) |

`--year` sets the year of classic syslog timestamps (sshd only; default: the current year). Pass it for reproducible replays.

Logs are untrusted input: lines over 64 KiB are rejected, and lines that are not security events or fail validation are counted and skipped, never fatal. Event IDs come from the line number, so replaying a file twice gives identical results.

## Writing a rule

```yaml
id: AUTH-001
version: 1
name: Brute Force Authentication
severity: high

when:
  type: authentication_failure

threshold:
  count: 10
  window: 60s

group_by:
  - network.sourceIp

attack:
  tactic: credential-access
  technique: T1110
```

`when` conditions must all match; `group_by` keeps a separate counter per value (per source IP here). Rules can only reference a fixed set of event fields (`type`, `source`, `actor.username`, `network.sourceIp`, `target.host`, `metadata.*`), and unknown keys are rejected.

## How it works

```text
events (JSON) ─► validate ─► Detection Engine ─► detections
                                  ▲
rules (YAML) ─► strict parse + validate
```

- **Sliding windows on event time**, keyed by rule + tenant + `group_by` values.
- **Alert storm protection**: once a detection is open, further matching events extend it instead of creating new detections. A 1,000-attempt attack is one detection, not a hundred.

## Security model

Rule files are treated as untrusted input:

- the rule format is a restricted declarative DSL: no expressions, templates or code execution;
- parsing is strict (unknown fields fail), files are size-limited, and windows are capped at 24h;
- YAML aliases and multi-document files are rejected (alias expansion can turn a few hundred bytes into gigabytes), and symbolic links in the rules directory are not followed;
- events are validated individually; malformed events are reported and skipped;
- log lines are length-bounded, matched with anchored linear-time patterns, and source IPs are validated;
- replay reads at most 64 MiB of input (split larger logs) and tracks at most 100,000 groups at once; beyond that it stops with an error instead of exhausting memory;
- event and rule fields are untrusted text: control and invisible characters (such as ANSI escape sequences in an sshd username) are printed as `<U+XXXX>`, never raw.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Development

```bash
go test -race ./...
golangci-lint run
```

CI runs tests, lint, [govulncheck](https://go.dev/doc/security/vuln/) and [gitleaks](https://github.com/gitleaks/gitleaks) on every push and pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- [x] Threshold detection engine, YAML rules, replay CLI
- [x] Parsers for real log sources (sshd `auth.log`, nginx)
- [ ] Sequence and correlation rules
- [ ] Alerts: deduplication, suppression, cooldown, persistence
- [ ] Incidents and timeline
- [ ] HTTP API and web UI
- [ ] Sigma rule import

## License

[Apache License 2.0](LICENSE)
