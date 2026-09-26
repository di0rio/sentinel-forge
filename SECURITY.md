# Security Policy

SentinelForge is a security tool, so vulnerabilities in it can weaken the defenses of whoever runs it. Please report them privately.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/di0rio/sentinel-forge/security/advisories/new)

Include:

- affected component and version or commit;
- steps to reproduce, ideally with a minimal rule file or event fixture;
- impact you observed or expect;
- any suggested fix.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment | 7 business days |
| Fix or mitigation plan | 30 days for high/critical issues |

This is a volunteer-maintained project, so these are goals, not guarantees.

## Disclosure

We follow coordinated disclosure. Once a fix is released, we publish a GitHub Security Advisory crediting the reporter (unless you prefer to stay anonymous). If no fix is available within 90 days of the report, we will agree on a disclosure date with you.

## Supported versions

SentinelForge is pre-1.0. Only the latest commit on `main` receives security fixes.

## Scope

Examples of issues we want to hear about:

- a rule file that causes code execution, file access outside its purpose, or unbounded resource use in the rule loader;
- an event payload that crashes, hangs or corrupts the detection engine;
- a crafted input that makes a detection silently fail to trigger;
- secrets or sensitive data written to logs or output.

Out of scope: vulnerabilities in third-party dependencies with no demonstrated impact on SentinelForge (report those upstream), and findings that require an already-compromised host.
