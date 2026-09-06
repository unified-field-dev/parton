# Security Policy

## Supported versions

Security fixes are accepted against the latest `main` branch and tagged releases (`0.1.x`) of this repository.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Prefer one of the following:

1. **GitHub Security Advisories** — use [Report a vulnerability](https://github.com/unified-field-dev/parton/security/advisories/new) on this repository when available.
2. Contact the maintainers privately via the repository owner listed at https://github.com/unified-field-dev/parton.

Include:

- a description of the issue and its impact
- steps to reproduce or a proof of concept when possible
- affected crate names and versions

We will acknowledge receipt as soon as practical and coordinate a fix and disclosure timeline with you.

## Scope

In scope: vulnerabilities in this repository's crates, documentation that could cause unsafe production defaults, and CI/supply-chain issues in this repository.

Out of scope: vulnerabilities solely in third-party Docker, SPIRE, or cosign tooling unless Parton mishandles them in a security-relevant way.
