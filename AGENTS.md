# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
before changing this project.

## Scope and current state

This repository covers only **CVE-2026-17106** (Docker copy destination escape). Its aliases
refer to the same exploit. Keep unrelated vulnerabilities in separate repositories.
The repository is an initialized research foundation. No checker, tests, or CI
workflow exists yet; never imply otherwise or document nonexistent commands.

## Project map

- `advisory.json`: source-preserving research record; detection is disabled.
- `README.md`: exact scope, advisory snapshot, primary sources, and current status.
- `docs/IMPLEMENTATION.md`: local implementation and verification checklist.
- `LICENSING.md`, `CONTRIBUTING.md`, `BRAND_ASSETS.md`: licensing and contribution terms.

## Implementation constraints

Follow the established [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) conventions. Prefer a small, auditable,
dependency-free checker when appropriate. Do not turn this project into a generic
product scanner or execute exploit payloads.

Version claims are evidence, not verified runtime state. Keep missing, conflicting,
malformed, prerelease, vendor/custom-build, backport, and uncovered-future cases
uncertain. Never equate `potentially_affected` with confirmed exploitability or
`fixed_version_reported` with a safety guarantee. Exploitability remains
`not_tested`. Configuration hints and source patterns are not proven reachability.

Keep offline modes offline. Any future collector must avoid application imports,
secrets, environment variables, hostnames, process arguments, and application data.
If passive fetching is justified, preserve verified TLS, relevant robots policy,
an honest User-Agent, pacing, bounds, conservative redirects, and no inherited
environment proxy. Editing this repository does not authorize scanning real targets.

Update sources and verification dates only after primary-source review. Preserve
all advisory caveats and document unresolved conflicts. Treat research metadata as
disabled until a real implementation is reviewed and tested.

## Validation and delivery

Use focused synthetic cases and local-only fixtures for meaningful behavior tests
once code exists. Do not invent passing tests, add prose-only tests, or publish
private assessments. Keep CLI, schemas, methodology, and README aligned. Distinguish
local results from hosted CI on the exact published commit. Preserve unrelated
work and follow the licensing and brand policies linked above.
