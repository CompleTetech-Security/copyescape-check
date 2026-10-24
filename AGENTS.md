# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
before changing this project.

## Scope and current state

This repository covers only **CVE-2026-17106** (Docker copy destination escape). Its aliases
refer to the same exploit. Keep unrelated vulnerabilities in separate repositories.
The checker is implemented: `copyescape_check.py` is an offline, standard-library-only
version triage tool covering Docker Engine/CLI, Docker Desktop, and `moby/go-archive`.
It has no network mode (version-only advisory). Docker Sandboxes has no verified
primary source and must stay unsupported until one is found. Document only commands
that exist (see `docs/REFERENCE.md`).

## Project map

- `copyescape_check.py`: the checker (`assess_copyescape`, inventory/CSV loaders, reports, CLI).
- `test_copyescape.py`: boundary, input, and output-safety tests (`python -m unittest -v`).
- `.github/workflows/tests.yml`: CI on Ubuntu and Windows, Python 3.10 and 3.14.
- `advisory.json`: source-preserving record plus implementation status and review date.
- `README.md`: scope, usage, result vocabulary, fixes, limits, and primary sources.
- `docs/REFERENCE.md`: inputs, fields, outputs, exit codes. `docs/example-*`: synthetic example.
- `docs/IMPLEMENTATION.md`: implementation and verification checklist.
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

Update sources, `RULES_DATE`, and verification dates only after primary-source review.
Preserve all advisory caveats and document unresolved conflicts. The go-archive range
`>=0.2.2 <0.3.0` stays `unknown` until the sources agree.

## Validation and delivery

Use focused synthetic cases and local-only fixtures for meaningful behavior tests.
Run `python -m unittest -v` and `python copyescape_check.py --help`. Do not invent passing tests, add prose-only tests, or publish
private assessments. Keep CLI, schemas, methodology, and README aligned. Distinguish
local results from hosted CI on the exact published commit. Preserve unrelated
work and follow the licensing and brand policies linked above.

Report publication regressions live in `test_review_regressions.py`. Preserve the staged-inode interruption reconciliation, keep the success-flag assignment inside its guarded try, never append a second stdout report, and retain explicit zero-result CSV summary metadata.
