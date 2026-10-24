<p align="center">
  <img src="docs/images/banner.png" alt="copyescape-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-research%20only-B45309" alt="Status: research only">
  <img src="https://img.shields.io/badge/checker-planned-64748B" alt="Checker: planned">
  <img src="https://img.shields.io/badge/detection-disabled-B91C1C" alt="Detection: disabled">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

<p align="center">
  <b>Docker copy destination escape</b><br>
  CVE-2026-17106 · research foundation · checker planned
</p>

---

> **Repository initialized; checker implementation pending.**
> This project currently contains research and an implementation checklist.
> It does not assess systems or provide an executable detection rule.

`copyescape-check` is the dedicated repository for **CVE-2026-17106** (alias `GHSA-hfg8-hc9c-6c3h`). It is intended to become an evidence-based checker that compares reported Docker Engine/CLI, Docker Desktop, and `go-archive` versions with the published fixes and reports uncertainty honestly. Today it holds only source-backed research and a work plan, by [CompleteTech LLC](https://complete.tech).

## Status and what is planned

There are no checker commands, downloadable binaries, test results, or CI claims yet, so there is nothing to install or run. To follow or contribute to the work:

1. Review [advisory.json](advisory.json) and the [primary sources](#primary-sources).
2. Work through the exploit-specific [implementation checklist](docs/IMPLEMENTATION.md).
3. Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) before contributing.

## One exploit, one repository

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-17106` |
| Aliases for this same exploit | `GHSA-hfg8-hc9c-6c3h` |
| Research verification date | 2026-10-23 |
| Implementation state | `planned` |
| Detection rule | **Disabled — research only** |

Aliases and multiple affected products identify this same exploit; they do not create additional scanner scopes. Future fixes for different vulnerabilities belong in independent repositories.

## Planned report layout

A report is planned but **not implemented**. The image below is an illustrative layout only: it contains placeholder values on reserved `example.*` domains and shows no assessment results.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Illustrative placeholder layout of a planned report; no checker is implemented" width="900">
  </picture>
</p>

<p align="center"><sub>ILLUSTRATIVE ONLY. Not produced by a checker; every value is a placeholder.</sub></p>

## Planned result vocabulary

Following the conventions of [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check), the planned statuses are below. They are **planned, not implemented**.

| Planned status | Intended meaning |
| --- | --- |
| `potentially_affected` | Evidence matches this advisory's documented range or condition. Not confirmed exploitability. |
| `fixed_version_reported` | The reported version meets the reported fix. Not a verified clean bill of health. |
| `unknown` | Missing, malformed, conflicting, prerelease, vendor-qualified, possible-backport, or uncovered versions. |

Exploitability would remain `not_tested` for every finding.

## Reported fixes (research only)

These values come from [advisory.json](advisory.json) and the sources below. They are research data, not an enabled rule.

| Component | Reported fixed version |
| --- | --- |
| Docker Engine / CLI | 29.7.0 |
| Docker Desktop | 4.86.0 |
| `go-archive` | 0.3.0 |

For `go-archive`, the publisher advisory lists affected versions `<0.2.2` while the GitHub-reviewed entry lists `<0.3.0`; both name 0.3.0 as patched. The range `>=0.2.2 <0.3.0` is treated as **uncertain** rather than asserted safe.

Other evidence notes preserved from the research record:

- Docker's official Engine release notes place the fix in 29.7.0, whereas some community reports claim 29.7.2. The official 29.7.0 source is preferred; 29.7.2 repaired compatibility regressions.
- A Sandboxes 0.38.0 claim appears in community reports but was not independently verified against a primary release source, so no Sandboxes version rule is proposed.

Deployment preconditions to establish separately: an untrusted container or archive, `docker cp` copy-out or `go-archive` extraction, and host filesystem write privileges.

> [!IMPORTANT]
> **Nothing has been assessed.** No checker or detection rule exists, and the research record is deliberately disabled (`detection_enabled: false`). A reported fixed version would never be a guarantee, and a potentially affected result would never be confirmed exploitability. Version and deployment evidence require separate assessment.

## How it is planned to work

- Prefer offline version, inventory, or configuration evidence appropriate to this exploit.
- Keep version state, documented preconditions, evidence provenance, and uncertainty separate.
- Never run exploit payloads or confirm compromise.
- Keep missing, malformed, conflicting, vendor-qualified, prerelease, and uncovered versions `unknown`.
- Add bounded, explicitly selected passive network behavior only if it provides useful evidence.
- Produce human-readable findings and machine-readable JSON/CSV, documenting each output before release.

## Primary sources

1. [docs.docker.com](https://docs.docker.com/engine/release-notes/29/#2970)
2. [docs.docker.com](https://docs.docker.com/security/security-announcements/)
3. [github.com](https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h)
4. [github.com](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h)

The research date records the supplied verification snapshot. Recheck primary advisories before enabling any detection logic, and retain contradictory evidence.

## Documentation

- [Implementation checklist](docs/IMPLEMENTATION.md): the outstanding work plan
- [advisory.json](advisory.json): source-preserving research record
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Agent instructions](AGENTS.md)

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

<p align="center">
  <sub>Built by <a href="https://complete.tech">CompleteTech LLC</a> · Innovation at Every Integration</sub>
</p>

Copyright © 2026 CompleteTech LLC.
