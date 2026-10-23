# copyescape-check

**Docker copy destination escape**  
By [CompleteTech LLC](https://complete.tech)

> **Repository initialized; checker implementation pending.**
> This project currently contains research and an implementation checklist.
> It does not assess systems or provide an executable detection rule.

## One exploit, one repository

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-17106` |
| Aliases for this same exploit | `GHSA-hfg8-hc9c-6c3h` |
| Research verification date | 2026-10-23 |
| Implementation state | `planned` |
| Detection rule | **Disabled — research only** |

This repository is dedicated to **CVE-2026-17106**. Aliases and multiple affected
products identify this same exploit; they do not create additional scanner scopes.
Future fixes for different vulnerabilities belong in independent repositories.

## Advisory snapshot

The following is source-backed research for implementation planning. It is not a
test result, a live rule feed, or an attestation that a deployed system is patched.

### Affected versions or conditions

```json
{
  "docker_engine_cli": {
    "fixed_version": "29.7.0",
    "source": "https://docs.docker.com/engine/release-notes/29/#2970"
  },
  "docker_desktop": {
    "fixed_version": "4.86.0",
    "source": "https://docs.docker.com/security/security-announcements/"
  },
  "go_archive": {
    "publisher_affected_range": "<0.2.2",
    "github_reviewed_affected_range": "<0.3.0",
    "fixed_version": "0.3.0",
    "uncertain_range": ">=0.2.2 <0.3.0",
    "sources": [
      "https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h",
      "https://github.com/advisories/GHSA-hfg8-hc9c-6c3h"
    ]
  }
}
```

### Reported fixes or remediation

```json
{
  "docker_engine_cli": {
    "fixed_version": "29.7.0",
    "source": "https://docs.docker.com/engine/release-notes/29/#2970"
  },
  "docker_desktop": {
    "fixed_version": "4.86.0",
    "source": "https://docs.docker.com/security/security-announcements/"
  },
  "go_archive": {
    "publisher_affected_range": "<0.2.2",
    "github_reviewed_affected_range": "<0.3.0",
    "fixed_version": "0.3.0",
    "uncertain_range": ">=0.2.2 <0.3.0",
    "sources": [
      "https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h",
      "https://github.com/advisories/GHSA-hfg8-hc9c-6c3h"
    ]
  }
}
```

### Deployment preconditions to establish

- untrusted container or archive
- docker cp copyout or go archive extract
- host filesystem write privileges

### Evidence notes and limitations

- Docker official Engine release notes place the fix in 29.7.0, whereas some community reports claim 29.7.2. Prefer 29.7.0 official release source; 29.7.2 repaired compatibility regressions.
- Publisher go-archive GHSA affected range is <0.2.2 while GitHub Reviewed entry says <0.3.0; both name patched 0.3.0. Treat the gap as unknown rather than asserting safety.
- Sandboxes 0.38.0 appears in community claims but was not independently verified against a primary release source; omit executable Sandboxes version rule until verified.

## Planned checker behavior

The intended checker follows the evidence and reporting conventions of
[node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check):

- Prefer offline version, inventory, or configuration evidence appropriate to this exploit.
- Keep version state, documented preconditions, evidence provenance, and uncertainty separate.
- Preserve `exploitability: not_tested`; never run exploit payloads or confirm compromise.
- Keep missing, malformed, conflicting, vendor-qualified, prerelease, and uncovered versions `unknown`.
- Produce human-readable findings and machine-readable JSON/CSV; document each output before release.
- Add bounded, explicitly selected passive network behavior only if it provides useful evidence.

These capabilities are **planned**, not implemented. There are currently no
checker commands, downloadable binaries, test results, or CI claims.

## Start here

1. Review [advisory.json](advisory.json) and the primary sources below.
2. Work through the exploit-specific [implementation checklist](docs/IMPLEMENTATION.md).
3. Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
   [SECURITY.md](SECURITY.md) before contributing.

## Primary sources

1. [docs.docker.com](https://docs.docker.com/engine/release-notes/29/#2970)
2. [docs.docker.com](https://docs.docker.com/security/security-announcements/)
3. [github.com](https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h)
4. [github.com](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h)

The research date records the supplied verification snapshot. Recheck primary
advisories before enabling any detection logic, and retain contradictory evidence.

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

Copyright © 2026 CompleteTech LLC.
