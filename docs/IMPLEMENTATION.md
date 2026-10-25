# Implementation checklist

**copyescape-check · CVE-2026-17106 · implemented (offline version triage)**

This is the work plan and acceptance record for one exploit. Checked items are
implemented and covered by `test_copyescape.py` or the documented review; unchecked
items are outstanding or intentionally not applicable, with the reason given.
Use [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) as format and quality references, while adapting evidence
collection to the specific product and advisory.

## 1. Confirm this exploit's contract

- [x] Re-read the primary sources listed in [README.md](../README.md#primary-sources).
- [x] Confirm `CVE-2026-17106` and its aliases refer to the same vulnerability.
- [x] Preserve the exact affected ranges, supported branches, and fixed-build exceptions.
- [x] Resolve source discrepancies explicitly or keep the disputed cases `unknown`.
- [x] Record the source URL, retrieval/review date, evidence type, and relevant product for each rule.
- [x] Treat platform conditions and configuration mitigations separately from patch state.

### Affected evidence to encode

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

### Fix evidence to encode

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

### Preconditions to collect without exploitation

- untrusted container or archive
- docker cp copyout or go archive extract
- host filesystem write privileges

### Caveats and how they are handled

- Docker official Engine release notes place the fix in 29.7.0, whereas some community reports claim 29.7.2. Prefer 29.7.0 official release source; 29.7.2 repaired compatibility regressions.
- Publisher go-archive GHSA affected range is <0.2.2 while GitHub Reviewed entry says <0.3.0; both name patched 0.3.0. Treat the gap as unknown rather than asserting safety.
- Sandboxes 0.38.0 appears in community claims but was not independently verified against a primary release source; omit executable Sandboxes version rule until verified.

## 2. Implement the minimum useful evidence collector

- [x] Define a small input schema for version/build provenance and this exploit's preconditions.
- [x] Prefer a standalone Python 3.10+ standard-library implementation when it fits the product.
- [x] Make offline modes perform no network requests and execute no application code.
- [x] Use explicit operator-provided facts or narrowly scoped local metadata collection.
- [x] Do not import the application, decode attacker-controlled input, execute uploaded code, or exercise the vulnerable path.
- [x] Avoid collecting credentials, environment variables, hostnames, process arguments, or application data.
- [x] Bound file size, file count, and parsing work for supplied evidence (1 MiB, 10,000 entries, 512-character fields). No archives or directories are read, so symlink/archive handling is not applicable.
- [x] Not applicable: no source patterns are examined; precondition fields are operator observations only.

## 3. Preserve uncertainty in the assessment

- [x] Keep `version_status`, precondition observations, and `exploitability` separate.
- [x] Emit `exploitability: not_tested` for every future finding.
- [x] Use `potentially_affected` only when evidence matches this advisory's documented range or condition.
- [x] Use `fixed_version_reported` only for a supported comparison, without claiming verified deployed patches.
- [x] Keep missing, malformed, conflicting, prerelease, vendor/custom-build, possible-backport, and uncovered-future cases `unknown`.
- [x] Document unsupported-version handling only where the vendor's lifecycle evidence supports it.
- [x] Never convert absent source matches, hidden versions, authentication walls, or blocked requests into a clean result.
- [x] Recommend a supported remediation based on the applicable vendor branch; avoid a universal threshold across incompatible branches.

## 4. Add usable reports and documented operation

- [x] Define JSON and CSV fields, schema version, evidence confidence, rule date, sources, and remediation.
- [x] Add a self-contained, script-free HTML report with escaped values and synthetic examples when useful.
- [x] Protect CSV consumers from formula injection and keep private paths/data out of shared examples.
- [x] Provide actual CLI help, input examples, exit-status semantics, and output-overwrite behavior.
- [x] Distinguish findings (exit 1 with `--fail-on-finding`) from operational errors (exit 2).
- [x] Preserve completed observations and distinguish interruption from operational errors. `test_review_regressions.py` covers interrupted stdout, pre-publication recovery, post-publication syscall/flag-line interruption, staged-inode identity, CSV failures and zero-result summary metadata; see the reference for exact semantics.
- [x] Add report branding controls (`--brand`); no logo option is provided.

## 5. Gate any optional network mode

- [x] Establish whether passive metadata can answer this exploit's question; omit network mode if it cannot. Decision: it cannot (patch state is not visible remotely), so there is no network mode.
- [x] Not applicable (no network mode): Require explicit target selection and ordinary, bounded requests with verified TLS.
- [x] Not applicable (no network mode): Follow robots policy where applicable; use a descriptive User-Agent, pacing, bounded bodies, and conservative redirects.
- [x] Not applicable (no network mode): Do not inherit environment proxies, downgrade HTTPS, bypass authentication, retry around restrictions, or request sensitive paths.
- [x] Keep real assessment targets and data out of automated tests and repository history.

## 6. Verify behavior and release honestly

- [x] Add focused synthetic tests for each relevant affected/fixed boundary and disputed case.
- [x] Cover malformed inputs, absent evidence, custom builds, and collector/output safety where implemented.
- [x] Use local mocks or loopback fixtures; do not scan public targets in tests.
- [x] Avoid tests that merely assert documentation wording or mirror implementation details.
- [x] Run documented commands against the actual executable; add CI only after meaningful tests exist.
- [ ] Distinguish local validation from hosted CI status for the published commit (recorded in the pull request, not here).
- [x] Review the diff for secrets, real inventories, unlicensed assets, and scope expansion.
- [x] Update README implementation status only after a usable checker and its documented behavior are verified.
- [ ] Enable a detection rule only in a reviewed implementation change (`advisory.json` is updated in this change; awaiting maintainer review).

## Current acceptance result

**Implemented: offline version triage.** `copyescape_check.py` compares reported
versions of Docker Engine/CLI, Docker Desktop, and `moby/go-archive` with the
primary-source fixes reviewed on 2026-10-24. No scanning, exploit verification,
network access, or exploitability testing is performed. Docker Sandboxes is
unsupported until a primary source exists, and the go-archive range `>=0.2.2 <0.3.0`
remains `unknown`. Hosted CI results are tracked on the pull request.

## Workflow extension (2026-10-25)

Explicit bounded shell/CI YAML inputs now produce separate unknown docker cp candidates with relative locations and direction. Client/server component identities are preserved. Synthetic tests cover both spellings, comments, wrappers, variables, directions, continuation/sequence syntax, independent component versions, privacy, output protection/parity and standalone execution. Original publication regression coverage is retained. Local and exact-head hosted checks remain separate; no Docker or exploit command was executed.
