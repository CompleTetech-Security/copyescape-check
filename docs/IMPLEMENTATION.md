# Implementation checklist

**copyescape-check · CVE-2026-17106 · implementation pending**

This is the local work plan for one exploit. Unchecked items are outstanding;
repository initialization does not satisfy the implementation or release gates.
Use [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) as format and quality references, while adapting evidence
collection to the specific product and advisory.

## 1. Confirm this exploit's contract

- [ ] Re-read the primary sources listed in [README.md](../README.md#primary-sources).
- [ ] Confirm `CVE-2026-17106` and its aliases refer to the same vulnerability.
- [ ] Preserve the exact affected ranges, supported branches, and fixed-build exceptions.
- [ ] Resolve source discrepancies explicitly or keep the disputed cases `unknown`.
- [ ] Record the source URL, retrieval/review date, evidence type, and relevant product for each rule.
- [ ] Treat platform conditions and configuration mitigations separately from patch state.

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

### Outstanding caveats

- Docker official Engine release notes place the fix in 29.7.0, whereas some community reports claim 29.7.2. Prefer 29.7.0 official release source; 29.7.2 repaired compatibility regressions.
- Publisher go-archive GHSA affected range is <0.2.2 while GitHub Reviewed entry says <0.3.0; both name patched 0.3.0. Treat the gap as unknown rather than asserting safety.
- Sandboxes 0.38.0 appears in community claims but was not independently verified against a primary release source; omit executable Sandboxes version rule until verified.

## 2. Implement the minimum useful evidence collector

- [ ] Define a small input schema for version/build provenance and this exploit's preconditions.
- [ ] Prefer a standalone Python 3.10+ standard-library implementation when it fits the product.
- [ ] Make offline modes perform no network requests and execute no application code.
- [ ] Use explicit operator-provided facts or narrowly scoped local metadata collection.
- [ ] Do not import the application, decode attacker-controlled input, execute uploaded code, or exercise the vulnerable path.
- [ ] Avoid collecting credentials, environment variables, hostnames, process arguments, or application data.
- [ ] Bound file size, file count, recursion, and parsing work for supplied evidence; keep symlink/archive handling explicit.
- [ ] If source patterns are examined, label them as review hints, not proof of reachability or taint.

## 3. Preserve uncertainty in the assessment

- [ ] Keep `version_status`, precondition observations, and `exploitability` separate.
- [ ] Emit `exploitability: not_tested` for every future finding.
- [ ] Use `potentially_affected` only when evidence matches this advisory's documented range or condition.
- [ ] Use `fixed_version_reported` only for a supported comparison, without claiming verified deployed patches.
- [ ] Keep missing, malformed, conflicting, prerelease, vendor/custom-build, possible-backport, and uncovered-future cases `unknown`.
- [ ] Document unsupported-version handling only where the vendor's lifecycle evidence supports it.
- [ ] Never convert absent source matches, hidden versions, authentication walls, or blocked requests into a clean result.
- [ ] Recommend a supported remediation based on the applicable vendor branch; avoid a universal threshold across incompatible branches.

## 4. Add usable reports and documented operation

- [ ] Define JSON and CSV fields, schema version, evidence confidence, rule date, sources, and remediation.
- [ ] Add a self-contained, script-free HTML report with escaped values and synthetic examples when useful.
- [ ] Protect CSV consumers from formula injection and keep private paths/data out of shared examples.
- [ ] Provide actual CLI help, input examples, exit-status semantics, and output-overwrite behavior.
- [ ] Preserve completed results during interruption; distinguish findings from operational errors.
- [ ] Add report branding controls only when the reporting implementation exists.

## 5. Gate any optional network mode

- [ ] Establish whether passive metadata can answer this exploit's question; omit network mode if it cannot.
- [ ] Require explicit target selection and ordinary, bounded requests with verified TLS.
- [ ] Follow robots policy where applicable; use a descriptive User-Agent, pacing, bounded bodies, and conservative redirects.
- [ ] Do not inherit environment proxies, downgrade HTTPS, bypass authentication, retry around restrictions, or request sensitive paths.
- [ ] Keep real assessment targets and data out of automated tests and repository history.

## 6. Verify behavior and release honestly

- [ ] Add focused synthetic tests for each relevant affected/fixed boundary and disputed case.
- [ ] Cover malformed inputs, absent evidence, custom builds, and collector/output safety where implemented.
- [ ] Use local mocks or loopback fixtures; do not scan public targets in tests.
- [ ] Avoid tests that merely assert documentation wording or mirror implementation details.
- [ ] Run documented commands against the actual executable; add CI only after meaningful tests exist.
- [ ] Distinguish local validation from hosted CI status for the published commit.
- [ ] Review the diff for secrets, real inventories, unlicensed assets, and scope expansion.
- [ ] Update README implementation status only after a usable checker and its documented behavior are verified.
- [ ] Enable a detection rule only in a reviewed implementation change; keep this research record's origin and history.

## Current acceptance result

**Foundation only.** No checker implementation, scanning, exploit verification,
or production readiness is claimed. The advisory metadata is deliberately disabled.
