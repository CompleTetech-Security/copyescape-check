# copyescape-check: full reference

`copyescape_check.py` is a standard-library-only Python 3.10+ checker for
version-based CVE-2026-17106 triage (alias `GHSA-hfg8-hc9c-6c3h`). It works on
Windows, macOS, and Linux. It is **offline**: it makes no network requests, does
not run Docker or any application code, and never exercises the vulnerable path.
Version-only advisories have no network mode, because passive metadata cannot
answer whether a component is patched.

## Components and rules

Rules reviewed 2026-10-24 (`rules_as_of`). Only plain stable `x.y.z` versions
(optional leading `v`) are compared.

| Component id | Aliases | Fixed | Line assessed | Below fix | At/above fix | Source |
| --- | --- | --- | --- | --- | --- | --- |
| `docker-engine` | `engine`, `docker-cli`, `docker-engine-cli` | 29.7.0 | 29.x | `potentially_affected` | `fixed_version_reported` | [Engine v29 release notes](https://docs.docker.com/engine/release-notes/29/#2970) |
| `docker-desktop` | `desktop` | 4.86.0 | 4.x | `potentially_affected` | `fixed_version_reported` | [Security announcements](https://docs.docker.com/security/security-announcements/) |
| `go-archive` | `moby-go-archive` | 0.3.0 | 0.x | `<0.2.2` `potentially_affected` | `>=0.3.0` `fixed_version_reported` | [Publisher advisory](https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h), [reviewed entry](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h) |

Evidence type: Engine, vendor release notes; Desktop, vendor security
announcement; go-archive, publisher advisory and GitHub-reviewed advisory.

Documented decisions:

- **Other major lines are `unknown`** (`uncovered_release_line`): Engine other than 29.x, Desktop other than 4.x, go-archive 1.x and later. The sources do not cover them. The sources also do not state the earliest affected version, so a version below the fix on the covered line is only *potentially* affected.
- **Engine 29.7.0 versus 29.7.2.** The official notes place the fix in 29.7.0. The 29.7.1 and 29.7.2 notes list regression fixes for 29.7.0 and are not the security fix. The threshold is 29.7.0.
- **go-archive `>=0.2.2 <0.3.0`** is `unknown` with version status `disputed_affected_range`: the publisher advisory says affected `<0.2.2`, the GitHub-reviewed entry says `<0.3.0`. It is not asserted safe.
- **Docker Sandboxes** has no rule. A "0.38.0" claim has no primary source; `--version docker-sandboxes=...` and inventory components naming Sandboxes are rejected as errors.
- A fixed Docker Engine does not update other software that embeds `go-archive`; assess that module separately.
- `unsupported_runtime` is not emitted: the reviewed vendor sources give no lifecycle evidence for these components.

## Inputs

All input modes can be combined; each entry becomes a separate result. Inputs are
limited to 1 MiB per file, 10,000 entries per run, and 512 characters per field.

### Command-line versions

```sh
python copyescape_check.py --version docker-engine=29.6.2 --version docker-desktop=4.86.0
python copyescape_check.py --version go-archive=0.3.0 --build-source vendor
```

`--version COMPONENT=VERSION` is repeatable. `--build-source` applies to every
`--version` value. Note that `--version` supplies a component version; use
`--tool-version` for the checker's own version.

### JSON inventory

`--inventory FILE` (repeatable) accepts one object or an array. A runnable synthetic example is
[example-inventory.json](example-inventory.json).

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | Integer | Required; must be `1`. |
| `component` | String | Required: a component id or alias above. |
| `version` | String | Required reported version. |
| `label` | String | Optional human-readable name. |
| `build_source` | String | Provenance claim; default `unknown`. |
| `platform`, `architecture` | String | Optional context. |
| `untrusted_archive_or_container` | Boolean or null | Operator observation of the first documented precondition. |
| `copy_or_extract_path_used` | Boolean or null | `docker cp` copy-out or `go-archive` extraction in use. |
| `host_write_privileges` | Boolean or null | The extracting process can write to the host filesystem. |

Strings (including CLI `--version` values and `--build-source`) are limited to 512 characters; component and version text must be ASCII, and look-alike Unicode is `unknown` or rejected. Unknown fields, duplicate JSON keys, non-finite numbers, wrong types, unsupported
schema versions, oversized files, and unsupported components are operational errors.

### CSV list

`--csv FILE` (repeatable) reads UTF-8 CSV with a header containing at least `component` and `version`,
and optionally the other inventory columns except `schema_version`. Precondition
columns accept exactly `true` or `false` (case-insensitive), or empty, `unknown`, or `null` for not observed. Other spellings such as `yes` or `1` are errors. Duplicate columns, unknown
columns, ragged rows, and invalid values are operational errors.

### Build provenance

`unknown`, `upstream`, `official`, and `official_upstream` (case-insensitive, or empty)
allow the ordinary comparison; they are operator claims, not verified provenance.
Any other value (vendor, distribution, custom) yields `unknown` with version
status `vendor_build_unverified`, because backports cannot be detected from a version.

## Results

| Field | Meaning |
| --- | --- |
| `copyescape_status` | `potentially_affected`, `fixed_version_reported`, or `unknown`. |
| `copyescape_version_status` | Why: `below_reported_fix`, `meets_reported_fix`, `disputed_affected_range`, `uncovered_release_line`, `version_not_disclosed`, `conflicting_versions`, `qualified_version_unverified`, `unrecognized_or_partial_version`, `vendor_build_unverified`. |
| `untrusted_archive_or_container`, `copy_or_extract_path_used`, `host_write_privileges` | `reported`, `not_reported`, or `unknown`. Observations only. |
| `precondition_summary` | `all_preconditions_reported`, `some_preconditions_not_reported`, or `preconditions_incomplete`. Never changes the status. |
| `copyescape_exploitability` | Always `not_tested`. |
| `schema_version` | Report schema version (`1.0`), present on every JSON and CSV row. |
| `copyescape_fixed_version`, `copyescape_sources`, `copyescape_evidence_type`, `copyescape_rules_as_of`, `copyescape_cve`, `copyescape_aliases` | Rule provenance. |
| `copyescape_evidence_confidence` | `primary_source` (Engine, Desktop) or `primary_source_range_conflict` (go-archive, where the two advisories disagree). |
| `copyescape_notes`, `copyescape_recommendation` | Limitations and next step. |
| `status` | Always `offline` (no network). |

Missing, empty, malformed, prerelease, `+`/`-`/`~`-qualified, Go pseudo-versions,
conflicting, vendor/custom, disputed, and uncovered versions are all `unknown`.

## Output formats

Select with `--format csv|json|html` (default `csv`) and `--output FILE` (default stdout).

- **CSV**: one flat row per result with `\n` line endings; fields containing line breaks are quoted; lists are joined with ` | `. Rows carry `schema_version` and the rule date, sources, evidence type and confidence, but there is no run-completeness envelope. Values that could be read as spreadsheet formulas (leading `=`, `+`, `-`, `@`, tab or carriage return, including after whitespace) are prefixed with an apostrophe.
- **JSON**: an object with `tool`, `tool_version`, `schema_version` (`1.0`), `cve`, `aliases`, `rules_as_of`, `sources`, `generated_at`, `complete`, and `results`.
- **HTML**: a single self-contained, script-free page (restrictive Content-Security-Policy, no remote assets) with escaped values, summary counts, per-row evidence and limits, and the fix table. `--brand` sets the organization name. See [example-report.html](example-report.html), generated from synthetic data.

An existing output file is refused unless `--force` is given. Output is written
to a temporary file and published atomically (a hard link without `--force`, so
a concurrently created file is never replaced; replacement with `--force`).
The output directory must exist. Input files cannot be the output path, even with `--force`.

## CLI options

| Argument | Description |
| --- | --- |
| `--version COMPONENT=VERSION` | Offline version assessment; repeatable. |
| `--build-source VALUE` | Provenance for `--version` values (default `unknown`). |
| `--inventory FILE` | JSON inventory; repeatable. |
| `--csv FILE` | CSV list; repeatable. |
| `--format csv\|json\|html` | Output format. |
| `--output FILE`, `--force` | Destination and explicit replacement. |
| `--brand NAME` | HTML organization name. |
| `--fail-on-finding` | Exit 1 when a result is `potentially_affected`. |
| `--tool-version` | Print the checker version. |
| `--help` | Usage, including exit codes. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Completed. No finding was requested, or none exists. |
| 1 | `--fail-on-finding` was given and at least one result is `potentially_affected`. |
| 130 | Interrupted (Ctrl+C) while loading inputs. Completed results are still written; JSON has `complete: false` and HTML shows an interrupted-run notice (CSV has no marker, so rely on the exit status). |
| 2 | Operational error: bad usage or arguments, unreadable or invalid input, unsupported component, refused or unwritable output. Operational errors take precedence over findings. The output path is validated before any input is read. |

Unknown results do not change the exit code; review them. Keep real inventories
and reports outside version control.
