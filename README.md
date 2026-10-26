<p align="center">
  <img src="docs/images/banner.png" alt="copyescape-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/checker-offline%20version%20triage-1E3A8A" alt="Checker: offline version triage">
  <img src="https://img.shields.io/badge/python-3.10%2B-64748B" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-64748B" alt="No dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

# copyescape-check

<p align="center">
  <b>Docker copy destination escape</b><br>
  CVE-2026-17106 · offline version triage
</p>

`copyescape-check` is the dedicated repository for **CVE-2026-17106** (alias `GHSA-hfg8-hc9c-6c3h`), a flaw where a crafted archive can make `docker cp` copy-out (and other `moby/go-archive` extraction) write outside the intended destination.

It is a standalone, standard-library-only Python 3.10+ tool that compares **operator-reported** versions of Docker Engine/CLI, Docker Desktop and `moby/go-archive` with the published fixes, and reports uncertainty honestly. It makes no network requests, runs no Docker or application code, and never tests exploitability. By [CompleteTech LLC](https://complete.tech).

> [!IMPORTANT]
> A version comparison is evidence, not verified runtime state. A `potentially_affected` result is not confirmed exploitability, and `fixed_version_reported` is not a safety guarantee or a verified deployed patch. Vendor backports and custom builds are not detectable from a version string.

## Contents

- [Scope](#scope)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Example report](#example-report)
- [Interpreting results](#interpreting-results)
- [Reported fixes](#reported-fixes)
- [Inputs](#inputs)
- [Output and exit codes](#output-and-exit-codes)
- [Limits and safety](#limits-and-safety)
- [Primary sources](#primary-sources)
- [Documentation and contributing](#documentation-and-contributing)
- [License](#license)

## Scope

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-17106` |
| Aliases for this same exploit | `GHSA-hfg8-hc9c-6c3h` |
| Rules reviewed against primary sources | 2026-10-24 |
| Implementation state | Implemented (offline version triage) |

Aliases and multiple affected products identify this same exploit; they do not create additional scanner scopes. Fixes for different vulnerabilities belong in independent repositories.

## Requirements

- Python 3.10 or newer, on Windows, macOS or Linux. CI runs on Ubuntu, Windows and macOS with Python 3.10 and 3.14.
- No third-party dependencies and no installation step. On systems where Python is called `python3`, substitute it in the commands below.

## Quick start

```sh
python copyescape_check.py --version docker-engine=29.6.2 --version go-archive=0.2.5 --format json
python copyescape_check.py --inventory inventory.json --format html --output report.html
python copyescape_check.py --csv components.csv --fail-on-finding
```

In the first command, Engine 29.6.2 is below the reported fix (`potentially_affected`), and `go-archive` 0.2.5 falls in a range where the sources disagree (`unknown`, never safe).

Run `python copyescape_check.py --help` for usage and exit codes, and `python copyescape_check.py --tool-version` for the checker version. Run the tests with `python -m unittest -v`. Inputs, fields and output formats are documented in the [reference](docs/REFERENCE.md).

## Example report

The images show the HTML report rendered from the synthetic, reserved-name inputs in [docs/example-inventory.json](docs/example-inventory.json); the output is [docs/example-report.html](docs/example-report.html). They are an example of the checker's real output, not an assessment of any system.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Synthetic example of the HTML report produced by the checker" width="900">
  </picture>
</p>

<p align="center"><sub>Synthetic example generated from made-up inputs; not a real assessment.</sub></p>

## Interpreting results

`copyescape_status` (the version status) is separate from precondition observations and from exploitability.

| Status | Meaning |
| --- | --- |
| `potentially_affected` | The reported plain version is below the reported fix on the one release line the sources cover. Not confirmed exploitability. |
| `fixed_version_reported` | The reported plain version meets the reported fix. Not a guarantee that the deployed build is patched. |
| `unknown` | Missing, malformed, prerelease, qualified, vendor/custom-build, conflicting, disputed-range, or uncovered-line versions. Review these; they never change the exit code. |

- **Exploitability** is `not_tested` for every result.
- **Preconditions** (untrusted container or archive, `docker cp` copy-out or `go-archive` extraction, host filesystem write privileges) can be supplied as operator observations. They are reported alongside the version result and never change it.
- **`unsupported_runtime`** is not used: the vendor sources reviewed do not publish lifecycle evidence for these components in this context.
- Only strict ASCII, plain `x.y.z` versions (optional leading `v`) are compared; everything else stays `unknown`.

The full list of version-status reasons and report fields is in the [reference](docs/REFERENCE.md#results).

## Reported fixes

Reviewed 2026-10-24 against the [primary sources](#primary-sources) below. Rules are a dated offline snapshot (`rules_as_of` appears in every report); recheck the advisories before relying on an old copy of this tool.

| Component | Reported fixed version | Line assessed | Source |
| --- | --- | --- | --- |
| Docker Engine / CLI | 29.7.0 | 29.x | Docker Engine v29 release notes |
| Docker Desktop | 4.86.0 | 4.x | Docker security announcements |
| `moby/go-archive` | 0.3.0 | 0.x | Publisher and GitHub-reviewed advisories |

Boundary handling and limits:

- **Docker Engine / CLI**: the official release notes list the fix (`go-archive` v0.3.0) under 29.7.0 (2026-07-30). Some community reports claim 29.7.2; the official notes show 29.7.1 and 29.7.2 only repair regressions introduced in 29.7.0, so 29.7.0 is the threshold. The notes do not state the earliest affected Engine version, and no 28.x or older fix is listed, so other majors are `unknown`. Treat Engine 28.x and older as an unassessed, likely unpatched line to verify with Docker, not as "probably fine".
- **Docker Desktop**: the security announcement lists the destination-escape flaw in `docker container cp` as fixed in 4.86.0. The earliest affected Desktop version is not stated, so other majors are `unknown`.
- **`moby/go-archive`**: the publisher advisory lists affected `<0.2.2`; the GitHub-reviewed entry lists `<0.3.0`; both name 0.3.0 as patched. Versions `>=0.2.2 <0.3.0` are therefore `unknown`, never safe. (No `v0.2.2` tag was found in the repository, but the checker cannot rely on that.) A fixed Docker Engine does not update other software that embeds `go-archive`.
- **Docker Sandboxes**: a "0.38.0" claim appears in community reports, but no primary source supports it (Docker's announcements mention Sandboxes only for other CVEs). No Sandboxes rule is provided; the checker rejects it explicitly.

## Inputs

All input modes can be combined; each entry becomes a separate result, and at least one input is required. Everything is offline: operator-supplied versions, JSON inventory, CSV list, existing Docker version exports, or explicitly selected workflow files. Version-only advisories have **no network mode**, because passive metadata cannot answer the question.

| Option | Input |
| --- | --- |
| `--version COMPONENT=VERSION` | A single reported version; repeatable. `--build-source VALUE` sets the provenance claim for every `--version` value (default `unknown`). |
| `--inventory FILE` | JSON inventory (`schema_version` 1); one object or an array; repeatable. |
| `--csv FILE` | UTF-8 CSV with at least `component` and `version` columns; repeatable. |
| `--docker-version FILE` | An already-created Docker version JSON or text export; repeatable. |
| `--source FILE` with `--source-root DIR` | Explicit `.sh`, `.bash`, `.yml` or `.yaml` files inspected for `docker cp` candidates; repeatable. |

Component ids are `docker-engine` (aliases `engine`, `docker-engine-cli`), `docker-cli` (alias `docker-client`), `docker-desktop` (alias `desktop`) and `go-archive` (alias `moby-go-archive`). `--tool-version` prints the checker's own version, while `--version` supplies a component version. Field-by-field formats, build-provenance values and precondition columns are in the [reference](docs/REFERENCE.md#inputs).

### Docker version exports

`--docker-version FILE` reads an already-created Docker version JSON or default text export. It never runs Docker.

- JSON `Client.Version` and `Server.Version` (plus an explicit `Server.Components` Engine version) are independent evidence. Default text extracts the Client Version and the Server Engine Version, ignoring containerd/runc/docker-init version fields.
- A missing server version or conflicting versions stay `unknown`, with `version_candidates` retained. Client API versions are never runtime versions.
- Contexts, hostnames and unrelated metadata are not reported.
- Docker Desktop's application version must still be supplied independently; a Server title is not used as its version inventory.
- Each export row carries `source_instance`: a SHA-256 of a fixed public namespace plus the 1-based `--docker-version` input ordinal. It does not encode an absolute path, image, host or runtime identity. It identifies an input slot, so preserve argument order for longitudinal comparisons; reordering exports changes it.

This is offline export ingestion, not a local runtime collector or attestation. Syntax provenance: [official Docker version reference](https://docs.docker.com/reference/cli/docker/version/), reviewed 2026-10-25.

### Workflow candidates (schema 1.1)

```sh
python copyescape_check.py --source docs/example-workflow.yml --source-root docs --format json
python copyescape_check.py --version docker-client=29.6.2 --version docker-engine=29.7.0 --source docs/example-workflow.yml --source-root docs --format html
```

Repeat `--source` for explicitly selected `.sh`, `.bash`, `.yml` or `.yaml` files. `--source-root` is required and resolved sources must stay inside it. Nothing is traversed or executed, and the checker invokes no Docker, shell, container copy or application command.

**What is recognized.** Plain shell commands and plain/block YAML `run:` values are tokenized for direct `docker cp` and `docker container cp`. Shell continuations and simple command separators are recognized; comments and `echo` arguments are not commands. Non-run YAML block scalars and literal here-document bodies are skipped. Quoted multiline text and active backslash continuations are tracked without executing shell syntax.

**What is reported.** Relative path and line, spelling, direction and limited coverage; source strings and operands are not included. JSON/CSV schema 1.1 adds `source_path`, `source_line`, `source_spelling`, `source_direction` and `source_coverage`, and HTML renders the same evidence notes. `source_candidate` is a 1-based candidate ordinal within the logical line, not an additional column.

**How to read it.**

- Literal container-to-host, host-to-container and stream syntax is a candidate, not proof of an untrusted archive, host writes, reachability or exploitation.
- Variable arguments, ambiguous operands/options and mixed container endpoints remain `unknown`. Drive-letter paths are not assumed to be container names.
- Wrappers (including `sudo`), aliases, global Docker options, shell functions, command substitution, here-documents, YAML anchors/expressions, folded/multiline semantics and complex quoting require manual review. Shell reserved-word prefixes, environment assignments, negation, `time`, wrappers and quoted YAML `run` scalars remain outside the supported bare command syntax. Folded YAML scalar bodies remain unresolved rather than being read as separate commands.
- Here-strings and unusual redirect delimiters remain unresolved (here-strings have no following body, and arithmetic shifts are not treated as here-documents). Unsupported substitutions and malformed heredoc/arithmetic markers emit explicit unresolved coverage observations without hiding later direct commands.
- No supported command match means unknown coverage, never absence or mitigation.
- Source rows remain `unknown`, with `not_tested` exploitability and no inferred operator preconditions, even when a separate reported component version is fixed.

**Client and server components.** `docker-cli` / `docker-client` retain a separate client component instead of normalizing to `docker-engine`. Both use the vendor release-note comparison; Desktop and `go-archive` keep their independent thresholds. A patched server never clears an older client observation. The legacy `docker-engine-cli` alias still normalizes to `docker-engine` for compatibility; name both components explicitly when versions differ.

Command syntax provenance: [official Docker cp reference](https://docs.docker.com/reference/cli/docker/container/cp/), reviewed 2026-10-25. Advisory thresholds and the rules date are unchanged by workflow inspection.

## Output and exit codes

Choose a format with `--format csv|json|html` (default `csv`) and a destination with `--output FILE` (default stdout).

| Format | Contents |
| --- | --- |
| CSV | One flat row per result; spreadsheet-formula safe. A zero-result report has an explicit summary row (`record_type` `summary`, versus `result` for asset observations) that preserves the completeness flag and metadata without inventing an asset finding. |
| JSON | An object with tool identity, schema version, CVE, aliases, `rules_as_of`, sources, `generated_at`, `complete` and `results`. |
| HTML | A single self-contained, script-free page: restrictive Content-Security-Policy, no remote assets, escaped values, summary counts, per-row evidence and limits, and the fix table. `--brand NAME` sets the organization name. |

CSV, JSON and HTML retain checker identity and a UTC report-generation timestamp, including empty and interrupted reports. Generation time identifies when the report was generated; it is not evidence-acquisition time or deployed-patch attestation. See the [reference](docs/REFERENCE.md#output-formats) for metadata and recovery semantics.

| Exit code | Meaning |
| --- | --- |
| 0 | Completed. No finding was requested, or none exists. |
| 1 | `--fail-on-finding` was given and at least one result is `potentially_affected`. |
| 2 | Operational error: bad usage or arguments, unreadable or invalid input, unsupported component, refused or unwritable output. Operational errors take precedence over findings. |
| 130 | Interrupted. Completed results are preserved where possible; JSON and HTML mark the run incomplete. |

Operational failures (exit 2) are not assessment results. `unknown` results do not change the exit code, so review them.

### Output protections and interruption

- An existing output file is refused unless `--force` is given. The output directory must already exist, and input files cannot be the output path, even with `--force`. The output path is validated before any input is read.
- Reports are fully rendered and UTF-8 checked before anything is written, then staged and published atomically without clobbering a concurrently created file. If the filesystem cannot hard-link, the run exits 2; `--force` replaces via atomic rename.
- Output checks also protect selected source paths and hardlink aliases, even with `--force`.
- On interruption before publication, the CLI retries once as an incomplete report under the same run timestamp. A second interruption does not replace an existing report. After stdout starts, no second report is appended and the stream may be truncated. After a file is published, the completed bytes and their original completeness flag are preserved. If publication cannot be verified, the outcome stays unknown and is not retried. Details are in the [reference](docs/REFERENCE.md#report-publication-and-interruption).

## Limits and safety

- **Bounds**: 1 MiB per input file, 100 input files per run, 10,000 combined results, 512 characters per field, and 20,000 tokens per workflow line. Workflow logical commands are limited to 64 KiB and 256 physical lines, with a 16 MiB cumulative character-work bound per source file.
- **Inputs must be regular files.** Use stable copies; ordinary file checks are not a filesystem sandbox.
- **Strict parsing**: ASCII-only component and version text; look-alike Unicode is `unknown` or rejected. Unknown fields, duplicate JSON keys, wrong types and oversized files are operational errors.
- **Build provenance** is an operator claim. Values other than `unknown`, `upstream`, `official` and `official_upstream` yield `unknown`, because backports cannot be detected from a version.
- **Privacy**: reports do not include workflow source strings, operands, Docker contexts or hostnames. Operational stderr may include operator input paths from filesystem exceptions; sanitize it separately before sharing. Keep real inventories and reports outside version control.
- **No target testing**: the checker only reads files you give it and never probes hosts, containers or services.

## Primary sources

1. [Docker Engine v29 release notes, 29.7.0](https://docs.docker.com/engine/release-notes/29/#2970)
2. [Docker security announcements](https://docs.docker.com/security/security-announcements/)
3. [moby/go-archive advisory GHSA-hfg8-hc9c-6c3h](https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h)
4. [GitHub Advisory Database entry](https://github.com/advisories/GHSA-hfg8-hc9c-6c3h)

## Documentation and contributing

- [Reference](docs/REFERENCE.md): inputs, fields, outputs, exit codes
- [Implementation checklist](docs/IMPLEMENTATION.md)
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
