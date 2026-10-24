# Contributing

This repository covers **CVE-2026-17106**. The offline checker is implemented in
`copyescape_check.py`; start with the [reference](docs/REFERENCE.md) and the
[implementation checklist](docs/IMPLEMENTATION.md).
Submit focused pull requests for this exploit. Report flaws requiring private
disclosure according to [SECURITY.md](SECURITY.md).

## Development expectations

Follow [AGENTS.md](AGENTS.md). Prefer a standalone Python 3.10+ checker with no
third-party runtime/test dependencies when suitable. Validate primary sources
before encoding affected or fixed ranges. Preserve evidence provenance and
`unknown` for missing or conflicting facts. Keep exploitability `not_tested`.

Use offline inventories, synthetic examples, mocks, and local fixtures. Do not
commit credentials, real target lists, private reports, or exploit payloads.
Network detection must be justified, optional, ordinary, bounded, and authorized.
Document implemented behavior and actual commands. Run `python -m unittest -v`
and `python copyescape_check.py --help` before submitting; rule changes need a
primary-source citation and a boundary test.

## Licensing of contributions

copyescape-check follows the AGPL-3.0 / commercial licensing model described in
[LICENSING.md](LICENSING.md). By submitting a contribution, you confirm that you
have the right to submit it. You license it to the public under AGPL-3.0 and
grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license
to use, modify, sublicense, and distribute it under any license, including a
commercial license. You keep the copyright in your contribution.
