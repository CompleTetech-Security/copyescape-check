# Security policy

## Reporting a flaw in this project

Use the repository's **Security → Report a vulnerability** option when available
for issues needing private disclosure. Otherwise contact CompleteTech LLC
through [complete.tech](https://complete.tech) to arrange private reporting.
Include the affected commit, a minimal local reproduction, expected and actual
behavior, and impact. Omit credentials, real target lists, and third-party data.
Do not publish sensitive details in a public issue while private review is underway.

Only the current default branch is maintained. Reproduce against its latest
revision when possible. No response-time guarantee is made.

## Advisory scope and implementation status

This project is dedicated to **CVE-2026-17106**. It provides an offline,
version-only checker. It makes no network requests, runs no application code,
and performs no exploit verification or security assessment of a system.

Output distinguishes reported versions and operator-reported preconditions from
confirmed exposure. Exploitability remains `not_tested`; a fixed version is a
report, not a guarantee. Keep real inventories and assessment results outside
the repo.

For a vulnerability in the affected upstream product or a service you assess,
follow that vendor's or service owner's published security-reporting process.
