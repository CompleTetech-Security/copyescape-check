#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline version-evidence triage for CVE-2026-17106 (Docker copy destination escape). Python 3.10+."""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
MAX_INPUT = 1024 * 1024
MAX_INPUTS = 10000
MAX_FIELD = 512
INVENTORY_SCHEMA = 1

RULES_DATE = "2026-10-24"
CVE = "CVE-2026-17106"
ALIASES = ("GHSA-hfg8-hc9c-6c3h",)
TOOL_SOURCES = (
    "https://docs.docker.com/engine/release-notes/29/#2970",
    "https://docs.docker.com/security/security-announcements/",
    "https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h",
    "https://github.com/advisories/GHSA-hfg8-hc9c-6c3h",
)

# One entry per component with a verified rule. Docker Sandboxes is deliberately absent:
# a "0.38.0" claim circulates but no primary source was found (the vendor page lists
# Sandboxes only for other CVEs), so no Sandboxes rule is encoded.
#   fixed:  first version the primary source names as containing the fix
#   major:  the only release line the sources cover; other majors stay unknown
#   gap:    (low, high) half-open range where primary sources disagree; always unknown
COMPONENTS = {
    "docker-engine": {
        "label": "Docker Engine / CLI",
        "fixed": (29, 7, 0),
        "major": 29,
        "gap": None,
        "evidence": "vendor release notes",
        "confidence": "primary_source",
        "sources": ("https://docs.docker.com/engine/release-notes/29/#2970",),
        "recommendation": (
            "Upgrade Docker Engine and CLI to 29.7.0 or later on the 29.x line, preferring the latest 29.7.x or newer "
            "patch release, and restart the daemon. Verify the installed binaries; a package or image tag is not proof."
        ),
        "notes": (
            "Docker's Engine v29 release notes list the CVE-2026-17106 fix (go-archive v0.3.0) under 29.7.0, dated 2026-07-30.",
            "The 29.7.1 and 29.7.2 notes list regression fixes for 29.7.0; they are not the security fix, so 29.7.0 is the reported threshold.",
            "The release notes do not state the earliest affected Engine version, and no 28.x or earlier fix is listed; those lines are not assessed.",
        ),
    },
    "docker-desktop": {
        "label": "Docker Desktop",
        "fixed": (4, 86, 0),
        "major": 4,
        "gap": None,
        "evidence": "vendor security announcement",
        "confidence": "primary_source",
        "sources": ("https://docs.docker.com/security/security-announcements/",),
        "recommendation": (
            "Upgrade Docker Desktop to 4.86.0 or later and confirm the installed build in the application."
        ),
        "notes": (
            "Docker's security announcements list a destination-escape flaw in docker container cp as fixed in Docker Desktop 4.86.0 on August 10.",
            "The announcement does not state the earliest affected Desktop version; versions below the fix on the 4.x line are only potentially affected.",
        ),
    },
    "go-archive": {
        "label": "github.com/moby/go-archive",
        "fixed": (0, 3, 0),
        "major": 0,
        "gap": ((0, 2, 2), (0, 3, 0)),
        "evidence": "publisher advisory and GitHub-reviewed advisory",
        "confidence": "primary_source_range_conflict",
        "sources": (
            "https://github.com/moby/go-archive/security/advisories/GHSA-hfg8-hc9c-6c3h",
            "https://github.com/advisories/GHSA-hfg8-hc9c-6c3h",
        ),
        "recommendation": (
            "Update the module to v0.3.0 or later, rebuild every binary that vendors or links it, and redeploy. "
            "A fixed Docker Engine does not update other software that embeds go-archive."
        ),
        "notes": (
            "The publisher advisory lists affected versions <0.2.2; the GitHub-reviewed entry lists <0.3.0. Both name 0.3.0 as patched.",
            "Versions from 0.2.2 up to but not including 0.3.0 are disputed between the two sources and stay unknown, not safe.",
        ),
    },
}
COMPONENT_ALIASES = {
    "docker-engine": "docker-engine", "engine": "docker-engine", "docker-cli": "docker-engine",
    "docker-engine-cli": "docker-engine", "docker-desktop": "docker-desktop", "desktop": "docker-desktop",
    "go-archive": "go-archive", "moby-go-archive": "go-archive",
}

PRECONDITIONS = (
    ("untrusted_archive_or_container", "An untrusted container or archive is in use"),
    ("copy_or_extract_path_used", "docker cp copy-out or go-archive extraction is used"),
    ("host_write_privileges", "The extracting process has host filesystem write privileges"),
)
TRUSTED_BUILD_SOURCES = {"", "unknown", "upstream", "official", "official_upstream"}
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
PARTIAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(.+)", re.ASCII | re.DOTALL)


def normalize_component(value) -> str:
    if not isinstance(value, str) or len(value) > MAX_FIELD or not value.isascii():
        raise ValueError("component must be one of: " + ", ".join(COMPONENTS))
    key = value.strip().lower().replace("_", "-")
    if key.startswith("docker-sandboxes") or key == "sandboxes":
        raise ValueError("No verified Docker Sandboxes rule exists for this CVE; it is intentionally unsupported")
    if key not in COMPONENT_ALIASES:
        raise ValueError("component must be one of: " + ", ".join(COMPONENTS))
    return COMPONENT_ALIASES[key]


def _dotted(parts) -> str:
    return ".".join(str(part) for part in parts)


def observe_preconditions(**observed) -> dict:
    """Map reported precondition facts to labels. They never influence version_status."""
    result = {}
    for key, _label in PRECONDITIONS:
        value = observed.get(key)
        result[key] = "reported" if value is True else "not_reported" if value is False else "unknown"
    states = set(result.values())
    if states == {"reported"}:
        summary = "all_preconditions_reported"
    elif "not_reported" in states:
        summary = "some_preconditions_not_reported"
    else:
        summary = "preconditions_incomplete"
    result["precondition_summary"] = summary
    return result


def assess_copyescape(component, version="", *, version_candidates=None, build_source="unknown"):
    """Compare a reported component version with the documented fix; nothing is executed or probed.

    Versions are evidence, not verified runtime state. Vendor backports, the actual
    docker cp / extraction exposure and exploitability are not established here.
    """
    name = normalize_component(component)
    rule = COMPONENTS[name]
    fixed = _dotted(rule["fixed"])
    result = {
        "copyescape_status": "unknown",
        "copyescape_version_status": "version_not_disclosed",
        "copyescape_fixed_version": fixed,
        "copyescape_exploitability": "not_tested",
        "copyescape_cve": CVE,
        "copyescape_aliases": list(ALIASES),
        "copyescape_rules_as_of": RULES_DATE,
        "copyescape_sources": list(rule["sources"]),
        "copyescape_evidence_type": rule["evidence"],
        "copyescape_evidence_confidence": rule["confidence"],
        "copyescape_notes": [
            "Version metadata only. Runtime identity, vendor backports, input reachability and exploitability are not verified.",
            *rule["notes"],
        ],
        "copyescape_recommendation": rule["recommendation"],
    }
    notes = result["copyescape_notes"]
    if version_candidates is None:
        values = [version]
    elif isinstance(version_candidates, (list, tuple, set, frozenset)):
        values = [version, *version_candidates]
    elif isinstance(version_candidates, str):
        values = [version, version_candidates]
    else:
        result["copyescape_version_status"] = "unrecognized_or_partial_version"
        notes.append("Version candidates must be strings in a collection; the supplied metadata cannot be compared.")
        return result
    if len(values) - 1 > 128:
        result["copyescape_version_status"] = "conflicting_versions"
        notes.append("Too many version candidates were supplied for a single assessment.")
        return result
    if any(value is not None and not isinstance(value, str) for value in values):
        result["copyescape_version_status"] = "unrecognized_or_partial_version"
        notes.append("Non-text version metadata cannot be compared safely.")
        return result
    if any(isinstance(value, str) and not value.isascii() for value in values):
        result["copyescape_version_status"] = "unrecognized_or_partial_version"
        notes.append("Non-ASCII version text cannot be compared safely.")
        return result
    versions = sorted({value.strip().removeprefix("v") for value in values if value and value.strip()})
    if not versions:
        notes.append("No complete version was reported. Missing metadata does not establish that the component is absent or fixed.")
        return result
    if len(versions) != 1:
        result["copyescape_version_status"] = "conflicting_versions"
        notes.append("Conflicting reported versions: " + ", ".join(value[:128] for value in versions))
        return result
    value = versions[0]
    match = None if len(value) > 128 else VERSION_RE.fullmatch(value)
    if not match:
        qualified = len(value) <= 128 and PARTIAL_RE.match(value)
        result["copyescape_version_status"] = "qualified_version_unverified" if qualified else "unrecognized_or_partial_version"
        notes.append(
            f"Version {value[:128]!r} is not a plain stable x.y.z version. Prereleases, package suffixes, pseudo-versions and custom builds need vendor verification."
        )
        return result
    source = build_source.strip().lower() if isinstance(build_source, str) and build_source.isascii() else "invalid"
    if source not in TRUSTED_BUILD_SOURCES:
        result["copyescape_version_status"] = "vendor_build_unverified"
        notes.append("A vendor, distribution, custom or unrecognized build source was reported. Its upstream version does not verify the applied patch set.")
        result["copyescape_recommendation"] = (
            "Verify the exact vendor package or custom build against its own security advisory and build provenance."
        )
        return result
    parsed = tuple(int(part) for part in match.groups())
    if parsed[0] != rule["major"]:
        result["copyescape_version_status"] = "uncovered_release_line"
        notes.append(
            f"The primary sources cover only the {rule['major']}.x line of this component. Version {value} is outside it and is not assessed."
        )
        return result
    gap = rule["gap"]
    if gap and gap[0] <= parsed < gap[1]:
        result["copyescape_version_status"] = "disputed_affected_range"
        notes.append(
            f"Version {value} lies in the range sources disagree on ({_dotted(gap[0])} up to but not including {_dotted(gap[1])}); it is neither asserted affected nor safe."
        )
        return result
    if parsed < rule["fixed"]:
        result["copyescape_status"] = "potentially_affected"
        result["copyescape_version_status"] = "below_reported_fix"
    else:
        result["copyescape_status"] = "fixed_version_reported"
        result["copyescape_version_status"] = "meets_reported_fix"
        result["copyescape_recommendation"] = (
            "No version-based action is indicated. The reported version is not proof of the deployed build; keep components current and verify actual binaries."
        )
    return result


@dataclass
class Result:
    schema_version: str = SCHEMA_VERSION
    label: str = ""
    source: str = "version"
    component: str = ""
    reported_version: str = ""
    build_source: str = "unknown"
    platform: str = ""
    architecture: str = ""
    untrusted_archive_or_container: str = "unknown"
    copy_or_extract_path_used: str = "unknown"
    host_write_privileges: str = "unknown"
    precondition_summary: str = "preconditions_incomplete"
    copyescape_status: str = "unknown"
    copyescape_version_status: str = "version_not_disclosed"
    copyescape_fixed_version: str = ""
    copyescape_exploitability: str = "not_tested"
    copyescape_cve: str = CVE
    copyescape_aliases: list = field(default_factory=list)
    copyescape_rules_as_of: str = RULES_DATE
    copyescape_sources: list = field(default_factory=list)
    copyescape_evidence_type: str = ""
    copyescape_evidence_confidence: str = ""
    copyescape_notes: list = field(default_factory=list)
    copyescape_recommendation: str = ""
    status: str = "offline"


def build_result(label, source, component, version, build_source="unknown", platform="", architecture="", **observed) -> Result:
    name = normalize_component(component)
    for key, item in (("label", label), ("version", version), ("build_source", build_source),
                      ("platform", platform), ("architecture", architecture)):
        if not isinstance(item, str) or len(item) > MAX_FIELD:
            raise ValueError(f"{key} must be a string of at most {MAX_FIELD} characters")
    result = Result(label=label, source=source, component=name, reported_version=version, build_source=build_source,
                    platform=platform, architecture=architecture)
    for key, item in {**observe_preconditions(**observed), **assess_copyescape(name, version, build_source=build_source)}.items():
        setattr(result, key, item)
    return result


INVENTORY_FIELDS = {"schema_version", "component", "label", "version", "build_source", "platform", "architecture",
                    *(key for key, _ in PRECONDITIONS)}


def _tri_bool(record, key):
    value = record.get(key)
    if value is not None and type(value) is not bool:
        raise ValueError(f"Inventory {key} must be true, false, or null")
    return value


def inventory_result(record, fallback_label="component", source="inventory") -> Result:
    if not isinstance(record, dict) or set(record) - INVENTORY_FIELDS:
        raise ValueError("Each inventory entry must be an object containing only documented fields")
    if type(record.get("schema_version")) is not int or record["schema_version"] != INVENTORY_SCHEMA:
        raise ValueError("Inventory schema_version must be 1")
    for required in ("component", "version"):
        if required not in record:
            raise ValueError(f"Inventory entry is missing {required}")
    for key in ("component", "label", "version", "build_source", "platform", "architecture"):
        if key in record and (not isinstance(record[key], str) or len(record[key]) > MAX_FIELD):
            raise ValueError(f"Inventory {key} must be a string of at most {MAX_FIELD} characters")
    observed = {key: _tri_bool(record, key) for key, _ in PRECONDITIONS}
    return build_result(record.get("label") or fallback_label, source, record["component"], record["version"],
                        record.get("build_source", "unknown"), record.get("platform", ""), record.get("architecture", ""),
                        **observed)


def _read_bounded(path: Path, what: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError(f"{what} exceeds the 1 MiB limit")
    return raw


def load_inventory(path: Path, sink: list) -> list:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate key in inventory JSON")
            value[key] = item
        return value

    def reject_constant(_value):
        raise ValueError("Non-finite JSON number")

    data = json.loads(_read_bounded(path, "Inventory").decode("utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)
    records = data if isinstance(data, list) else [data]
    if not records or len(records) > MAX_INPUTS:
        raise ValueError(f"Inventory must contain between 1 and {MAX_INPUTS:,} entries")
    for index, record in enumerate(records):
        sink.append(inventory_result(record, f"{Path(path).stem}:{index + 1}"))
        if len(sink) > MAX_INPUTS:
            raise ValueError(f"A run is limited to {MAX_INPUTS:,} inputs")
    return sink


def _csv_bool(value, column):
    text = (value or "").strip().lower()
    if text in {"", "unknown", "null"}:
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    raise ValueError(f"CSV column {column} must be true, false, or empty")


def _validate_csv_quotes(text: str) -> None:
    """Reject a bare quote inside an unquoted field and text after a closing quote."""
    state = "start"  # start of field, unquoted field, quoted field, just after a closing quote
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if state == "start":
            state = "quoted" if char == '"' else "plain"
            if char in ",\r\n":
                state = "start"
        elif state == "plain":
            if char == '"':
                raise ValueError("CSV list contains a bare quote inside an unquoted field")
            if char in ",\r\n":
                state = "start"
        elif state == "quoted":
            if char == '"':
                if text[index + 1:index + 2] == '"':
                    index += 1
                else:
                    state = "closed"
        else:  # closed
            if char in ",\r\n":
                state = "start"
            else:
                raise ValueError("CSV list has text after a closing quote")
        index += 1
    if state == "quoted":
        raise ValueError("CSV list has an unterminated quoted field")


def load_csv(path: Path, sink: list) -> list:
    text = _read_bounded(path, "CSV list").decode("utf-8-sig")
    _validate_csv_quotes(text)
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    names = reader.fieldnames or []
    allowed = INVENTORY_FIELDS - {"schema_version"}
    if len(set(names)) != len(names) or set(names) - allowed or not {"component", "version"} <= set(names):
        raise ValueError("CSV header must contain component and version, and only documented columns")
    count = 0
    for index, row in enumerate(reader):
        if None in row or None in row.values():
            raise ValueError(f"CSV row {index + 2} has a different number of fields than the header")
        if any(len(value) > MAX_FIELD for value in row.values()):
            raise ValueError(f"CSV row {index + 2} has a field over {MAX_FIELD} characters")
        observed = {key: _csv_bool(row.get(key), key) for key, _ in PRECONDITIONS}
        sink.append(build_result(row.get("label") or f"{Path(path).stem}:{index + 1}", "csv", row["component"],
                                    row["version"], row.get("build_source") or "unknown", row.get("platform") or "",
                                    row.get("architecture") or "", **observed))
        count += 1
        if len(sink) > MAX_INPUTS:
            raise ValueError(f"A run is limited to {MAX_INPUTS:,} inputs")
    if not count:
        raise ValueError("CSV list contains no entries")
    return sink


def parse_version_argument(text: str, build_source: str) -> Result:
    component, separator, version = text.partition("=")
    if not separator:
        raise ValueError("--version must look like COMPONENT=VERSION, e.g. go-archive=0.3.0")
    if len(text) > 2 * MAX_FIELD + 1:
        raise ValueError("--version value is too long")
    name = normalize_component(component)
    return build_result(f"{COMPONENTS[name]['label']} {version}", "version", name, version, build_source)


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(str(item) for item in value)
    # Neutralize spreadsheet formulas, including after leading whitespace or a control character.
    if isinstance(value, str) and (value.lstrip().startswith(("=", "+", "-", "@")) or value[:1] in ("\t", "\r", "\n")):
        return "'" + value
    return value


REPORT_CSS = """
:root{--bg:#F8FAFC;--surface:#FFFFFF;--surface-2:#EEF2FF;--ink:#0F172A;--ink-2:#1E293B;--ink-3:#64748B;--line:#E2E8F0;
--accent:#1E3A8A;--accent-text:#1E3A8A;--on-accent:#FFFFFF;--bad:#B42318;--bad-bg:#FEE4E2;--ok:#067647;--ok-bg:#DCFAE6;--unk:#475467;--unk-bg:#EAECF0}
@media (prefers-color-scheme:dark){:root{--bg:#0F172A;--surface:#1E293B;--surface-2:#273449;--ink:#F1F5F9;--ink-2:#CBD5E1;--ink-3:#94A3B8;
--line:#334155;--accent-text:#93C5FD;--bad:#FDA29B;--bad-bg:#55160C;--ok:#75E0A7;--ok-bg:#053321;--unk:#D0D5DD;--unk-bg:#344054}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;gap:20px;align-items:center;padding:20px 0;border-bottom:3px solid var(--accent);margin-bottom:20px}
header img{height:64px;width:auto;border-radius:8px;background:#F8FAFC;padding:4px}
.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent-text);text-transform:uppercase}
h1{margin:2px 0;font-size:26px}.sub{color:var(--ink-3);margin:0}h2{margin:32px 0 10px;font-size:18px;color:var(--ink-2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;color:var(--accent-text)}.tile span{color:var(--ink-3);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line)}
table.narrow{max-width:360px}
th{background:var(--accent);color:var(--on-accent);text-align:left;padding:8px 10px;font-size:13px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}tr:nth-child(even) td{background:var(--surface-2)}
td.site{overflow-wrap:anywhere;min-width:200px}td.notes{color:var(--ink-3);font-size:13px;min-width:240px}
code{font:13px Consolas,monospace}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.unsupported_runtime,.pill.potentially_affected{color:var(--bad);background:var(--bad-bg)}.pill.fixed_version_reported{color:var(--ok);background:var(--ok-bg)}
.pill.unknown{color:var(--unk);background:var(--unk-bg)}
.callout{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;color:var(--ink-2)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px}
a{color:var(--accent-text)}
@media print{body{background:#fff}tr,.tile{break-inside:avoid}}
"""

STATUS_ORDER = {"potentially_affected": 0, "unknown": 1, "fixed_version_reported": 2}
STATUS_LABELS = {"potentially_affected": "Potentially affected", "unknown": "Unknown",
                 "fixed_version_reported": "Fixed version reported"}


def render_html(rows, *, brand="CompleteTech LLC", generated_at=None, complete=True) -> str:
    def esc(value):
        return html.escape("" if value is None else str(value), quote=True)

    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = sorted(rows, key=lambda row: STATUS_ORDER.get(row.get("copyescape_status"), 1))
    counts = {key: sum(row.get("copyescape_status") == key for row in rows) for key in STATUS_ORDER}
    tiles = [("", len(rows), "Inputs assessed"), ("bad", counts["potentially_affected"], "Potentially affected"),
             ("", counts["unknown"], "Unknown"), ("ok", counts["fixed_version_reported"], "Fixed version reported")]
    body = []
    for row in rows:
        status = row.get("copyescape_status") if row.get("copyescape_status") in STATUS_ORDER else "unknown"
        conditions = "".join(
            f"<li>{esc(label)}: <code>{esc(row.get(key))}</code></li>" for key, label in PRECONDITIONS)
        notes = "".join(f"<li>{esc(note)}</li>" for note in dict.fromkeys(row.get("copyescape_notes", [])))
        body.append(
            "<tr>"
            f"<td class='site'>{esc(row.get('label'))}<br><small>{esc(row.get('component'))}</small></td>"
            f"<td><span class='pill {status}'>{STATUS_LABELS[status]}</span><br><small>{esc(row.get('copyescape_version_status'))}</small></td>"
            f"<td><code>{esc(row.get('reported_version') or '—')}</code></td>"
            f"<td><code>{esc(row.get('copyescape_fixed_version') or '—')}</code></td>"
            f"<td><code>{esc(row.get('copyescape_exploitability'))}</code></td>"
            f"<td class='notes'><p>{esc(row.get('copyescape_recommendation'))}</p>"
            f"<details><summary>Preconditions reported separately ({esc(row.get('precondition_summary'))})</summary><ul>{conditions}</ul></details>"
            f"<details><summary>Evidence and limitations</summary><ul>{notes}</ul></details></td></tr>"
        )
    fixes = "".join(
        f"<tr><td>{esc(rule['label'])}</td><td><code>{esc(_dotted(rule['fixed']))}</code></td></tr>"
        for rule in COMPONENTS.values())
    tile_html = "".join(f"<div class='tile {cls}'><b>{value}</b><span>{esc(label)}</span></div>" for cls, value, label in tiles)
    sources = " · ".join(f"<a href='{esc(url)}'>{esc(url.split('//', 1)[1].split('/', 1)[0])}</a>" for url in TOOL_SOURCES)
    incomplete = "" if complete else "<p class='callout'><b>Interrupted run.</b> Only completed inputs are shown. Re-run the unfinished inputs.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>CopyEscape Version Report</title><style>{REPORT_CSS}
details{{max-width:430px}}summary{{cursor:pointer;color:var(--accent-text)}}details ul{{padding-left:18px}}
@media print{{details>summary{{display:none}}details>ul{{display:block}}}}
</style></head><body><main>
<header><div><div class="eyebrow">{esc(brand)}</div><h1>CopyEscape Version Report</h1>
<p class="sub">{CVE} · generated {esc(generated_at)} · rules as of {RULES_DATE}</p></div></header>
<p class="callout"><b>Version evidence, not a proof of exploitability.</b> Every result has exploitability <code>not_tested</code>.
Unknown results need investigation. Precondition observations are operator-reported and never change the version result.</p>
{incomplete}<div class="tiles">{tile_html}</div>
<h2>Results</h2><div class="wrap"><table><thead><tr><th>Input</th><th>Version assessment</th><th>Reported</th>
<th>Reported fix</th><th>Exploitability</th><th>Next step and evidence</th></tr></thead>
<tbody>{''.join(body) or '<tr><td colspan="6">No results.</td></tr>'}</tbody></table></div>
<h2>Reported fix thresholds</h2><div class="wrap"><table class="narrow"><thead><tr><th>Component</th><th>Fixed in</th></tr></thead><tbody>{fixes}</tbody></table></div>
<h2>Verify the deployed software</h2>
<p>Check the binaries that actually run, not the package request. Upgrade, rebuild software that embeds go-archive, restart, then collect metadata again.
A fixed version is a report from vendor sources, not a guarantee. Docker Sandboxes is not assessed because no primary-source rule was verified.</p>
<footer>{esc(brand)} · copyescape-check {TOOL_VERSION} · {sources}</footer>
</main></body></html>
"""


def write_report(output, rows, *, format="csv", brand="CompleteTech LLC", complete=True):
    if format == "csv":
        writer = csv.DictWriter(output, fieldnames=[*Result.__dataclass_fields__, "complete"], lineterminator="\n", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{key: csv_safe(value) for key, value in row.items()}, "complete": "true" if complete else "false"})
    elif format == "json":
        json.dump({"tool": "copyescape-check", "tool_version": TOOL_VERSION, "schema_version": SCHEMA_VERSION,
                   "cve": CVE, "aliases": list(ALIASES), "rules_as_of": RULES_DATE, "sources": list(TOOL_SOURCES),
                   "generated_at": datetime.now(timezone.utc).isoformat(), "complete": complete, "results": rows},
                  output, ensure_ascii=False, indent=2)
        output.write("\n")
    else:
        output.write(render_html(rows, brand=brand, complete=complete))


def save_report(path, rows, *, force=False, **options):
    """Render fully first, then publish; refuse an existing path unless force (hard link only, never a rename)."""
    buffer = io.StringIO(newline="")
    write_report(buffer, rows, **options)
    text = buffer.getvalue()
    text.encode("utf-8")  # Surface lone surrogates before anything is written.
    if path is None:
        sys.stdout.write(text)
        return
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=".copyescape-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)  # Atomic no-clobber publication; there is deliberately no rename fallback.
            except FileExistsError:
                raise ValueError("Output exists; use a new path or explicitly pass --force") from None
            except OSError:
                raise ValueError("Cannot publish without overwrite: the filesystem does not support hard links; choose another directory or pass --force") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


EPILOG = """\
exit status:
  0  completed; no finding requested or none present
  1  --fail-on-finding was given and a potentially_affected result exists
  2  operational error (bad usage, unreadable or invalid input, output refused or unwritable)
  130  interrupted; completed results were written (JSON/HTML mark the run incomplete)

components: docker-engine, docker-desktop, go-archive. Docker Sandboxes has no verified rule.
This tool is offline: it makes no network requests and runs no Docker or application code.
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="append", default=[], metavar="COMPONENT=VERSION",
                        help="Assess a reported version offline, e.g. docker-engine=29.6.0; repeatable")
    parser.add_argument("--build-source", default="unknown", help="Build provenance applied to --version values (default: unknown); vendor or custom keeps results unknown")
    parser.add_argument("--inventory", action="append", default=[], type=Path, metavar="FILE", help="Read JSON inventory (schema_version 1); repeatable")
    parser.add_argument("--csv", action="append", default=[], type=Path, metavar="FILE", dest="csv_lists", help="Read a CSV list with a component,version header; repeatable")
    parser.add_argument("--format", choices=("csv", "json", "html"), default="csv", help="Output format (default: csv)")
    parser.add_argument("--output", type=Path, help="Save report to a new file; default: stdout")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file explicitly")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Organization name for the HTML report")
    parser.add_argument("--fail-on-finding", action="store_true", help="Exit 1 when a result is potentially_affected (errors still exit 2)")
    parser.add_argument("--tool-version", action="version", version=f"copyescape-check {TOOL_VERSION}")
    args = parser.parse_args(argv)
    rows = []
    complete = True

    def add(result):
        rows.append(result)
        if len(rows) > MAX_INPUTS:
            raise ValueError(f"A run is limited to {MAX_INPUTS:,} inputs")

    try:
        if not (args.version or args.inventory or args.csv_lists):
            parser.error("provide --version, --inventory, or --csv")
        if len(args.brand) > MAX_FIELD or any(ord(c) < 32 or ord(c) == 127 for c in args.brand):
            raise ValueError(f"--brand must be at most {MAX_FIELD} characters without control characters")
        if len(args.version) > MAX_INPUTS:
            raise ValueError(f"A run is limited to {MAX_INPUTS:,} inputs")
        if args.output:  # Validate the destination before reading any input.
            inputs = [*args.inventory, *args.csv_lists]
            if any(args.output.resolve() == p.resolve() for p in inputs):
                raise ValueError("--output must differ from every input file, even with --force")
            if args.output.exists() and not args.force:
                raise ValueError("Output exists; use a new path or explicitly pass --force")
            if not args.output.parent.is_dir():
                raise ValueError("Output directory must already exist")
        try:
            for text in args.version:
                add(parse_version_argument(text, args.build_source))
            for path in args.inventory:
                load_inventory(path, rows)
            for path in args.csv_lists:
                load_csv(path, rows)
        except KeyboardInterrupt:
            complete = False
            print("Interrupted; preserving completed results.", file=sys.stderr)
    except RuntimeError:
        print(f"{parser.prog}: error: a path could not be resolved (symlink loop?)", file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, RecursionError, csv.Error) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2
    records = [asdict(row) for row in rows]
    for attempt in (1, 2):
        try:
            save_report(args.output, records, force=args.force, format=args.format, brand=args.brand, complete=complete)
            break
        except KeyboardInterrupt:
            complete = False  # Retry once, marking the report incomplete.
            print("Interrupted while writing; retrying once as an incomplete report.", file=sys.stderr)
            if attempt == 2:
                return 130
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Cannot write report: {exc if not isinstance(exc, RuntimeError) else 'path error'}", file=sys.stderr)
            return 2
    if not complete:
        return 130
    if args.fail_on_finding and any(row["copyescape_status"] == "potentially_affected" for row in records):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
