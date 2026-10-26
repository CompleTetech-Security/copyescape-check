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
import hashlib
import os
import re
import shlex
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.1.0"
SCHEMA_VERSION = "1.1"
MAX_WORKFLOW_WALK = 16 * 1024**2
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
COMPONENTS["docker-cli"] = {**COMPONENTS["docker-engine"], "label": "Docker CLI"}
COMPONENT_ALIASES = {
    "docker-engine": "docker-engine", "engine": "docker-engine", "docker-cli": "docker-cli", "docker-client": "docker-cli",
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
    source_path: str = ""
    source_line: int = 0
    source_spelling: str = ""
    source_direction: str = "unknown"
    source_coverage: str = ""
    version_candidates: list = field(default_factory=list)
    source_candidate: int = 0
    source_instance: str = ""


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
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"{what} must be a regular file")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError(f"{what} exceeds the 1 MiB limit")
    return raw


def _workflow_lines(text, yaml=False):
    """Plain shell lines or plain/block YAML run values, never a YAML evaluator."""
    block_indent, content_indent, folded = None, None, False
    pending, first_line = "", 0
    physical_lines = 0
    skipped_scalar = None
    heredocs = []
    walk_budget = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if len(raw)>65536:
            raise ValueError("Workflow physical line limit exceeded")
        line = raw
        if yaml:
            indent = len(raw) - len(raw.lstrip())
            if block_indent is not None and raw.strip() and indent <= block_indent:
                if pending:
                    yield first_line, pending
                    pending = ""
                block_indent, content_indent, folded = None, None, False
            if block_indent is None:
                if skipped_scalar is not None:
                    if not raw.strip() or indent > skipped_scalar:
                        continue
                    skipped_scalar = None
                scalar = re.match(r"^\s*(?:-\s*)?(?P<key>[^\s:#][^:#]*):\s*[|>](?:[1-9][-+]?|[-+][1-9]?)?(?:[ \t]+#.*)?$", raw)
                if scalar and scalar["key"].strip() != "run":
                    skipped_scalar = scalar.start("key")
                    continue
                match = re.match(r"^\s*(?:-\s*)?(?P<key>run):\s*(?P<value>.*)$", raw)
                if not match:
                    continue
                heredocs = []  # Each YAML run value is an independent script.
                line = match["value"]
                if line.lstrip().startswith(("\"", "'")):
                    yield number, "$(unsupported_yaml_scalar)"
                    continue
                if re.fullmatch(r"[|>](?:[1-9][-+]?|[-+][1-9]?)?(?:[ \t]+#.*)?", line.strip()):
                    block_indent = match.start("key")
                    content_indent = None
                    folded = line.strip().startswith(">")
                    if folded:
                        yield number, "$(unsupported_yaml_scalar)"
                    continue
            else:
                if folded:
                    continue  # Folded-scalar shell semantics remain unsupported.
                if raw.strip() and content_indent is None:
                    content_indent = indent
                line = raw[content_indent:] if content_indent is not None else ""
            # No YAML expression evaluation, anchors, includes or shell execution.
        if heredocs:
            delimiter, tabs = heredocs[0]
            if (line.lstrip("\t") if tabs else line) == delimiter:
                heredocs.pop(0)
            continue
        if not pending:
            first_line = number
            physical_lines = 0
        physical_lines += 1
        pending += line
        if len(pending) > 65536 or physical_lines > 256:
            raise ValueError("Workflow logical command limit exceeded")
        walk_budget += len(pending)
        if walk_budget > MAX_WORKFLOW_WALK:
            raise ValueError("Workflow lexical work limit exceeded")
        _, continuation, quote, _ = _shell_walk(pending)
        if continuation:
            pending = pending[:-1]
            continue
        if quote:
            pending += "\n"
            continue
        markers = _heredoc_markers(pending)
        if any(delimiter == "\0unsupported" for delimiter,_ in markers):
            yield first_line, "$(unsupported_heredoc_syntax)"
            pending = ""
            continue
        heredocs.extend(markers)
        if len(heredocs) > 32:
            raise ValueError("Too many here-document delimiters")
        yield first_line, pending
        pending = ""
    if pending:
        yield first_line, pending


def _heredoc_markers(line):
    """Recognize active redirection operators before shlex removes quoting."""
    quote, escaped, index, word_start = None, False, 0, True
    markers = []
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            word_start = False
            index += 1
            continue
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote: quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and word_start:
            break
        elif line[index:index+3] == "$((" or line[index:index+2] == "((":
            end = line.find("))", index+2)
            if end < 0:
                markers.append(("\0unsupported",False))
                break
            index = end+2
            continue
        elif line[index:index+2] == "<<":
            if line[index:index+3] == "<<<":
                index += 3
                continue
            tail = line[index+2:]
            tabs = tail.startswith("-")
            if tabs: tail = tail[1:]
            try:
                lexer = shlex.shlex(tail, posix=True, punctuation_chars="()<>;&|")
                lexer.whitespace_split = True
                lexer.commenters = ""
                delimiter = next(iter(lexer), "")
            except ValueError:
                delimiter = ""
            if not delimiter:
                markers.append(("\0unsupported", False))
            else:
                markers.append((delimiter, tabs))
            index += 2
            continue
        word_start = char.isspace() or char in "()<>;&|"
        index += 1
    return markers


def _copy_direction(arguments):
    operands, options = [], True
    for arg in arguments:
        if options and arg == "--":
            options = False
        elif options and arg.startswith("-") and arg != "-":
            if arg not in {"-a", "--archive", "-L", "--follow-link", "-aL", "-La", "-q", "--quiet"}:
                return "unknown"
        else:
            operands.append(arg)
    if len(operands) != 2 or any(any(c in arg for c in "$`%{}") for arg in operands):
        return "unknown"
    if "-" in operands:
        return "stream_candidate"
    def container(arg):
        if re.match(r"^[A-Za-z]:[\\/]", arg):
            return False
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*:", arg))
    source, destination = map(container, operands)
    if source and not destination:
        return "container_to_host_candidate"
    if destination and not source:
        return "host_to_container_candidate"
    return "unknown"


def _shell_walk(line):
    """Shared quote/comment/escape walk for continuation and command boundaries."""
    quote, escaped, first, index, word_start = None, False, 0, 0, True
    segments, unsupported = [], False
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            word_start = False
        elif char == "\\" and quote != "'":
            escaped = True
            word_start = False
        elif quote:
            if quote == '"' and (char == "`" or line[index:index + 2] == "$("):
                unsupported = True
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
            word_start = False
        elif char == "#" and word_start:
            line = line[:index]
            break
        elif char == "`" or line[index:index + 2] == "$(":
            unsupported = True
            word_start = False
        elif line[index:index+2] in {">&", "<&"}:
            unsupported = True
            index += 2
            word_start = True
            continue
        elif char in ";&|":
            segments.append(line[first:index])
            width = 2 if line[index:index + 2] in {"&&", "||"} else 1
            index += width
            first = index
            word_start = True
            continue
        elif quote is None:
            word_start = char.isspace() or char in "()<>"
        index += 1
    segments.append(line[first:])
    return segments, escaped and quote != "'", quote, unsupported


def _shell_segments(line):
    segments, continuation, quote, unsupported = _shell_walk(line)
    return [] if continuation or quote or unsupported else segments


def scan_workflow_text(text, relative_path, *, yaml=False):
    rows = []
    for number, line in _workflow_lines(text, yaml):
        token_count = 0
        ordinal = 0
        segments = _shell_segments(line)
        if not segments and line.strip():
            row = build_result(relative_path, "source", "docker-cli", "")
            row.source_path, row.source_line = relative_path, number
            row.source_coverage = "unresolved_syntax"
            row.copyescape_evidence_confidence = "insufficient"
            row.copyescape_evidence_type = "source_coverage"
            row.copyescape_notes.append("Unsupported shell syntax at this logical line was not assessed; no command absence, direction or runtime trust is established.")
            rows.append(row)
            if len(rows)>MAX_INPUTS:
                raise ValueError("Too many workflow observations")
        for segment in segments:
            lexer = shlex.shlex(segment, posix=True, punctuation_chars="()<>")
            lexer.whitespace_split = True
            lexer.commenters = ""
            try:
                command = list(lexer)
            except ValueError:
                continue
            token_count += len(command)
            if token_count > 20000:
                raise ValueError("Workflow line exceeds the token limit")
            offset, spelling = None, ""
            if command[:2] == ["docker", "cp"]:
                offset, spelling = 2, "docker cp"
            elif command[:3] == ["docker", "container", "cp"]:
                offset, spelling = 3, "docker container cp"
            if offset is None:
                continue
            direction = _copy_direction(command[offset:])
            row = build_result(relative_path, "source", "docker-cli", "")
            row.source_path, row.source_line = relative_path, number
            ordinal += 1
            row.source_candidate = ordinal
            row.source_spelling, row.source_direction = spelling, direction
            row.source_coverage = "limited_lexical"
            row.copyescape_evidence_type = "lexical_workflow_candidate"
            row.copyescape_evidence_confidence = "insufficient"
            row.copyescape_notes.append(
                f"Workflow candidate {relative_path}:{number}: {spelling}; direction={direction}. "
                "Static syntax does not prove attacker control, deployment, host permissions or a reachable extraction path. "
                "Aliases, wrappers, interpolation, shell/YAML semantics and multiline quoting need manual review.")
            rows.append(row)
            if len(rows) > MAX_INPUTS:
                raise ValueError("Too many workflow candidates")
    if not rows:
        row = build_result(relative_path, "source", "docker-cli", "")
        row.source_path, row.source_coverage = relative_path, "limited_lexical"
        row.copyescape_evidence_type = "source_coverage"
        row.copyescape_evidence_confidence = "insufficient"
        row.copyescape_notes.append("No supported direct docker cp candidate found; wrappers, aliases, dynamic commands and unsupported YAML/shell remain unknown. No absence or mitigation is established.")
        rows.append(row)
    return rows


def load_source(path, root, sink):
    relative = path.resolve().relative_to(root.resolve()).as_posix()
    if len(relative) > MAX_FIELD:
        raise ValueError("Source relative path exceeds the field limit")
    data = _read_bounded(path, "Source").decode("utf-8-sig")
    rows = scan_workflow_text(data, relative, yaml=path.suffix.lower() in {".yml", ".yaml"})
    if len(sink) + len(rows) > MAX_INPUTS:
        raise ValueError("Too many combined inputs")
    sink.extend(rows)


def load_docker_version(path, sink, ordinal=1):
    """Read an existing docker version export. Never invoke Docker or a shell."""
    text = _read_bounded(path, "Docker version export").decode("utf-8-sig")
    candidates = {"docker-cli": [], "docker-engine": []}
    if text.lstrip().startswith("{"):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate Docker metadata key")
                result[key] = value
            return result
        def reject(_):
            raise ValueError("Non-finite Docker metadata number")
        data = json.loads(text, object_pairs_hook=unique, parse_constant=reject)
        if not isinstance(data, dict):
            raise ValueError("Docker version JSON must be an object")
        for section, component in [("Client", "docker-cli"), ("Server", "docker-engine")]:
            value = data.get(section)
            if value is None:
                continue
            if not isinstance(value, dict):
                raise ValueError("Docker Client/Server metadata must be an object or null")
            if "Version" in value:
                candidates[component].append(value["Version"])
            if section == "Server" and "Components" in value:
                if not isinstance(value["Components"], list) or len(value["Components"]) > 100:
                    raise ValueError("Invalid Docker component list")
                for item in value["Components"]:
                    if not isinstance(item, dict):
                        raise ValueError("Invalid Docker component metadata")
                    if item.get("Name") == "Engine" and "Version" in item:
                        candidates[component].append(item["Version"])
    else:
        section, subcomponent = None, None
        for line in text.split("\n"):
            line = line.removesuffix("\r")
            match = re.match(r"^(Client|Server):", line)
            if match:
                section = "docker-cli" if match[1] == "Client" else "docker-engine"
                subcomponent = None
                continue
            heading = re.match(r"^\s+([^:\s][^:]*):\s*$", line)
            if heading and heading[1].strip() != "Version":
                subcomponent = heading[1].strip()
                continue
            version = re.match(r"^[ \t]+Version:[ \t]*(.*?)[ \t]*$", line)
            if version and section and (subcomponent is None or (section == "docker-engine" and subcomponent == "Engine")):
                candidates[section].append(version[1])
    if len(sink) + 2 > MAX_INPUTS:
        raise ValueError("Too many combined inputs")
    for component, versions in candidates.items():
        if len(versions) > 128 or any(not isinstance(v, str) or len(v) > MAX_FIELD for v in versions):
            raise ValueError("Docker versions must be bounded strings")
        versions = sorted(set(versions))
        row = build_result(component + " export", "docker_version_export", component, versions[0] if len(versions) == 1 else "")
        if len(versions) > 1:
            for key, value in assess_copyescape(component, versions[0], version_candidates=versions[1:]).items():
                setattr(row, key, value)
        if any(not version.strip() for version in versions):
            row.copyescape_status = "unknown"
            row.copyescape_version_status = "missing_or_conflicting_export_version"
            row.copyescape_recommendation = COMPONENTS[component]["recommendation"]
            row.copyescape_notes.append("An explicit blank version field is unresolved; another version cannot clear it.")
        elif len(versions) > 1 and row.copyescape_status != "unknown":
            # Equivalent supported spellings can agree after the assessor's
            # single normalization. Give that non-conflicting row a version.
            row.reported_version = versions[0].strip(" \t\r\n").removeprefix("v")
        if not versions:
            row.copyescape_notes.append("No supported component Version field was recognized; custom templates or unsupported text remain unknown, not clean.")
        row.source_instance = hashlib.sha256(("docker-version-export:"+str(ordinal)).encode("ascii")).hexdigest()
        row.copyescape_evidence_type = "docker_version_export"
        row.copyescape_evidence_confidence = "insufficient" if row.copyescape_status == "unknown" else "low"
        row.version_candidates = versions
        if versions:
            row.copyescape_notes.append("Export version candidates: " + ", ".join(version or "(blank)" for version in versions))
        row.copyescape_notes.append("Existing Docker version export, not live runtime attestation. Client and server are independent; API versions, contexts, hosts, scripts and other component versions are not collected. Desktop version must be supplied independently.")
        sink.append(row)


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
    if "\x00" in text:
        raise ValueError("CSV input cannot contain NUL characters")
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
    if isinstance(value, str) and "\x00" in value:
        raise ValueError("CSV values cannot contain NUL characters")
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
        writer = csv.DictWriter(output, fieldnames=[*Result.__dataclass_fields__, "complete", "record_type"], lineterminator="\n", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{key: csv_safe(value) for key, value in row.items()}, "record_type": "result", "complete": "true" if complete else "false"})
        if not rows:
            writer.writerow({"record_type": "summary", "complete": "true" if complete else "false",
                             "schema_version": SCHEMA_VERSION, "copyescape_cve": CVE,
                             "copyescape_rules_as_of": RULES_DATE, "copyescape_exploitability": "not_tested"})
    elif format == "json":
        json.dump({"tool": "copyescape-check", "tool_version": TOOL_VERSION, "schema_version": SCHEMA_VERSION,
                   "cve": CVE, "aliases": list(ALIASES), "rules_as_of": RULES_DATE, "sources": list(TOOL_SOURCES),
                   "generated_at": datetime.now(timezone.utc).isoformat(), "complete": complete, "results": rows},
                  output, ensure_ascii=False, indent=2)
        output.write("\n")
    else:
        output.write(render_html(rows, brand=brand, complete=complete))


def save_report(path, rows, *, force=False, state=None, **options):
    """Render before writing and reconcile an interrupted atomic publication by inode."""
    state = {} if state is None else state
    buffer = io.StringIO(newline="")
    write_report(buffer, rows, **options)
    text = buffer.getvalue()
    text.encode("utf-8")
    if path is None:
        state["stdout_started"] = True
        sys.stdout.write(text)
        state["published"] = True
        return
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent,
                                         prefix=".copyescape-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            staged_identity = os.fstat(stream.fileno())
        try:
            state["publication_started"] = True
            if force:
                os.replace(temporary, path)
            else:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    raise ValueError("Output exists; use a new path or explicitly pass --force") from None
                except OSError:
                    raise ValueError("Cannot publish without overwrite: hard links are unavailable here") from None
            state["published"] = True
        except KeyboardInterrupt:
            try:
                destination = os.stat(path, follow_symlinks=False)
            except FileNotFoundError:
                state["publication_started"] = False
            except OSError:
                pass  # Indeterminate: retain the pre-mutation retry barrier.
            else:
                if os.path.samestat(staged_identity, destination):
                    state["published"] = True
                else:
                    state["publication_started"] = False
            raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


EPILOG = """\
exit status:
  0  completed; no finding requested or none present
  1  --fail-on-finding was given and a potentially_affected result exists
  2  operational error (bad usage, unreadable or invalid input, output refused or unwritable)
  130  interrupted; completed results were written (JSON/HTML mark the run incomplete)

components: docker-engine, docker-cli (docker-client), docker-desktop, go-archive. Docker Sandboxes has no verified rule.
This tool is offline: it makes no network requests and runs no Docker or application code.
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="append", default=[], metavar="COMPONENT=VERSION",
                        help="Assess a reported version offline, e.g. docker-engine=29.6.0; repeatable")
    parser.add_argument("--build-source", default="unknown", help="Build provenance applied to --version values (default: unknown); vendor or custom keeps results unknown")
    parser.add_argument("--inventory", action="append", default=[], type=Path, metavar="FILE", help="Read JSON inventory (schema_version 1); repeatable")
    parser.add_argument("--csv", action="append", default=[], type=Path, metavar="FILE", dest="csv_lists", help="Read a CSV list with a component,version header; repeatable")
    parser.add_argument("--docker-version", action="append", default=[], type=Path, metavar="FILE", help="Read an existing Docker version JSON/text export; never invokes Docker")
    parser.add_argument("--source", action="append", default=[], type=Path, metavar="FILE", help="Explicit shell or CI YAML file for docker cp candidates; repeatable, never executed")
    parser.add_argument("--source-root", type=Path, metavar="DIR", help="Required with --source; report relative file/line evidence")
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
        if not (args.version or args.inventory or args.csv_lists or args.source or args.docker_version):
            parser.error("provide --version, --inventory, --csv, --docker-version or --source")
        if len(args.brand) > MAX_FIELD or any(ord(c) < 32 or ord(c) == 127 for c in args.brand):
            raise ValueError(f"--brand must be at most {MAX_FIELD} characters without control characters")
        if len(args.version) > MAX_INPUTS:
            raise ValueError(f"A run is limited to {MAX_INPUTS:,} inputs")
        inputs = [*args.inventory, *args.csv_lists, *args.source, *args.docker_version]
        if len(inputs) > 100:
            raise ValueError("A run is limited to 100 input files")
        if args.source and (args.source_root is None or not args.source_root.is_dir()):
            raise ValueError("--source requires an existing --source-root directory")
        for path in args.source:
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError("Source must be a regular file")
            if path.suffix.lower() not in {".sh", ".bash", ".yml", ".yaml"}:
                raise ValueError("Source must be an explicit shell or CI YAML file")
            path.resolve().relative_to(args.source_root.resolve())
        if args.output:  # Validate the destination before reading any input.
            if any(args.output.resolve() == p.resolve() or (args.output.exists() and os.path.samefile(args.output, p)) for p in inputs):
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
            for ordinal,path in enumerate(args.docker_version,1):
                load_docker_version(path, rows, ordinal)
            for path in args.source:
                load_source(path, args.source_root, rows)
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
    state = {"published": False, "stdout_started": False, "publication_started": False}
    for attempt in (1, 2):
        try:
            save_report(args.output, records, force=args.force, format=args.format, brand=args.brand, complete=complete, state=state)
            break
        except KeyboardInterrupt:
            if state["published"]:
                print("Interrupted after the report was published; not retrying.", file=sys.stderr)
                return 130
            if state.get("publication_started"):
                print("Interrupted; publication could not be verified and will not be retried.", file=sys.stderr)
                return 130
            if state["stdout_started"]:
                print("Interrupted while writing stdout; output may be truncated and no second report is written.", file=sys.stderr)
                return 130
            complete = False  # Retry once, marking the report incomplete.
            print("Interrupted while writing; retrying once as an incomplete report.", file=sys.stderr)
            if attempt == 2:
                return 130
        except (OSError, ValueError, RuntimeError, csv.Error) as exc:
            print(f"Cannot write report: {exc if not isinstance(exc, RuntimeError) else 'path error'}", file=sys.stderr)
            return 2
    if not complete:
        return 130
    if args.fail_on_finding and any(row["copyescape_status"] == "potentially_affected" for row in records):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
