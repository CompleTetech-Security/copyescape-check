"""Boundary, input, and output-safety tests for copyescape_check. Local and offline only."""

import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

import copyescape_check as cc
from copyescape_check import assess_copyescape


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cc.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class BoundaryTests(unittest.TestCase):
    def check(self, component, cases):
        for version, status, version_status in cases:
            with self.subTest(component=component, version=version):
                result = assess_copyescape(component, version)
                self.assertEqual(status, result["copyescape_status"])
                self.assertEqual(version_status, result["copyescape_version_status"])
                self.assertEqual("not_tested", result["copyescape_exploitability"])

    def test_docker_engine_boundaries(self):
        self.check("docker-engine", [
            ("29.0.0", "potentially_affected", "below_reported_fix"),
            ("29.6.2", "potentially_affected", "below_reported_fix"),
            ("29.7.0", "fixed_version_reported", "meets_reported_fix"),
            ("v29.7.0", "fixed_version_reported", "meets_reported_fix"),
            ("29.7.2", "fixed_version_reported", "meets_reported_fix"),
            ("29.9.2", "fixed_version_reported", "meets_reported_fix"),
            ("28.5.1", "unknown", "uncovered_release_line"),
            ("30.0.0", "unknown", "uncovered_release_line"),
        ])

    def test_docker_desktop_boundaries(self):
        self.check("docker-desktop", [
            ("4.71.0", "potentially_affected", "below_reported_fix"),
            ("4.85.9", "potentially_affected", "below_reported_fix"),
            ("4.86.0", "fixed_version_reported", "meets_reported_fix"),
            ("4.86.1", "fixed_version_reported", "meets_reported_fix"),
            ("4.100.0", "fixed_version_reported", "meets_reported_fix"),
            ("3.9.9", "unknown", "uncovered_release_line"),
            ("5.0.0", "unknown", "uncovered_release_line"),
        ])

    def test_go_archive_boundaries_keep_publisher_and_reviewed_gap_unknown(self):
        self.check("go-archive", [
            ("0.1.0", "potentially_affected", "below_reported_fix"),
            ("0.2.1", "potentially_affected", "below_reported_fix"),
            ("0.2.2", "unknown", "disputed_affected_range"),
            ("0.2.9", "unknown", "disputed_affected_range"),
            ("0.2.10", "unknown", "disputed_affected_range"),
            ("0.3.0", "fixed_version_reported", "meets_reported_fix"),
            ("0.3.3", "fixed_version_reported", "meets_reported_fix"),
            ("v0.3.0", "fixed_version_reported", "meets_reported_fix"),
            ("1.0.0", "unknown", "uncovered_release_line"),
        ])

    def test_numeric_not_lexical_comparison(self):
        self.assertEqual("potentially_affected", assess_copyescape("docker-engine", "29.6.10")["copyescape_status"])
        self.assertEqual("fixed_version_reported", assess_copyescape("docker-engine", "29.10.0")["copyescape_status"])

    def test_malformed_prerelease_and_qualified_versions_are_unknown(self):
        values = ["29.7", "29", "latest", "29.7.0-rc.1", "29.7.0+vendor", "29.7.0~deb1", "29.7.0.1", "029.7.0",
                  "29.07.0", "２９.７.０", "-29.7.0", "v", "29.7.0junk", "1" * 129 + ".0.0", 29, True, "0.0.0-20260101-abcdef"]
        for component in cc.COMPONENTS:
            for value in values:
                with self.subTest(component=component, value=value):
                    self.assertEqual("unknown", assess_copyescape(component, value)["copyescape_status"])

    def test_missing_empty_and_conflicting_evidence_is_unknown(self):
        for value in ("", "   ", None):
            result = assess_copyescape("go-archive", value)
            self.assertEqual("unknown", result["copyescape_status"])
            self.assertEqual("version_not_disclosed", result["copyescape_version_status"])
        result = assess_copyescape("docker-engine", "29.7.0", version_candidates=["29.6.0"])
        self.assertEqual("conflicting_versions", result["copyescape_version_status"])
        self.assertEqual("unknown", result["copyescape_status"])
        self.assertEqual("fixed_version_reported",
                         assess_copyescape("docker-engine", "v29.7.0", version_candidates=[" 29.7.0 "])["copyescape_status"])
        self.assertEqual("unknown", assess_copyescape("docker-engine", "29.7.0", version_candidates=5)["copyescape_status"])

    def test_vendor_and_custom_builds_are_not_cleared_or_flagged(self):
        for source in ("vendor", "custom", "distro", "mystery", None):
            for version in ("29.6.0", "29.7.0"):
                with self.subTest(source=source, version=version):
                    result = assess_copyescape("docker-engine", version, build_source=source)
                    self.assertEqual("unknown", result["copyescape_status"])
                    self.assertEqual("vendor_build_unverified", result["copyescape_version_status"])
        for source in ("", "unknown", "upstream", "Official", "official_upstream"):
            self.assertEqual("fixed_version_reported",
                             assess_copyescape("docker-engine", "29.7.0", build_source=source)["copyescape_status"])

    def test_unsupported_components_are_rejected(self):
        for name in ("docker-sandboxes", "sandboxes", "podman", "", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                assess_copyescape(name, "0.38.0")

    def test_preconditions_never_change_version_status(self):
        base = assess_copyescape("docker-engine", "29.6.0")["copyescape_status"]
        for flags in ({}, dict(untrusted_archive_or_container=True, copy_or_extract_path_used=True, host_write_privileges=True),
                      dict(untrusted_archive_or_container=False, copy_or_extract_path_used=False, host_write_privileges=False)):
            row = cc.build_result("x", "version", "docker-engine", "29.6.0", **flags)
            self.assertEqual(base, row.copyescape_status)
            self.assertEqual("not_tested", row.copyescape_exploitability)
        self.assertEqual("all_preconditions_reported", cc.observe_preconditions(
            untrusted_archive_or_container=True, copy_or_extract_path_used=True, host_write_privileges=True)["precondition_summary"])
        self.assertEqual("some_preconditions_not_reported", cc.observe_preconditions(host_write_privileges=False)["precondition_summary"])
        self.assertEqual("preconditions_incomplete", cc.observe_preconditions()["precondition_summary"])


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path

    def entry(self, **extra):
        return {"schema_version": 1, "component": "go-archive", "version": "0.2.1", **extra}

    def test_inventory_object_and_array(self):
        path = self.write("inv.json", json.dumps([self.entry(host_write_privileges=True), self.entry(version="0.3.0")]))
        code, out, _ = run("--inventory", str(path), "--format", "json")
        self.assertEqual(0, code)
        results = json.loads(out)["results"]
        self.assertEqual(["potentially_affected", "fixed_version_reported"], [r["copyescape_status"] for r in results])
        self.assertEqual("reported", results[0]["host_write_privileges"])
        self.assertEqual("unknown", results[0]["copy_or_extract_path_used"])

    def test_invalid_inventories_are_operational_errors(self):
        bad = [
            "[]", "{", '{"schema_version":1,"component":"go-archive","version":"0.1.0","version":"0.3.0"}',
            json.dumps(self.entry(unexpected=1)), json.dumps({**self.entry(), "schema_version": 2}),
            json.dumps({**self.entry(), "schema_version": True}), json.dumps(self.entry(host_write_privileges="yes")),
            json.dumps(self.entry(label="x" * 513)), json.dumps({"schema_version": 1, "component": "go-archive"}),
            json.dumps(self.entry(component="docker-sandboxes")), '{"schema_version":1,"component":"go-archive","version":NaN}',
            "\u0000",
        ]
        for index, text in enumerate(bad):
            with self.subTest(index=index):
                path = self.write(f"bad{index}.json", text)
                code, out, err = run("--inventory", str(path))
                self.assertEqual(2, code)
                self.assertEqual("", out)

    def test_oversized_and_overcount_inputs_are_refused(self):
        big = self.write("big.json", " " * (cc.MAX_INPUT + 1))
        self.assertEqual(2, run("--inventory", str(big))[0])
        many = self.write("many.json", json.dumps([self.entry()] * (cc.MAX_INPUTS + 1)))
        self.assertEqual(2, run("--inventory", str(many))[0])

    def test_missing_input_file_is_operational_error(self):
        self.assertEqual(2, run("--inventory", str(self.dir / "absent.json"))[0])

    def test_csv_list(self):
        path = self.write("l.csv", "component,version,label,host_write_privileges\n"
                                  "docker-desktop,4.85.0,laptop,true\ndocker-desktop,4.86.0,,\n")
        code, out, _ = run("--csv", str(path), "--format", "json")
        self.assertEqual(0, code)
        results = json.loads(out)["results"]
        self.assertEqual(["potentially_affected", "fixed_version_reported"], [r["copyescape_status"] for r in results])
        self.assertEqual("reported", results[0]["host_write_privileges"])

    def test_invalid_csv_lists_are_operational_errors(self):
        for text in ("version\n1.0.0\n", "component,version,bogus\na,b,c\n", "component,version\ngo-archive\n",
                     "component,version\ngo-archive,0.1.0,extra\n", "component,version\n", "component,version,host_write_privileges\ngo-archive,0.1.0,maybe\n",
                     "component,component,version\na,b,c\n"):
            with self.subTest(text=text):
                self.assertEqual(2, run("--csv", str(self.write("b.csv", text)))[0])

    def test_version_argument_forms(self):
        self.assertEqual(2, run("--version", "29.7.0")[0])
        self.assertEqual(2, run("--version", "podman=1.0.0")[0])
        self.assertEqual(2, run()[0])
        code, out, _ = run("--version", "engine=29.7.0", "--version", "go_archive=0.2.2", "--format", "json")
        self.assertEqual(0, code)
        self.assertEqual(["fixed_version_reported", "unknown"], [r["copyescape_status"] for r in json.loads(out)["results"]])

    def test_build_source_applies_to_version_arguments(self):
        _, out, _ = run("--version", "docker-engine=29.6.0", "--build-source", "vendor", "--format", "json")
        self.assertEqual("unknown", json.loads(out)["results"][0]["copyescape_status"])


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_csv_formula_injection_is_neutralized(self):
        for payload in ("=1+1", "+cmd", "-2", "@SUM(A1)", "  =1", "\t=1", "\r=1"):
            with self.subTest(payload=payload):
                self.assertTrue(cc.csv_safe(payload).startswith("'"))
        self.assertEqual("29.7.0", cc.csv_safe("29.7.0"))
        path = self.dir / "inv.json"
        path.write_text(json.dumps({"schema_version": 1, "component": "go-archive", "version": "=cmd|' /C calc'!A0", "label": "@evil"}))
        code, out, _ = run("--inventory", str(path))
        self.assertEqual(0, code)
        rows = list(__import__("csv").DictReader(io.StringIO(out)))
        self.assertEqual("'@evil", rows[0]["label"])
        self.assertEqual("'=cmd|' /C calc'!A0", rows[0]["reported_version"])

    def test_html_is_script_free_and_escapes_values(self):
        path = self.dir / "inv.json"
        path.write_text(json.dumps({"schema_version": 1, "component": "go-archive", "version": "<script>alert(1)</script>",
                                    "label": "\"><img src=x onerror=alert(1)>", "platform": "<b>"}))
        code, out, _ = run("--inventory", str(path), "--format", "html", "--brand", "<i>Brand</i>")
        self.assertEqual(0, code)
        self.assertNotIn("<script", out.lower())
        for raw in ("<script>alert(1)</script>", "<img src=x", "<i>Brand</i>"):
            self.assertNotIn(raw, out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("&lt;i&gt;Brand&lt;/i&gt;", out)
        self.assertIn("default-src 'none'", out)
        self.assertNotRegex(out, r"(?:src|href)=['\"](?!https://)")

    def test_json_envelope_and_rows(self):
        _, out, _ = run("--version", "go-archive=0.2.1", "--format", "json")
        data = json.loads(out)
        self.assertEqual("1.0", data["schema_version"])
        self.assertEqual(cc.RULES_DATE, data["rules_as_of"])
        self.assertEqual(list(cc.TOOL_SOURCES), data["sources"])
        row = data["results"][0]
        self.assertEqual("not_tested", row["copyescape_exploitability"])
        self.assertTrue(row["copyescape_sources"])

    def test_every_format_always_reports_not_tested(self):
        args = ("--version", "docker-engine=29.6.0", "--version", "docker-engine=29.7.0", "--version", "go-archive=0.2.2")
        rows = list(__import__("csv").DictReader(io.StringIO(run(*args)[1])))
        self.assertEqual(["not_tested"] * 3, [r["copyescape_exploitability"] for r in rows])
        data = json.loads(run(*args, "--format", "json")[1])
        self.assertEqual({"not_tested"}, {r["copyescape_exploitability"] for r in data["results"]})
        page = run(*args, "--format", "html")[1]
        self.assertEqual(3, len(re.findall(r"<td><code>not_tested</code></td>", page)))

    def test_existing_output_survives_without_force(self):
        target = self.dir / "report.json"
        target.write_text("keep", encoding="utf-8")
        code, out, err = run("--version", "go-archive=0.1.0", "--format", "json", "--output", str(target))
        self.assertEqual(2, code)
        self.assertEqual("keep", target.read_text(encoding="utf-8"))
        self.assertEqual("", out)

    def test_force_replaces_with_valid_report_and_new_path_works(self):
        target = self.dir / "report.json"
        target.write_text("old", encoding="utf-8")
        self.assertEqual(0, run("--version", "go-archive=0.1.0", "--format", "json", "--output", str(target), "--force")[0])
        self.assertEqual("potentially_affected", json.loads(target.read_text(encoding="utf-8"))["results"][0]["copyescape_status"])
        fresh = self.dir / "fresh.csv"
        self.assertEqual(0, run("--version", "go-archive=0.1.0", "--output", str(fresh))[0])
        self.assertTrue(fresh.is_file())
        self.assertEqual([], [p for p in self.dir.iterdir() if p.name.startswith(".copyescape-")])

    def test_input_files_and_missing_directory_cannot_be_output(self):
        path = self.dir / "inv.json"
        content = json.dumps({"schema_version": 1, "component": "go-archive", "version": "0.1.0"})
        path.write_text(content, encoding="utf-8")
        self.assertEqual(2, run("--inventory", str(path), "--output", str(path), "--force")[0])
        self.assertEqual(content, path.read_text(encoding="utf-8"))
        self.assertEqual(2, run("--inventory", str(path), "--output", str(self.dir / "nodir" / "x.json"))[0])

    def test_exit_codes_distinguish_findings_from_errors(self):
        self.assertEqual(0, run("--version", "go-archive=0.1.0")[0])
        self.assertEqual(1, run("--version", "go-archive=0.1.0", "--fail-on-finding")[0])
        self.assertEqual(0, run("--version", "go-archive=0.2.2", "--version", "go-archive=0.3.0", "--fail-on-finding")[0])
        self.assertEqual(2, run("--version", "nope=1", "--fail-on-finding")[0])

    def test_help_and_tool_version_are_real(self):
        code, out, _ = run("--help")
        self.assertEqual(0, code)
        for text in ("--inventory", "--csv", "--fail-on-finding", "exit status"):
            self.assertIn(text, out)
        self.assertEqual(0, run("--tool-version")[0])

    def test_offline_modules_only(self):
        source = Path(cc.__file__).read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(?:import|from)\s+(?:socket|urllib|http|ssl|requests|subprocess)\b")


if __name__ == "__main__":
    unittest.main()
