# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Synthetic CLI regressions for report publication under interruption."""
import ast
import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import copyescape_check as checker

BASE = ['--version', 'docker-engine=29.7.0']
RECORD = {'schema_version': 1, 'component': 'docker-engine', 'version': '29.7.0'}
COMPLETE_COLUMN = 'complete'
CSV_FLAG = '--csv'
BEYOND = False


def run(*args, sink=None):
    output = sink if sink is not None else io.StringIO()
    error = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        try:
            code = checker.main(list(args))
        except SystemExit as exc:
            code = exc.code
    return code, output.getvalue() if hasattr(output, "getvalue") else "", error.getvalue()


class PublicationTests(unittest.TestCase):
    def test_interrupted_stdout_never_appends_a_second_report(self):
        class Sink:
            calls = 0
            def write(self, data):
                self.calls += 1
                if self.calls == 1:
                    raise KeyboardInterrupt
            def flush(self):
                pass
        for fmt in ("json", "csv", "html"):
            sink = Sink()
            code, _, _ = run(*BASE, "--format", fmt, sink=sink)
            self.assertEqual(130, code)
            self.assertEqual(1, sink.calls)

    def test_post_success_link_and_replace_interrupts_preserve_complete_report(self):
        for force in (False, True):
            with self.subTest(force=force), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/"report.json"
                if force:
                    target.write_bytes(b"previous synthetic report")
                operation = "replace" if force else "link"
                original = getattr(checker.os, operation)
                calls, published = [], []
                def publish_then_interrupt(*args, **kwargs):
                    calls.append(1)
                    original(*args, **kwargs)
                    published.append(target.read_bytes())
                    raise KeyboardInterrupt
                with patch.object(checker.os, operation, publish_then_interrupt):
                    code, output, _ = run(*BASE, "--format", "json", "--output", str(target), *(["--force"] if force else []))
                self.assertEqual(130, code)
                self.assertEqual("", output)
                self.assertEqual(1, len(calls))
                self.assertEqual(published[0], target.read_bytes())
                self.assertTrue(json.loads(target.read_text())["complete"])
                self.assertEqual(["report.json"], sorted(p.name for p in Path(directory).iterdir()))

    def test_interrupt_at_success_flag_line_is_reconciled(self):
        tree = ast.parse(Path(checker.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "save_report")
        guarded = next(node for node in ast.walk(function) if isinstance(node, ast.Try)
                       and any(isinstance(handler.type, ast.Name) and handler.type.id == "KeyboardInterrupt" for handler in node.handlers))
        flag_line = guarded.body[-1].lineno
        for force in (False, True):
            with self.subTest(force=force), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/"report.json"
                if force:
                    target.write_bytes(b"previous synthetic report")
                operation = "replace" if force else "link"
                original = getattr(checker.os, operation)
                calls, published = [], []
                def counted_publication(*args, **kwargs):
                    calls.append(1)
                    return original(*args, **kwargs)
                def trace(frame, event, argument):
                    if frame.f_code is checker.save_report.__code__ and event == "line" and frame.f_lineno == flag_line:
                        published.append(target.read_bytes())
                        sys.settrace(None)
                        raise KeyboardInterrupt
                    return trace
                try:
                    with patch.object(checker.os, operation, counted_publication):
                        sys.settrace(trace)
                        code, output, _ = run(*BASE, "--format", "json", "--output", str(target), *(["--force"] if force else []))
                finally:
                    sys.settrace(None)
                self.assertEqual(130, code)
                self.assertEqual(1, len(calls))
                self.assertEqual(published[0], target.read_bytes())
                self.assertTrue(json.loads(target.read_text())["complete"])

    def test_competing_destination_is_not_mistaken_for_our_staged_inode(self):
        _, output, _ = run(*BASE, "--format", "json")
        rows = json.loads(output)["results"]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/"report.json"
            state = {"published": False, "stdout_started": False}
            def competitor_then_interrupt(staged, destination):
                target.write_bytes(b"competing synthetic report")
                raise KeyboardInterrupt
            with patch.object(checker.os, "link", competitor_then_interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    if BEYOND:
                        checker.save_report(target, checker.render(rows, "json", True), False, state=state)
                    else:
                        checker.save_report(target, rows, force=False, state=state, format="json", complete=True)
            self.assertFalse(state["published"])
            self.assertEqual(b"competing synthetic report", target.read_bytes())
            self.assertEqual(["report.json"], sorted(p.name for p in Path(directory).iterdir()))

    def test_interrupt_before_stdout_recovers_one_valid_incomplete_report(self):
        function = "render" if BEYOND else "write_report"
        original = getattr(checker, function)
        calls = []
        def interrupted(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise KeyboardInterrupt
            return original(*args, **kwargs)
        with patch.object(checker, function, interrupted):
            code, output, _ = run(*BASE, "--format", "json")
        self.assertEqual(130, code)
        self.assertFalse(json.loads(output)["complete"])
        self.assertEqual(1, len(json.loads(output)["results"]))


class CsvTests(unittest.TestCase):
    def test_nul_inventory_csv_fails_before_stdout_new_or_force_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory)/"synthetic.json", Path(directory)/"report.csv"
            source.write_text(json.dumps(dict(RECORD, label="synthetic\x00=1+1")))
            for mode in ("stdout", "new", "force"):
                args = [] if mode == "stdout" else ["--output", str(target)]
                if mode == "force":
                    target.write_bytes(b"previous synthetic report")
                    args += ["--force"]
                code, output, error = run("--inventory", str(source), "--format", "csv", *args)
                self.assertEqual(2, code)
                self.assertEqual("", output)
                self.assertNotIn("Traceback", error)
                if mode == "force":
                    self.assertEqual(b"previous synthetic report", target.read_bytes())
                else:
                    self.assertFalse(target.exists())
                self.assertEqual(["report.csv", "synthetic.json"] if mode == "force" else ["synthetic.json"], sorted(p.name for p in Path(directory).iterdir()))

    def test_nul_csv_input_is_rejected_portably(self):
        if CSV_FLAG is None:
            self.skipTest("This checker has no CSV input mode")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"synthetic.csv"
            record = dict(RECORD, label="synthetic\x00=1+1")
            record.pop("schema_version")
            with source.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(record))
                writer.writeheader()
                # Bypass Python 3.10's CSV writer NUL rejection to exercise the loader.
            source.write_text(",".join(record) + "\n" + ",".join(str(v) for v in record.values()) + "\n")
            code, output, error = run(CSV_FLAG, str(source), "--format", "json")
            self.assertEqual(2, code)
            self.assertEqual("", output)
            self.assertNotIn("Traceback", error)

    def test_mixed_whitespace_formula_prefix_is_neutralized_in_cli_report(self):
        for label in ("\u00a0=1+1", " \u00a0@synthetic", " \t=1+1", "\v=1+1"):
            with self.subTest(label=repr(label)), tempfile.TemporaryDirectory() as directory:
                source = Path(directory)/"synthetic.json"
                source.write_text(json.dumps(dict(RECORD, label=label)))
                code, output, _ = run("--inventory", str(source), "--format", "csv")
                if code == 2:  # Some input schemas reject control characters outright.
                    self.assertEqual("", output)
                    continue
                self.assertEqual(0, code)
                row = next(csv.DictReader(io.StringIO(output, newline="")))
                value = next(row[key] for key in ("label", "input_id") if key in row)
                self.assertTrue(value.startswith("'"), repr(value))
                self.assertEqual("result", row["record_type"])

    def test_empty_interruption_csv_preserves_summary_without_finding(self):
        with patch.object(checker, "load_inventory", side_effect=KeyboardInterrupt):
            code, output, _ = run("--inventory", "synthetic.json", "--format", "csv")
        rows = list(csv.DictReader(io.StringIO(output, newline="")))
        self.assertEqual(130, code)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("summary", row["record_type"])
        self.assertEqual("false", row[COMPLETE_COLUMN])
        self.assertTrue(any(key.endswith("exploitability") and value == "not_tested" for key, value in row.items()))
        self.assertTrue(row["schema_version"])
        self.assertFalse(any(value for key, value in row.items() if key in {"status", "copyescape_status", "docker_hub_pat_status", "version_status"}))

    def test_csv_render_errors_are_operational_and_do_not_replace_evidence(self):
        for mode in ("stdout", "new", "force"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/"report.csv"
                args = [] if mode == "stdout" else ["--output", str(target)]
                if mode == "force":
                    target.write_bytes(b"previous synthetic report")
                    args += ["--force"]
                with patch.object(checker.csv, "writer" if BEYOND else "DictWriter", side_effect=csv.Error("synthetic CSV failure")):
                    code, output, _ = run(*BASE, "--format", "csv", *args)
                self.assertEqual(2, code)
                self.assertEqual("", output)
                if mode == "force":
                    self.assertEqual(b"previous synthetic report", target.read_bytes())
                else:
                    self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
