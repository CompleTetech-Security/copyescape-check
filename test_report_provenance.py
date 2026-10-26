"""Offline report provenance and interruption-context regressions."""
import contextlib
import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import copyescape_check as checker


class ReportProvenanceTests(unittest.TestCase):
    stamp = "2026-10-26T03:00:00+00:00"

    def test_context_matches_formats_rows_and_empty_summaries(self):
        result = checker.asdict(checker.parse_version_argument("docker-engine=29.7.0", "unknown"))
        original = [*checker.Result.__dataclass_fields__, "complete", "record_type"]
        for rows in ([result, result], []):
            for complete in (True, False):
                streams = {fmt: io.StringIO() for fmt in ("csv", "json", "html")}
                for fmt, stream in streams.items():
                    checker.write_report(stream, rows, format=fmt, complete=complete, generated_at=self.stamp)
                parsed = list(csv.DictReader(io.StringIO(streams["csv"].getvalue())))
                header = next(csv.reader(io.StringIO(streams["csv"].getvalue())))
                self.assertEqual(original, header[:len(original)])
                self.assertEqual(max(1, len(rows)), len(parsed))
                for row in parsed:
                    self.assertEqual("copyescape-check", row["tool"])
                    self.assertEqual(checker.TOOL_VERSION, row["tool_version"])
                    self.assertEqual(self.stamp, row["generated_at"])
                    self.assertEqual(str(complete).lower(), row["complete"])
                self.assertEqual(self.stamp, json.loads(streams["json"].getvalue())["generated_at"])
                self.assertIn(self.stamp, streams["html"].getvalue())

    def test_cli_recovery_reuses_one_timezone_aware_run_context(self):
        real_save = checker.save_report
        for fmt in ("csv", "json", "html"):
            calls = []
            def interrupt_once(path, rows, **options):
                calls.append(options.copy())
                if len(calls) == 1:
                    raise KeyboardInterrupt
                return real_save(path, rows, **options)
            output = io.StringIO()
            with patch.object(checker, "save_report", side_effect=interrupt_once), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = checker.main(["--version", "docker-engine=29.7.0", "--format", fmt])
            self.assertEqual(130, code)
            self.assertEqual(2, len(calls))
            self.assertEqual(calls[0]["generated_at"], calls[1]["generated_at"])
            self.assertEqual(timezone.utc, datetime.fromisoformat(calls[1]["generated_at"]).tzinfo)
            self.assertFalse(calls[1]["complete"])
            self.assertIn(calls[1]["generated_at"], output.getvalue())

    def test_run_identity_is_authoritative_and_csv_safe(self):
        result = checker.asdict(checker.parse_version_argument("docker-engine=29.7.0", "unknown"))
        result.update(tool="=private", tool_version="@private", generated_at="private", label="=synthetic")
        output = io.StringIO()
        checker.write_report(output, [result], generated_at=self.stamp)
        row = next(csv.DictReader(io.StringIO(output.getvalue())))
        self.assertEqual("copyescape-check", row["tool"])
        self.assertEqual(checker.TOOL_VERSION, row["tool_version"])
        self.assertEqual(self.stamp, row["generated_at"])
        self.assertEqual("'=synthetic", row["label"])
        second = io.StringIO()
        checker.write_report(second, [], generated_at="2026-10-26T03:00:01+00:00")
        self.assertNotEqual(row["generated_at"], next(csv.DictReader(io.StringIO(second.getvalue())))["generated_at"])

    def test_first_and_later_conversion_interrupt_preserves_all_completed_inputs(self):
        original = checker.asdict
        for fmt in ("csv", "json", "html"):
            for interrupt_at in (1, 2):
                with self.subTest(format=fmt, interrupt_at=interrupt_at):
                    calls = []
                    def convert(row):
                        calls.append(1)
                        if len(calls) == interrupt_at:
                            raise KeyboardInterrupt
                        return original(row)
                    output = io.StringIO()
                    with patch.object(checker, "asdict", side_effect=convert), \
                         contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                        code = checker.main(["--version", "docker-engine=29.7.0", "--version", "go-archive=0.3.0", "--format", fmt])
                    self.assertEqual(130, code)
                    text = output.getvalue()
                    if fmt == "json":
                        report = json.loads(text)
                        self.assertFalse(report["complete"])
                        self.assertEqual(2, len(report["results"]))
                    elif fmt == "csv":
                        records = list(csv.DictReader(io.StringIO(text)))
                        self.assertEqual(2, len(records))
                        self.assertTrue(all(row["complete"] == "false" for row in records))
                    else:
                        self.assertEqual(1, text.count("<!doctype html>"))
                        self.assertIn("Interrupted run", text)
                        self.assertIn("docker-engine", text)
                        self.assertIn("go-archive", text)

    def test_conversion_recovery_is_bounded_and_preserves_output_protection(self):
        original = checker.asdict
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            target.write_text("previous report", encoding="utf-8")
            with patch.object(checker, "asdict", side_effect=KeyboardInterrupt) as convert, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = checker.main(["--version", "docker-engine=29.7.0", "--output", str(target), "--force"])
            self.assertEqual(130, code)
            self.assertEqual(2, convert.call_count)
            self.assertEqual("previous report", target.read_text(encoding="utf-8"))
            target.unlink()
            calls = []
            def competing_output(row):
                calls.append(1)
                if len(calls) == 1:
                    target.write_text("concurrent report", encoding="utf-8")
                    raise KeyboardInterrupt
                return original(row)
            with patch.object(checker, "asdict", side_effect=competing_output), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = checker.main(["--version", "docker-engine=29.7.0", "--output", str(target)])
            self.assertEqual(2, code)
            self.assertEqual("concurrent report", target.read_text(encoding="utf-8"))
            self.assertEqual(["report.json"], [p.name for p in Path(directory).iterdir()])


if __name__ == "__main__":
    unittest.main()
