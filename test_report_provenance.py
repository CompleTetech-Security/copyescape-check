"""Offline report provenance and interruption-context regressions."""
import contextlib
import csv
from datetime import datetime, timezone
import io
import json
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


if __name__ == "__main__":
    unittest.main()
