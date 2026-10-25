"""Synthetic shell/YAML candidate fixtures; no Docker invocation."""
import contextlib
import csv
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import copyescape_check as c


class WorkflowTests(unittest.TestCase):
    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            result = c.main(list(args))
        return result, out.getvalue(), err.getvalue()

    def scan(self, text, yaml=False):
        return c.scan_workflow_text(text, "ci/build.yml" if yaml else "scripts/copy.sh", yaml=yaml)

    def test_spellings_and_copy_directions_without_runtime_preconditions(self):
        for command, direction in [
            ("docker cp container:/data ./out", "container_to_host_candidate"),
            ("docker container cp ./input container:/data", "host_to_container_candidate"),
            ("docker cp -a -L container:/data ./out", "container_to_host_candidate"),
            ("docker cp --quiet container:/data ./out", "container_to_host_candidate"),
            ("docker cp container:/data -", "stream_candidate"),
            ("docker cp - container:/data", "stream_candidate"),
            ("docker cp '$CONTAINER:/data' ./out", "unknown"),
            ("docker cp container:/data $DEST", "unknown"),
            ("docker cp --future-flag container:/data ./out", "unknown"),
            ("docker cp c:/data d:/data", "unknown"),
        ]:
            with self.subTest(command=command):
                row = self.scan(command)[0]
                self.assertEqual(direction, row.source_direction)
                self.assertEqual("unknown", row.copyescape_status)
                self.assertEqual("not_tested", row.copyescape_exploitability)
                self.assertEqual("unknown", row.copy_or_extract_path_used)
                self.assertEqual("unknown", row.untrusted_archive_or_container)

    def test_comments_echo_wrappers_and_aliases_do_not_prove_invocation(self):
        for source in ["# docker cp container:/data ./out", "echo 'docker cp container:/data ./out'", "sudo docker cp container:/data ./out", "dcp container:/data ./out", "docker --context prod cp container:/data ./out"]:
            with self.subTest(source=source):
                row = self.scan(source)[0]
                self.assertEqual("source_coverage", row.copyescape_evidence_type)
                self.assertEqual("unknown", row.source_direction)

    def test_shell_sequences_and_line_continuations_have_relative_locations(self):
        rows = self.scan("echo ready && docker cp c:/data ./out\n\ndocker container \\\ncp ./input ctr:/data\n")
        self.assertEqual([1, 3], [r.source_line for r in rows])
        self.assertEqual(["docker cp", "docker container cp"], [r.source_spelling for r in rows])
        self.assertEqual("host_to_container_candidate", rows[1].source_direction)

    def test_yaml_run_plain_and_block_only_without_parsing_other_keys(self):
        source = """steps:
  - name: docker cp should not be a command
    env:
      NOTE: docker cp container:/secret ./out
    run: |
      # docker cp container:/comment ./out
      docker cp container:/data ./out
  - run: docker container cp ./input container:/data
  - name: done
    description: docker cp container:/text ./out
"""
        rows = self.scan(source, yaml=True)
        self.assertEqual(2, len(rows))
        self.assertEqual([7, 8], [r.source_line for r in rows])
        self.assertEqual(["container_to_host_candidate", "host_to_container_candidate"], [r.source_direction for r in rows])

    def test_no_source_contents_or_operands_in_report(self):
        row = self.scan("docker cp SECRET-CONTAINER:/PRIVATE-FILE ./PRIVATE-OUTPUT")[0]
        data = json.dumps(asdict(row))
        for secret in ["SECRET-CONTAINER", "PRIVATE-FILE", "PRIVATE-OUTPUT"]:
            self.assertNotIn(secret, data)

    def test_client_engine_desktop_versions_do_not_clear_each_other(self):
        args = ["--version", "docker-client=29.6.2", "--version", "docker-engine=29.7.0", "--version", "docker-desktop=4.86.0", "--format", "json"]
        code, out, _ = self.cli(*args)
        self.assertEqual(0, code)
        rows = json.loads(out)["results"]
        self.assertEqual(["docker-cli", "docker-engine", "docker-desktop"], [r["component"] for r in rows])
        self.assertEqual(["potentially_affected", "fixed_version_reported", "fixed_version_reported"], [r["copyescape_status"] for r in rows])

    def test_docker_version_exports_keep_engine_client_and_runtime_components_separate(self):
        fixtures = [
            json.dumps({"Client": {"Version": "29.6.2", "Context": "PRIVATE-CONTEXT"}, "Server": {"Version": "29.7.0", "Components": [{"Name": "Engine", "Version": "29.7.0"}, {"Name": "containerd", "Version": "9.9.9"}]}}),
            "Client: Docker Engine - Community\n Version: 29.6.2\n Context: PRIVATE-CONTEXT\nServer: Docker Desktop 4.86.0\n Engine:\n  Version: 29.7.0\n containerd:\n  Version: 9.9.9\n runc:\n  Version: 1.0.0\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "version.txt"
            for fixture in fixtures:
                path.write_text(fixture, encoding="utf-8")
                code, out, _ = self.cli("--docker-version", str(path), "--format", "json")
                self.assertEqual(0, code)
                rows = json.loads(out)["results"]
                self.assertEqual(["docker-cli", "docker-engine"], [r["component"] for r in rows])
                self.assertEqual(["29.6.2", "29.7.0"], [r["reported_version"] for r in rows])
                self.assertEqual(["potentially_affected", "fixed_version_reported"], [r["copyescape_status"] for r in rows])
                for private in ["PRIVATE-CONTEXT", "9.9.9", "4.86.0", directory]:
                    self.assertNotIn(private, out)

    def test_export_conflicts_missing_server_and_invalid_json_keep_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "version.json"
            path.write_text(json.dumps({"Client": {"Version": "29.7.0"}, "Server": {"Version": "29.7.0", "Components": [{"Name": "Engine", "Version": "29.6.2"}]}}), encoding="utf-8")
            code, out, _ = self.cli("--docker-version", str(path), "--format", "json")
            row = json.loads(out)["results"][1]
            self.assertEqual("unknown", row["copyescape_status"])
            self.assertEqual(["29.6.2", "29.7.0"], row["version_candidates"])
            path.write_text('{"Client":{"Version":"29.7.0"},"Server":null}', encoding="utf-8")
            _, out, _ = self.cli("--docker-version", str(path), "--format", "json")
            self.assertEqual("unknown", json.loads(out)["results"][1]["copyescape_status"])
            for text in ['{"Client":{"Version":true}}', '{"Client":{},"Client":{}}', '{"Client":{},"x":NaN}']:
                path.write_text(text, encoding="utf-8")
                code, out, _ = self.cli("--docker-version", str(path), "--format", "json")
                self.assertEqual((2, ""), (code, out))
            self.assertEqual(2, self.cli("--docker-version", str(path), "--output", str(path), "--force")[0])

    def test_explicit_source_root_output_protection_and_standalone_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "copy.sh"
            source = "docker cp container:/data ./out\n"
            path.write_text(source, encoding="utf-8")
            args = ["--source", str(path), "--source-root", directory]
            self.assertEqual(2, self.cli("--source", str(path))[0])
            self.assertEqual(2, self.cli(*args, "--output", str(path), "--force")[0])
            alias = root / "alias.sh"
            os.link(path, alias)
            self.assertEqual(2, self.cli(*args, "--output", str(alias), "--force")[0])
            self.assertEqual(source, path.read_text(encoding="utf-8"))
            code, out, _ = self.cli(*args, "--format", "json")
            self.assertEqual(0, code)
            self.assertNotIn(directory, out)
            self.assertEqual("copy.sh", json.loads(out)["results"][0]["source_path"])
            _, out, _ = self.cli(*args, "--format", "csv")
            self.assertEqual("container_to_host_candidate", list(csv.DictReader(io.StringIO(out)))[0]["source_direction"])
            _, out, _ = self.cli(*args, "--format", "html")
            self.assertIn("copy.sh:1", out)
            checker = root / "checker.py"
            checker.write_bytes(Path(c.__file__).read_bytes())
            process = subprocess.run([sys.executable, str(checker), *args, "--format", "json"], capture_output=True, text=True, check=True)
            self.assertEqual("docker cp", json.loads(process.stdout)["results"][0]["source_spelling"])

    def test_bounds_regular_files_and_no_docker_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "copy.sh"
            path.write_text("docker cp container:/data ./out", encoding="utf-8")
            with patch.object(subprocess, "run", side_effect=AssertionError("no execution")):
                self.assertEqual(0, self.cli("--source", str(path), "--source-root", directory)[0])
            path.write_bytes(b" " * (c.MAX_INPUT + 1))
            self.assertEqual(2, self.cli("--source", str(path), "--source-root", directory)[0])
            if hasattr(os, "mkfifo"):
                fifo = root / "pipe.sh"
                os.mkfifo(fifo)
                self.assertEqual(2, self.cli("--source", str(fifo), "--source-root", directory)[0])


if __name__ == "__main__":
    unittest.main()
