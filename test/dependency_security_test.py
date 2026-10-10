#!/usr/bin/env python3
"""Offline policy, Go parsing, query decoding and evidence failure regressions."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dependency_security", ROOT / "scripts/dependency_security.py")
SECURITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECURITY)


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="moto-security-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = SECURITY.read_policy(ROOT)
        (self.root / SECURITY.POLICY).parent.mkdir(parents=True)
        (self.root / SECURITY.POLICY).write_text(json.dumps(self.policy), encoding="utf-8")
        self.module_text = "module example.invalid/moto\n\ngo 1.27.2\n"
        for entry in self.policy["dependencies"]:
            self.module_text += f"require {entry['module']} {entry['version']}\n"
            if "replacement" in entry:
                replacement = entry["replacement"]
                self.module_text += f"replace {entry['module']} => {replacement['module']} {replacement['version']}\n"
        self.write_module(self.module_text)
        copied = self.policy["dependencies"][2]["copied_source"]
        (self.root / SECURITY.IMPORTER).parent.mkdir(parents=True)
        self.importer = f"VERSION = {copied['version']!r}\nZIP_SHA256 = {copied['archive_sha256']!r}\n"
        (self.root / SECURITY.IMPORTER).write_text(self.importer, encoding="utf-8")

    def write_module(self, text):
        (self.root / "go.mod").write_text(text, encoding="utf-8")

    def stream(self, entry, advisory=False):
        values = [{"config": {
            "protocol_version": "v1.0.0", "scanner_name": "govulncheck",
            "scanner_version": self.policy["scanner_version"], "scan_mode": "query",
            "db": SECURITY.DATABASE, "db_last_modified": "2026-10-09T12:00:00Z",
        }}, {"progress": {"message": "Looking up vulnerabilities"}}]
        if advisory:
            values.append({"osv": {"id": "GO-2026-1234", "affected": [{"package": {
                "name": entry["advisory"]["module"], "ecosystem": "Go",
            }}]}})
        return "\n".join(json.dumps(value) for value in values) + "\n"

    def parse(self, text):
        return SECURITY.parse_query(text, self.policy["dependencies"][0], self.policy["scanner_version"])

    def test_offline_go_parser_accepts_exact_and_quoted_remote_pins(self):
        before = (self.root / "go.mod").read_bytes()
        SECURITY.check_boundary(self.root, self.policy)
        self.assertEqual((self.root / "go.mod").read_bytes(), before)
        self.write_module(self.module_text.replace("github.com/cppla/utls", '"github.com/cppla/utls"'))
        SECURITY.check_boundary(self.root, self.policy)
        self.assertFalse((self.root / "go.sum").exists())

    def test_changed_missing_local_scoped_and_duplicate_replacements_fail(self):
        entry = self.policy["dependencies"][0]
        replacement = entry["replacement"]
        line = f"replace {entry['module']} => {replacement['module']} {replacement['version']}"
        bad = [
            "", line.replace(replacement["version"], "v1.0.0"),
            line.replace(replacement["module"], "github.com/other/utls"),
            f"replace {entry['module']} => ../utls",
            f'replace "{entry["module"]}" => "../utls"',
            line.replace(" =>", " " + entry["version"] + " =>"),
            line + "\n" + line.replace(" =>", " " + entry["version"] + " =>"),
        ]
        for value in bad:
            with self.subTest(replacement=value):
                self.write_module(self.module_text.replace(line, value))
                with self.assertRaises(ValueError):
                    SECURITY.check_boundary(self.root, self.policy)

    def test_baseline_and_duplicate_module_identities_fail(self):
        utls = self.policy["dependencies"][0]
        cases = [
            self.module_text.replace(utls["version"], "v1.8.2"),
            self.module_text + f"require {utls['replacement']['module']} {utls['replacement']['version']}\n",
            self.module_text + f"require {utls['module']}/submodule v1.0.0\n",
            self.module_text + f"replace {utls['module']}/submodule => ../utls\n",
            self.module_text + "replace golang.org/x/net => ../net\n",
            self.module_text + f"replace example.invalid/other => {utls['replacement']['module']} {utls['replacement']['version']}\n",
        ]
        for text in cases:
            with self.subTest(module=text):
                self.write_module(text)
                with self.assertRaises(ValueError):
                    SECURITY.check_boundary(self.root, self.policy)

    def test_unrelated_dependency_is_not_prohibited(self):
        self.write_module(self.module_text + "require example.invalid/other v1.2.3\nreplace github.com/cppla/utls-extra => example.invalid/other v1.2.3\n")
        SECURITY.check_boundary(self.root, self.policy)

    def test_copied_source_version_hash_and_duplicate_constants_fail(self):
        for text in (self.importer.replace("v0.60.0", "v0.59.0"),
                     self.importer.replace("052e0453", "152e0453"),
                     self.importer + "VERSION = 'v0.60.0'\n"):
            (self.root / SECURITY.IMPORTER).write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                SECURITY.check_boundary(self.root, self.policy)

    def test_policy_rejects_missing_baselines_unknown_fields_and_mutable_pins(self):
        changes = [
            lambda p: p["dependencies"].pop(),
            lambda p: p.update(ignore_advisories=True),
            lambda p: p["dependencies"][0]["replacement"].update(version="main"),
            lambda p: p["dependencies"][2]["advisory"].update(version="v0.59.0"),
            lambda p: p["dependencies"][0]["advisory"].update(module="github.com/cppla/utls"),
        ]
        for change in changes:
            policy = copy.deepcopy(self.policy)
            change(policy)
            (self.root / SECURITY.POLICY).write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaises(ValueError):
                SECURITY.read_policy(self.root)
        with self.assertRaises(ValueError):
            SECURITY.json_document('{"version": 1, "version": 2}')

    def test_valid_query_retains_candidates(self):
        entry = self.policy["dependencies"][0]
        self.assertEqual(self.parse(self.stream(entry))[0], [])
        self.assertEqual(self.parse(self.stream(entry, advisory=True))[0], ["GO-2026-1234"])

    def test_query_rejects_empty_truncated_duplicate_and_unknown_output(self):
        valid = self.stream(self.policy["dependencies"][0])
        bad = ["", " \n", "<html>bad gateway</html>", "[]", valid + "{", valid + '{"finding": {}}',
               valid + '{"osv": null}', valid + '{"osv": {"id": "GO-2026-1"}}',
               valid + '{"progress": {}, "osv": {}}',
               valid.replace('"scan_mode": "query"', '"scan_mode": "source"'),
               valid.replace('"scan_mode": "query"', '"scan_mode": "source", "scan_mode": "query"'),
               valid.replace(SECURITY.DATABASE, "https://example.invalid"),
               valid.replace('"v1.0.0"', '"v2.0.0"'),
               valid + '{"progress": {"message": NaN}}']
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self.parse(text)

    def test_advisories_cannot_be_for_an_unrelated_module(self):
        text = self.stream(self.policy["dependencies"][0], advisory=True)
        with self.assertRaises(ValueError):
            self.parse(text.replace("github.com/refraction-networking/utls", "example.invalid/other"))

    def fake_queries(self, outcomes):
        def run(command, **kwargs):
            if command[1] == "install":
                return subprocess.CompletedProcess(command, 0)
            query = command[-1]
            entry = next(item for item in self.policy["dependencies"] if query == item["advisory"]["module"] + "@" + item["advisory"]["version"])
            output, code = outcomes(entry)
            kwargs["stdout"].write(output.encode())
            kwargs["stderr"].write(b"diagnostic evidence\n")
            return subprocess.CompletedProcess(command, code)
        return run

    def query(self, outcomes):
        with mock.patch.object(SECURITY, "check_boundary"), mock.patch.object(
            SECURITY.subprocess, "run", side_effect=self.fake_queries(outcomes)
        ), mock.patch("builtins.print"):
            status = SECURITY.query_upstreams(self.root, self.root / "evidence")
        directories = list((self.root / "evidence").iterdir())
        self.assertEqual(len(directories), 1)
        evidence = directories[0]
        summary = json.loads((evidence / "summary.json").read_text())
        return status, evidence, summary

    def test_no_candidates_succeeds_with_three_original_queries(self):
        status, evidence, summary = self.query(lambda entry: (self.stream(entry), 0))
        self.assertEqual(status, 0)
        self.assertEqual(summary["status"], "no_candidates")
        self.assertEqual(len(summary["queries"]), 3)
        self.assertTrue((evidence / "baselines.json").is_file())

    def test_candidates_stop_gate_without_discarding_raw_evidence(self):
        status, evidence, summary = self.query(lambda entry: (self.stream(entry, advisory=True), 0))
        self.assertEqual(status, 1)
        self.assertEqual(len(summary["queries"]), 3)
        for entry, result in zip(self.policy["dependencies"], summary["queries"]):
            self.assertEqual(result["status"], "review_required")
            self.assertEqual(result["advisories"], ["GO-2026-1234"])
            self.assertEqual((evidence / (entry["id"] + ".json")).read_text(), self.stream(entry, advisory=True))
            self.assertEqual((evidence / (entry["id"] + ".stderr")).read_text(), "diagnostic evidence\n")

    def test_failed_or_malformed_query_does_not_skip_remaining_queries(self):
        outcomes = {"utls": ("partial raw failure", 7), "quic": ("not json", 0)}
        status, evidence, summary = self.query(lambda entry: outcomes.get(entry["id"], (self.stream(entry), 0)))
        self.assertEqual(status, 1)
        self.assertEqual([item["status"] for item in summary["queries"]], ["failed", "failed", "no_candidates"])
        self.assertEqual((evidence / "utls.json").read_text(), "partial raw failure")
        self.assertEqual(summary["queries"][0]["exit_code"], 7)

    def test_install_failure_retains_failed_summary(self):
        with mock.patch.object(SECURITY, "check_boundary"), mock.patch.object(
            SECURITY.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)
        ), mock.patch("builtins.print"):
            status = SECURITY.query_upstreams(self.root, self.root / "evidence")
        self.assertEqual(status, 1)
        summary = json.loads(next((self.root / "evidence").glob("*/summary.json")).read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["queries"], [])
        self.assertIn("installation failed", summary["error"])

    def test_query_timeout_preserves_partial_output_and_continues(self):
        ordinary = self.fake_queries(lambda entry: (self.stream(entry), 0))

        def run(command, **kwargs):
            if command[-1].startswith("github.com/refraction-networking/utls@"):
                kwargs["stdout"].write(b"partial timeout output")
                raise subprocess.TimeoutExpired(command, 90)
            return ordinary(command, **kwargs)

        with mock.patch.object(SECURITY, "check_boundary"), mock.patch.object(
            SECURITY.subprocess, "run", side_effect=run
        ), mock.patch("builtins.print"):
            status = SECURITY.query_upstreams(self.root, self.root / "evidence")
        self.assertEqual(status, 1)
        evidence = next((self.root / "evidence").iterdir())
        summary = json.loads((evidence / "summary.json").read_text())
        self.assertEqual([item["status"] for item in summary["queries"]], ["failed", "no_candidates", "no_candidates"])
        self.assertEqual((evidence / "utls.json").read_text(), "partial timeout output")


if __name__ == "__main__":
    unittest.main()
