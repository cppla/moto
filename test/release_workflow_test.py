#!/usr/bin/env python3
"""Verify release commands without transport tests or external writes."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TransportRegressionOutputTests(unittest.TestCase):
    def run_gate(self, child_exit):
        with tempfile.TemporaryDirectory(prefix="moto-output-test-") as temporary:
            directory = Path(temporary)
            child = directory / "mock_make.py"
            child.write_text(
                "import json, pathlib, sys\n"
                "pathlib.Path('invocation.json').write_text(json.dumps(sys.argv[1:]))\n"
                "print('PRIVATE_COMPARISON_STDOUT')\n"
                "print('PRIVATE_COMPARISON_STDERR', file=sys.stderr)\n"
                f"sys.exit({child_exit})\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "make", "--no-print-directory", "-f", str(ROOT / "Makefile"),
                    "transport-regression-check",
                    f"MAKE={shlex.quote(sys.executable)} {shlex.quote(str(child))}",
                ],
                cwd=directory,
                env={**os.environ, "TMPDIR": str(directory)},
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(
                json.loads((directory / "invocation.json").read_text(encoding="utf-8")),
                ["--no-print-directory", "browser-profile-check"],
            )
            self.assertNotIn("PRIVATE_COMPARISON", result.stdout + result.stderr)
            self.assertFalse(list(directory.glob("moto-transport-regression.*")))
            return result

    def test_success_is_reported_without_comparison_details(self):
        result = self.run_gate(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Transport regression checks passed.\n")
        self.assertEqual(result.stderr, "")

    def test_failure_is_preserved_without_comparison_details(self):
        result = self.run_gate(17)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("passed", result.stdout + result.stderr)
        self.assertIn("Transport regression checks failed.", result.stderr)
        self.assertIn("Reproduce locally with make browser-profile-check.", result.stderr)


class ReleasePublicationTests(unittest.TestCase):
    def run_publication(self, has_notes, child_exit=0):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Publish GitHub release\n", 1)[1]
        body = step.split("        run: |\n", 1)[1]
        commands = []
        for line in body.splitlines():
            if line.startswith("          "):
                commands.append(line[10:])
            elif not line.strip():
                commands.append("")
            else:
                break
        self.assertTrue(commands, "publication shell commands were not found")

        release = "v1.0.5"
        notes = f"packaging/release-notes/{release}.md"
        assets = sorted([
            *(f"dist/moto_{release}_{target}.tar.gz" for target in (
                "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64",
            )),
            f"dist/moto_{release}_sbom.zip",
            "dist/SHA256SUMS",
        ])
        with tempfile.TemporaryDirectory(prefix="moto-release-test-") as temporary:
            directory = Path(temporary)
            (directory / "dist").mkdir()
            for asset in assets:
                (directory / asset).write_text("release asset", encoding="utf-8")
            if has_notes:
                (directory / notes).parent.mkdir(parents=True)
                (directory / notes).write_text("upgrade instructions", encoding="utf-8")
            child = directory / "mock_gh.py"
            child.write_text(
                "import json, pathlib, sys\n"
                "pathlib.Path('invocation.json').write_text(json.dumps(sys.argv[1:]))\n"
                f"sys.exit({child_exit})\n",
                encoding="utf-8",
            )
            # A shell function shadows gh, so the workflow cannot reach GitHub.
            prefix = (
                f"gh() {{ {shlex.quote(sys.executable)} "
                f"{shlex.quote(str(child))} \"$@\"; }}\n"
            )
            result = subprocess.run(
                ["bash", "-c", prefix + "\n".join(commands)],
                cwd=directory,
                env={**os.environ, "GITHUB_REF_NAME": release, "LC_ALL": "C"},
                text=True,
                capture_output=True,
                timeout=10,
            )
            arguments = json.loads(
                (directory / "invocation.json").read_text(encoding="utf-8")
            )
        expected = ["release", "create", release, *assets, "--verify-tag"]
        expected += ["--notes-file", notes] if has_notes else ["--generate-notes"]
        expected += ["--title", release]
        self.assertEqual(arguments, expected)
        return result

    def test_versioned_notes_are_used_with_all_release_assets(self):
        result = self.run_publication(has_notes=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_notes_fall_back_to_generated_notes(self):
        result = self.run_publication(has_notes=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_publication_failure_is_preserved(self):
        for has_notes in (True, False):
            with self.subTest(has_notes=has_notes):
                result = self.run_publication(has_notes=has_notes, child_exit=17)
                self.assertEqual(result.returncode, 17, result.stderr)


if __name__ == "__main__":
    unittest.main()
