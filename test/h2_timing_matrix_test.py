#!/usr/bin/env python3
"""Offline subprocess mocks for matrix bounds, interruption and evidence saving."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("h2_timing_matrix", Path(__file__).with_name("h2_timing_matrix.py"))
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
EVIDENCE = {"streams": [], "lost_ping": False, "recovery_ok": True}
OUTPUT = MATRIX.PREFIX + json.dumps(EVIDENCE) + "\n"


class FakeProcess:
    def __init__(self, on_communicate=None, stdout=OUTPUT):
        self.on_communicate = on_communicate
        self.stdout = stdout
        self.returncode = None
        self.terminated = False
        self.killed = False

    def communicate(self, timeout):
        if self.on_communicate and not self.terminated and not self.killed:
            self.on_communicate()
        if self.returncode is None:
            self.returncode = 0
        return self.stdout, ""

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        return self.returncode


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="moto-matrix-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("binary", "config", "ca"):
            (self.root / name).touch()
        self.output = self.root / "reports"
        self.arguments = ["--binary", str(self.root / "binary"), "--config", str(self.root / "config"),
                          "--ca", str(self.root / "ca"), "--destination", "origin.invalid:443",
                          "--output", str(self.output), "--targets", "0", "--profiles", "normal", "--workers", "1"]
        self.handlers = {}

    def register_signal(self, signum, handler):
        previous = self.handlers.get(signum, signal.SIG_DFL)
        self.handlers[signum] = handler
        return previous

    def invoke(self, popen=None, cleanup=None, timings=None):
        popen = popen or (lambda *_args, **_kwargs: FakeProcess())
        if cleanup is None:
            cleanup = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(MATRIX.subprocess, "Popen", side_effect=popen) as launched, \
                mock.patch.object(MATRIX.subprocess, "run", side_effect=cleanup if callable(cleanup) else None,
                                  return_value=cleanup) as removed, \
                mock.patch.object(MATRIX.signal, "signal", side_effect=self.register_signal), \
                mock.patch.object(MATRIX, "TIMINGS", timings or [(15, 10)]), \
                contextlib.redirect_stdout(io.StringIO()):
            code = MATRIX.main(self.arguments)
        self.assertEqual(self.handlers[signal.SIGTERM], signal.SIG_DFL)
        self.assertEqual(self.handlers[signal.SIGINT], signal.SIG_DFL)
        self.summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(set(self.summary), {"planned", "completed", "valid", "elapsed_seconds", "results"})
        self.assertEqual(self.summary["completed"], len(self.summary["results"]))
        for result in self.summary["results"]:
            job = result["job"]
            label = f"r{job['repetition']}-t{job['target']}-{job['profile']}-{job['idle']}-{job['ping']}"
            self.assertEqual(json.loads((self.output / f"{label}.json").read_text()), result)
        names = {call.args[0][call.args[0].index("--name") + 1] for call in launched.call_args_list}
        for call in removed.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:3], ["docker", "rm", "-f"])
            self.assertEqual(len(command), 4)
            self.assertIn(command[3], names)
        return code, launched, removed

    def test_normal_results_keep_existing_schema_and_evidence(self):
        code, launched, removed = self.invoke()
        self.assertEqual(code, 0)
        self.assertEqual(launched.call_count, 1)
        self.assertEqual(removed.call_count, 1)
        self.assertEqual(self.summary["valid"], 1)
        result = self.summary["results"][0]
        self.assertEqual(set(result), {"job", "runner_ok", "exit_code", "evidence", "elapsed_seconds"})
        self.assertEqual(result["evidence"], EVIDENCE)
        plan = json.loads((self.output / "plan.json").read_text())
        self.assertEqual(plan["outage_after_seconds"], 9.5)
        self.assertIn("MOTO_H2_REAL_OUTAGE_AFTER_SECONDS=9.5", launched.call_args.args[0])

    def test_custom_outage_phase_is_recorded_and_forwarded(self):
        self.arguments += ["--outage-after", "13.25"]
        code, launched, _ = self.invoke()
        self.assertEqual(code, 0)
        plan = json.loads((self.output / "plan.json").read_text())
        self.assertEqual(set(plan), {"seed", "workers", "outage_after_seconds", "jobs"})
        self.assertEqual(plan["outage_after_seconds"], 13.25)
        self.assertIn("MOTO_H2_REAL_OUTAGE_AFTER_SECONDS=13.25", launched.call_args.args[0])

    def test_outage_phase_accepts_inclusive_bounds(self):
        for phase in (0, 20):
            with self.subTest(phase=phase):
                self.output = self.root / f"reports-{phase}"
                self.arguments[self.arguments.index("--output") + 1] = str(self.output)
                original = self.arguments[:]
                self.arguments += ["--outage-after", str(phase)]
                code, launched, _ = self.invoke()
                self.arguments = original
                self.assertEqual(code, 0)
                self.assertIn(f"MOTO_H2_REAL_OUTAGE_AFTER_SECONDS={float(phase)}", launched.call_args.args[0])

    def test_invalid_outage_phase_rejected_before_output_or_docker(self):
        for phase in ("-0.001", "20.001", "nan", "inf", "-inf", "not-a-number"):
            with self.subTest(phase=phase), mock.patch.object(MATRIX.subprocess, "Popen") as launched, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                MATRIX.main(self.arguments + [f"--outage-after={phase}"])
            self.assertEqual(failure.exception.code, 2)
            launched.assert_not_called()
            self.assertFalse(self.output.exists())

    def test_sigterm_stops_queued_jobs_and_saves_interrupted_case(self):
        self.check_signal(signal.SIGTERM)

    def test_sigint_stops_queued_jobs_and_saves_interrupted_case(self):
        self.check_signal(signal.SIGINT)

    def check_signal(self, signum):
        def interrupt():
            self.handlers[signum](signum, None)
            raise subprocess.TimeoutExpired("docker", 0.2, output=OUTPUT.encode(), stderr=b"")

        process = FakeProcess(on_communicate=interrupt)
        code, launched, removed = self.invoke(popen=lambda *_a, **_kw: process, timings=MATRIX.TIMINGS)
        self.assertEqual(code, 1)
        self.assertEqual(launched.call_count, 1)
        self.assertTrue(process.terminated)
        self.assertEqual(removed.call_count, 1)
        self.assertEqual((self.summary["planned"], self.summary["completed"]), (4, 1))
        self.assertEqual(self.summary["results"][0]["runner_error"], "runner_interrupted")
        self.assertEqual(self.summary["results"][0]["evidence"], EVIDENCE)

    def test_cleanup_exception_preserves_case_log_evidence_and_summary(self):
        def unavailable(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("docker rm", 10)

        code, _, removed = self.invoke(cleanup=unavailable)
        self.assertEqual(code, 1)
        self.assertEqual(removed.call_count, 2)
        result = self.summary["results"][0]
        self.assertEqual(result["runner_error"], "container_cleanup_failed")
        self.assertEqual(result["evidence"], EVIDENCE)
        self.assertEqual((self.output / "r1-t0-normal-15-10.log").read_text(), OUTPUT)

    def test_auto_removed_container_is_not_cleanup_failure(self):
        code, _, _ = self.invoke(cleanup=subprocess.CompletedProcess([], 1, "", "Error: No such container: generated"))
        self.assertEqual(code, 0)

    def test_spawn_error_still_writes_case_and_summary(self):
        def fail(*_args, **_kwargs):
            raise OSError("subprocess failed")

        code, _, _ = self.invoke(popen=fail)
        self.assertEqual(code, 1)
        self.assertEqual(self.summary["completed"], 1)
        self.assertEqual(self.summary["results"][0]["runner_error"], "runner_error")

    def test_timeout_terminates_cli_and_retains_partial_bytes_output(self):
        def timeout():
            raise subprocess.TimeoutExpired("docker", 0.2, output=OUTPUT.encode(), stderr=b"partial")

        process = FakeProcess(on_communicate=timeout)
        # A controlled clock makes the case timeout immediate without real sleeps.
        with mock.patch.object(MATRIX.time, "monotonic", side_effect=[0, 0, 106]):
            with mock.patch.object(MATRIX.subprocess, "Popen", return_value=process):
                code, stdout, _, error = MATRIX.run_command(["docker", "run"], MATRIX.StopRequest())
        self.assertEqual(error, "runner_timeout")
        self.assertEqual(code, -15)
        self.assertEqual(stdout, OUTPUT)
        self.assertTrue(process.terminated)

    def test_stop_before_start_does_not_launch_subprocess(self):
        stop = MATRIX.StopRequest()
        stop.set()
        with mock.patch.object(MATRIX.subprocess, "Popen") as launched:
            result = MATRIX.run_command(["docker", "run"], stop)
        launched.assert_not_called()
        self.assertEqual(result[-1], "runner_interrupted")

    def test_unresponsive_cli_is_killed_after_terminate(self):
        stop = MATRIX.StopRequest()

        class UnresponsiveProcess(FakeProcess):
            def terminate(self):
                self.terminated = True

            def communicate(self, timeout):
                if not self.killed:
                    stop.set()
                    raise subprocess.TimeoutExpired("docker", timeout, output=OUTPUT.encode())
                return OUTPUT, ""

        process = UnresponsiveProcess()
        with mock.patch.object(MATRIX.subprocess, "Popen", return_value=process):
            code, stdout, _, error = MATRIX.run_command(["docker", "run"], stop)
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)
        self.assertEqual(code, -9)
        self.assertEqual(stdout, OUTPUT)
        self.assertEqual(error, "runner_interrupted")

    def test_keyboard_interrupt_drains_only_started_work(self):
        launched_event = threading.Event()

        def waiting():
            launched_event.set()
            raise subprocess.TimeoutExpired("docker", 0.2, output=OUTPUT.encode())

        def interrupt(*_args, **_kwargs):
            self.assertTrue(launched_event.wait(timeout=1))
            raise KeyboardInterrupt

        process = FakeProcess(on_communicate=waiting)
        with mock.patch.object(MATRIX.concurrent.futures, "wait", side_effect=interrupt):
            code, launched, removed = self.invoke(popen=lambda *_a, **_kw: process, timings=MATRIX.TIMINGS)
        self.assertEqual(code, 1)
        self.assertEqual(launched.call_count, 1)
        self.assertEqual(removed.call_count, 1)
        self.assertTrue(process.terminated)
        self.assertEqual(self.summary["completed"], 1)

    def test_matrix_over_384_jobs_rejected_before_output_or_docker(self):
        self.arguments[self.arguments.index("--targets") + 1] = ",".join(str(value) for value in range(97))
        with mock.patch.object(MATRIX.subprocess, "Popen") as launched, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            MATRIX.main(self.arguments)
        self.assertEqual(failure.exception.code, 2)
        launched.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
