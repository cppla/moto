#!/usr/bin/env python3
"""Offline tests for the fixed Go regression gate; no Go toolchain is invoked."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("routing_regression", Path(__file__).with_name("routing_regression.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load routing regression utility")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
NAMES = sorted([
    "TestCachedBoostReplacementHonorsCacheLifecycle",
    "TestCachedBoostLateFailureCannotDeleteNewGeneration",
    "TestCachedBoostConcurrentReplacementsHaveSingleOwner",
    "TestCachedBoostReplacementTokenCannotInvalidateLaterWinner",
    "TestFreshBoostLateReplyCannotReplaceNewWinner",
    "TestCachedBoostHitDoesNotCreateDecisionLease",
    "TestFreshBoostCacheDecisionRejectsABA",
    "TestLazyBoostRefreshCannotReplaceNewWinner",
    "TestCachedBoostHedgeDelayClampsTwiceEWMA",
    "TestCachedBoostHardFailureStartsFallbackWithoutHedgeDelay",
    "TestCachedBoostNeutralConnectFailurePreservesRuleWinner",
    "TestCachedBoostSlowPrimaryLaunchesHedgeOnSignalAndCancelsLoser",
    "TestFreshBoostSOCKS5UsesStaleExplorerInTopTwo",
    "TestFreshBoostRecoveryProbeFinishesBeforeSingleHealthyFallback",
    "TestFreshBoostTargetSaturationReturnsAttemptBudget",
    "TestRaceBoostTargetsClosesEveryLoser",
    "TestRaceBoostTargetsHonorsCancellation",
    "TestBoostProtocolCanaryGetsExclusiveSetupAndReleasesLease",
    "TestBoostProtocolCanaryFailureRefillsHealthyTarget",
    "TestSelectTargetsExcludingReservesOnePenalizedProtocolCanary",
    "TestSelectTargetsExcludingDefersProtocolPenaltyUntilHealthyAlternativesExhausted",
    "TestRouteHealthTripsAfterThreeConsecutiveFailures",
    "TestRouteHealthAllowsOnlyOneConcurrentHalfOpenProbe",
    "TestRouteHealthProbeBackoffAndRecovery",
    "TestRouteHealthCancelledProbeIsNeutralAndReleasesClaim",
    "TestRouteHealthIgnoresOutOfOrderPreCircuitResults",
    "TestHTTP3RepeatedDegradationUsesH2CooldownAndHalfOpenRecovery",
    "TestHTTP3DegradationCooldownRequiresReachableHTTP2",
    "TestHTTP3RuleBreakerDifferentIPsRequireDataPlaneProbation",
    "TestHTTP3RuleRecoveryDueEvictsH2OnlyCacheForMixedCanary",
    "TestHTTP3UDPBlackholeStaleGenerationCannotCommitCooldown",
    "TestHTTP3StreamResetClosesOrphanedPhysicalConnections",
    "TestHTTP3StreamResetPreservesActiveSibling",
    "TestHTTP3PhysicalDialCompletingDuringCloseIsClosed",
    "TestReloadRulesKeepsOldStreamAndSwitchesNewConnections",
    "TestReloadRulesRollsBackAllStagedListenersOnBindFailure",
    "TestConcurrentReloadAndConnectionsUseWholeGenerations",
    "TestHTTP2ConnectPingProductionDefaults",
    "TestHTTP2ConnectPingTimeoutClosesSharedConnectionAndReconnects",
    "TestHTTP2SharedTLSSetupFailureCountsOncePerRoute",
    "TestHTTP2IndependentSetupFailuresTripCircuit",
    "TestHTTP2SharedSetupParentCancellationIsNeutral",
    "TestHTTP2ConnectStatusFailuresAreNotSharedSetupFailures",
    "TestConnectProxySharedSetupCompositePreservesIndependentFailures",
])


def successful_events(names=NAMES, count=2):
    events = []
    for _ in range(count):
        for name in names:
            events.extend({"Action": action, "Package": RUNNER.PACKAGE, "Test": name}
                          for action in ("run", "pass"))
    events.append({"Action": "pass", "Package": RUNNER.PACKAGE})
    return events


class RoutingRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)

    def invoke(self, *, names=NAMES, events=None, returncode=0, discovery_status=0,
               discovery_error=None, run_error=None, raw=None, changed_source=False, interrupted=False):
        before = set(self.output.glob("run-*"))
        if events is None:
            events = successful_events(names)

        def fake_command(command, stdout, stderr, *, timeout=RUNNER.PROCESS_TIMEOUT):
            stderr.write_text("fixture stderr\n", encoding="utf-8")
            if "-list" in command:
                stdout.write_text("\n".join(names) + "\nok\tmoto/controller\t0.01s\n", encoding="utf-8")
                return discovery_status, discovery_error
            stdout.write_text(raw if raw is not None else "".join(json.dumps(event) + "\n" for event in events),
                              encoding="utf-8")
            if interrupted:
                raise KeyboardInterrupt()
            return returncode, run_error

        with mock.patch.object(RUNNER, "run_command", side_effect=fake_command) as execute, \
                mock.patch.object(RUNNER, "public_version", side_effect=["fixture-commit", "go version fixture"]), \
                mock.patch.object(RUNNER, "source_fingerprint", side_effect=["fixture-source-sha256",
                                  "changed-source-sha256" if changed_source else "fixture-source-sha256"]), \
                contextlib.redirect_stdout(io.StringIO()) as console:
            status = RUNNER.main(["--output", str(self.output), "--seed", "17", "--count", "2"])
        created = set(self.output.glob("run-*")) - before
        self.assertEqual(len(created), 1, "each invocation must create exactly one evidence directory")
        directory = created.pop()
        summary = json.loads((directory / "summary.json").read_text())
        return status, summary, directory, execute.call_args_list, console.getvalue()

    def test_success_records_evidence_and_exact_command(self):
        status, summary, directory, calls, console = self.invoke()
        self.assertEqual(status, 0)
        self.assertTrue(summary["passed"])
        self.assertEqual(summary["tests"], NAMES)
        self.assertEqual(summary["counts"], {name: {"run": 2, "pass": 2} for name in NAMES})
        metadata = json.loads((directory / "metadata.json").read_text())
        self.assertEqual(set(metadata), {"seed", "commands", "platform", "source_revision", "source_sha256", "go_version"})
        self.assertEqual(metadata["seed"], 17)
        self.assertEqual(metadata["source_revision"], "fixture-commit")
        self.assertEqual(metadata["source_sha256"], "fixture-source-sha256")
        self.assertEqual(metadata["commands"]["test"], ["go", "test", "-race", "-json", "-shuffle=17",
                         "-count=2", "-timeout=8m", "./controller", "-run", "^(" + "|".join(NAMES) + ")$"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].kwargs, {"timeout": 180})
        self.assertIn("Reproduce: go test -race -json -shuffle=17", console)
        self.assertEqual((directory / "stderr.log").read_text(), "fixture stderr\n")
        self.assertEqual(len((directory / "events.jsonl").read_text().splitlines()), len(successful_events()))

    def test_empty_discovery_fails_without_running_tests(self):
        status, summary, directory, calls, _ = self.invoke(names=[])
        self.assertEqual(status, 1)
        self.assertIn("no routing regression tests discovered", summary["errors"])
        self.assertEqual(len(calls), 1)
        self.assertEqual((directory / "events.jsonl").read_bytes(), b"")

    def test_missing_each_required_sentinel_fails(self):
        for missing in NAMES:
            with self.subTest(missing=missing):
                status, summary, _, calls, _ = self.invoke(names=[name for name in NAMES if name != missing])
                self.assertEqual(status, 1)
                self.assertTrue(any("missing required" in error for error in summary["errors"]))
                self.assertEqual(len(calls), 1)

    def test_fixed_selection_matches_only_the_pinned_tests(self):
        self.assertEqual(len(NAMES), 44)
        self.assertEqual(RUNNER.REQUIRED_TESTS, set(NAMES))
        for name in NAMES:
            self.assertIsNotNone(re.fullmatch(RUNNER.TEST_PATTERN, name))
            self.assertIsNone(re.fullmatch(RUNNER.TEST_PATTERN, name + "Extra"))
        for name in ("TestHTTP3NetemRuleBreakerCooldownAndDataPlaneProbation",
                     "TestHTTP2ConnectPingTCPNetemRealClock", "TestUnknown"):
            self.assertIsNone(re.fullmatch(RUNNER.TEST_PATTERN, name))

    def test_duplicate_or_extra_discovered_tests_fail_before_execution(self):
        for names, message in ((NAMES + [NAMES[0]], "duplicate top-level"),
                               (NAMES + ["TestUnexpected"], "unexpected discovered")):
            with self.subTest(message=message):
                status, summary, _, calls, _ = self.invoke(names=names)
                self.assertEqual(status, 1)
                self.assertTrue(any(message in error for error in summary["errors"]))
                self.assertEqual(len(calls), 1)

    def test_skip_or_failure_at_any_level_fails(self):
        for action in ("skip", "fail"):
            for name in (NAMES[0], NAMES[0] + "/child", ""):
                with self.subTest(action=action, name=name):
                    events = successful_events()
                    events.insert(-1, {"Action": action, "Package": RUNNER.PACKAGE, "Test": name})
                    status, summary, *_ = self.invoke(events=events)
                    self.assertEqual(status, 1)
                    self.assertTrue(any(error.startswith(action + ":") for error in summary["errors"]))

    def test_missing_or_extra_run_and_pass_counts_fail(self):
        for action in ("run", "pass"):
            for extra in (False, True):
                with self.subTest(action=action, extra=extra):
                    events = successful_events()
                    event = {"Action": action, "Package": RUNNER.PACKAGE, "Test": NAMES[0]}
                    if extra:
                        events.insert(-1, event)
                    else:
                        events.remove(event)
                    status, summary, *_ = self.invoke(events=events)
                    self.assertEqual(status, 1)
                    self.assertTrue(any("expected=2" in error for error in summary["errors"]))

    def test_missing_test_or_package_completion_fails(self):
        for events in (successful_events(NAMES[1:]), successful_events()[:-1], []):
            with self.subTest(events=len(events)):
                status, summary, *_ = self.invoke(events=events)
                self.assertEqual(status, 1)
                self.assertFalse(summary["passed"])

    def test_nonzero_exit_fails_even_with_complete_pass_events(self):
        status, summary, *_ = self.invoke(returncode=2)
        self.assertEqual(status, 1)
        self.assertEqual(summary["returncode"], 2)
        self.assertIn("test command failed: exit 2", summary["errors"])

    def test_changed_source_invalidates_successful_test_events(self):
        status, summary, *_ = self.invoke(changed_source=True)
        self.assertEqual(status, 1)
        self.assertFalse(summary["passed"])
        self.assertTrue(any("sources changed" in error for error in summary["errors"]))
        self.assertEqual(summary["source_sha256_after"], "changed-source-sha256")

    def test_interrupt_records_failed_summary_and_retains_partial_output(self):
        status, summary, directory, *_ = self.invoke(interrupted=True)
        self.assertEqual(status, 130)
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["errors"], ["runner interrupted"])
        self.assertTrue((directory / "events.jsonl").read_bytes())

    def test_invalid_json_or_event_fails(self):
        valid = "".join(json.dumps(event) + "\n" for event in successful_events())
        for invalid in ("not-json\n", "{\n", "[]\n", "{}\n", '{"Action":"run","Test":[]}\n'):
            with self.subTest(invalid=invalid):
                status, summary, *_ = self.invoke(raw=valid + invalid)
                self.assertEqual(status, 1)
                self.assertTrue(any("line" in error for error in summary["errors"]))

    def test_unlisted_top_level_test_fails(self):
        events = successful_events()
        events.insert(0, {"Action": "run", "Package": RUNNER.PACKAGE, "Test": "TestUnexpected"})
        status, summary, *_ = self.invoke(events=events)
        self.assertEqual(status, 1)
        self.assertTrue(any("unexpected top-level" in error for error in summary["errors"]))

    def test_discovery_process_failure_is_retained(self):
        for status_code, reason in ((1, None), (None, "could not start command"), (-9, "command exceeded 510 seconds")):
            with self.subTest(reason=reason):
                status, summary, directory, calls, _ = self.invoke(
                    discovery_status=status_code, discovery_error=reason)
                self.assertEqual(status, 1)
                self.assertFalse(summary["passed"])
                self.assertEqual(len(calls), 1)
                self.assertTrue((directory / "metadata.json").is_file())
                self.assertTrue((directory / "list.stderr.log").is_file())

    def test_test_process_timeout_or_startup_error_cannot_pass(self):
        for reason in ("command exceeded 510 seconds", "could not start command"):
            with self.subTest(reason=reason):
                status, summary, directory, *_ = self.invoke(returncode=None, run_error=reason)
                self.assertEqual(status, 1)
                self.assertTrue(any(reason in error for error in summary["errors"]))
                self.assertTrue((directory / "events.jsonl").is_file())

    def test_run_directories_never_reuse_prior_success(self):
        _, success, previous, *_ = self.invoke()
        status, failure, current, *_ = self.invoke(names=[])
        self.assertTrue(success["passed"])
        self.assertEqual(status, 1)
        self.assertFalse(failure["passed"])
        self.assertNotEqual(previous, current)
        self.assertEqual(len(list(self.output.glob("run-*"))), 2)
        self.assertTrue(json.loads((previous / "summary.json").read_text())["passed"])

    def test_result_selection_does_not_depend_on_directory_mtime(self):
        original_main = RUNNER.main
        timestamp = 2_000_000_000

        def backwards_clock(argv):
            nonlocal timestamp
            before = set(self.output.glob("run-*"))
            result = original_main(argv)
            for directory in set(self.output.glob("run-*")) - before:
                os.utime(directory, ns=(timestamp, timestamp))
            timestamp -= 1_000_000_000
            return result

        with mock.patch.object(RUNNER, "main", side_effect=backwards_clock):
            _, success, previous, *_ = self.invoke()
            status, failure, current, *_ = self.invoke(names=[])
        self.assertTrue(success["passed"])
        self.assertEqual(status, 1)
        self.assertFalse(failure["passed"])
        self.assertNotEqual(previous, current)

    def test_argument_bounds_and_fixed_selection(self):
        for arguments in (["--count", "0"], ["--count", "101"], ["--count", "a"],
                          ["--seed", "-1"], ["--seed", str(1 << 63)], ["--seed", "a"],
                          ["--run", "Anything"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    RUNNER.main(arguments)
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(RUNNER.seed_argument("0"), 0)
        self.assertEqual(RUNNER.seed_argument(str((1 << 63) - 1)), (1 << 63) - 1)
        self.assertEqual(RUNNER.count_argument("100"), 100)

    def test_command_startup_failure_writes_stderr(self):
        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=FileNotFoundError("fixture executable")):
            status, error = RUNNER.run_command(["missing-go"], self.output / "out", self.output / "err")
        self.assertIsNone(status)
        self.assertIn("could not start", error)
        self.assertIn("fixture executable", (self.output / "err").read_text())

    def test_command_timeout_kills_process_group_and_retains_output(self):
        process = mock.Mock(pid=23456, returncode=-9)
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture", RUNNER.PROCESS_TIMEOUT), -9]

        def fake_popen(_command, **kwargs):
            self.assertNotIn("shell", kwargs)
            kwargs["stdout"].write(b"partial output\n")
            kwargs["stderr"].write(b"partial stderr\n")
            return process

        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=fake_popen), \
                mock.patch.object(RUNNER.os, "killpg", create=True) as kill_group:
            status, error = RUNNER.run_command(["fake-go"], self.output / "out", self.output / "err")
        self.assertEqual(status, -9)
        self.assertIn("exceeded", error)
        if RUNNER.os.name == "posix":
            kill_group.assert_called_once_with(process.pid, RUNNER.signal.SIGKILL)
        else:
            process.kill.assert_called_once_with()
        self.assertEqual((self.output / "out").read_bytes(), b"partial output\n")
        self.assertEqual((self.output / "err").read_bytes(), b"partial stderr\n")

    def test_actual_child_exit_and_output_capture(self):
        status, error = RUNNER.run_command(
            [sys.executable, "-c", "import sys; print('fixture'); print('err', file=sys.stderr); sys.exit(3)"],
            self.output / "out", self.output / "err")
        self.assertEqual(status, 3)
        self.assertIsNone(error)
        self.assertEqual((self.output / "out").read_text(), "fixture\n")
        self.assertEqual((self.output / "err").read_text(), "err\n")

    def test_command_interrupt_also_kills_process_group(self):
        process = mock.Mock(pid=23456, returncode=-9)
        process.wait.side_effect = [KeyboardInterrupt(), -9]
        with mock.patch.object(RUNNER.subprocess, "Popen", return_value=process), \
                mock.patch.object(RUNNER.os, "killpg", create=True) as kill_group:
            with self.assertRaises(KeyboardInterrupt):
                RUNNER.run_command(["fake-go"], self.output / "out", self.output / "err")
        if RUNNER.os.name == "posix":
            kill_group.assert_called_once_with(process.pid, RUNNER.signal.SIGKILL)
        else:
            process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)

    def test_sigterm_is_mapped_to_interrupt_and_original_handler_restored(self):
        def terminate(_args):
            installed = handlers.call_args_list[0].args[1]
            installed(RUNNER.signal.SIGTERM, None)

        original = object()
        with mock.patch.object(RUNNER.signal, "signal", return_value=original) as handlers, \
                mock.patch.object(RUNNER, "run", side_effect=terminate), \
                contextlib.redirect_stdout(io.StringIO()):
            status = RUNNER.main([])
        self.assertEqual(status, 130)
        self.assertEqual(handlers.call_count, 2)
        self.assertEqual(handlers.call_args_list[-1].args, (RUNNER.signal.SIGTERM, original))


    def test_source_fingerprint_tracks_only_named_source_paths(self):
        for name in ("go.mod", "go.sum", "main.go"):
            (self.output / name).write_text(name)
        config = self.output / "config"
        config.mkdir()
        (config / "config.go").write_text("package config")
        private = config / "setting.json"
        private.write_text("fixture private config")
        before = RUNNER.source_fingerprint(self.output)
        private.write_text("changed private config")
        self.assertEqual(before, RUNNER.source_fingerprint(self.output))
        (config / "config.go").write_text("package changed")
        self.assertNotEqual(before, RUNNER.source_fingerprint(self.output))
        after = RUNNER.source_fingerprint(self.output)
        (config / "config.go").rename(config / "renamed.go")
        self.assertNotEqual(after, RUNNER.source_fingerprint(self.output))


if __name__ == "__main__":
    unittest.main()
