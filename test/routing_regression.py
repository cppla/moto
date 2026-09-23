#!/usr/bin/env python3
"""Run fixed Boost/cache/health/recovery regressions with reproducible evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import signal
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "moto/controller"
PROCESS_TIMEOUT = 8 * 60 + 30
DISCOVERY_TIMEOUT = 180
REQUIRED_TESTS = {
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
}
# Exact names exclude opt-in network experiments and cannot silently lose a
# renamed/deleted sentinel. Discovery and JSON run/pass counts must agree.
TEST_PATTERN = "^(" + "|".join(sorted(REQUIRED_TESTS)) + ")$"


def count_argument(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("count must be an integer from 1 to 100") from exc
    if not 1 <= number <= 100:
        raise argparse.ArgumentTypeError("count must be an integer from 1 to 100")
    return number


def seed_argument(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seed must be a nonnegative int64") from exc
    if not 0 <= number <= (1 << 63) - 1:
        raise argparse.ArgumentTypeError("seed must be a nonnegative int64")
    return number


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_fingerprint(root: Path = ROOT) -> str:
    """Hash only Go sources/module files, including an uncommitted checkout."""
    paths = [root / "go.mod", root / "go.sum", *root.glob("*.go")]
    for directory in ("controller", "config", "utils"):
        paths.extend((root / directory).rglob("*.go"))
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise OSError(f"refusing symlink in source fingerprint: {path.relative_to(root)}")
        content = path.read_bytes()
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def public_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def run_command(command: list[str], stdout: Path, stderr: Path, *,
                timeout: int = PROCESS_TIMEOUT) -> tuple[int | None, str | None]:
    """Keep partial output on failure and kill the Go test process group on timeout."""
    with stdout.open("wb") as output, stderr.open("wb") as errors:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=errors,
                                       start_new_session=(os.name == "posix"))
        except OSError as exc:
            message = f"could not start command: {exc}"
            errors.write((message + "\n").encode("utf-8"))
            return None, message
        try:
            return process.wait(timeout=timeout), None
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            if isinstance(exc, KeyboardInterrupt):
                raise
            return process.returncode, f"command exceeded {timeout} seconds"


def listed_tests(path: Path) -> tuple[list[str], list[str]]:
    names = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
             if re.fullmatch(r"Test\w*", line.strip())]
    errors = []
    if not names:
        errors.append("no routing regression tests discovered")
    if len(names) != len(set(names)):
        errors.append("duplicate top-level test names in discovery output")
    missing = sorted(REQUIRED_TESTS - set(names))
    if missing:
        errors.append("missing required tests: " + ", ".join(missing))
    unexpected = sorted(set(names) - REQUIRED_TESTS)
    if unexpected:
        errors.append("unexpected discovered tests: " + ", ".join(unexpected))
    return sorted(set(names)), errors


def validate_events(path: Path, names: list[str], count: int) -> tuple[dict, list[str]]:
    runs, passes, package_passes = Counter(), Counter(), Counter()
    errors = []
    expected = set(names)
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"malformed JSON at line {line_number}")
                continue
            if not isinstance(event, dict) or not isinstance(event.get("Action"), str):
                errors.append(f"invalid Go test event at line {line_number}")
                continue
            action, name, package = event["Action"], event.get("Test", ""), event.get("Package", "")
            if not isinstance(name, str) or not isinstance(package, str):
                errors.append(f"invalid test/package name at line {line_number}")
                continue
            if action in {"skip", "fail", "build-fail"}:
                errors.append(f"{action}: {name or package or 'build'}")
            if action == "pass" and not name:
                package_passes[package] += 1
            if not name or "/" in name or action not in {"run", "pass"}:
                continue
            if package != PACKAGE or name not in expected:
                errors.append(f"unexpected top-level test: {package} {name}")
                continue
            (runs if action == "run" else passes)[name] += 1
    for name in names:
        if runs[name] != count or passes[name] != count:
            errors.append(f"{name}: run={runs[name]}, pass={passes[name]}, expected={count}")
    if package_passes != Counter({PACKAGE: 1}):
        errors.append("expected exactly one successful controller package completion")
    counts = {name: {"run": runs[name], "pass": passes[name]} for name in names}
    return counts, errors


def run(args: argparse.Namespace) -> int:
    args.output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=args.output.resolve()))
    events, stderr = directory / "events.jsonl", directory / "stderr.log"
    events.touch()
    stderr.touch()
    seed = args.seed if args.seed is not None else secrets.randbits(63)
    command = [args.go, "test", "-race", "-json", f"-shuffle={seed}",
               f"-count={args.count}", "-timeout=8m", "./controller", "-run", TEST_PATTERN]
    discovery = [args.go, "test", "-race", "-list", TEST_PATTERN, "./controller"]
    metadata = {"seed": seed, "commands": {"list": discovery, "test": command},
                "platform": {"system": platform.system(), "machine": platform.machine()},
                "source_revision": None, "source_sha256": None, "go_version": None}
    summary = {"passed": False, "errors": ["run incomplete"], "count": args.count,
               "tests": [], "counts": {}, "returncode": None}
    write_json(directory / "metadata.json", metadata)
    write_json(directory / "summary.json", summary)
    print(f"Routing regression: seed={seed}, count={args.count}, evidence={directory}", flush=True)
    print("Reproduce: " + shlex.join(command), flush=True)
    interrupted = False
    try:
        metadata["source_sha256"] = source_fingerprint()
        metadata["source_revision"] = public_version(["git", "rev-parse", "HEAD"])
        metadata["go_version"] = public_version([args.go, "version"])
        write_json(directory / "metadata.json", metadata)
        status, error = run_command(discovery, directory / "list.txt", directory / "list.stderr.log",
                                    timeout=DISCOVERY_TIMEOUT)
        summary["errors"] = []
        if error or status != 0:
            summary["errors"].append(f"test discovery failed: {error or f'exit {status}'}")
        else:
            names, errors = listed_tests(directory / "list.txt")
            summary["tests"], summary["errors"] = names, errors
            if not errors:
                print(f"Discovered {len(names)} tests; running race/shuffle regression.", flush=True)
                status, error = run_command(command, events, stderr)
                summary["returncode"] = status
                counts, errors = validate_events(events, names, args.count)
                summary["counts"], summary["errors"] = counts, errors
                if error or status != 0:
                    summary["errors"].append(f"test command failed: {error or f'exit {status}'}")
                summary["source_sha256_after"] = source_fingerprint()
                if summary["source_sha256_after"] != metadata["source_sha256"]:
                    summary["errors"].append("Go sources changed during regression; rerun on an unchanged checkout")
        summary["passed"] = not summary["errors"]
    except KeyboardInterrupt:
        interrupted = True
        summary["passed"] = False
        summary["errors"] = ["runner interrupted"]
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        summary["passed"] = False
        summary["errors"] = [f"runner failed: {exc}"]
    finally:
        write_json(directory / "summary.json", summary)
    print(f"Routing regression {'PASS' if summary['passed'] else 'FAIL'}: {directory}", flush=True)
    for error in summary["errors"][:5]:
        print(f"  {error}", flush=True)
    return 130 if interrupted else (0 if summary["passed"] else 1)


def interrupt_on_termination(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt("received SIGTERM")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable (no shell arguments)")
    parser.add_argument("--count", type=count_argument, default=10)
    parser.add_argument("--seed", type=seed_argument, help="shuffle seed; defaults to a random nonnegative int64")
    parser.add_argument("--output", type=Path, default=ROOT / "bin" / "routing-regression")
    args = parser.parse_args(argv)
    previous_handler = signal.signal(signal.SIGTERM, interrupt_on_termination)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("Routing regression FAIL: interrupted before evidence was ready", flush=True)
        return 130
    except OSError as exc:
        print(f"Routing regression FAIL: cannot prepare/write evidence: {exc}", flush=True)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
