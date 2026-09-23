#!/usr/bin/env python3
"""Run bounded H2 PING experiments in separate disposable Docker networks.

The mounted Go test binary must include TestHTTP2RealRoutePingTiming. Private
configuration and origin CA stay read-only and never enter the image. Reports
use target indices. This harness never uses host networking or changes defaults.
"""

import argparse
import concurrent.futures
import json
import math
import os
from pathlib import Path
import random
import signal
import subprocess
import threading
import time
import uuid


TIMINGS = [(15, 10), (10, 10), (10, 5), (15, 5)]
PROFILES = {"normal", "weak", "blackhole", "outage4", "outage8", "outage14", "outage18"}
PREFIX = "MOTO_H2_REAL_RESULT "
MAX_JOBS = 384
CASE_TIMEOUT = 105
PROCESS_POLL_SECONDS = 0.2


class StopRequest:
    """A signal handler must not acquire a possibly interrupted Python lock."""
    requested = False

    def set(self):
        self.requested = True

    def is_set(self):
        return self.requested


def write_json(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
        json.dump(data, output, ensure_ascii=False, sort_keys=True, indent=2)
        output.write("\n")


def captured_text(value):
    # TimeoutExpired.output may be bytes even with text=True.
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""


def cleanup_container(container):
    """Best-effort exact-name removal; cleanup must not discard case evidence."""
    try:
        result = subprocess.run(["docker", "rm", "-f", container],
                                capture_output=True, text=True, timeout=10)
        # --rm normally removes successful containers before this cleanup.
        return result.returncode == 0 or "no such container" in captured_text(result.stderr).lower()
    except Exception:
        return False


def run_command(command, stop):
    process = None
    stdout = stderr = ""
    error = None
    exit_code = None
    try:
        if stop.is_set():
            return None, stdout, stderr, "runner_interrupted"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + CASE_TIMEOUT
        while True:
            if stop.is_set():
                error = "runner_interrupted"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = "runner_timeout"
                break
            try:
                stdout, stderr = process.communicate(timeout=min(PROCESS_POLL_SECONDS, remaining))
                exit_code = process.returncode
                break
            except subprocess.TimeoutExpired as failure:
                stdout, stderr = captured_text(failure.stdout), captured_text(failure.stderr)
    except Exception:
        error = "runner_error"
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired as failure:
                        stdout, stderr = captured_text(failure.stdout), captured_text(failure.stderr)
                        process.kill()
                        stdout, stderr = process.communicate(timeout=2)
                exit_code = process.returncode
            except Exception:
                # A failed terminate/communicate must not prevent docker rm or
                # saving the last captured output. Reap after the fallback kill.
                try:
                    process.kill()
                    process.wait(timeout=2)
                except Exception:
                    pass
                error = error or "runner_error"
    return exit_code, captured_text(stdout), captured_text(stderr), error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--image", default="moto-h2-timing:20260922")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--targets", default="0,1,2,3")
    parser.add_argument("--profiles", default="normal,weak,blackhole,outage4,outage8,outage14")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--outage-after", type=float, default=9.5)
    args = parser.parse_args(argv)
    try:
        targets = [int(value) for value in args.targets.split(",")]
    except ValueError:
        parser.error("invalid bounded matrix")
    profiles = args.profiles.split(",")
    if (not targets or len(set(targets)) != len(targets) or any(value < 0 or value > 127 for value in targets)
            or not profiles or len(set(profiles)) != len(profiles) or not set(profiles) <= PROFILES
            or not 1 <= args.rounds <= 3 or not 1 <= args.workers <= 4
            or not math.isfinite(args.outage_after) or not 0 <= args.outage_after <= 20
            or len(targets) * len(profiles) * len(TIMINGS) * args.rounds > MAX_JOBS):
        parser.error("invalid bounded matrix")
    for name in ("binary", "config", "ca"):
        path = getattr(args, name).resolve()
        if not path.is_file() or "," in str(path):
            parser.error("invalid input file")
        setattr(args, name, path)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    generator = random.Random(args.seed)
    jobs = []
    for repetition in range(args.rounds):
        blocks = [(target, profile) for target in targets for profile in profiles]
        generator.shuffle(blocks)
        for target, profile in blocks:
            timings = TIMINGS[:]
            generator.shuffle(timings)
            for idle, ping in timings:
                jobs.append(dict(target=target, profile=profile, idle=idle, ping=ping, repetition=repetition + 1))
    run_id = uuid.uuid4().hex[:10]
    write_json(args.output / "plan.json", {"seed": args.seed, "workers": args.workers,
                                          "outage_after_seconds": args.outage_after, "jobs": jobs})
    running = set()
    guard = threading.Lock()
    stop = StopRequest()
    started = time.monotonic()

    def request_stop(_signum, _frame):
        stop.set()

    def run(job):
        label = f"r{job['repetition']}-t{job['target']}-{job['profile']}-{job['idle']}-{job['ping']}"
        container = f"moto-h2-{run_id}-{label}"
        command = ["docker", "run", "--rm", "--name", container, "--network", "bridge",
                   "--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--memory=192m", "--pids-limit=128"]
        for source, target in ((args.binary, "/test/controller.test"), (args.config, "/test/private.json"), (args.ca, "/test/origin.crt")):
            command += ["--mount", f"type=bind,src={source},dst={target},readonly"]
        environment = {
            "GOMAXPROCS": "2", "MOTO_H2_REAL_CONFIG": "/test/private.json", "MOTO_H2_REAL_ISOLATED": "1",
            "MOTO_H2_REAL_TARGET": str(job["target"]), "MOTO_H2_REAL_IDLE": str(job["idle"]),
            "MOTO_H2_REAL_PING": str(job["ping"]), "MOTO_H2_REAL_PROFILE": job["profile"],
            "MOTO_H2_REAL_DESTINATION": args.destination, "MOTO_H2_REAL_ORIGIN_CA": "/test/origin.crt",
            "MOTO_H2_REAL_OUTAGE_AFTER_SECONDS": str(args.outage_after),
        }
        for key, value in environment.items():
            command += ["-e", f"{key}={value}"]
        command += [args.image, "/test/controller.test", "-test.run=^TestHTTP2RealRoutePingTiming$", "-test.v", "-test.timeout=90s"]
        with guard:
            running.add(container)
        began = time.monotonic()
        result = {"job": job, "runner_ok": False}
        log = ""
        try:
            exit_code, stdout, stderr, error = run_command(command, stop)
            log = stdout + stderr
            evidence = [json.loads(line[len(PREFIX):]) for line in stdout.splitlines() if line.startswith(PREFIX)]
            if exit_code is not None:
                result["exit_code"] = exit_code
            result["runner_ok"] = error is None and exit_code == 0 and len(evidence) == 1
            if error:
                result["runner_error"] = error
            if len(evidence) == 1:
                result["evidence"] = evidence[0]
            elif not error:
                result["runner_error"] = "result_missing_or_ambiguous"
        except Exception:
            result["runner_error"] = "runner_error"
        finally:
            # Exact generated container name, never a broad Docker prune.
            if cleanup_container(container):
                with guard:
                    running.discard(container)
            else:
                result["runner_ok"] = False
                result.setdefault("runner_error", "container_cleanup_failed")
        result["elapsed_seconds"] = time.monotonic() - began
        write_json(args.output / f"{label}.json", result)
        with os.fdopen(os.open(args.output / f"{label}.log", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
            output.write(log)
        evidence = result.get("evidence", {})
        with guard:
            print(json.dumps({"case": label, "ok": result["runner_ok"], "error": evidence.get("error", result.get("runner_error")),
                              "states": [stream.get("state") for stream in evidence.get("streams", [])],
                              "lost_ping": evidence.get("lost_ping"), "recovery_ok": evidence.get("recovery_ok")}), flush=True)
        return result

    results = []
    pending = {}
    executor = None
    handlers = {}

    def collect(future, job):
        if future.cancelled():
            return
        try:
            result = future.result()
        except Exception:
            result = {"job": job, "runner_ok": False, "runner_error": "runner_error", "elapsed_seconds": 0}
            label = f"r{job['repetition']}-t{job['target']}-{job['profile']}-{job['idle']}-{job['ping']}"
            write_json(args.output / f"{label}.json", result)
        results.append(result)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, request_stop)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
        remaining_jobs = iter(jobs)
        exhausted = False
        while pending or not exhausted:
            while not stop.is_set() and not exhausted and len(pending) < args.workers:
                job = next(remaining_jobs, None)
                if job is None:
                    exhausted = True
                    break
                pending[executor.submit(run, job)] = job
            if not pending or stop.is_set():
                break
            done, _ = concurrent.futures.wait(pending, timeout=PROCESS_POLL_SECONDS,
                                              return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                collect(future, pending.pop(future))
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        # Only at most workers jobs were submitted. Workers terminate their CLI
        # child promptly and remove their own exact container before returning.
        for future in pending:
            future.cancel()
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        for future, job in pending.items():
            collect(future, job)
        with guard:
            active = list(running)
        for container in active:
            cleanup_container(container)
        summary = {"planned": len(jobs), "completed": len(results), "valid": sum(item["runner_ok"] for item in results),
                   "elapsed_seconds": time.monotonic() - started, "results": results}
        try:
            write_json(args.output / "summary.json", summary)
        finally:
            for signum, previous in handlers.items():
                signal.signal(signum, previous)
    return 0 if summary["valid"] == summary["planned"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
