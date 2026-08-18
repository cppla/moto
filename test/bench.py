#!/usr/bin/env python3
"""Moto benchmark and deterministic local regression gate.

The historical/default mode drives an already-running Moto instance whose
targets are SOCKS5 servers. ``--self-contained`` instead starts loopback-only
HTTP fixtures and a temporary Moto process, then measures direct, cold, and
warm traffic without contacting the network.
"""

import argparse
import asyncio
import hashlib
import json
import os
import random
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 84
TARGET_HOST = "www.baidu.com"
TARGET_PORT = 80
EXPECT_STATUS_MIN = 200
EXPECT_STATUS_MAX = 399
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


class Result:
    __slots__ = (
        "ok",
        "error",
        "connect_ms",
        "first_byte_ms",
        "total_ms",
        "status",
        "phase",
    )

    def __init__(
        self,
        ok: bool,
        error: Optional[str],
        connect_ms: float,
        first_byte_ms: float,
        total_ms: float,
        status: Optional[int],
        phase: str,
    ):
        self.ok = ok
        self.error = error
        self.connect_ms = connect_ms
        self.first_byte_ms = first_byte_ms
        self.total_ms = total_ms
        self.status = status
        self.phase = phase

    def as_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "error": self.error,
            "connect_ms": self.connect_ms,
            "first_byte_ms": self.first_byte_ms,
            "total_ms": self.total_ms,
            "status": self.status,
            "phase": self.phase,
        }


Request = Callable[[str], Awaitable[Result]]


def http_request(host: str) -> bytes:
    return (
        "GET /benchmark HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: moto-benchmark/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


async def read_http_response(
    reader: asyncio.StreamReader,
    timeout: float,
    started: float,
) -> Tuple[int, float, bytes]:
    first_chunk = await asyncio.wait_for(reader.read(1), timeout=timeout)
    if not first_chunk:
        raise RuntimeError("empty first byte")
    first_byte_ms = (time.monotonic() - started) * 1000.0

    response = bytearray(first_chunk)
    while True:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            break
        response += chunk
        if len(response) > 64 * 1024:
            raise RuntimeError("HTTP response exceeds 64 KiB")

    status_line = bytes(response).split(b"\r\n", 1)[0]
    parts = status_line.split()
    if len(parts) < 2 or not status_line.startswith(b"HTTP/") or not parts[1].isdigit():
        raise RuntimeError("response is not HTTP")
    return int(parts[1]), first_byte_ms, bytes(response)


async def plain_http_get(
    host: str,
    port: int,
    timeout: float,
    phase: str,
    request_host: str = "fixture.local",
) -> Result:
    started = time.monotonic()
    writer = None
    try:
        connect_started = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        connect_ms = (time.monotonic() - connect_started) * 1000.0
        writer.write(http_request(request_host))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status, first_byte_ms, response = await read_http_response(reader, timeout, started)
        total_ms = (time.monotonic() - started) * 1000.0
        if b"\r\n\r\nmoto benchmark fixture " not in response:
            raise RuntimeError("response did not contain the local fixture marker")
        if not EXPECT_STATUS_MIN <= status <= EXPECT_STATUS_MAX:
            raise RuntimeError(
                f"unexpected HTTP status: {status} "
                f"(expected {EXPECT_STATUS_MIN}-{EXPECT_STATUS_MAX})"
            )
        return Result(True, None, connect_ms, first_byte_ms, total_ms, status, phase)
    except Exception as exc:  # A failed request is benchmark data, not a crash.
        return Result(
            False,
            str(exc),
            0.0,
            0.0,
            (time.monotonic() - started) * 1000.0,
            None,
            phase,
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def socks5_http_get(timeout: float, phase: str) -> Result:
    started = time.monotonic()
    writer = None
    try:
        connect_started = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(PROXY_HOST, PROXY_PORT), timeout=timeout
        )
        writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        response = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if response != b"\x05\x00":
            raise RuntimeError(f"socks5 greet response invalid: {response!r}")

        encoded_host = TARGET_HOST.encode("idna")
        if len(encoded_host) > 255:
            raise RuntimeError("SOCKS5 target hostname exceeds 255 bytes")
        packet = bytearray(b"\x05\x01\x00\x03")
        packet += bytes([len(encoded_host)])
        packet += encoded_host
        packet += TARGET_PORT.to_bytes(2, "big")
        writer.write(packet)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        reply = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if reply[0] != 5 or reply[1] != 0:
            raise RuntimeError(f"socks5 connect failed: {reply!r}")
        if reply[3] == 1:
            await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
        elif reply[3] == 3:
            length = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(length[0] + 2), timeout=timeout)
        elif reply[3] == 4:
            await asyncio.wait_for(reader.readexactly(18), timeout=timeout)
        else:
            raise RuntimeError(f"unsupported SOCKS5 address type: {reply[3]}")

        connect_ms = (time.monotonic() - connect_started) * 1000.0
        writer.write(http_request(TARGET_HOST))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        status, first_byte_ms, _ = await read_http_response(reader, timeout, started)
        total_ms = (time.monotonic() - started) * 1000.0
        if not EXPECT_STATUS_MIN <= status <= EXPECT_STATUS_MAX:
            raise RuntimeError(
                f"unexpected HTTP status: {status} "
                f"(expected {EXPECT_STATUS_MIN}-{EXPECT_STATUS_MAX})"
            )
        return Result(True, None, connect_ms, first_byte_ms, total_ms, status, phase)
    except Exception as exc:
        return Result(
            False,
            str(exc),
            0.0,
            0.0,
            (time.monotonic() - started) * 1000.0,
            None,
            phase,
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def percentiles(
    values: Sequence[float], percent_values: Sequence[int] = (50, 90, 95, 99)
) -> Dict[int, float]:
    if not values:
        return {value: 0.0 for value in percent_values}
    ordered = sorted(values)
    last = len(ordered) - 1
    return {
        value: ordered[int(round((value / 100.0) * last))]
        for value in percent_values
    }


async def run_phase(
    phase_name: str,
    concurrency: int,
    total: int,
    jitter: float,
    request: Request,
) -> Tuple[List[Result], float]:
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Result] = []

    async def worker() -> None:
        async with semaphore:
            if jitter > 0:
                await asyncio.sleep(random.random() * jitter)
            results.append(await request(phase_name))

    started = time.monotonic()
    await asyncio.gather(*(worker() for _ in range(total)))
    return results, max(time.monotonic() - started, 1e-9)


def phase_summary(results: Sequence[Result], elapsed: float) -> Dict[str, object]:
    successes = [result for result in results if result.ok]
    latency = percentiles([result.total_ms for result in successes])
    first_byte = percentiles([result.first_byte_ms for result in successes])
    connect = percentiles([result.connect_ms for result in successes])
    return {
        "requests": len(results),
        "ok": len(successes),
        "failed": len(results) - len(successes),
        "success_rate": (100.0 * len(successes) / len(results)) if results else 0.0,
        "elapsed_seconds": elapsed,
        "throughput_rps": len(results) / elapsed,
        "latency_ms": {f"p{p}": latency[p] for p in (50, 90, 95, 99)},
        "first_byte_ms": {f"p{p}": first_byte[p] for p in (50, 90, 95, 99)},
        "connect_ms": {f"p{p}": connect[p] for p in (50, 90, 95, 99)},
    }


def summarize_external(results: Sequence[Result], elapsed: float) -> str:
    successes = [result for result in results if result.ok]
    failures = [result for result in results if not result.ok]
    codes = Counter(result.status for result in successes if result.status is not None)
    errors = Counter(result.error for result in failures)

    def format_distribution(values: Counter, top: int = 5) -> str:
        return ", ".join(f"{key}:{count}" for key, count in values.most_common(top)) or "-"

    summary = phase_summary(results, elapsed)
    lines = [
        f"Total={summary['requests']} OK={summary['ok']} Fail={summary['failed']} "
        f"SuccessRate={summary['success_rate']:.2f}%"
    ]
    if successes:
        for field, title in (
            ("connect_ms", "Connect(ms)"),
            ("first_byte_ms", "FirstByte(ms)"),
            ("latency_ms", "Total(ms)"),
        ):
            values = summary[field]
            lines.append(
                f"{title} p50={values['p50']:.1f} p90={values['p90']:.1f} "
                f"p95={values['p95']:.1f} p99={values['p99']:.1f}"
            )
    lines.append(f"HTTP Codes: {format_distribution(codes)}")
    if failures:
        lines.append(f"Errors: {format_distribution(errors)}")

    by_phase = defaultdict(list)
    for result in results:
        by_phase[result.phase].append(result)
    if len(by_phase) > 1:
        lines.append("Per-Phase Success:")
        for phase, phase_results in by_phase.items():
            ok = sum(1 for result in phase_results if result.ok)
            lines.append(
                f"  {phase}: {ok}/{len(phase_results)} = "
                f"{ok / len(phase_results) * 100:.1f}%"
            )
    return "\n".join(lines)


class LocalHTTPFixtures:
    """Small HTTP/1.1 fixtures bound only to dynamically assigned loopback ports."""

    def __init__(self) -> None:
        self.servers: List[asyncio.AbstractServer] = []

    async def start(self, count: int = 2) -> None:
        for fixture_id in range(count):
            server = await asyncio.start_server(
                lambda reader, writer, value=fixture_id: self.handle(value, reader, writer),
                "127.0.0.1",
                0,
            )
            self.servers.append(server)

    @property
    def addresses(self) -> List[Tuple[str, int]]:
        addresses = []
        for server in self.servers:
            sockname = server.sockets[0].getsockname()
            addresses.append((str(sockname[0]), int(sockname[1])))
        return addresses

    async def handle(
        self,
        fixture_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2.0)
            if len(request) > 16 * 1024 or not request.startswith(b"GET "):
                status = "400 Bad Request"
                body = b"bad request\n"
            else:
                status = "200 OK"
                body = f"moto benchmark fixture {fixture_id}\n".encode("ascii")
            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Content-Type: text/plain\r\n"
                f"X-Moto-Fixture: {fixture_id}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii") + body
            writer.write(response)
            await writer.drain()
        except (
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
        ):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def close(self) -> None:
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))


def sample_process_resources(pid: int) -> Dict[str, Tuple[Optional[object], Optional[str]]]:
    """Collect portable process counters without making optional tools mandatory."""
    samples: Dict[str, Tuple[Optional[object], Optional[str]]] = {}
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            ("ps", "-o", "%cpu=", "-o", "rss=", "-p", str(pid)),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1.0,
            env=environment,
        )
        fields = completed.stdout.split()
        if len(fields) < 2:
            raise RuntimeError("ps returned no CPU/RSS row")
        samples["cpu_percent"] = (float(fields[0]), None)
        samples["rss_bytes"] = (int(fields[1]) * 1024, None)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = f"ps unavailable: {exc}"
        samples["cpu_percent"] = (None, reason)
        samples["rss_bytes"] = (None, reason)

    proc_fds = Path("/proc") / str(pid) / "fd"
    if proc_fds.is_dir():
        try:
            samples["file_descriptors"] = (len(os.listdir(proc_fds)), None)
        except OSError as exc:
            samples["file_descriptors"] = (None, f"cannot read {proc_fds}: {exc}")
    else:
        lsof = shutil.which("lsof")
        if lsof is None:
            samples["file_descriptors"] = (
                None,
                "unsupported: /proc fd directory and lsof are unavailable",
            )
        else:
            try:
                completed = subprocess.run(
                    (lsof, "-a", "-p", str(pid), "-d", "0-999999", "-F", "f"),
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=1.0,
                    env=environment,
                )
                count = sum(
                    1
                    for line in completed.stdout.splitlines()
                    if line.startswith("f") and line[1:].isdigit()
                )
                samples["file_descriptors"] = (count, None)
            except (OSError, subprocess.SubprocessError) as exc:
                samples["file_descriptors"] = (None, f"lsof unavailable: {exc}")
    return samples


async def scrape_goroutines(metrics_port: int) -> Tuple[Optional[int], Optional[str]]:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", metrics_port), timeout=0.5
        )
        writer.write(
            b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        await asyncio.wait_for(writer.drain(), timeout=0.5)
        response = bytearray()
        while len(response) <= 512 * 1024:
            chunk = await asyncio.wait_for(reader.read(64 * 1024), timeout=0.75)
            if not chunk:
                break
            response += chunk
        if len(response) > 512 * 1024:
            raise RuntimeError("metrics response exceeds 512 KiB")
        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator or b" 200 " not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError("metrics scrape did not return HTTP 200")
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("moto_go_goroutines "):
                value = int(float(line.split(None, 1)[1]))
                if value < 1:
                    raise RuntimeError("moto_go_goroutines was not positive")
                return value, None
        raise RuntimeError("moto_go_goroutines metric is missing")
    except (OSError, ValueError, asyncio.TimeoutError, RuntimeError) as exc:
        return None, f"metrics unavailable: {exc}"
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class ResourceSampler:
    metric_names = ("cpu_percent", "rss_bytes", "file_descriptors", "goroutines")

    def __init__(self, pid: int, metrics_port: int, interval: float) -> None:
        self.pid = pid
        self.metrics_port = metrics_port
        self.interval = interval
        self.values: Dict[str, List[object]] = {
            name: [] for name in self.metric_names
        }
        self.errors: Dict[str, List[str]] = {name: [] for name in self.metric_names}
        self.sample_attempts = 0
        self.stop_event = asyncio.Event()
        self.task = None

    def record(self, name: str, value: Optional[object], error: Optional[str]) -> None:
        if value is not None:
            self.values[name].append(value)
        elif error:
            self.errors[name].append(error)

    async def sample(self) -> None:
        self.sample_attempts += 1
        loop = asyncio.get_running_loop()
        process_future = loop.run_in_executor(None, sample_process_resources, self.pid)
        goroutine_future = asyncio.create_task(scrape_goroutines(self.metrics_port))
        try:
            process_samples, goroutine_sample = await asyncio.gather(
                process_future, goroutine_future
            )
            for name in ("cpu_percent", "rss_bytes", "file_descriptors"):
                value, error = process_samples[name]
                self.record(name, value, error)
            self.record("goroutines", goroutine_sample[0], goroutine_sample[1])
        except Exception as exc:
            reason = f"sampler unavailable: {exc}"
            for name in self.metric_names:
                self.record(name, None, reason)

    async def run(self) -> None:
        while not self.stop_event.is_set():
            await self.sample()
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass

    async def start(self) -> None:
        self.task = asyncio.create_task(self.run())
        await asyncio.sleep(0)

    async def stop(self) -> Dict[str, object]:
        self.stop_event.set()
        if self.task is not None:
            try:
                await self.task
            except Exception as exc:
                reason = f"sampler task failed: {exc}"
                for name in self.metric_names:
                    self.record(name, None, reason)
        await self.sample()
        metrics = {}
        for name in self.metric_names:
            values = self.values[name]
            errors = self.errors[name]
            metrics[name] = {
                "status": "ok" if values else "unsupported",
                "peak": max(values) if values else None,
                "last": values[-1] if values else None,
                "samples": len(values),
                "errors": len(errors),
                "reason": None if values else (errors[-1] if errors else "unsupported"),
            }
        return {
            "sample_attempts": self.sample_attempts,
            "sample_interval_seconds": self.interval,
            **metrics,
        }


def print_resource_summary(resources: Dict[str, object]) -> None:
    print("\n=== Moto process resources ===")
    print(
        f"samples={resources['sample_attempts']} "
        f"interval={resources['sample_interval_seconds']:.3f}s"
    )
    def format_value(name: str, value: object) -> str:
        if name == "cpu_percent":
            return f"{float(value):.2f}%"
        if name == "rss_bytes":
            return f"{int(value)} bytes ({int(value) / (1024 * 1024):.2f} MiB)"
        return str(value)

    for name in ResourceSampler.metric_names:
        metric = resources[name]
        if metric["status"] == "ok":
            print(
                f"{name}: peak={format_value(name, metric['peak'])} "
                f"last={format_value(name, metric['last'])} "
                f"samples={metric['samples']}"
            )
        else:
            print(f"{name}: peak=null last=null status=unsupported ({metric['reason']})")


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def command_text(command: Sequence[str], fallback: str = "unknown") -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=str(REPOSITORY_ROOT),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
        return completed.stdout.strip() or fallback
    except (OSError, subprocess.SubprocessError):
        return fallback


def benchmark_meta(mode: str) -> Dict[str, object]:
    return {
        "git_commit": command_text(("git", "rev-parse", "HEAD")),
        "git_dirty": command_text(("git", "status", "--porcelain"), "") != "",
        "go_toolchain": command_text(("go", "version")),
        "mode": mode,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def make_local_config(
    mode: str,
    moto_port: int,
    metrics_port: int,
    targets: Sequence[Tuple[str, int]],
    concurrency: int,
) -> Dict[str, object]:
    target_entries = []
    for host, port in targets:
        entry = {"address": f"{host}:{port}"}
        if mode == "regex":
            entry["regexp"] = "^GET "
        target_entries.append(entry)
    limit = max(128, concurrency * 4)
    return {
        "log": {"level": "error", "path": "", "version": "benchmark", "date": ""},
        "metrics": {"enabled": True, "listen": f"127.0.0.1:{metrics_port}"},
        "rules": [
            {
                "name": f"benchmark-{mode}",
                "listen": f"127.0.0.1:{moto_port}",
                "mode": mode,
                "prewarm": False,
                "timeout": 2000,
                "allowlist": ["127.0.0.0/8"],
                "maxConnections": limit,
                "maxConnectionsPerIP": limit,
                "blacklist": {},
                "targets": target_entries,
            }
        ],
    }


def config_summary(config: Dict[str, object]) -> Dict[str, object]:
    rule = config["rules"][0]
    return {
        "rule_count": len(config["rules"]),
        "rule_name": rule["name"],
        "listen": rule["listen"],
        "mode": rule["mode"],
        "prewarm": rule["prewarm"],
        "target_count": len(rule["targets"]),
        "targets": [target["address"] for target in rule["targets"]],
        "timeout_ms": rule["timeout"],
        "max_connections": rule["maxConnections"],
        "max_connections_per_ip": rule["maxConnectionsPerIP"],
        "metrics_listen": config["metrics"]["listen"],
    }


def build_moto(destination: Path) -> None:
    environment = os.environ.copy()
    environment["CGO_ENABLED"] = "0"
    completed = subprocess.run(
        (
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-o",
            str(destination),
            ".",
        ),
        cwd=str(REPOSITORY_ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"failed to build Moto:\n{completed.stdout}")


async def wait_for_moto_ready(
    process: subprocess.Popen,
    metrics_port: int,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not started"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Moto exited during startup with code {process.returncode}")
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", metrics_port)
            writer.write(
                b"GET /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout=0.5)
            if b" 200 " in status_line:
                return
            last_error = status_line.decode("ascii", "replace").strip()
        except (OSError, asyncio.TimeoutError) as exc:
            last_error = str(exc)
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        await asyncio.sleep(0.02)
    raise RuntimeError(f"Moto did not become ready within {timeout:.1f}s: {last_error}")


async def stop_moto(process: subprocess.Popen) -> int:
    if process.poll() is not None:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        return int(process.returncode)
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    else:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.run_in_executor(None, process.wait), timeout=5.0)
    except asyncio.TimeoutError:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await loop.run_in_executor(None, process.wait)
    return int(process.returncode)


def print_local_summary(summaries: Dict[str, Dict[str, object]]) -> None:
    print("\n=== Self-contained benchmark ===")
    print("phase      success      throughput       p50       p95       p99")
    for phase in ("direct", "cold", "warm"):
        summary = summaries[phase]
        latency = summary["latency_ms"]
        print(
            f"{phase:<10}"
            f"{summary['success_rate']:>7.2f}%"
            f"{summary['throughput_rps']:>14.1f} rps"
            f"{latency['p50']:>9.2f}"
            f"{latency['p95']:>10.2f}"
            f"{latency['p99']:>10.2f} ms"
        )


def evaluate_local_thresholds(
    summaries: Dict[str, Dict[str, object]], args: argparse.Namespace
) -> List[str]:
    failures = []
    for phase in ("direct", "cold", "warm"):
        success_rate = float(summaries[phase]["success_rate"])
        if success_rate < args.min_success_rate:
            failures.append(
                f"{phase} success rate {success_rate:.2f}% is below "
                f"{args.min_success_rate:.2f}%"
            )

    direct_throughput = float(summaries["direct"]["throughput_rps"])
    warm_throughput = float(summaries["warm"]["throughput_rps"])
    throughput_ratio = warm_throughput / direct_throughput if direct_throughput > 0 else 0.0
    if throughput_ratio < args.min_warm_throughput_ratio:
        failures.append(
            f"warm/direct throughput ratio {throughput_ratio:.3f} is below "
            f"{args.min_warm_throughput_ratio:.3f}"
        )

    warm_p95 = float(summaries["warm"]["latency_ms"]["p95"])
    if warm_p95 > args.max_warm_p95_ms:
        failures.append(
            f"warm p95 {warm_p95:.2f}ms exceeds {args.max_warm_p95_ms:.2f}ms"
        )
    return failures


def write_json(path: str, payload: Dict[str, object]) -> None:
    output = Path(path).expanduser()
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Saved JSON results -> {output}")


async def run_self_contained(args: argparse.Namespace) -> int:
    if args.ramp is not None:
        raise SystemExit("--self-contained currently requires fixed --concurrency")
    concurrency = args.concurrency if args.concurrency is not None else 4
    total = args.total if args.total is not None else 16
    if concurrency <= 0 or total <= 0:
        raise SystemExit("--concurrency and --total must be positive integers")
    if args.warmup < 0:
        raise SystemExit("--warmup must not be negative")

    fixtures = LocalHTTPFixtures()
    process = None
    log_handle = None
    results_by_phase: Dict[str, List[Result]] = {}
    summaries: Dict[str, Dict[str, object]] = {}
    config = None
    config_bytes = b""
    moto_log = ""
    moto_exit_code = None
    startup_attempts = 0
    resource_sampler = None
    resources = None

    with tempfile.TemporaryDirectory(prefix="moto-benchmark-") as temp_name:
        temp_dir = Path(temp_name)
        try:
            await fixtures.start(2)
            targets = fixtures.addresses
            direct_request = lambda phase: plain_http_get(
                targets[0][0], targets[0][1], args.timeout, phase
            )
            direct_results, direct_elapsed = await run_phase(
                "direct", concurrency, total, args.jitter, direct_request
            )
            results_by_phase["direct"] = direct_results
            summaries["direct"] = phase_summary(direct_results, direct_elapsed)

            if args.moto_binary:
                moto_binary = Path(args.moto_binary).expanduser().resolve()
                if not moto_binary.is_file():
                    raise RuntimeError(f"Moto binary does not exist: {moto_binary}")
            else:
                moto_binary = temp_dir / "moto"
                build_moto(moto_binary)

            startup_logs = []
            for startup_attempts in range(1, 4):
                moto_port = available_loopback_port()
                metrics_port = available_loopback_port()
                while metrics_port == moto_port:
                    metrics_port = available_loopback_port()
                config = make_local_config(
                    args.mode, moto_port, metrics_port, targets, concurrency
                )
                config_bytes = (
                    json.dumps(
                        config,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                config_path = temp_dir / f"setting-{startup_attempts}.json"
                config_path.write_bytes(config_bytes)

                log_path = temp_dir / f"moto-{startup_attempts}.log"
                log_handle = log_path.open("w+", encoding="utf-8")
                try:
                    process = subprocess.Popen(
                        (str(moto_binary), "--config", str(config_path)),
                        cwd=str(REPOSITORY_ROOT),
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        start_new_session=(os.name == "posix"),
                    )
                    await wait_for_moto_ready(
                        process, metrics_port, args.startup_timeout
                    )
                    break
                except Exception as exc:
                    if process is not None:
                        await stop_moto(process)
                    log_handle.flush()
                    log_handle.seek(0)
                    startup_log = log_handle.read()
                    startup_logs.append(
                        f"attempt {startup_attempts}: {exc}\n{startup_log}".rstrip()
                    )
                    log_handle.close()
                    log_handle = None
                    process = None
                    if startup_attempts == 3:
                        detail = "\n\n".join(startup_logs)
                        raise RuntimeError(
                            f"Moto startup failed after 3 attempts:\n{detail}"
                        ) from exc
                    await asyncio.sleep(0.02)

            resource_sampler = ResourceSampler(
                process.pid, metrics_port, args.resource_sample_interval
            )
            await resource_sampler.start()
            proxy_request = lambda phase: plain_http_get(
                "127.0.0.1", moto_port, args.timeout, phase
            )
            cold_results, cold_elapsed = await run_phase(
                "cold", concurrency, total, args.jitter, proxy_request
            )
            results_by_phase["cold"] = cold_results
            summaries["cold"] = phase_summary(cold_results, cold_elapsed)

            if args.warmup:
                await run_phase("warmup", concurrency, args.warmup, 0.0, proxy_request)
            warm_results, warm_elapsed = await run_phase(
                "warm", concurrency, total, args.jitter, proxy_request
            )
            results_by_phase["warm"] = warm_results
            summaries["warm"] = phase_summary(warm_results, warm_elapsed)
        finally:
            if resource_sampler is not None:
                resources = await resource_sampler.stop()
            if process is not None:
                moto_exit_code = await stop_moto(process)
            if log_handle is not None:
                log_handle.flush()
                log_handle.seek(0)
                moto_log = log_handle.read()
                log_handle.close()
            await fixtures.close()

        if config is None:
            raise RuntimeError("self-contained benchmark did not create a configuration")
        if resources is None:
            raise RuntimeError("self-contained benchmark did not sample Moto resources")
        meta = benchmark_meta(args.mode)
        meta.update(
            {
                "self_contained": True,
                "concurrency": concurrency,
                "requests_per_phase": total,
                "warmup_requests": args.warmup,
                "moto_exit_code": moto_exit_code,
                "startup_attempts": startup_attempts,
                "resource_sample_interval_seconds": args.resource_sample_interval,
                "configuration": config_summary(config),
                "configuration_sha256": hashlib.sha256(config_bytes).hexdigest(),
            }
        )
        payload = {
            "meta": meta,
            "phases": summaries,
            "resources": resources,
            "results": {
                phase: [result.as_dict() for result in results]
                for phase, results in results_by_phase.items()
            },
        }

        print_local_summary(summaries)
        print_resource_summary(resources)
        failures = evaluate_local_thresholds(summaries, args)
        direct_rps = float(summaries["direct"]["throughput_rps"])
        warm_rps = float(summaries["warm"]["throughput_rps"])
        ratio = warm_rps / direct_rps if direct_rps > 0 else 0.0
        print(f"warm/direct throughput ratio: {ratio:.3f}")
        if args.save:
            write_json(args.save, payload)
        if moto_exit_code != 0:
            failures.append(f"Moto exited with code {moto_exit_code}")
        if failures:
            for failure in failures:
                print(f"THRESHOLD FAILED: {failure}", file=sys.stderr)
            if moto_log:
                print("Moto log (tail):", file=sys.stderr)
                print("\n".join(moto_log.splitlines()[-20:]), file=sys.stderr)
            return 2
        print("Thresholds: PASS")
        return 0


async def run_external(args: argparse.Namespace) -> int:
    if args.concurrency is None and args.ramp is None:
        raise SystemExit("external mode requires --concurrency or --ramp")
    results: List[Result] = []
    started = time.monotonic()

    request = lambda phase: socks5_http_get(args.timeout, phase)
    if args.concurrency is not None:
        if args.concurrency <= 0 or args.total is None or args.total <= 0:
            raise SystemExit("--concurrency and --total must be positive integers")
        print(f"[Phase single] concurrency={args.concurrency} total={args.total}")
        phase_results, _ = await run_phase(
            "phase1", args.concurrency, args.total, args.jitter, request
        )
        results.extend(phase_results)
    else:
        try:
            stages = [int(value.strip()) for value in args.ramp.split(",") if value.strip()]
        except ValueError as exc:
            raise SystemExit("--ramp must be a comma-separated list of positive integers") from exc
        if not stages or any(stage <= 0 for stage in stages):
            raise SystemExit("--ramp must contain positive integers")
        if args.per_stage is None or args.per_stage <= 0:
            raise SystemExit("--per-stage must be a positive integer with --ramp")
        for index, concurrency in enumerate(stages, 1):
            print(f"[Phase {index}] concurrency={concurrency} total={args.per_stage}")
            phase_results, _ = await run_phase(
                f"phase{index}", concurrency, args.per_stage, args.jitter, request
            )
            results.extend(phase_results)

    elapsed = max(time.monotonic() - started, 1e-9)
    print("\n=== Summary ===")
    print(summarize_external(results, elapsed))
    print(f"Elapsed: {elapsed:.2f}s  Approx QPS: {len(results) / elapsed:.1f}")

    meta = benchmark_meta("external-socks5")
    meta.update(
        {
            "self_contained": False,
            "proxy": f"{PROXY_HOST}:{PROXY_PORT}",
            "target": f"{TARGET_HOST}:{TARGET_PORT}",
            "elapsed_seconds": elapsed,
            "min_success_rate": args.min_success_rate,
            "configuration": {
                "source": "external Moto process",
                "proxy": f"{PROXY_HOST}:{PROXY_PORT}",
                "target": f"{TARGET_HOST}:{TARGET_PORT}",
            },
            "configuration_sha256": hashlib.sha256(
                f"{PROXY_HOST}:{PROXY_PORT}->{TARGET_HOST}:{TARGET_PORT}".encode("utf-8")
            ).hexdigest(),
        }
    )
    if args.save:
        write_json(
            args.save,
            {
                "meta": meta,
                "summary": phase_summary(results, elapsed),
                "results": [result.as_dict() for result in results],
            },
        )

    threshold_failures = []
    by_phase = defaultdict(list)
    for result in results:
        by_phase[result.phase].append(result)
    for phase, phase_results in by_phase.items():
        success_rate = (
            sum(1 for result in phase_results if result.ok)
            / len(phase_results)
            * 100
        )
        if success_rate < args.min_success_rate:
            threshold_failures.append(
                f"{phase} success rate {success_rate:.2f}% is below required "
                f"{args.min_success_rate:.2f}%"
            )
    if threshold_failures:
        for failure in threshold_failures:
            print(f"THRESHOLD FAILED: {failure}", file=sys.stderr)
        return 2
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Moto SOCKS5 load test or deterministic local regression benchmark"
    )
    concurrency = parser.add_mutually_exclusive_group()
    concurrency.add_argument("-c", "--concurrency", type=int, help="fixed concurrency")
    concurrency.add_argument("-r", "--ramp", help="external-mode stages, e.g. 50,100,200")
    parser.add_argument("-t", "--total", type=int, help="requests per fixed phase")
    parser.add_argument("--per-stage", type=int, help="requests per external ramp stage")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-request timeout seconds")
    parser.add_argument("--jitter", type=float, default=0.0, help="maximum startup jitter seconds")
    parser.add_argument("--proxy-host", default=PROXY_HOST, help="external Moto host")
    parser.add_argument("--proxy-port", type=int, default=PROXY_PORT, help="external Moto port")
    parser.add_argument("--target-host", default=TARGET_HOST, help="external SOCKS5 target host")
    parser.add_argument(
        "--target-port",
        type=int,
        default=TARGET_PORT,
        help="external SOCKS5 target port",
    )
    parser.add_argument("--expect-status-min", type=int, default=EXPECT_STATUS_MIN)
    parser.add_argument("--expect-status-max", type=int, default=EXPECT_STATUS_MAX)
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=99.0,
        help="minimum success percentage for every measured phase",
    )
    parser.add_argument("--save", help="write raw results and metadata as JSON")
    parser.add_argument("--seed", type=int, default=1, help="random seed (default: 1)")

    local = parser.add_argument_group("self-contained local benchmark")
    local.add_argument(
        "--self-contained",
        action="store_true",
        help="start loopback HTTP fixtures and a temporary Moto process",
    )
    local.add_argument(
        "--mode",
        choices=("normal", "regex", "boost", "roundrobin"),
        default="normal",
        help="Moto routing mode for --self-contained",
    )
    local.add_argument(
        "--moto-binary",
        help="existing Moto binary; otherwise go build writes one under a temporary directory",
    )
    local.add_argument(
        "--warmup",
        type=int,
        default=4,
        help="unmeasured requests before warm phase",
    )
    local.add_argument("--startup-timeout", type=float, default=10.0)
    local.add_argument(
        "--resource-sample-interval",
        type=float,
        default=0.10,
        help="seconds between best-effort Moto process resource samples",
    )
    local.add_argument(
        "--min-warm-throughput-ratio",
        type=float,
        default=0.10,
        help="minimum warm/direct request throughput ratio",
    )
    local.add_argument(
        "--max-warm-p95-ms",
        type=float,
        default=500.0,
        help="maximum warm total-latency p95",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    global PROXY_HOST, PROXY_PORT, TARGET_HOST, TARGET_PORT
    global EXPECT_STATUS_MIN, EXPECT_STATUS_MAX

    PROXY_HOST = args.proxy_host
    PROXY_PORT = args.proxy_port
    TARGET_HOST = args.target_host
    TARGET_PORT = args.target_port
    EXPECT_STATUS_MIN = args.expect_status_min
    EXPECT_STATUS_MAX = args.expect_status_max

    if not 0 <= args.min_success_rate <= 100:
        raise SystemExit("--min-success-rate must be between 0 and 100")
    if not 1 <= PROXY_PORT <= 65535 or not 1 <= TARGET_PORT <= 65535:
        raise SystemExit("ports must be between 1 and 65535")
    if (
        args.timeout <= 0
        or args.jitter < 0
        or args.startup_timeout <= 0
        or args.resource_sample_interval <= 0
    ):
        raise SystemExit("timeouts must be positive and --jitter must not be negative")
    if not 100 <= EXPECT_STATUS_MIN <= EXPECT_STATUS_MAX <= 599:
        raise SystemExit("invalid expected HTTP status range")
    if args.min_warm_throughput_ratio < 0:
        raise SystemExit("--min-warm-throughput-ratio must not be negative")
    if args.max_warm_p95_ms <= 0:
        raise SystemExit("--max-warm-p95-ms must be positive")
    random.seed(args.seed)


async def async_main() -> int:
    args = parse_args()
    validate_args(args)
    print("=" * 72)
    if args.self_contained:
        print(f" Moto self-contained benchmark: mode={args.mode} (loopback only)")
        print("=" * 72)
        return await run_self_contained(args)

    print(" Moto external SOCKS5 concurrency benchmark")
    print("=" * 72)
    print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    return await run_external(args)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
