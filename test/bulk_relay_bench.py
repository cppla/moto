#!/usr/bin/env python3
"""Self-contained bulk TCP relay benchmark for Moto.

The benchmark starts a deterministic TCP fixture and, unless --proxy is used,
an isolated Moto process with a temporary normal-mode configuration.  It runs
the same upload/download workload directly and through Moto, verifies every
payload byte, and reports goodput, latency, Moto CPU time, RSS, and file
descriptors.

Optional netem settings are applied only to a throw-away network namespace and
veth pair.  Existing interfaces and qdiscs are never modified.  Creating the
namespace requires root or --netem-sudo with non-interactive sudo permission.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
MAGIC = b"MOTOBLK1"
HEADER = struct.Struct("!8sQQ")
READY = b"R"
SUCCESS = b"K"
FAILURE = b"E"
PAYLOAD = bytes([0xA5]) * (1024 * 1024)
MAX_TRANSFER_BYTES = 1 << 40


@dataclass
class TransferResult:
    ok: bool
    error: Optional[str]
    connect_ms: float
    total_ms: float
    upload_bytes: int
    download_bytes: int


@dataclass
class ProcessSample:
    monotonic_seconds: float
    cpu_seconds: Optional[float]
    rss_bytes: Optional[int]
    file_descriptors: Optional[int]


def percentile(values: Sequence[float], value: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((value / 100.0) * (len(ordered) - 1)))
    return float(ordered[index])


def human_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    current = float(value)
    for unit in units:
        if abs(current) < 1024.0 or unit == units[-1]:
            return f"{current:.2f} {unit}"
        current /= 1024.0
    return f"{current:.2f} TiB"


def parse_size(value: str) -> int:
    text = value.strip().lower()
    suffixes = {
        "k": 1000,
        "kb": 1000,
        "kib": 1024,
        "m": 1000**2,
        "mb": 1000**2,
        "mib": 1024**2,
        "g": 1000**3,
        "gb": 1000**3,
        "gib": 1024**3,
    }
    multiplier = 1
    for suffix in sorted(suffixes, key=len, reverse=True):
        if text.endswith(suffix):
            multiplier = suffixes[suffix]
            text = text[: -len(suffix)]
            break
    try:
        parsed = float(text) * multiplier
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid byte size: {value!r}") from exc
    if not parsed.is_integer() or parsed <= 0 or parsed > MAX_TRANSFER_BYTES:
        raise argparse.ArgumentTypeError(
            f"byte size must be an integer in 1..{MAX_TRANSFER_BYTES}"
        )
    return int(parsed)


def parse_nonnegative_size(value: str) -> int:
    if value.strip() == "0":
        return 0
    return parse_size(value)


def split_host_port(value: str) -> Tuple[str, int]:
    try:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError(
            "address must be HOST:PORT (IPv6 literals are not supported here)"
        ) from exc
    if not host or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("address must contain a valid host and port")
    return host, port


async def send_payload(writer: asyncio.StreamWriter, size: int, chunk_size: int) -> None:
    remaining = size
    while remaining:
        length = min(remaining, chunk_size)
        writer.write(PAYLOAD[:length])
        await writer.drain()
        remaining -= length


async def receive_payload(
    reader: asyncio.StreamReader, size: int, chunk_size: int
) -> None:
    remaining = size
    while remaining:
        length = min(remaining, chunk_size)
        chunk = await reader.readexactly(length)
        if chunk != PAYLOAD[:length]:
            raise RuntimeError(f"payload verification failed with {remaining} bytes left")
        remaining -= length


async def gather_or_cancel(*coroutines: object) -> None:
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


class BulkFixture:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self.server: Optional[asyncio.AbstractServer] = None
        self.handlers: set[asyncio.Task] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle, self.host, self.port)
        sockname = self.server.sockets[0].getsockname()
        self.host = str(sockname[0])
        self.port = int(sockname[1])

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.handlers.add(task)
        try:
            raw_header = await reader.readexactly(HEADER.size)
            magic, upload_bytes, download_bytes = HEADER.unpack(raw_header)
            if magic != MAGIC:
                raise RuntimeError("invalid bulk benchmark protocol magic")
            if upload_bytes > MAX_TRANSFER_BYTES or download_bytes > MAX_TRANSFER_BYTES:
                raise RuntimeError("requested transfer exceeds fixture safety limit")

            writer.write(READY)
            await writer.drain()
            await gather_or_cancel(
                receive_payload(reader, upload_bytes, len(PAYLOAD)),
                send_payload(writer, download_bytes, len(PAYLOAD)),
            )
            writer.write(SUCCESS)
            await writer.drain()
        except (
            asyncio.IncompleteReadError,
            asyncio.TimeoutError,
            ConnectionError,
            OSError,
            RuntimeError,
        ):
            try:
                writer.write(FAILURE)
                await writer.drain()
            except (ConnectionError, OSError):
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            if task is not None:
                self.handlers.discard(task)

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        if self.handlers:
            for task in list(self.handlers):
                task.cancel()
            await asyncio.gather(*list(self.handlers), return_exceptions=True)


async def transfer_once(
    host: str,
    port: int,
    upload_bytes: int,
    download_bytes: int,
    chunk_size: int,
    timeout: float,
) -> TransferResult:
    started = time.monotonic()
    writer: Optional[asyncio.StreamWriter] = None

    async def transfer() -> Tuple[float, float]:
        nonlocal writer
        connect_started = time.monotonic()
        reader, writer = await asyncio.open_connection(host, port)
        connect_ms = (time.monotonic() - connect_started) * 1000.0
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        writer.write(HEADER.pack(MAGIC, upload_bytes, download_bytes))
        await writer.drain()
        ready = await reader.readexactly(1)
        if ready != READY:
            raise RuntimeError(f"fixture rejected benchmark header: {ready!r}")
        await gather_or_cancel(
            send_payload(writer, upload_bytes, chunk_size),
            receive_payload(reader, download_bytes, chunk_size),
        )
        status = await reader.readexactly(1)
        if status != SUCCESS:
            raise RuntimeError(f"fixture reported transfer failure: {status!r}")
        return connect_ms, (time.monotonic() - started) * 1000.0

    try:
        connect_ms, total_ms = await asyncio.wait_for(transfer(), timeout=timeout)
        return TransferResult(
            ok=True,
            error=None,
            connect_ms=connect_ms,
            total_ms=total_ms,
            upload_bytes=upload_bytes,
            download_bytes=download_bytes,
        )
    except Exception as exc:
        return TransferResult(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            connect_ms=0.0,
            total_ms=(time.monotonic() - started) * 1000.0,
            upload_bytes=0,
            download_bytes=0,
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def run_phase(
    host: str,
    port: int,
    concurrency: int,
    connections: int,
    upload_bytes: int,
    download_bytes: int,
    chunk_size: int,
    timeout: float,
) -> Tuple[List[TransferResult], float]:
    semaphore = asyncio.Semaphore(concurrency)

    async def worker() -> TransferResult:
        async with semaphore:
            return await transfer_once(
                host,
                port,
                upload_bytes,
                download_bytes,
                chunk_size,
                timeout,
            )

    started = time.monotonic()
    results = await asyncio.gather(*(worker() for _ in range(connections)))
    return list(results), max(time.monotonic() - started, 1e-9)


def phase_summary(
    results: Sequence[TransferResult], elapsed: float
) -> Dict[str, object]:
    successes = [result for result in results if result.ok]
    upload_bytes = sum(result.upload_bytes for result in successes)
    download_bytes = sum(result.download_bytes for result in successes)
    combined_bytes = upload_bytes + download_bytes
    total_ms = [result.total_ms for result in successes]
    connect_ms = [result.connect_ms for result in successes]
    errors: Dict[str, int] = {}
    for result in results:
        if result.ok:
            continue
        key = result.error or "unknown"
        errors[key] = errors.get(key, 0) + 1
    return {
        "connections": len(results),
        "ok": len(successes),
        "failed": len(results) - len(successes),
        "success_rate": 100.0 * len(successes) / len(results) if results else 0.0,
        "elapsed_seconds": elapsed,
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "combined_bytes": combined_bytes,
        "upload_gbps": upload_bytes * 8.0 / elapsed / 1_000_000_000.0,
        "download_gbps": download_bytes * 8.0 / elapsed / 1_000_000_000.0,
        "combined_gbps": combined_bytes * 8.0 / elapsed / 1_000_000_000.0,
        "connection_ms": {
            "p50": percentile(connect_ms, 50),
            "p95": percentile(connect_ms, 95),
            "p99": percentile(connect_ms, 99),
        },
        "transfer_ms": {
            "p50": percentile(total_ms, 50),
            "p95": percentile(total_ms, 95),
            "p99": percentile(total_ms, 99),
        },
        "errors": errors,
    }


def parse_proc_stat_cpu(pid: int) -> Optional[float]:
    path = Path("/proc") / str(pid) / "stat"
    try:
        raw = path.read_text(encoding="ascii")
        fields = raw.rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        return ticks / float(os.sysconf("SC_CLK_TCK"))
    except (IndexError, OSError, ValueError):
        return None


def parse_ps_cpu_time(value: str) -> Optional[float]:
    text = value.strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        day_text, text = text.split("-", 1)
        days = int(day_text)
    parts = text.split(":")
    if len(parts) == 3:
        hours, minutes, seconds = parts
    elif len(parts) == 2:
        hours = "0"
        minutes, seconds = parts
    else:
        return None
    return days * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def sample_process(pid: int) -> ProcessSample:
    now = time.monotonic()
    cpu_seconds = parse_proc_stat_cpu(pid)
    rss_bytes: Optional[int] = None
    file_descriptors: Optional[int] = None

    status_path = Path("/proc") / str(pid) / "status"
    try:
        for line in status_path.read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                rss_bytes = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    fd_path = Path("/proc") / str(pid) / "fd"
    try:
        file_descriptors = len(os.listdir(fd_path))
    except OSError:
        pass

    if cpu_seconds is None or rss_bytes is None:
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            completed = subprocess.run(
                ("ps", "-o", "time=", "-o", "rss=", "-p", str(pid)),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1.0,
                env=environment,
            )
            fields = completed.stdout.split()
            if len(fields) >= 2:
                if cpu_seconds is None:
                    cpu_seconds = parse_ps_cpu_time(fields[0])
                if rss_bytes is None:
                    rss_bytes = int(fields[1]) * 1024
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return ProcessSample(now, cpu_seconds, rss_bytes, file_descriptors)


class ProcessSampler:
    def __init__(self, pid: int, interval: float) -> None:
        self.pid = pid
        self.interval = interval
        self.samples: List[ProcessSample] = []
        self.stop_event = asyncio.Event()
        self.task: Optional[asyncio.Task] = None

    async def record(self) -> None:
        self.samples.append(await asyncio.to_thread(sample_process, self.pid))

    async def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                await self.record()

    async def start(self) -> None:
        await self.record()
        self.task = asyncio.create_task(self.run())

    async def stop(self, measured_elapsed: float) -> Dict[str, object]:
        self.stop_event.set()
        if self.task is not None:
            await self.task
        await self.record()
        cpu_samples = [sample for sample in self.samples if sample.cpu_seconds is not None]
        rss = [sample.rss_bytes for sample in self.samples if sample.rss_bytes is not None]
        fds = [
            sample.file_descriptors
            for sample in self.samples
            if sample.file_descriptors is not None
        ]
        cpu_seconds: Optional[float] = None
        average_cpu_cores: Optional[float] = None
        peak_cpu_cores: Optional[float] = None
        if len(cpu_samples) >= 2:
            cpu_seconds = max(
                0.0,
                float(cpu_samples[-1].cpu_seconds) - float(cpu_samples[0].cpu_seconds),
            )
            average_cpu_cores = cpu_seconds / max(measured_elapsed, 1e-9)
            intervals = []
            for previous, current in zip(cpu_samples, cpu_samples[1:]):
                wall = current.monotonic_seconds - previous.monotonic_seconds
                cpu = float(current.cpu_seconds) - float(previous.cpu_seconds)
                if wall > 0 and cpu >= 0:
                    intervals.append(cpu / wall)
            if intervals:
                peak_cpu_cores = max(intervals)
        return {
            "samples": len(self.samples),
            "sample_interval_seconds": self.interval,
            "cpu_seconds": cpu_seconds,
            "average_cpu_cores": average_cpu_cores,
            "peak_sample_cpu_cores": peak_cpu_cores,
            "rss_peak_bytes": max(rss) if rss else None,
            "rss_mean_bytes": int(statistics.fmean(rss)) if rss else None,
            "fd_peak": max(fds) if fds else None,
        }


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


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


def make_config(
    moto_port: int, metrics_port: int, backend: Tuple[str, int], concurrency: int
) -> Dict[str, object]:
    limit = max(128, concurrency * 4)
    return {
        "log": {"level": "error", "path": ""},
        "metrics": {"enabled": True, "listen": f"127.0.0.1:{metrics_port}"},
        "rules": [
            {
                "name": "bulk-relay-benchmark",
                "listen": f"127.0.0.1:{moto_port}",
                "mode": "normal",
                "prewarm": False,
                "timeout": 3000,
                "allowlist": ["127.0.0.0/8"],
                "maxConnections": limit,
                "maxConnectionsPerIP": limit,
                "blacklist": {},
                "targets": [{"address": f"{backend[0]}:{backend[1]}"}],
            }
        ],
    }


async def wait_for_moto_ready(
    process: subprocess.Popen, metrics_port: int, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not started"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Moto exited during startup with code {process.returncode}")
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", metrics_port)
            writer.write(
                b"GET /readyz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            status = await asyncio.wait_for(reader.readline(), timeout=0.5)
            if b" 200 " in status:
                return
            last_error = status.decode("ascii", "replace").strip()
        except (OSError, asyncio.TimeoutError) as exc:
            last_error = str(exc)
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
        await asyncio.sleep(0.02)
    raise RuntimeError(f"Moto was not ready after {timeout:.1f}s: {last_error}")


async def stop_process(process: subprocess.Popen, timeout: float = 5.0) -> int:
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        await asyncio.to_thread(process.wait)
    return int(process.returncode)


def run_checked(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        tuple(command),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10.0,
    )


class NetemNamespace:
    """Disposable veth/netns test path; never changes an existing qdisc."""

    def __init__(self, args: argparse.Namespace) -> None:
        # A random component prevents a stale namespace from an interrupted
        # earlier run with a reused PID from colliding with this benchmark.
        suffix = f"{os.getpid():x}{secrets.token_hex(2)}"[-7:]
        self.namespace = f"moto-bench-{suffix}"
        self.host_interface = f"mbh{suffix}"[:15]
        self.peer_interface = f"mbn{suffix}"[:15]
        self.args = args
        self.prefix: List[str] = []
        self.created = False
        self.backend_process: Optional[subprocess.Popen] = None
        self.host_address = ""
        self.peer_address = ""
        self.backend_port = 39091
        self.commands: List[List[str]] = []

    def privileged(self, *command: str) -> List[str]:
        return [*self.prefix, *command]

    def execute(self, *command: str) -> subprocess.CompletedProcess:
        full = self.privileged(*command)
        self.commands.append(full)
        return run_checked(full)

    def choose_network(self) -> ipaddress.IPv4Network:
        completed = run_checked(("ip", "-j", "route", "show", "table", "all"))
        routes = []
        for item in json.loads(completed.stdout):
            destination = item.get("dst")
            if not destination or destination == "default":
                continue
            try:
                routes.append(ipaddress.ip_network(destination, strict=False))
            except ValueError:
                continue
        pool = ipaddress.ip_network("198.18.0.0/15")
        candidates = list(pool.subnets(new_prefix=30))
        offset = os.getpid() % len(candidates)
        for index in range(len(candidates)):
            candidate = candidates[(offset + index) % len(candidates)]
            if not any(candidate.overlaps(route) for route in routes):
                return candidate
        raise RuntimeError("no unused RFC 2544 /30 network is available for netem")

    def netem_arguments(self) -> List[str]:
        values: List[str] = []
        if self.args.netem_delay_ms > 0:
            values.extend(("delay", f"{self.args.netem_delay_ms:g}ms"))
            if self.args.netem_jitter_ms > 0:
                values.append(f"{self.args.netem_jitter_ms:g}ms")
        if self.args.netem_loss_percent > 0:
            values.extend(("loss", f"{self.args.netem_loss_percent:g}%"))
        if self.args.netem_rate_mbit > 0:
            values.extend(("rate", f"{self.args.netem_rate_mbit:g}mbit"))
        return values

    async def start(self) -> Tuple[str, int]:
        if platform.system() != "Linux":
            raise RuntimeError("netem namespace mode requires Linux")
        for program in ("ip", "tc"):
            if shutil.which(program) is None:
                raise RuntimeError(f"netem namespace mode requires {program!r}")
        if os.geteuid() != 0:
            if not self.args.netem_sudo:
                raise RuntimeError(
                    "netem requires root; rerun with --netem-sudo after granting "
                    "non-interactive sudo for ip/tc"
                )
            if shutil.which("sudo") is None:
                raise RuntimeError("--netem-sudo requested but sudo is unavailable")
            run_checked(("sudo", "-n", "true"))
            self.prefix = ["sudo", "-n"]

        network = self.choose_network()
        addresses = list(network.hosts())
        self.host_address = str(addresses[0])
        self.peer_address = str(addresses[1])

        try:
            self.execute("ip", "netns", "add", self.namespace)
            self.created = True
            self.execute(
                "ip",
                "link",
                "add",
                self.host_interface,
                "type",
                "veth",
                "peer",
                "name",
                self.peer_interface,
            )
            self.execute(
                "ip", "link", "set", self.peer_interface, "netns", self.namespace
            )
            self.execute(
                "ip",
                "address",
                "add",
                f"{self.host_address}/{network.prefixlen}",
                "dev",
                self.host_interface,
            )
            self.execute("ip", "link", "set", self.host_interface, "up")
            self.execute("ip", "-n", self.namespace, "link", "set", "lo", "up")
            self.execute(
                "ip",
                "-n",
                self.namespace,
                "address",
                "add",
                f"{self.peer_address}/{network.prefixlen}",
                "dev",
                self.peer_interface,
            )
            self.execute(
                "ip",
                "-n",
                self.namespace,
                "link",
                "set",
                self.peer_interface,
                "up",
            )
            netem = self.netem_arguments()
            self.execute(
                "tc", "qdisc", "add", "dev", self.host_interface, "root", "netem", *netem
            )
            self.execute(
                "ip",
                "netns",
                "exec",
                self.namespace,
                "tc",
                "qdisc",
                "add",
                "dev",
                self.peer_interface,
                "root",
                "netem",
                *netem,
            )

            command = self.privileged(
                "ip",
                "netns",
                "exec",
                self.namespace,
                sys.executable,
                str(Path(__file__).resolve()),
                "--backend-only",
                "--backend-bind",
                self.peer_address,
                "--backend-port",
                str(self.backend_port),
            )
            self.backend_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=(os.name == "posix"),
            )
            line = await asyncio.wait_for(
                asyncio.to_thread(self.backend_process.stdout.readline), timeout=5.0
            )
            expected = f"READY {self.peer_address}:{self.backend_port}"
            if line.strip() != expected:
                raise RuntimeError(
                    f"netns backend did not become ready: {line.strip()!r}, "
                    f"expected {expected!r}"
                )
            return self.peer_address, self.backend_port
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        if self.backend_process is not None:
            await stop_process(self.backend_process)
            self.backend_process = None
        if self.created:
            try:
                self.execute("ip", "netns", "delete", self.namespace)
            except (OSError, subprocess.SubprocessError):
                print(
                    "WARNING: failed to remove network namespace; run: "
                    + " ".join(self.privileged("ip", "netns", "delete", self.namespace)),
                    file=sys.stderr,
                )
            self.created = False

    def summary(self) -> Dict[str, object]:
        return {
            "enabled": True,
            "namespace": self.namespace,
            "host_interface": self.host_interface,
            "peer_interface": self.peer_interface,
            "host_address": self.host_address,
            "peer_address": self.peer_address,
            "one_way_delay_ms_each_direction": self.args.netem_delay_ms,
            "jitter_ms_each_direction": self.args.netem_jitter_ms,
            "loss_percent_each_direction": self.args.netem_loss_percent,
            "rate_mbit_each_direction": self.args.netem_rate_mbit,
        }


def command_text(command: Sequence[str], fallback: str = "unknown") -> str:
    try:
        completed = subprocess.run(
            tuple(command),
            check=True,
            cwd=str(REPOSITORY_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0,
        )
        return completed.stdout.strip() or fallback
    except (OSError, subprocess.SubprocessError):
        return fallback


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def benchmark_meta() -> Dict[str, object]:
    return {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": command_text(("git", "rev-parse", "HEAD")),
        "git_dirty": command_text(("git", "status", "--porcelain"), "") != "",
        "go_toolchain": command_text(("go", "version")),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "logical_cpu_count": os.cpu_count(),
        "benchmark_sha256": file_sha256(Path(__file__).resolve()),
    }


def print_phase(name: str, summary: Dict[str, object]) -> None:
    print(
        f"{name:<8} success={summary['success_rate']:6.2f}% "
        f"combined={summary['combined_gbps']:7.3f} Gbit/s "
        f"upload={summary['upload_gbps']:7.3f} "
        f"download={summary['download_gbps']:7.3f} "
        f"p95={summary['transfer_ms']['p95']:9.2f} ms"
    )
    if summary["errors"]:
        print(f"{name:<8} errors={json.dumps(summary['errors'], sort_keys=True)}")


def print_resources(resources: Dict[str, object]) -> None:
    print("\nMoto resources during proxy phase:")
    average = resources.get("average_cpu_cores")
    peak = resources.get("peak_sample_cpu_cores")
    rss = resources.get("rss_peak_bytes")
    fds = resources.get("fd_peak")
    print(
        "  cpu="
        + (f"{float(average):.3f} average cores" if average is not None else "unsupported")
        + ", peak-sample="
        + (f"{float(peak):.3f} cores" if peak is not None else "unsupported")
    )
    print(
        "  rss-peak="
        + (human_bytes(float(rss)) if rss is not None else "unsupported")
        + f", fd-peak={fds if fds is not None else 'unsupported'}"
    )


def netem_requested(args: argparse.Namespace) -> bool:
    return any(
        value > 0
        for value in (
            args.netem_delay_ms,
            args.netem_jitter_ms,
            args.netem_loss_percent,
            args.netem_rate_mbit,
        )
    )


async def run_backend_only(args: argparse.Namespace) -> int:
    fixture = BulkFixture(args.backend_bind, args.backend_port)
    await fixture.start()
    print(f"READY {fixture.host}:{fixture.port}", flush=True)
    try:
        await asyncio.Future()
    finally:
        await fixture.close()
    return 0


async def run_benchmark(args: argparse.Namespace) -> int:
    upload_bytes = args.bytes_per_direction if args.direction in ("upload", "both") else 0
    download_bytes = (
        args.bytes_per_direction if args.direction in ("download", "both") else 0
    )
    fixture: Optional[BulkFixture] = None
    namespace: Optional[NetemNamespace] = None
    moto_process: Optional[subprocess.Popen] = None
    moto_log_handle = None
    moto_log = ""
    moto_exit_code: Optional[int] = None
    configuration: Optional[Dict[str, object]] = None
    configuration_bytes = b""
    moto_binary_source: Optional[str] = None
    moto_binary_sha256: Optional[str] = None
    moto_version: Optional[str] = None
    sampler: Optional[ProcessSampler] = None
    sampler_started_at: Optional[float] = None
    resources: Optional[Dict[str, object]] = None
    direct_results: List[TransferResult] = []
    proxy_results: List[TransferResult] = []
    direct_summary: Optional[Dict[str, object]] = None
    proxy_summary: Optional[Dict[str, object]] = None
    netem_summary: Dict[str, object] = {"enabled": False}

    with tempfile.TemporaryDirectory(prefix="moto-bulk-bench-") as temp_name:
        temp_dir = Path(temp_name)
        try:
            if args.backend:
                backend = split_host_port(args.backend)
            elif netem_requested(args):
                namespace = NetemNamespace(args)
                backend = await namespace.start()
                netem_summary = namespace.summary()
                print(
                    "netem namespace: "
                    f"{namespace.namespace}, one-way delay on each direction="
                    f"{args.netem_delay_ms:g} ms, loss={args.netem_loss_percent:g}%"
                )
            else:
                fixture = BulkFixture()
                await fixture.start()
                backend = (fixture.host, fixture.port)

            print(
                f"workload: direction={args.direction} concurrency={args.concurrency} "
                f"connections={args.connections} bytes/direction/connection="
                f"{human_bytes(args.bytes_per_direction)}"
            )
            if args.proxy:
                proxy_host, proxy_port = split_host_port(args.proxy)
                if args.moto_pid is not None:
                    sampler = ProcessSampler(args.moto_pid, args.sample_interval)
            else:
                if args.moto_binary:
                    moto_binary = Path(args.moto_binary).expanduser().resolve()
                    if not moto_binary.is_file():
                        raise RuntimeError(f"Moto binary does not exist: {moto_binary}")
                    moto_binary_source = str(moto_binary)
                else:
                    moto_binary = temp_dir / "moto"
                    build_moto(moto_binary)
                    moto_binary_source = "temporary build from repository"
                moto_binary_sha256 = file_sha256(moto_binary)
                moto_version = command_text((str(moto_binary), "--version"))

                startup_errors = []
                for startup_attempt in range(1, 4):
                    moto_port = available_loopback_port()
                    metrics_port = available_loopback_port()
                    while metrics_port == moto_port:
                        metrics_port = available_loopback_port()
                    configuration = make_config(
                        moto_port, metrics_port, backend, args.concurrency
                    )
                    configuration_bytes = (
                        json.dumps(configuration, sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode("utf-8")
                    config_path = temp_dir / f"setting-{startup_attempt}.json"
                    config_path.write_bytes(configuration_bytes)
                    log_path = temp_dir / f"moto-{startup_attempt}.log"
                    moto_log_handle = log_path.open("w+", encoding="utf-8")
                    moto_process = subprocess.Popen(
                        (str(moto_binary), "--config", str(config_path)),
                        cwd=str(REPOSITORY_ROOT),
                        stdout=moto_log_handle,
                        stderr=subprocess.STDOUT,
                        start_new_session=(os.name == "posix"),
                    )
                    try:
                        await wait_for_moto_ready(
                            moto_process, metrics_port, args.startup_timeout
                        )
                        break
                    except Exception as exc:
                        await stop_process(moto_process)
                        moto_log_handle.flush()
                        moto_log_handle.seek(0)
                        startup_errors.append(
                            f"attempt {startup_attempt}: {exc}\n{moto_log_handle.read()}"
                        )
                        moto_log_handle.close()
                        moto_log_handle = None
                        moto_process = None
                        if startup_attempt == 3:
                            raise RuntimeError(
                                "Moto startup failed:\n" + "\n".join(startup_errors)
                            ) from exc
                proxy_host, proxy_port = "127.0.0.1", moto_port
                sampler = ProcessSampler(moto_process.pid, args.sample_interval)

            if args.warmup_bytes > 0:
                warm_upload = args.warmup_bytes if upload_bytes else 0
                warm_download = args.warmup_bytes if download_bytes else 0
                for name, host, port in (
                    ("direct", backend[0], backend[1]),
                    ("proxy", proxy_host, proxy_port),
                ):
                    warm = await transfer_once(
                        host,
                        port,
                        warm_upload,
                        warm_download,
                        args.chunk_size,
                        args.timeout,
                    )
                    if not warm.ok:
                        raise RuntimeError(f"{name} warmup failed: {warm.error}")

            async def measure_direct() -> None:
                nonlocal direct_results, direct_summary
                direct_results, elapsed = await run_phase(
                    backend[0],
                    backend[1],
                    args.concurrency,
                    args.connections,
                    upload_bytes,
                    download_bytes,
                    args.chunk_size,
                    args.timeout,
                )
                direct_summary = phase_summary(direct_results, elapsed)

            async def measure_proxy() -> None:
                nonlocal proxy_results, proxy_summary, resources
                nonlocal sampler, sampler_started_at
                if sampler is not None:
                    await sampler.start()
                    sampler_started_at = time.monotonic()
                proxy_results, elapsed = await run_phase(
                    proxy_host,
                    proxy_port,
                    args.concurrency,
                    args.connections,
                    upload_bytes,
                    download_bytes,
                    args.chunk_size,
                    args.timeout,
                )
                proxy_summary = phase_summary(proxy_results, elapsed)
                if sampler is not None:
                    resources = await sampler.stop(elapsed)
                    sampler = None
                    sampler_started_at = None

            if args.proxy_first:
                await measure_proxy()
                await measure_direct()
            else:
                await measure_direct()
                await measure_proxy()
        finally:
            if sampler is not None:
                measured_elapsed = (
                    float(proxy_summary["elapsed_seconds"])
                    if proxy_summary is not None
                    else max(time.monotonic() - (sampler_started_at or time.monotonic()), 1e-9)
                )
                resources = await sampler.stop(measured_elapsed)
            if moto_process is not None:
                moto_exit_code = await stop_process(moto_process)
            if moto_log_handle is not None:
                moto_log_handle.flush()
                moto_log_handle.seek(0)
                moto_log = moto_log_handle.read()
                moto_log_handle.close()
            if fixture is not None:
                await fixture.close()
            if namespace is not None:
                await namespace.close()

        if direct_summary is None or proxy_summary is None:
            raise RuntimeError("benchmark phases did not complete")
        ratio = (
            float(proxy_summary["combined_gbps"])
            / float(direct_summary["combined_gbps"])
            if float(direct_summary["combined_gbps"]) > 0
            else 0.0
        )
        payload: Dict[str, object] = {
            "meta": {
                **benchmark_meta(),
                "direction": args.direction,
                "concurrency": args.concurrency,
                "connections": args.connections,
                "bytes_per_direction_per_connection": args.bytes_per_direction,
                "chunk_size": args.chunk_size,
                "warmup_bytes_per_active_direction": args.warmup_bytes,
                "transfer_timeout_seconds": args.timeout,
                "proxy": args.proxy or "self-contained Moto",
                "phase_order": "proxy,direct" if args.proxy_first else "direct,proxy",
                "moto_exit_code": moto_exit_code,
                "moto_binary_source": moto_binary_source,
                "moto_binary_sha256": moto_binary_sha256,
                "moto_version": moto_version,
                "configuration_sha256": (
                    hashlib.sha256(configuration_bytes).hexdigest()
                    if configuration_bytes
                    else None
                ),
                "netem": netem_summary,
            },
            "phases": {"direct": direct_summary, "proxy": proxy_summary},
            "proxy_direct_goodput_ratio": ratio,
            "moto_resources": resources,
            "results": {
                "direct": [asdict(result) for result in direct_results],
                "proxy": [asdict(result) for result in proxy_results],
            },
        }
        print("\n=== Bulk relay result ===")
        print_phase("direct", direct_summary)
        print_phase("proxy", proxy_summary)
        print(f"proxy/direct combined goodput ratio={ratio:.3f}")
        if resources is not None:
            print_resources(resources)
        if args.save:
            destination = Path(args.save).expanduser().resolve()
            destination.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"saved JSON -> {destination}")

        failures = []
        for phase_name, summary in (("direct", direct_summary), ("proxy", proxy_summary)):
            if float(summary["success_rate"]) < args.min_success_rate:
                failures.append(
                    f"{phase_name} success rate {summary['success_rate']:.2f}% is below "
                    f"{args.min_success_rate:.2f}%"
                )
        if ratio < args.min_proxy_direct_ratio:
            failures.append(
                f"proxy/direct goodput ratio {ratio:.3f} is below "
                f"{args.min_proxy_direct_ratio:.3f}"
            )
        if moto_exit_code not in (None, 0):
            failures.append(f"Moto exited with code {moto_exit_code}")
        if failures:
            for failure in failures:
                print(f"THRESHOLD FAILED: {failure}", file=sys.stderr)
            if moto_log:
                print("Moto log tail:", file=sys.stderr)
                print("\n".join(moto_log.splitlines()[-20:]), file=sys.stderr)
            return 2
        print("Thresholds: PASS")
        return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--direction", choices=("upload", "download", "both"), default="both"
    )
    parser.add_argument("-c", "--concurrency", type=int, default=4)
    parser.add_argument("-n", "--connections", type=int, default=4)
    parser.add_argument(
        "--bytes-per-direction", type=parse_size, default=parse_size("64MiB")
    )
    parser.add_argument("--chunk-size", type=parse_size, default=parse_size("64KiB"))
    parser.add_argument(
        "--warmup-bytes",
        type=parse_nonnegative_size,
        default=parse_size("2MiB"),
        help="proxy warmup bytes per active direction; 0 disables warmup",
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    parser.add_argument("--sample-interval", type=float, default=0.10)
    parser.add_argument(
        "--moto-binary",
        help="existing Moto binary; otherwise build a temporary one",
    )
    parser.add_argument(
        "--proxy",
        help="benchmark an existing Moto HOST:PORT (requires --backend)",
    )
    parser.add_argument(
        "--backend",
        help="existing bulk fixture HOST:PORT used for direct baseline with --proxy",
    )
    parser.add_argument("--moto-pid", type=int, help="resource sampling PID with --proxy")
    parser.add_argument(
        "--proxy-first",
        action="store_true",
        help="measure proxy before direct; alternate this across repeated A/B runs",
    )
    parser.add_argument("--save", help="write JSON result to this path")
    parser.add_argument("--min-success-rate", type=float, default=100.0)
    parser.add_argument("--min-proxy-direct-ratio", type=float, default=0.0)

    netem = parser.add_argument_group("disposable Linux network namespace/netem")
    netem.add_argument("--netem-delay-ms", type=float, default=0.0)
    netem.add_argument("--netem-jitter-ms", type=float, default=0.0)
    netem.add_argument("--netem-loss-percent", type=float, default=0.0)
    netem.add_argument("--netem-rate-mbit", type=float, default=0.0)
    netem.add_argument(
        "--netem-sudo",
        action="store_true",
        help="use sudo -n only for isolated ip/tc namespace commands",
    )

    internal = parser.add_argument_group("internal fixture process")
    internal.add_argument("--backend-only", action="store_true", help=argparse.SUPPRESS)
    internal.add_argument("--backend-bind", default="127.0.0.1", help=argparse.SUPPRESS)
    internal.add_argument("--backend-port", type=int, default=0, help=argparse.SUPPRESS)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.backend_only:
        if not 0 <= args.backend_port <= 65535:
            raise SystemExit("--backend-port must be in 0..65535")
        return
    if args.concurrency <= 0 or args.connections <= 0:
        raise SystemExit("--concurrency and --connections must be positive")
    if args.concurrency > args.connections:
        raise SystemExit("--concurrency cannot exceed --connections")
    if not 1 <= args.chunk_size <= len(PAYLOAD):
        raise SystemExit(f"--chunk-size must be in 1..{len(PAYLOAD)}")
    if args.timeout <= 0 or args.startup_timeout <= 0 or args.sample_interval <= 0:
        raise SystemExit("timeouts and --sample-interval must be positive")
    if not 0 <= args.min_success_rate <= 100:
        raise SystemExit("--min-success-rate must be in 0..100")
    if args.min_proxy_direct_ratio < 0:
        raise SystemExit("--min-proxy-direct-ratio must not be negative")
    if bool(args.proxy) != bool(args.backend):
        raise SystemExit("--proxy and --backend must be supplied together")
    if args.proxy:
        split_host_port(args.proxy)
        split_host_port(args.backend)
        if netem_requested(args):
            raise SystemExit("--proxy cannot be combined with self-contained netem")
        if args.moto_binary:
            raise SystemExit("--proxy cannot be combined with --moto-binary")
    elif args.moto_pid is not None:
        raise SystemExit("--moto-pid requires --proxy")
    if args.moto_pid is not None and args.moto_pid <= 0:
        raise SystemExit("--moto-pid must be positive")
    if not 0 <= args.netem_loss_percent < 100:
        raise SystemExit("--netem-loss-percent must be in 0..<100")
    if args.netem_delay_ms < 0 or args.netem_jitter_ms < 0 or args.netem_rate_mbit < 0:
        raise SystemExit("netem delay, jitter, and rate must not be negative")
    if args.netem_jitter_ms > 0 and args.netem_delay_ms <= 0:
        raise SystemExit("--netem-jitter-ms requires --netem-delay-ms")


async def async_main() -> int:
    args = parse_args()
    validate_args(args)
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    received_signal: List[int] = []
    installed: List[int] = []

    def cancel_for_signal(number: int) -> None:
        if not received_signal:
            received_signal.append(number)
        if task is not None:
            task.cancel()

    if os.name == "posix":
        for name in ("SIGHUP", "SIGTERM"):
            number = getattr(signal, name, None)
            if number is None:
                continue
            try:
                loop.add_signal_handler(number, cancel_for_signal, number)
                installed.append(number)
            except (NotImplementedError, RuntimeError):
                pass
    try:
        if args.backend_only:
            return await run_backend_only(args)
        return await run_benchmark(args)
    except asyncio.CancelledError:
        if received_signal:
            number = received_signal[0]
            print(f"interrupted by signal {number}", file=sys.stderr)
            return 128 + number
        raise
    finally:
        for number in installed:
            loop.remove_signal_handler(number)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
