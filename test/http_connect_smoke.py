#!/usr/bin/env python3
"""Bounded HTTPS smoke test through an isolated Moto HTTP CONNECT listener.

Run this script beside a Moto binary on the machine or container being tested.
The source configuration is never modified. Credentials and process logs stay
inside a private temporary directory, which is removed when the run finishes.
Only sanitized JSON is printed; redirects are not followed. In auto mode the
report describes configured protocol order, not the winning upstream transport.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit


MAX_BODY_BYTES = 1 << 20
MAX_CONFIG_BYTES = 4 << 20
MAX_CONNECT_HEADER_BYTES = 32 << 10


class SmokeFailure(Exception):
    """An intentionally fixed, non-sensitive diagnostic code."""


def isolated_config(source: dict, port: int, protocol: str, target_index: int | None) -> dict:
    rules = source.get("rules", [])
    if not isinstance(rules, list):
        raise SmokeFailure("invalid_config")
    candidates = [rule for rule in rules if isinstance(rule, dict) and rule.get("protocol") == "http"]
    if not candidates:
        raise SmokeFailure("no_http_rule")
    selected = next((rule for rule in candidates if rule.get("listen") == "127.0.0.1:9006"), candidates[0])
    rule = copy.deepcopy(selected)
    if rule.get("mode") not in {"normal", "boost", "roundrobin"}:
        raise SmokeFailure("invalid_http_rule_mode")
    targets = rule.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SmokeFailure("missing_upstream_targets")
    if target_index is not None:
        if target_index < 0 or target_index >= len(targets):
            raise SmokeFailure("target_index_out_of_range")
        targets = [targets[target_index]]
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("connectProxy"), dict):
            raise SmokeFailure("invalid_connect_proxy_target")
        proxy = target["connectProxy"]
        if protocol != "auto":
            proxy["protocols"] = [protocol]
        protocols = proxy.get("protocols") or ["h2"]
        if not isinstance(protocols, list) or any(item not in {"h2", "h3"} for item in protocols):
            raise SmokeFailure("invalid_upstream_protocols")
    rule.update(name="http-connect-smoke", listen=f"127.0.0.1:{port}", targets=targets,
                allowlist=["127.0.0.1/32"], blacklist={})
    # One explicit request should not also start periodic upstream probes.
    rule.pop("healthCheck", None)
    return {"log": {"level": "error", "path": ""}, "metrics": {"enabled": False}, "rules": [rule]}


def https_destination(value: str) -> tuple[str, str, str]:
    try:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii")
        port = 443 if parsed.port is None else parsed.port
        if not 1 <= port <= 65535:
            raise ValueError
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        path.encode("ascii")
        return host, authority, path
    except (ValueError, UnicodeError):
        raise SmokeFailure("invalid_https_url") from None


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def wait_ready(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeFailure("moto_startup_failed")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                if process.poll() is not None:
                    raise SmokeFailure("moto_startup_failed")
                return
        except OSError:
            time.sleep(0.05)
    raise SmokeFailure("moto_startup_timeout")


def https_through_proxy(port: int, destination: tuple[str, str, str], timeout: float, report: dict) -> None:
    host, authority, path = destination
    start = time.monotonic()
    deadline = start + timeout

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise SmokeFailure("timeout")
        return value

    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=remaining()) as raw:
        raw.settimeout(remaining())
        raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            if len(header) >= MAX_CONNECT_HEADER_BYTES:
                raise SmokeFailure("invalid_connect_response")
            raw.settimeout(remaining())
            chunk = raw.recv(1)  # Do not consume bytes belonging to the TLS tunnel.
            if not chunk:
                raise SmokeFailure("incomplete_connect_response")
            header.extend(chunk)
        try:
            version, status, _ = bytes(header).split(b"\r\n", 1)[0].split(b" ", 2)
            if version != b"HTTP/1.1" or len(status) != 3 or not status.isdigit():
                raise ValueError
            report["connect_status"] = int(status)
        except ValueError:
            raise SmokeFailure("invalid_connect_response") from None
        report["timing_ms"]["connect"] = round((time.monotonic() - start) * 1000, 2)
        if report["connect_status"] != 200:
            raise SmokeFailure("connect_rejected")

        raw.settimeout(remaining())
        with context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False) as secured:
            expired = threading.Event()

            def abort() -> None:
                expired.set()
                try:
                    secured.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                secured.close()

            # HTTPResponse internally reads several lines/chunks. A watchdog
            # enforces the total budget even if an origin trickles bytes.
            timer = threading.Timer(remaining(), abort)
            timer.daemon = True
            timer.start()
            try:
                tls_start = time.monotonic()
                secured.settimeout(remaining())
                secured.do_handshake()
                report["timing_ms"]["tls"] = round((time.monotonic() - tls_start) * 1000, 2)
                secured.sendall((f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
                                 "User-Agent: Moto-HTTP-Connect-Smoke/1.0\r\n"
                                 "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii"))
                response = http.client.HTTPResponse(secured, method="GET")
                try:
                    response.begin()
                    report["origin_status"] = response.status
                    if not 200 <= response.status < 300:
                        raise SmokeFailure("origin_not_2xx")
                    digest = hashlib.sha256()
                    while report["bytes"] <= MAX_BODY_BYTES:
                        chunk = response.read(min(64 << 10, MAX_BODY_BYTES - report["bytes"] + 1))
                        if not chunk:
                            if response.length not in (None, 0):
                                raise SmokeFailure("incomplete_origin_body")
                            report["body_complete"] = True
                            report["sha256"] = digest.hexdigest()
                            break
                        retained = chunk[:MAX_BODY_BYTES - report["bytes"]]
                        report["bytes"] += len(retained)
                        digest.update(retained)
                        if len(retained) != len(chunk):
                            break
                    if expired.is_set():
                        raise SmokeFailure("timeout")
                    report["ok"] = True
                finally:
                    response.close()
            except (OSError, http.client.HTTPException):
                if expired.is_set():
                    raise SmokeFailure("timeout") from None
                raise
            finally:
                timer.cancel()
                timer.join(timeout=1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Existing configuration; read only")
    parser.add_argument("--binary", required=True, type=Path, help="Moto binary to run in isolation")
    parser.add_argument("--protocol", choices=("auto", "h2", "h3"), default="auto", help="Upstream policy; auto preserves configured order")
    parser.add_argument("--target-index", type=int, help="Select one upstream by zero-based index")
    parser.add_argument("--url", default="https://example.com/", help="HTTPS destination (no redirects; not printed)")
    parser.add_argument("--timeout", type=float, default=20, help="Total CONNECT/TLS/GET budget in seconds (1..120)")
    args = parser.parse_args()
    report = {"ok": False, "protocol": args.protocol, "mode": None, "target_count": 0,
              "connect_status": None, "origin_status": None, "bytes": 0,
              "body_complete": False, "sha256": None, "timing_ms": {}}
    start = time.monotonic()
    try:
        if not 1 <= args.timeout <= 120:
            raise SmokeFailure("invalid_timeout")
        destination = https_destination(args.url)
        binary = args.binary.resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SmokeFailure("binary_not_executable")
        with args.config.open("rb") as source_file:
            encoded = source_file.read(MAX_CONFIG_BYTES + 1)
        if len(encoded) > MAX_CONFIG_BYTES:
            raise SmokeFailure("config_too_large")
        source = json.loads(encoded)
        if not isinstance(source, dict):
            raise SmokeFailure("invalid_config")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        configuration = isolated_config(source, port, args.protocol, args.target_index)
        rule = configuration["rules"][0]
        report.update(mode=rule["mode"], target_count=len(rule["targets"]),
                      configured_protocols=[target["connectProxy"].get("protocols") or ["h2"] for target in rule["targets"]])
        with tempfile.TemporaryDirectory(prefix="moto-http-smoke-") as directory:
            config_path = Path(directory) / "config.json"
            with os.fdopen(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as config_file:
                json.dump(configuration, config_file, allow_nan=False)
            log_path = Path(directory) / "process.log"
            with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log_file:
                process = subprocess.Popen([str(binary), "--config", str(config_path)],
                                           stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
                                           cwd=directory)
                try:
                    wait_ready(process, port)
                    report["timing_ms"]["startup"] = round((time.monotonic() - start) * 1000, 2)
                    https_through_proxy(port, destination, args.timeout, report)
                finally:
                    stop_process(process)
    except SmokeFailure as error:
        report["error"] = str(error)
    except ssl.SSLCertVerificationError:
        report["error"] = "origin_certificate_verification_failed"
    except (TimeoutError, socket.timeout):
        report["error"] = "timeout"
    except (json.JSONDecodeError, UnicodeError, ValueError, TypeError):
        report["error"] = "invalid_input"
    except (OSError, http.client.HTTPException):
        report["error"] = "io_or_http_error"
    except subprocess.SubprocessError:
        report["error"] = "process_cleanup_failed"
    except KeyboardInterrupt:
        report["error"] = "interrupted"
    except Exception:
        # Never expose exception messages derived from configuration, URLs,
        # certificate subjects, HTTP headers, or subprocess output.
        report["error"] = "unexpected_error"
    report["timing_ms"]["total"] = round((time.monotonic() - start) * 1000, 2)
    if "error" in report:
        report["ok"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
