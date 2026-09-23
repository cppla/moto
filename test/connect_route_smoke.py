#!/usr/bin/env python3
"""Bounded, redacted real-route checks through isolated Moto HTTP CONNECT.

Each target and then the Boost group run in separate Moto processes. Repeated
requests within a case share one process, allowing transport reuse. The source configuration is read only. Reports contain target indices,
not addresses, credentials, URLs, HTTP headers, or process logs.

--bytes and --total-bytes bound origin body bytes consumed by this client, not
wire traffic: handshakes, headers, buffering and retransmissions cost extra.
This is a connectivity evidence harness, not proof of speed improvement.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit


RULE_NAME = "connect-route-smoke"
MAX_CONFIG_BYTES = 4 << 20
MAX_METRICS_BYTES = 4 << 20
MAX_CONNECT_HEADER_BYTES = 32 << 10
PAYLOAD_METRIC = "moto_connect_proxy_payload_bytes_total"
ATTEMPT_METRIC = "moto_connect_proxy_attempts_total"
ACTIVE_METRIC = "moto_connect_proxy_active_tunnels"
METRIC_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{(.*)\}\s+([^\s]+)\s*$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"(?:,|$)')


class SmokeFailure(Exception):
    """A fixed diagnostic code, never text obtained from private inputs."""


def select_rule(source: dict) -> dict:
    rules = source.get("rules", [])
    if not isinstance(rules, list):
        raise SmokeFailure("invalid_config")
    for protocol in ("http", "socks5"):
        candidates = [rule for rule in rules if isinstance(rule, dict) and rule.get("protocol") == protocol]
        if candidates:
            preferred = "127.0.0.1:9006" if protocol == "http" else "127.0.0.1:9005"
            rule = copy.deepcopy(next((rule for rule in candidates if rule.get("listen") == preferred), candidates[0]))
            targets = rule.get("targets")
            if not isinstance(targets, list) or not targets or len(targets) > 128:
                raise SmokeFailure("invalid_upstream_targets")
            addresses = set()
            for target in targets:
                if not isinstance(target, dict) or not isinstance(target.get("address"), str) or not target["address"]:
                    raise SmokeFailure("invalid_upstream_targets")
                if target["address"] in addresses:
                    raise SmokeFailure("duplicate_upstream_address")
                addresses.add(target["address"])
                proxy = target.get("connectProxy")
                if not isinstance(proxy, dict):
                    raise SmokeFailure("invalid_connect_proxy_target")
                protocols = proxy.get("protocols") or ["h2"]
                if not isinstance(protocols, list) or any(item not in {"h2", "h3"} for item in protocols):
                    raise SmokeFailure("invalid_upstream_protocols")
            return rule
    raise SmokeFailure("no_connect_rule")


def isolated_config(rule: dict, port: int, metrics_port: int, protocol: str, indices: list[int], group: bool) -> dict:
    selected = copy.deepcopy(rule)
    if not indices or any(index < 0 or index >= len(selected["targets"]) for index in indices):
        raise SmokeFailure("target_index_out_of_range")
    selected["targets"] = [selected["targets"][index] for index in indices]
    if protocol != "auto":
        for target in selected["targets"]:
            target["connectProxy"]["protocols"] = [protocol]
    selected.update(name=RULE_NAME, protocol="http", mode="boost" if group else "normal",
                    listen=f"127.0.0.1:{port}", prewarm=False,
                    allowlist=["127.0.0.1/32"], blacklist={})
    selected.pop("healthCheck", None)
    if not group or len(indices) < 2:
        selected.pop("hedge", None)
    return {"log": {"level": "error", "path": ""},
            "metrics": {"enabled": True, "listen": f"127.0.0.1:{metrics_port}"}, "rules": [selected]}


def https_destination(value: str) -> tuple[str, str, str]:
    try:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
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


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise SmokeFailure("time_budget_exhausted")
    return value


def https_request(port: int, destination: tuple[str, str, str], deadline: float, limit: int,
                  expected_sha256: str | None, report: dict, *, ca_file: str | None = None) -> None:
    host, authority, path = destination
    started = time.monotonic()
    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=remaining(deadline)) as raw:
        raw.settimeout(remaining(deadline))
        raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            if len(header) >= MAX_CONNECT_HEADER_BYTES:
                raise SmokeFailure("invalid_connect_response")
            raw.settimeout(remaining(deadline))
            chunk = raw.recv(1)
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
        report["timing_ms"]["connect"] = round((time.monotonic() - started) * 1000, 2)
        if report["connect_status"] != 200:
            raise SmokeFailure("connect_rejected")
        raw.settimeout(remaining(deadline))
        with context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False) as secured:
            expired = threading.Event()

            def abort() -> None:
                expired.set()
                try:
                    secured.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                secured.close()

            timer = threading.Timer(remaining(deadline), abort)
            timer.daemon = True
            timer.start()
            try:
                secured.settimeout(remaining(deadline))
                secured.do_handshake()
                report["timing_ms"]["tls_complete"] = round((time.monotonic() - started) * 1000, 2)
                report["tls_verified"] = True
                secured.sendall((f"GET {path} HTTP/1.1\r\nHost: {authority}\r\n"
                                 "User-Agent: Moto-Route-Smoke/1.0\r\nAccept-Encoding: identity\r\n"
                                 "Connection: close\r\n\r\n").encode("ascii"))
                response = http.client.HTTPResponse(secured, method="GET")
                try:
                    response.begin()
                    report["origin_status"] = response.status
                    report["timing_ms"]["response_headers"] = round((time.monotonic() - started) * 1000, 2)
                    if not 200 <= response.status < 300:
                        raise SmokeFailure("origin_not_2xx")
                    if response.getheader("Content-Encoding", "identity").lower() not in {"", "identity"}:
                        raise SmokeFailure("unexpected_content_encoding")
                    digest = hashlib.sha256()
                    while report["bytes"] < limit:
                        secured.settimeout(remaining(deadline))
                        # read1 retains partial progress if the peer later stalls.
                        chunk = response.read1(min(64 << 10, limit - report["bytes"]))
                        if not chunk:
                            if response.length not in (None, 0):
                                raise SmokeFailure("incomplete_origin_body")
                            report["body_complete"] = True
                            break
                        if report["bytes"] == 0:
                            report["timing_ms"]["first_body_byte"] = round((time.monotonic() - started) * 1000, 2)
                        report["bytes"] += len(chunk)
                        digest.update(chunk)
                    if response.length == 0:
                        report["body_complete"] = True
                    if expired.is_set():
                        raise SmokeFailure("time_budget_exhausted")
                    report["sha256"] = digest.hexdigest()
                    report["hash_scope"] = "complete_body" if report["body_complete"] else "bounded_prefix"
                    if expected_sha256 is not None:
                        if not report["body_complete"]:
                            raise SmokeFailure("hash_requires_complete_body")
                        if report["sha256"] != expected_sha256:
                            raise SmokeFailure("body_hash_mismatch")
                    report["ok"] = True
                finally:
                    response.close()
            except (OSError, http.client.HTTPException):
                if expired.is_set():
                    raise SmokeFailure("time_budget_exhausted") from None
                raise
            finally:
                timer.cancel()
                timer.join(timeout=1)


def parse_metrics(encoded: str) -> dict[tuple, float]:
    result = {}
    names = {PAYLOAD_METRIC, ATTEMPT_METRIC, ACTIVE_METRIC}
    for line in encoded.splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC_LINE.fullmatch(line)
        if not match or match[1] not in names:
            continue
        try:
            labels = {}
            position = 0
            while position < len(match[2]):
                label = LABEL.match(match[2], position)
                if not label or label[1] in labels:
                    raise ValueError
                labels[label[1]] = json.loads('"' + label[2] + '"')
                position = label.end()
            value = float(match[3])
            if not math.isfinite(value) or value < 0:
                raise ValueError
            if labels.get("rule") != RULE_NAME:
                continue
            result[(match[1], tuple(sorted(labels.items())))] = value
        except (ValueError, json.JSONDecodeError):
            raise SmokeFailure("invalid_metrics") from None
    return result


def read_metrics(port: int, deadline: float) -> dict[tuple, float]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=min(2, remaining(deadline)))
    try:
        connection.request("GET", "/metrics")
        response = connection.getresponse()
        if response.status != 200:
            raise SmokeFailure("metrics_unavailable")
        body = response.read(MAX_METRICS_BYTES + 1)
        if len(body) > MAX_METRICS_BYTES:
            raise SmokeFailure("metrics_too_large")
        return parse_metrics(body.decode("utf-8"))
    finally:
        connection.close()


def metric_evidence(before: dict, after: dict, addresses: dict[str, int]) -> dict:
    payload = {}
    attempts = []
    for (name, label_items), value in sorted(after.items()):
        labels = dict(label_items)
        delta = max(0, value - before.get((name, label_items), 0))
        target_index = addresses.get(labels.get("target"))
        protocol = labels.get("protocol")
        if target_index is None:
            continue
        if name == PAYLOAD_METRIC and delta > 0 and protocol in {"h2", "h3"}:
            key = (target_index, protocol)
            payload[key] = payload.get(key, 0) + int(delta)
        elif name == ATTEMPT_METRIC and delta > 0 and protocol in {"h2", "h3"}:
            outcome = labels.get("outcome", "")
            if re.fullmatch(r"[a-z_]{1,64}", outcome):
                attempts.append({"target_index": target_index, "protocol": protocol, "outcome": outcome, "count": int(delta)})
    routes = [{"target_index": index, "protocol": protocol, "tunnel_payload_bytes": count}
              for (index, protocol), count in sorted(payload.items())]
    return {"actual_routes": routes, "attempts": attempts}


def tunnels_drained(snapshot: dict) -> bool:
    return not any(name == ACTIVE_METRIC and value > 0 for (name, _labels), value in snapshot.items())


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def wait_ready(process: subprocess.Popen, port: int, deadline: float) -> None:
    startup_deadline = min(deadline, time.monotonic() + 5)
    while time.monotonic() < startup_deadline:
        if process.poll() is not None:
            raise SmokeFailure("moto_startup_failed")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=min(0.2, remaining(startup_deadline))):
                if process.poll() is not None:
                    raise SmokeFailure("moto_startup_failed")
                return
        except OSError:
            time.sleep(min(0.05, remaining(startup_deadline)))
    raise SmokeFailure("moto_startup_timeout")


def error_code(error: Exception) -> str:
    if isinstance(error, SmokeFailure):
        return str(error)
    if isinstance(error, ssl.SSLCertVerificationError):
        return "origin_certificate_verification_failed"
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(error, (ValueError, TypeError, UnicodeError)):
        return "invalid_input"
    if isinstance(error, (OSError, http.client.HTTPException)):
        return "io_or_http_error"
    if isinstance(error, subprocess.SubprocessError):
        return "process_cleanup_failed"
    return "unexpected_error"


def run_case(args: argparse.Namespace, rule: dict, indices: list[int], group: bool,
             destination: tuple[str, str, str], deadline: float, budget: dict, case: dict) -> None:
    addresses = {target["address"]: index for index, target in enumerate(rule["targets"])}
    with socket.socket() as inbound, socket.socket() as metrics:
        inbound.bind(("127.0.0.1", 0))
        metrics.bind(("127.0.0.1", 0))
        port = inbound.getsockname()[1]
        metrics_port = metrics.getsockname()[1]
    configuration = isolated_config(rule, port, metrics_port, args.protocol, indices, group)
    with tempfile.TemporaryDirectory(prefix="moto-connect-route-smoke-") as directory:
        config_path = Path(directory) / "config.json"
        with os.fdopen(os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as config_file:
            json.dump(configuration, config_file, allow_nan=False)
        with os.fdopen(os.open(Path(directory) / "process.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log_file:
            process = subprocess.Popen([str(args.binary), "--config", str(config_path)], stdin=subprocess.DEVNULL,
                                       stdout=log_file, stderr=subprocess.STDOUT, cwd=directory)
            try:
                wait_ready(process, port, deadline)
                wait_ready(process, metrics_port, deadline)
                for round_number in range(args.rounds):
                    remaining(deadline)
                    limit = min(args.bytes, budget["remaining_bytes"])
                    if limit <= 0:
                        raise SmokeFailure("byte_budget_exhausted")
                    sample = {"round": round_number + 1, "ok": False, "bytes": 0,
                              "body_complete": False, "tls_verified": False, "timing_ms": {}}
                    case["samples"].append(sample)
                    before = read_metrics(metrics_port, deadline)
                    started = time.monotonic()
                    try:
                        https_request(port, destination, min(deadline, started + args.timeout), limit,
                                      args.expected_sha256, sample, ca_file=args.ca_file)
                    except Exception as error:
                        sample["error"] = error_code(error)
                        sample["ok"] = False
                    finally:
                        budget["remaining_bytes"] -= sample["bytes"]
                        sample["timing_ms"]["total"] = round((time.monotonic() - started) * 1000, 2)
                    # Relay finalization is asynchronous. A short, bounded poll
                    # avoids guessing protocol from configured preference order.
                    settle = min(deadline, time.monotonic() + 1)
                    while True:
                        after = read_metrics(metrics_port, deadline)
                        evidence = metric_evidence(before, after, addresses)
                        sample.update(evidence)
                        if tunnels_drained(after) and (evidence["actual_routes"] or not sample["ok"]):
                            break
                        if time.monotonic() >= settle:
                            break
                        time.sleep(max(0, min(0.02, settle - time.monotonic())))
                    if not tunnels_drained(after):
                        # Never attribute a late write from the previous request
                        # to the next request's winning route.
                        sample.update(ok=False, error="tunnel_cleanup_not_observed")
                        raise SmokeFailure("tunnel_cleanup_not_observed")
                    if sample["ok"] and len(sample["actual_routes"]) != 1:
                        sample.update(ok=False, error="winner_evidence_missing_or_ambiguous")
                    if sample["ok"] and args.protocol != "auto" and sample["actual_routes"][0]["protocol"] != args.protocol:
                        sample.update(ok=False, error="unexpected_upstream_protocol")
                    if args.pause and round_number + 1 < args.rounds:
                        time.sleep(min(args.pause, remaining(deadline)))
                case["ok"] = all(sample["ok"] for sample in case["samples"])
            finally:
                stop_process(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--protocol", choices=("auto", "h2", "h3"), default="auto")
    parser.add_argument("--scope", choices=("all", "targets", "group"), default="all")
    parser.add_argument("--target-index", type=int)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--url", default="https://example.com/")
    parser.add_argument("--bytes", type=int, default=1 << 20, help="Maximum origin body bytes consumed per request")
    parser.add_argument("--total-bytes", type=int, default=32 << 20, help="Maximum consumed origin body bytes across all requests")
    parser.add_argument("--timeout", type=float, default=20, help="Per-request total seconds")
    parser.add_argument("--total-timeout", type=float, default=180, help="Overall work budget; cleanup may take up to 5s extra")
    parser.add_argument("--pause", type=float, default=0, help="Pause between requests within one process")
    parser.add_argument("--ca-file", type=Path, help="Optional origin CA file; does not change upstream TLS verification")
    parser.add_argument("--expected-sha256", help="Require a complete body matching this SHA-256 digest")
    args = parser.parse_args()
    started = time.monotonic()
    report = {"ok": False, "protocol_policy": args.protocol, "cases": [], "bytes": 0,
              "evidence_scope": "bounded_connectivity_not_speed_benchmark"}
    try:
        if not 1 <= args.rounds <= 1000 or not 1 <= args.bytes <= 64 << 20 or not 1 <= args.total_bytes <= 1 << 30:
            raise SmokeFailure("invalid_byte_or_round_budget")
        if not all(math.isfinite(value) for value in (args.timeout, args.total_timeout, args.pause)) or not 1 <= args.timeout <= 120 or not 1 <= args.total_timeout <= 3600 or not 0 <= args.pause <= 60:
            raise SmokeFailure("invalid_time_budget")
        if args.expected_sha256 is not None:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_sha256):
                raise SmokeFailure("invalid_expected_sha256")
            args.expected_sha256 = args.expected_sha256.lower()
        if args.ca_file is not None:
            args.ca_file = args.ca_file.resolve()
            if not args.ca_file.is_file() or not os.access(args.ca_file, os.R_OK):
                raise SmokeFailure("invalid_origin_ca_file")
            args.ca_file = str(args.ca_file)
        destination = https_destination(args.url)
        args.binary = args.binary.resolve()
        if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
            raise SmokeFailure("binary_not_executable")
        with args.config.open("rb") as source_file:
            encoded = source_file.read(MAX_CONFIG_BYTES + 1)
        if len(encoded) > MAX_CONFIG_BYTES:
            raise SmokeFailure("config_too_large")
        source = json.loads(encoded)
        if not isinstance(source, dict):
            raise SmokeFailure("invalid_config")
        rule = select_rule(source)
        indices = list(range(len(rule["targets"]))) if args.target_index is None else [args.target_index]
        if any(index < 0 or index >= len(rule["targets"]) for index in indices):
            raise SmokeFailure("target_index_out_of_range")
        planned = []
        if args.scope in {"all", "targets"}:
            planned.extend(([index], False) for index in indices)
        if args.scope in {"all", "group"}:
            planned.append((indices, True))
        report["target_count"] = len(indices)
        report["planned_requests"] = len(planned) * args.rounds
        report["configured_protocols"] = [{"target_index": index,
                                           "protocols": rule["targets"][index]["connectProxy"].get("protocols") or ["h2"]}
                                          for index in indices]
        budget = {"remaining_bytes": args.total_bytes}
        deadline = started + args.total_timeout
        for selected, group in planned:
            case = {"kind": "boost_group" if group else "single_target", "target_indices": selected,
                    "samples": [], "ok": False}
            report["cases"].append(case)
            try:
                remaining(deadline)
                if budget["remaining_bytes"] <= 0:
                    raise SmokeFailure("byte_budget_exhausted")
                run_case(args, rule, selected, group, destination, deadline, budget, case)
            except Exception as error:
                case["error"] = error_code(error)
                case["ok"] = False
                if budget["remaining_bytes"] <= 0 or time.monotonic() >= deadline:
                    break
        report["ok"] = len(report["cases"]) == len(planned) and all(case["ok"] for case in report["cases"])
    except KeyboardInterrupt:
        report["error"] = "interrupted"
    except Exception as error:
        report["error"] = error_code(error)
    report["bytes"] = sum(sample["bytes"] for case in report["cases"] for sample in case["samples"])
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    if "error" in report:
        report["ok"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
