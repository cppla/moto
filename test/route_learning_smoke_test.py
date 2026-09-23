#!/usr/bin/env python3
"""Offline stdlib tests for bounded, private real-route learning checks."""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("route_learning_smoke", Path(__file__).with_name("route_learning_smoke.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load route learning smoke utility")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
SENTINEL = "private-redaction-sentinel"


def configuration():
    return {"rules": [{"name": SENTINEL, "protocol": "socks5", "mode": "boost", "listen": "127.0.0.1:9005",
                       "prewarm": False, "timeout": 3000, "hedge": {"minDelay": 25, "maxDelay": 250},
                       "healthCheck": {"type": "tcp", "interval": 10000},
                       "targets": [
                           {"address": "one.example:443", "connectProxy": {"protocols": ["h3", "h2"],
                            "basicAuth": {"username": SENTINEL, "password": SENTINEL}}},
                           {"address": "two.example:443", "connectProxy": {"protocols": ["h2"]}},
                       ]}]}


class FakeSocket:
    def __init__(self, response=b""):
        self.stream = io.BytesIO(response)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def settimeout(self, _value):
        pass

    def recv(self, count):
        return self.stream.read(count)

    def sendall(self, data):
        self.sent.append(data)

    def do_handshake(self):
        pass

    def makefile(self, *_args):
        return self.stream

    def shutdown(self, *_args):
        pass

    def close(self):
        pass


def payload(target="one.example:443", protocol="h2", count=100):
    return f'{SMOKE.PAYLOAD_METRIC}{{rule="{SMOKE.RULE_NAME}",target="{target}",protocol="{protocol}",direction="target_to_client"}} {count}\n'


class RouteLearningSmokeTests(unittest.TestCase):
    def test_http_preferred_socks_fallback_and_source_unchanged(self):
        source = configuration()
        original = copy.deepcopy(source)
        socks = SMOKE.select_rule(source)
        result = SMOKE.isolated_config(socks, 12000, 12001, "auto", [0, 1], True)
        rule = result["rules"][0]
        self.assertEqual(source, original)
        self.assertEqual(rule["protocol"], "http")
        self.assertEqual(rule["mode"], "boost")
        self.assertEqual(rule["targets"][0]["connectProxy"]["protocols"], ["h3", "h2"])
        self.assertEqual(rule["targets"][0]["connectProxy"]["basicAuth"]["password"], SENTINEL)
        self.assertEqual(rule["allowlist"], ["127.0.0.1/32"])
        self.assertNotIn("healthCheck", rule)
        self.assertEqual(result["metrics"], {"enabled": True, "listen": "127.0.0.1:12001"})
        http = copy.deepcopy(socks)
        http.update(protocol="http", listen="127.0.0.1:9006", name="preferred")
        source["rules"].append(http)
        self.assertEqual(SMOKE.select_rule(source)["name"], "preferred")

    def test_single_target_removes_invalid_hedge_and_overrides_protocol(self):
        rule = SMOKE.select_rule(configuration())
        result = SMOKE.isolated_config(rule, 12000, 12001, "h3", [1], False)["rules"][0]
        self.assertEqual(result["mode"], "normal")
        self.assertEqual(result["targets"][0]["address"], "two.example:443")
        self.assertEqual(result["targets"][0]["connectProxy"]["protocols"], ["h3"])
        self.assertNotIn("hedge", result)
        result = SMOKE.isolated_config(rule, 12000, 12001, "auto", [1], True)["rules"][0]
        self.assertNotIn("hedge", result)
        for indices in ([], [-1], [2]):
            with self.subTest(indices=indices), self.assertRaisesRegex(SMOKE.SmokeFailure, "target_index_out_of_range"):
                SMOKE.isolated_config(rule, 12000, 12001, "auto", indices, False)

    def test_duplicate_target_cannot_create_ambiguous_evidence(self):
        source = configuration()
        source["rules"][0]["targets"][1]["address"] = "one.example:443"
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "duplicate_upstream_address"):
            SMOKE.select_rule(source)

    def test_invalid_configuration(self):
        for source in ({}, {"rules": {}}, {"rules": [{"protocol": "http", "targets": []}]}):
            with self.subTest(source=source), self.assertRaises(SMOKE.SmokeFailure):
                SMOKE.select_rule(source)

    def test_url_validation_and_no_credentials(self):
        self.assertEqual(SMOKE.https_destination("https://[::1]:8443/x?q=2"), ("::1", "[::1]:8443", "/x?q=2"))
        for value in ("http://example.com/", "https://x@y/", "https://example.com:0/", "https://example.com/#fragment", "https://example.com/\r\nInjected: x"):
            with self.subTest(value=value), self.assertRaisesRegex(SMOKE.SmokeFailure, "invalid_https_url"):
                SMOKE.https_destination(value)

    def perform_request(self, body, *, limit=1024, declared=None, connect_status=200, expected=None, origin_status=200, extra_headers=b""):
        raw = FakeSocket(f"HTTP/1.1 {connect_status} Status\r\n\r\n".encode())
        size = len(body) if declared is None else declared
        secured = FakeSocket(f"HTTP/1.1 {origin_status} Status\r\nContent-Length: {size}\r\n".encode() + extra_headers + b"\r\n" + body)
        self.context = mock.Mock()
        self.context.wrap_socket.return_value = secured
        self.sample = {"ok": False, "bytes": 0, "body_complete": False, "timing_ms": {}}
        with mock.patch.object(SMOKE.socket, "create_connection", return_value=raw), \
                mock.patch.object(SMOKE.ssl, "create_default_context", return_value=self.context) as trust:
            SMOKE.https_request(12000, ("origin.example", "origin.example:443", "/" + SENTINEL), time.monotonic() + 5, limit, expected, self.sample)
            trust.assert_called_once_with()
        self.context.wrap_socket.assert_called_once_with(raw, server_hostname="origin.example", do_handshake_on_connect=False)
        self.context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        self.assertNotIn(SENTINEL, json.dumps(self.sample))
        return self.sample

    def test_verified_complete_body_and_expected_hash(self):
        body = b"verified\x00\xff"
        digest = hashlib.sha256(body).hexdigest()
        sample = self.perform_request(body, expected=digest)
        self.assertTrue(sample["ok"])
        self.assertTrue(sample["tls_verified"])
        self.assertTrue(sample["body_complete"])
        self.assertEqual(sample["sha256"], digest)
        self.assertEqual(sample["hash_scope"], "complete_body")

    def test_strict_prefix_limit_not_complete_body(self):
        sample = self.perform_request(b"x" * 100, limit=20)
        self.assertEqual(sample["bytes"], 20)
        self.assertFalse(sample["body_complete"])
        self.assertEqual(sample["hash_scope"], "bounded_prefix")
        self.assertEqual(sample["sha256"], hashlib.sha256(b"x" * 20).hexdigest())

    def test_exact_size_is_complete_without_extra_byte_read(self):
        sample = self.perform_request(b"x" * 100, limit=100)
        self.assertEqual(sample["bytes"], 100)
        self.assertTrue(sample["body_complete"])

    def test_truncated_body_retains_bytes_but_fails(self):
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "incomplete_origin_body"):
            self.perform_request(b"short", declared=100)
        self.assertEqual(self.sample["bytes"], 5)
        self.assertFalse(self.sample["body_complete"])

    def test_wrong_hash_or_incomplete_hash_fails(self):
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "body_hash_mismatch"):
            self.perform_request(b"body", expected="0" * 64)
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "hash_requires_complete_body"):
            self.perform_request(b"body", limit=2, expected="0" * 64)

    def test_connect_rejection_never_handshakes_tls(self):
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "connect_rejected"):
            self.perform_request(b"", connect_status=503)
        self.context.wrap_socket.assert_not_called()

    def test_no_redirect_or_error_page_success(self):
        for status in (301, 403, 503):
            with self.subTest(status=status), self.assertRaisesRegex(SMOKE.SmokeFailure, "origin_not_2xx"):
                self.perform_request(b"error", origin_status=status)
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "unexpected_content_encoding"):
            self.perform_request(b"encoded", extra_headers=b"Content-Encoding: gzip\r\n")

    def test_protocol_and_target_evidence_from_payload_not_successful_attempts(self):
        before = SMOKE.parse_metrics(payload(count=10))
        encoded = payload(count=110)
        encoded += f'{SMOKE.ATTEMPT_METRIC}{{rule="{SMOKE.RULE_NAME}",target="two.example:443",protocol="h3",outcome="success"}} 1\n'
        encoded += f'{SMOKE.ATTEMPT_METRIC}{{rule="{SMOKE.RULE_NAME}",target="one.example:443",protocol="h2",outcome="success"}} 1\n'
        evidence = SMOKE.metric_evidence(before, SMOKE.parse_metrics(encoded), {"one.example:443": 0, "two.example:443": 1})
        self.assertEqual(evidence["actual_routes"], [{"target_index": 0, "protocol": "h2", "tunnel_payload_bytes": 100}])
        self.assertEqual(len(evidence["attempts"]), 2)
        self.assertNotIn("example", json.dumps(evidence))

    def test_metrics_unknown_targets_and_unrelated_metrics_not_leaked(self):
        encoded = payload(target=SENTINEL) + f'private_secret{{rule="{SMOKE.RULE_NAME}",target="one.example:443",secret="{SENTINEL}"}} 10\n'
        evidence = SMOKE.metric_evidence({}, SMOKE.parse_metrics(encoded), {"one.example:443": 0})
        self.assertEqual(evidence, {"actual_routes": [], "attempts": [], "learning": []})
        self.assertNotIn(SENTINEL, json.dumps(evidence))

    def test_metrics_nonfinite_rejected_and_counter_reset_not_negative(self):
        for value in ("NaN", "Inf", "-1"):
            with self.subTest(value=value), self.assertRaisesRegex(SMOKE.SmokeFailure, "invalid_metrics"):
                SMOKE.parse_metrics(payload(count=value))
        evidence = SMOKE.metric_evidence(SMOKE.parse_metrics(payload(count=100)), SMOKE.parse_metrics(payload(count=10)), {"one.example:443": 0})
        self.assertEqual(evidence["actual_routes"], [])

    def test_metrics_label_escaping(self):
        encoded = payload(target='one\\\\name\\\"quoted.example:443')
        result = SMOKE.parse_metrics(encoded)
        labels = dict(next(iter(result))[1])
        self.assertEqual(labels["target"], 'one\\name"quoted.example:443')

    def test_lingering_tunnel_blocks_next_request_evidence(self):
        encoded = f'{SMOKE.ACTIVE_METRIC}{{rule="{SMOKE.RULE_NAME}",target="one.example:443",protocol="h2"}} 1\n'
        self.assertFalse(SMOKE.tunnels_drained(SMOKE.parse_metrics(encoded)))
        self.assertTrue(SMOKE.tunnels_drained(SMOKE.parse_metrics(encoded.replace('} 1', '} 0'))))
        evidence = SMOKE.metric_evidence({}, SMOKE.parse_metrics(encoded), {"one.example:443": 0})
        self.assertEqual(evidence["actual_routes"], [])

    def test_learning_metrics_are_whitelisted_with_redacted_targets(self):
        labels = f'rule="{SMOKE.RULE_NAME}",target="one.example:443",protocol="h2"'
        before = SMOKE.parse_metrics('moto_route_learning_decisions_total{' + labels + ',reason="quality"} 2\n')
        encoded = ('moto_route_learning_samples{' + labels + '} 3\n' +
                   'moto_route_learning_confidence{' + labels + '} 0.4\n' +
                   'moto_route_learning_preferred{' + labels + '} 1\n' +
                   'moto_route_learning_decisions_total{' + labels + ',reason="quality"} 5\n' +
                   'moto_route_learning_decisions_total{' + labels + ',reason="' + SENTINEL + '"} 1\n')
        evidence = SMOKE.metric_evidence(before, SMOKE.parse_metrics(encoded), {"one.example:443": 0})
        self.assertEqual(len(evidence["learning"]), 4)
        decisions = next(item for item in evidence["learning"] if item["metric"].endswith("decisions_total"))
        self.assertEqual(decisions["delta"], 3)
        self.assertEqual(decisions["reason"], "quality")
        self.assertNotIn(SENTINEL, json.dumps(evidence))
        self.assertNotIn("one.example", json.dumps(evidence))

    def test_rule_level_decisions_do_not_require_or_invent_target_protocol(self):
        name = "moto_route_learning_decisions_total"
        labels = f'rule="{SMOKE.RULE_NAME}"'
        before = SMOKE.parse_metrics(name + '{' + labels + ',reason="quality"} 2\n')
        encoded = (name + '{' + labels + ',reason="quality"} 5\n' +
                   name + '{' + labels + ',reason="explore"} 1\n' +
                   name + '{' + labels + ',reason="' + SENTINEL + '"} 9\n' +
                   name + '{rule="' + SENTINEL + '",reason="quality"} 20\n')
        evidence = SMOKE.metric_evidence(before, SMOKE.parse_metrics(encoded), {})
        self.assertEqual(evidence["actual_routes"], [])
        self.assertEqual(len(evidence["learning"]), 2)
        for item in evidence["learning"]:
            self.assertEqual(item["scope"], "rule")
            self.assertNotIn("target_index", item)
            self.assertNotIn("protocol", item)
        decisions = {item["reason"]: item for item in evidence["learning"]}
        self.assertEqual(decisions["quality"]["value"], 5)
        self.assertEqual(decisions["quality"]["delta"], 3)
        self.assertEqual(decisions["explore"]["delta"], 1)
        self.assertNotIn(SENTINEL, json.dumps(evidence))

    def test_rule_level_decision_counter_reset_never_reports_negative_delta(self):
        line = 'moto_route_learning_decisions_total{rule="' + SMOKE.RULE_NAME + '",reason="quality"} '
        evidence = SMOKE.metric_evidence(SMOKE.parse_metrics(line + '20\n'), SMOKE.parse_metrics(line + '1\n'), {})
        self.assertEqual(evidence["learning"][0]["value"], 1)
        self.assertEqual(evidence["learning"][0]["delta"], 0)

    def test_private_process_reused_and_cleanup(self):
        rule = SMOKE.select_rule(configuration())
        process = mock.Mock()
        process.poll.return_value = None
        directories = []

        def start(arguments, **kwargs):
            path = Path(arguments[2])
            directories.append(path.parent)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)
            self.assertEqual(os.fstat(kwargs["stdout"].fileno()).st_mode & 0o777, 0o600)
            with open(path, encoding="utf-8") as config_file:
                self.assertEqual(json.load(config_file)["rules"][0]["targets"][0]["connectProxy"]["basicAuth"]["password"], SENTINEL)
            return process

        def fetch(_port, _destination, _deadline, limit, _hash, sample):
            sample.update(ok=True, bytes=min(8, limit), body_complete=True, tls_verified=True)

        args = argparse.Namespace(binary=Path("/unused/moto"), protocol="auto", rounds=3, bytes=8,
                                  timeout=5, pause=0, expected_sha256=None)
        case = {"samples": [], "ok": False}
        budget = {"remaining_bytes": 20}
        snapshots = [SMOKE.parse_metrics(payload(count=count)) for count in (0, 100, 100, 200, 200, 300)]
        with mock.patch.object(SMOKE.subprocess, "Popen", side_effect=start) as popen, \
                mock.patch.object(SMOKE, "wait_ready"), mock.patch.object(SMOKE, "https_request", side_effect=fetch) as fetch_mock, \
                mock.patch.object(SMOKE, "read_metrics", side_effect=snapshots):
            SMOKE.run_case(args, rule, [0, 1], True, ("origin.example", "origin.example:443", "/"),
                           time.monotonic() + 20, budget, case)
        self.assertTrue(case["ok"])
        self.assertEqual([sample["bytes"] for sample in case["samples"]], [8, 8, 4])
        self.assertEqual(budget["remaining_bytes"], 0)
        self.assertEqual(fetch_mock.call_count, 3)
        popen.assert_called_once()
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)
        self.assertFalse(directories[0].exists())

    def test_request_error_is_redacted_and_counted(self):
        self.assertEqual(SMOKE.error_code(OSError(SENTINEL)), "io_or_http_error")
        self.assertEqual(SMOKE.error_code(ValueError(SENTINEL)), "invalid_input")
        self.assertEqual(SMOKE.error_code(RuntimeError(SENTINEL)), "unexpected_error")

    def test_main_invalid_budgets_redacted(self):
        for arguments in (["--timeout", "nan"], ["--pause", "inf"], ["--rounds", "0"], ["--bytes", "0"], ["--expected-sha256", SENTINEL]):
            with self.subTest(arguments=arguments):
                output = io.StringIO()
                with mock.patch.object(sys, "argv", ["smoke", "--config", "/unused/config", "--binary", "/unused/moto"] + arguments), contextlib.redirect_stdout(output):
                    self.assertEqual(SMOKE.main(), 1)
                self.assertFalse(json.loads(output.getvalue())["ok"])
                self.assertNotIn(SENTINEL, output.getvalue())

    def test_main_runs_each_target_then_group_without_private_output(self):
        output = io.StringIO()
        calls = []

        def run_case(_args, _rule, indices, group, _destination, _deadline, budget, case):
            calls.append((indices, group))
            case["samples"].append({"ok": True, "bytes": 2})
            budget["remaining_bytes"] -= 2
            case["ok"] = True

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", ["smoke", "--config", "/unused/config", "--binary", "/unused/moto", "--url", "https://origin.example/?" + SENTINEL]))
            stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))
            stack.enter_context(mock.patch.object(SMOKE.os, "access", return_value=True))
            stack.enter_context(mock.patch.object(Path, "open", return_value=io.BytesIO(json.dumps(configuration()).encode())))
            stack.enter_context(mock.patch.object(SMOKE, "run_case", side_effect=run_case))
            stack.enter_context(contextlib.redirect_stdout(output))
            self.assertEqual(SMOKE.main(), 0)
        self.assertEqual(calls, [([0], False), ([1], False), ([0, 1], True)])
        result = json.loads(output.getvalue())
        self.assertEqual(result["bytes"], 6)
        self.assertEqual(result["planned_requests"], 9)
        self.assertNotIn(SENTINEL, output.getvalue())
        self.assertNotIn("example", output.getvalue())

    def test_main_global_budget_prevents_later_case(self):
        output = io.StringIO()

        def run_case(_args, _rule, _indices, _group, _destination, _deadline, budget, case):
            case["samples"].append({"ok": True, "bytes": 2})
            budget["remaining_bytes"] = 0
            case["ok"] = True

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", ["smoke", "--config", "/unused/config", "--binary", "/unused/moto", "--total-bytes", "2"]))
            stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))
            stack.enter_context(mock.patch.object(SMOKE.os, "access", return_value=True))
            stack.enter_context(mock.patch.object(Path, "open", return_value=io.BytesIO(json.dumps(configuration()).encode())))
            run = stack.enter_context(mock.patch.object(SMOKE, "run_case", side_effect=run_case))
            stack.enter_context(contextlib.redirect_stdout(output))
            self.assertEqual(SMOKE.main(), 1)
        run.assert_called_once()
        result = json.loads(output.getvalue())
        self.assertEqual(result["bytes"], 2)
        self.assertEqual(result["cases"][-1]["error"], "byte_budget_exhausted")


if __name__ == "__main__":
    unittest.main()
