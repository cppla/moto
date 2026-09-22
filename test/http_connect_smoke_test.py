#!/usr/bin/env python3
"""Offline checks for the isolated HTTP CONNECT smoke utility (stdlib only)."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("http_connect_smoke.py")
SPEC = importlib.util.spec_from_file_location("http_connect_smoke", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load HTTP CONNECT smoke utility")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)

SENTINEL = "smoke-test-redaction-sentinel"


class FakeSocket:
    def __init__(self, response: bytes = b""):
        self.stream = io.BytesIO(response)
        self.sent: list[bytes] = []

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


def example_configuration() -> dict:
    return {
        "rules": [
            {"protocol": "http", "listen": "127.0.0.1:8000", "mode": "normal", "targets": []},
            {
                "protocol": "http",
                "listen": "127.0.0.1:9006",
                "mode": "boost",
                "allowlist": ["192.0.2.0/24"],
                "blacklist": {"127.0.0.1": True},
                "healthCheck": {"type": "tcp"},
                "targets": [
                    {"address": "proxy.example:443", "connectProxy": {
                        "protocols": ["h3", "h2"],
                        "basicAuth": {"username": "test-user", "password": SENTINEL},
                    }},
                    {"address": "other.example:443", "connectProxy": {"protocols": ["h2"]}},
                ],
            },
        ],
    }


class HTTPConnectSmokeTests(unittest.TestCase):
    def test_isolated_config_preserves_source_credentials_and_protocol_order(self):
        source = example_configuration()
        original = copy.deepcopy(source)
        result = SMOKE.isolated_config(source, 12345, "auto", None)
        self.assertEqual(source, original)
        rule = result["rules"][0]
        self.assertEqual(len(result["rules"]), 1)
        self.assertEqual(rule["mode"], "boost")
        self.assertEqual(rule["listen"], "127.0.0.1:12345")
        self.assertEqual(rule["targets"][0]["connectProxy"]["basicAuth"]["password"], SENTINEL)
        self.assertEqual(rule["targets"][0]["connectProxy"]["protocols"], ["h3", "h2"])
        self.assertEqual(rule["allowlist"], ["127.0.0.1/32"])
        self.assertEqual(rule["blacklist"], {})
        self.assertNotIn("healthCheck", rule)
        self.assertFalse(result["metrics"]["enabled"])
        self.assertEqual(result["log"], {"level": "error", "path": ""})

    def test_single_target_protocol_override_and_index_validation(self):
        source = example_configuration()
        original = copy.deepcopy(source)
        result = SMOKE.isolated_config(source, 12345, "h3", 1)
        targets = result["rules"][0]["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["address"], "other.example:443")
        self.assertEqual(targets[0]["connectProxy"]["protocols"], ["h3"])
        self.assertEqual(source, original)
        for index in (-1, 2):
            with self.subTest(index=index), self.assertRaisesRegex(SMOKE.SmokeFailure, "^target_index_out_of_range$"):
                SMOKE.isolated_config(source, 12345, "h2", index)

    def test_https_url_validation(self):
        self.assertEqual(SMOKE.https_destination("https://[::1]:8443/path?q=1"),
                         ("::1", "[::1]:8443", "/path?q=1"))
        self.assertEqual(SMOKE.https_destination("https://example.com/"),
                         ("example.com", "example.com:443", "/"))
        invalid = [
            "http://example.com/",
            f"https://test-user:{SENTINEL}@example.com/",
            "https://example.com/\r\nHeader: value",
            "https://example.com:0/",
            "https://example.com:65536/",
        ]
        for index, value in enumerate(invalid):
            with self.subTest(index=index), self.assertRaisesRegex(SMOKE.SmokeFailure, "^invalid_https_url$"):
                SMOKE.https_destination(value)

    def run_request(self, body: bytes, declared: int | None = None, connect: int = 200) -> dict:
        raw = FakeSocket(f"HTTP/1.1 {connect} Status\r\n\r\n".encode())
        length = len(body) if declared is None else declared
        secured = FakeSocket(f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode() + body)
        self.tls_context = mock.Mock()
        self.tls_context.wrap_socket.return_value = secured
        self.report = {"bytes": 0, "body_complete": False, "sha256": None, "timing_ms": {}}
        with mock.patch.object(SMOKE.socket, "create_connection", return_value=raw) as dial, \
                mock.patch.object(SMOKE.ssl, "create_default_context", return_value=self.tls_context) as trust:
            SMOKE.https_through_proxy(12345, ("example.com", "example.com:443", f"/?token={SENTINEL}"), 2, self.report)
            self.assertEqual(dial.call_args.args[0], ("127.0.0.1", 12345))
            trust.assert_called_once_with()
        self.tls_context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        self.tls_context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com", do_handshake_on_connect=False)
        self.assertTrue(raw.sent[0].startswith(b"CONNECT example.com:443 HTTP/1.1\r\n"))
        self.assertEqual(len(raw.sent), 1)
        self.assertTrue(secured.sent[0].startswith(f"GET /?token={SENTINEL} HTTP/1.1\r\n".encode()))
        return self.report

    def test_complete_body_and_hash_through_connect_then_tls(self):
        body = b"complete\x00\xff"
        report = self.run_request(body)
        self.assertTrue(report["ok"])
        self.assertTrue(report["body_complete"])
        self.assertEqual(report["bytes"], len(body))
        self.assertEqual(report["connect_status"], 200)
        self.assertEqual(report["origin_status"], 200)
        self.assertEqual(report["sha256"], hashlib.sha256(body).hexdigest())

    def test_bounded_body_never_claims_complete_hash(self):
        report = self.run_request(b"x" * (SMOKE.MAX_BODY_BYTES + 10))
        self.assertEqual(report["bytes"], SMOKE.MAX_BODY_BYTES)
        self.assertFalse(report["body_complete"])
        self.assertIsNone(report["sha256"])

    def test_exact_limit_complete_body(self):
        report = self.run_request(b"x" * SMOKE.MAX_BODY_BYTES)
        self.assertTrue(report["body_complete"])
        self.assertEqual(report["bytes"], SMOKE.MAX_BODY_BYTES)

    def test_short_content_length_body_rejected(self):
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "^incomplete_origin_body$"):
            self.run_request(b"short", declared=100)
        self.assertFalse(self.report["body_complete"])
        self.assertIsNone(self.report["sha256"])

    def test_connect_denied_before_tls(self):
        with self.assertRaisesRegex(SMOKE.SmokeFailure, "^connect_rejected$"):
            self.run_request(b"", connect=403)
        self.assertEqual(self.report["connect_status"], 403)
        self.tls_context.wrap_socket.assert_not_called()

    def test_private_files_process_cleanup_and_sanitized_failure(self):
        source = example_configuration()
        process = mock.Mock()
        process.poll.return_value = None
        directories = []

        def start(arguments, **kwargs):
            path = Path(arguments[2])
            directories.append(path.parent)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)
            self.assertEqual(os.fstat(kwargs["stdout"].fileno()).st_mode & 0o777, 0o600)
            with open(path, encoding="utf-8") as temporary_config:
                saved = json.load(temporary_config)
            self.assertEqual(saved["rules"][0]["targets"][0]["connectProxy"]["basicAuth"]["password"], SENTINEL)
            self.assertEqual(saved["log"]["path"], "")
            return process

        output = io.StringIO()
        arguments = ["smoke", "--binary", "/unused/moto", "--config", "/unused/config", "--url", f"https://example.com/?{SENTINEL}"]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", arguments))
            stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))
            stack.enter_context(mock.patch.object(SMOKE.os, "access", return_value=True))
            stack.enter_context(mock.patch.object(Path, "open", return_value=io.BytesIO(json.dumps(source).encode())))
            stack.enter_context(mock.patch.object(SMOKE.subprocess, "Popen", side_effect=start))
            stack.enter_context(mock.patch.object(SMOKE, "wait_ready"))
            stack.enter_context(mock.patch.object(SMOKE, "https_through_proxy", side_effect=OSError(SENTINEL)))
            reservation = stack.enter_context(mock.patch.object(SMOKE.socket, "socket"))
            reservation.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 12345)
            stack.enter_context(contextlib.redirect_stdout(output))
            result = SMOKE.main()
        self.assertEqual(result, 1)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)
        self.assertEqual(len(directories), 1)
        self.assertFalse(directories[0].exists())
        report = json.loads(output.getvalue())
        self.assertEqual(report["error"], "io_or_http_error")
        self.assertNotIn(SENTINEL, output.getvalue())
        self.assertNotIn("proxy.example", output.getvalue())


if __name__ == "__main__":
    unittest.main()
