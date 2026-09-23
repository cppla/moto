#!/usr/bin/env python3
"""Loopback-only tests for the bounded TLS echo origin (stdlib + openssl)."""

from __future__ import annotations

import contextlib
import importlib.util
import json
from pathlib import Path
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("h2_timing_origin.py")
SPEC = importlib.util.spec_from_file_location("h2_timing_origin", SCRIPT)
ORIGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORIGIN)


class OriginArgumentsTests(unittest.TestCase):
    def test_defaults_and_invalid_values(self):
        base = ["--cert", "certificate", "--key", "private-key"]
        args = ORIGIN.arguments(base)
        self.assertEqual((args.listen, args.port, args.duration), ("0.0.0.0", 443, 1800))
        self.assertEqual(ORIGIN.arguments(base + ["--duration", "7200"]).duration, 7200)
        for extra in (["--duration", "nan"], ["--duration", "inf"],
                      ["--duration", "0"], ["--duration", "7201"],
                      ["--port", "65536"], ["--listen", "localhost"],
                      ["--unknown-secret", "sensitive-value"]):
            with self.subTest(extra=extra), self.assertRaises(ORIGIN.InvalidArguments):
                ORIGIN.arguments(base + extra)

    def test_configuration_errors_are_redacted(self):
        for args, expected in ((["--cert", "private-sentinel", "--key", "private-sentinel"], 1),
                               (["--secret-sentinel"], 2)):
            result = subprocess.run([sys.executable, str(SCRIPT), *args],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stderr, "")
            self.assertNotIn("sentinel", result.stdout)
            self.assertEqual(json.loads(result.stdout.splitlines()[-1])["event"], "summary")


@unittest.skipUnless(shutil.which("openssl"), "openssl is required to generate local certificates")
class TLSOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="moto-origin-test-")
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)

        def openssl(*args, input=None):
            result = subprocess.run(["openssl", *args], cwd=cls.directory,
                                    input=input, capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError("local test certificate generation failed")

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=OriginFixtureTestCA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key",
                "-out", "server.csr", "-subj", "/CN=localhost")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "server.crt", "-days", "1", "-extfile", "/dev/stdin",
                input="subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
        cls.context = ssl.create_default_context(cafile=str(cls.directory / "ca.crt"))

    @contextlib.contextmanager
    def running(self, duration=10, **limits):
        # Tightened limits exist only in this child process, never as public CLI
        # knobs that could increase the deployed service's resource ceilings.
        bootstrap = ("import sys; sys.path.insert(0, " + repr(str(SCRIPT.parent)) + "); "
                     "import h2_timing_origin as origin; "
                     + " ".join(f"origin.{name} = {value!r};" for name, value in limits.items())
                     + " sys.exit(origin.main())")
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", bootstrap, "--listen", "127.0.0.1", "--port", "0",
             "--cert", str(self.directory / "server.crt"), "--key", str(self.directory / "server.key"),
             "--duration", str(duration)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.process = process
        self.events = []
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(3), "origin did not become ready")
            ready = json.loads(process.stdout.readline())
            self.assertEqual(ready["event"], "ready")
            self.port = ready["port"]
            self.events.append(ready)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                output, errors = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("origin did not terminate within 3 seconds")
            self.assertEqual(errors, "")
            self.events.extend(json.loads(line) for line in output.splitlines())
            self.assertEqual(process.returncode, 0)
            self.assertEqual(self.events[-1]["event"], "summary")
            summary = self.events[-1]
            self.assertEqual(summary["accepted"], summary["completed"])
            self.assertNotIn("127.0.0.1", output)
            self.assertNotIn("payload-sentinel", output)

    def connect(self, hostname="localhost", context=None):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        try:
            return (context or self.context).wrap_socket(raw, server_hostname=hostname)
        except Exception:
            raw.close()
            raise

    def receive(self, conn, length):
        result = bytearray()
        while len(result) < length:
            part = conn.recv(min(16384, length - len(result)))
            if not part:
                break
            result.extend(part)
        return bytes(result)

    def test_verified_tls_echo_binary_data_and_remain_silent_when_idle(self):
        with self.running():
            with self.connect() as conn:
                self.assertIn(conn.version(), ("TLSv1.2", "TLSv1.3"))
                self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(self.context.check_hostname)
                payload = b"payload-sentinel\x00\xff\n" + bytes(range(256))
                conn.sendall(payload)
                self.assertEqual(self.receive(conn, len(payload)), payload)
                conn.settimeout(0.15)
                with self.assertRaises(TimeoutError):
                    conn.recv(1)
                conn.settimeout(2)
                conn.sendall(b"after idle")
                self.assertEqual(self.receive(conn, 10), b"after idle")
        summary = self.events[-1]
        self.assertEqual(summary["received_bytes"], len(payload) + 10)
        self.assertEqual(summary["received_bytes"], summary["echoed_bytes"])

    def test_wrong_hostname_rejected_and_tls12_supported(self):
        tls12 = ssl.create_default_context(cafile=str(self.directory / "ca.crt"))
        tls12.maximum_version = ssl.TLSVersion.TLSv1_2
        with self.running():
            with self.assertRaises(ssl.SSLCertVerificationError) as failure:
                self.connect(hostname="invalid.example")
            self.assertIn("hostname mismatch", failure.exception.verify_message.lower())
            with self.connect(context=tls12) as conn:
                self.assertEqual(conn.version(), "TLSv1.2")
                conn.sendall(b"tls12")
                self.assertEqual(self.receive(conn, 5), b"tls12")

    def test_payload_budget_counts_receive_and_echo(self):
        with self.running():
            with self.connect() as conn:
                chunk = b"x" * 16384
                for _ in range((ORIGIN.MAX_PAYLOAD_BYTES // 2) // len(chunk)):
                    conn.sendall(chunk)
                    self.assertEqual(self.receive(conn, len(chunk)), chunk)
                self.assertEqual(conn.recv(1), b"")
        summary = self.events[-1]
        self.assertEqual(summary["received_bytes"] + summary["echoed_bytes"], ORIGIN.MAX_PAYLOAD_BYTES)
        self.assertEqual(summary["categories"]["payload_limit"], 1)

    def test_capacity_includes_incomplete_handshakes_and_is_reusable(self):
        with self.running(MAX_CONNECTIONS=1, HANDSHAKE_SECONDS=0.4):
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as raw:
                # Wait until the first socket has entered the bounded worker.
                time.sleep(0.1)
                with self.assertRaises((ssl.SSLError, OSError)):
                    self.connect()
                self.assertEqual(raw.recv(1), b"")
            with self.connect() as conn:
                conn.sendall(b"reused")
                self.assertEqual(self.receive(conn, 6), b"reused")
        summary = self.events[-1]
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["categories"]["handshake_timeout"], 1)

    def test_idle_and_lifetime_limits(self):
        for limits, category in (({"IDLE_SECONDS": 0.15}, "idle_timeout"),
                                 ({"CONNECTION_SECONDS": 0.2}, "lifetime_limit")):
            with self.subTest(category=category):
                with self.running(**limits):
                    with self.connect() as conn:
                        self.assertEqual(conn.recv(1), b"")
                self.assertEqual(self.events[-1]["categories"][category], 1)

    def test_sigterm_closes_idle_tls_and_pending_handshake(self):
        with self.running() as process:
            with self.connect() as conn, socket.create_connection(("127.0.0.1", self.port), timeout=2) as raw:
                process.send_signal(signal.SIGTERM)
                self.assertEqual(conn.recv(1), b"")
                self.assertEqual(raw.recv(1), b"")
                process.wait(timeout=2)
        self.assertEqual(self.events[-1]["reason"], "signal")

    def test_activity_does_not_extend_lifetime(self):
        with self.running(CONNECTION_SECONDS=0.3, IDLE_SECONDS=0.2):
            with self.connect() as conn:
                started = time.monotonic()
                while time.monotonic() - started < 1:
                    try:
                        conn.sendall(b"active")
                        if self.receive(conn, 6) != b"active":
                            break
                    except (OSError, ssl.SSLError):
                        break
                    time.sleep(0.04)
                else:
                    self.fail("traffic extended the connection lifetime")
        self.assertEqual(self.events[-1]["categories"]["lifetime_limit"], 1)

    def test_duration_closes_pending_connections(self):
        with self.running(duration=0.4) as process:
            with self.connect() as conn:
                self.assertEqual(conn.recv(1), b"")
                process.wait(timeout=2)
        self.assertEqual(self.events[-1]["reason"], "duration")


if __name__ == "__main__":
    unittest.main()
