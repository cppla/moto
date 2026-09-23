#!/usr/bin/env python3
"""Bounded TLS echo origin for a temporary, controlled H2 tunnel timing test.

This is a raw TLS echo service, not an HTTP/H2 server or a forwarding proxy.
It sends application data only in response to received data. The 1 MiB payload
budget counts input plus echoed output, permitting at most 512 KiB of input.
Only the explicitly supplied certificate and private-key files are loaded.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import select
import signal
import socket
import ssl
import sys
import threading
import time


MAX_CONNECTIONS = 32
HANDSHAKE_SECONDS = 10.0
CONNECTION_SECONDS = 180.0
IDLE_SECONDS = 90.0
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_DURATION_SECONDS = 7200.0
POLL_SECONDS = 0.1
CHUNK_BYTES = 16 * 1024


class InvalidArguments(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse's default error includes untrusted values and file paths.
        raise InvalidArguments


class Report:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {
            "accepted": 0, "completed": 0, "rejected": 0,
            "received_bytes": 0, "echoed_bytes": 0,
        }
        self.events: dict[str, int] = {}

    def emit(self, event: str, **fields):
        with self.lock:
            print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)

    def add(self, **counts):
        with self.lock:
            for name, value in counts.items():
                self.counts[name] += value

    def record(self, category: str):
        with self.lock:
            count = self.events.get(category, 0)
            self.events[category] = count + 1
            # Avoid unbounded logs if a client repeatedly fails or is rejected.
            if count == 0:
                print(json.dumps({"event": "error", "category": category}), flush=True)

    def summary(self, reason: str):
        with self.lock:
            print(json.dumps({"event": "summary", "reason": reason,
                              **self.counts, "categories": self.events},
                             sort_keys=True), flush=True)


def close_socket(conn: socket.socket):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


class EchoServer:
    def __init__(self, context: ssl.SSLContext, report: Report, duration: float):
        self.context = context
        self.report = report
        self.deadline = time.monotonic() + duration
        self.reason = "duration"
        self.stopping = False
        self.lock = threading.Lock()
        self.connections: set[socket.socket] = set()
        self.workers: set[threading.Thread] = set()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def request_stop(self, _signum=None, _frame=None):
        # Signal handlers only set flags; cleanup occurs in the serving loop.
        self.reason = "signal"
        self.stopping = True

    def perform(self, conn: ssl.SSLSocket, operation, deadline: float):
        # A close from another thread does not reliably interrupt a blocking
        # TLS handshake on every OS. Nonblocking TLS bounds stop latency too.
        while not self.stopping:
            remaining = min(deadline, self.deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                return operation()
            except ssl.SSLWantReadError:
                readable, writable = [conn], []
            except ssl.SSLWantWriteError:
                readable, writable = [], [conn]
            try:
                select.select(readable, writable, [], min(POLL_SECONDS, remaining))
            except ValueError:
                # Shutdown may have closed the fd between the TLS call and
                # select. Surface only the fixed connection-error category.
                raise ConnectionError from None
        raise InterruptedError

    def handle(self, raw: socket.socket, accepted_at: float):
        conn = raw
        deadline = accepted_at + CONNECTION_SECONDS
        handshaking = True
        received = 0
        echoed = 0
        try:
            # Serialize replacement with shutdown's socket snapshot so that a
            # detached raw socket never escapes the tracked set.
            with self.lock:
                if self.stopping:
                    return
                raw.setblocking(False)
                conn = self.context.wrap_socket(raw, server_side=True,
                                                do_handshake_on_connect=False)
                self.connections.remove(raw)
                self.connections.add(conn)
            self.perform(conn, conn.do_handshake,
                         min(deadline, accepted_at + HANDSHAKE_SECONDS))
            handshaking = False
            input_budget = MAX_PAYLOAD_BYTES // 2
            while not self.stopping and received < input_budget:
                payload = self.perform(
                    conn, lambda: conn.recv(min(CHUNK_BYTES, input_budget - received)),
                    min(deadline, time.monotonic() + IDLE_SECONDS))
                if not payload:
                    break
                received += len(payload)
                # Count actual writes, including a partial echo before failure.
                pending = memoryview(payload)
                while pending and not self.stopping:
                    sent = self.perform(conn, lambda: conn.send(pending),
                                        min(deadline, time.monotonic() + IDLE_SECONDS))
                    if sent == 0:
                        raise ConnectionError
                    echoed += sent
                    pending = pending[sent:]
            if received == input_budget:
                self.report.record("payload_limit")
        except (TimeoutError, socket.timeout):
            if not self.stopping:
                category = "handshake_timeout" if handshaking else "idle_timeout"
                if time.monotonic() >= min(deadline, self.deadline):
                    category = "lifetime_limit"
                self.report.record(category)
        except ssl.SSLError:
            if not self.stopping:
                self.report.record("tls_error")
        except OSError:
            if not self.stopping:
                self.report.record("connection_error")
        except Exception:
            if not self.stopping:
                self.report.record("worker_error")
        finally:
            close_socket(conn)
            self.report.add(completed=1, received_bytes=received, echoed_bytes=echoed)
            with self.lock:
                self.connections.discard(raw)
                self.connections.discard(conn)
                self.workers.discard(threading.current_thread())
                self.slots.release()

    def serve(self, listen: str, port: int):
        family = socket.AF_INET6 if ipaddress.ip_address(listen).version == 6 else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((listen, port))
            listener.listen(MAX_CONNECTIONS)
            listener.settimeout(POLL_SECONDS)
            self.report.emit("ready", port=listener.getsockname()[1])
            while not self.stopping and time.monotonic() < self.deadline:
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    self.report.record("accept_error")
                    self.reason = "resource_error"
                    break
                accepted_at = time.monotonic()
                if self.stopping or accepted_at >= self.deadline or not self.slots.acquire(False):
                    close_socket(raw)
                    self.report.add(rejected=1)
                    self.report.record("capacity_limit")
                    continue
                self.report.add(accepted=1)
                worker = None
                try:
                    worker = threading.Thread(target=self.handle, args=(raw, accepted_at),
                                              daemon=True)
                    with self.lock:
                        self.connections.add(raw)
                        self.workers.add(worker)
                    worker.start()
                except (RuntimeError, MemoryError):
                    close_socket(raw)
                    with self.lock:
                        self.connections.discard(raw)
                        self.workers.discard(worker)
                    self.slots.release()
                    self.report.add(completed=1)
                    self.report.record("resource_error")
                    self.reason = "resource_error"
                    break
        finally:
            self.stopping = True
            close_socket(listener)
            with self.lock:
                workers = list(self.workers)
            # Workers observe stopping within one short select interval and
            # close their own TLS socket. Avoid concurrent OpenSSL operations.
            for worker in workers:
                worker.join()
            with self.lock:
                active = list(self.connections)
            for conn in active:
                close_socket(conn)


def arguments(argv):
    parser = Parser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0", help="numeric local IP address")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--duration", type=float, default=1800.0)
    args = parser.parse_args(argv)
    try:
        ipaddress.ip_address(args.listen)
    except ValueError:
        raise InvalidArguments from None
    if not 0 <= args.port <= 65535 or not math.isfinite(args.duration) or not 0 < args.duration <= MAX_DURATION_SECONDS:
        raise InvalidArguments
    return args


def main(argv=None):
    report = Report()
    reason = "startup_error"
    handlers = {}
    try:
        args = arguments(argv)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # A callback prevents interactive prompts when given an encrypted key.
        context.load_cert_chain(args.cert, args.key, password=lambda: "")
        server = EchoServer(context, report, args.duration)
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, server.request_stop)
        server.serve(args.listen, args.port)
        reason = server.reason
        return 1 if reason == "resource_error" else 0
    except InvalidArguments:
        reason = "invalid_arguments"
        report.record(reason)
        return 2
    except (OSError, ssl.SSLError, ValueError):
        report.record("startup_error")
        return 1
    except Exception:
        reason = "internal_error"
        report.record(reason)
        return 1
    finally:
        for signum, previous in handlers.items():
            signal.signal(signum, previous)
        report.summary(reason)


if __name__ == "__main__":
    sys.exit(main())
