#!/usr/bin/env python3
"""Mocked runner safeguards: no browser or network access is needed."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("browser_profile_regression.py")
SPEC = importlib.util.spec_from_file_location("browser_profile_regression", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


REJECT_SCENARIO = "connect_rejected_after_headers"
SUCCESS_SCENARIOS = ("h2_sni_reuse", "h2_auth_reuse")
SUCCESS_URLS = ["https://one.baseline.invalid/one", "https://two.baseline.invalid/two"]


def ready(protocol="h2", scenario=REJECT_SCENARIO):
    result = {"protocol": protocol, "endpoint": "127.0.0.1:5443",
              "proxy_url": ("https" if protocol == "h2" else "quic") + "://127.0.0.1:5443",
              "spki": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
    if scenario in SUCCESS_SCENARIOS:
        result.update(scenario=scenario, proxy_host="proxy.baseline.invalid",
                      proxy_url="https://proxy.baseline.invalid:5443", urls=list(SUCCESS_URLS),
                      expected_bodies=["fixture response one\n", "fixture response two\n"])
        if scenario == "h2_auth_reuse":
            result["test_credentials"] = {"username": "baseline-user", "password": "baseline-pass"}
    return result


def profile(actor="chrome", protocol="h2", scenario=REJECT_SCENARIO):
    result = {"schema_version": 1, "actor": actor, "protocol": protocol,
              "scenario": scenario, "features": {"tls.alpn": [protocol]},
              "evidence": {"connect_received": True, "response_status": 502}}
    if scenario in SUCCESS_SCENARIOS:
        authenticated = scenario == "h2_auth_reuse"
        result["features"]["tls.server_name"] = "proxy.baseline.invalid"
        result["features"].update({"tls.cipher_suites": ["0x1301"], "tls.extension_ids": ["0x0000"],
                                   "tls.key_share_groups": [{"group": "0x001d", "key_exchange_bytes": 32}],
                                   "tls.signature_algorithms": ["0x0403"], "tls.supported_groups": ["0x001d"],
                                   "tls.supported_versions": ["0x0304"], "h2.settings": [{"id": 1, "value": 65536}],
                                   "h2.connection_window_increment": 15663105, "connect.user_agent": "fixture-chrome-133",
                                   "connect.reused_physical_connection": True})
        result["evidence"].update(response_status=200, successful_tunnels=2, completed_payloads=2,
                                  client_payloads_verified=True, reused_physical_connection=True,
                                  server_name="proxy.baseline.invalid", auth_required=authenticated,
                                  auth_validated=2 if authenticated else 0,
                                  auth_challenges=1 if authenticated and actor == "chrome" else 0)
        requests = []
        if authenticated and actor == "chrome":
            requests.append({"connection_id": 1, "stream_id": 1, "method": "CONNECT",
                             "authority": "one.baseline.invalid:443", "auth": "none", "status": 407,
                             "payload_completed": False})
        for host, path in (("one.baseline.invalid", "/one"), ("two.baseline.invalid", "/two")):
            requests.append({"connection_id": 1, "stream_id": len(requests) * 2 + 1, "method": "CONNECT",
                             "authority": host + ":443", "auth": "valid" if authenticated else "none",
                             "status": 200, "payload_completed": True, "origin_method": "GET", "origin_host": host,
                             "origin_path": path, "response_bytes": 117})
        result["evidence"]["requests"] = requests
        result["evidence"]["connections"] = [{"id": 1, "server_name": "proxy.baseline.invalid",
                                               "negotiated_protocol": "h2", "wire_requests": [
                                                   {field: request[field] for field in ("stream_id", "authority", "auth")}
                                                   for request in requests]}]
        for wire in result["evidence"]["connections"][0]["wire_requests"]:
            wire.update(header_names=[":method", ":authority", "user-agent"],
                        hpack_representations=["indexed_dynamic"] * 3, user_agent="fixture-chrome-133")
            if wire["auth"] == "valid":
                wire["header_names"].append("proxy-authorization")
                wire["hpack_representations"].append("indexed_dynamic")
        for index, name in enumerate(("first", "second")):
            wire = result["evidence"]["connections"][0]["wire_requests"][-2 + index]
            for field in ("header_names", "hpack_representations"):
                result["features"][f"connect.{name}.{field}"] = list(wire[field])
        result["features"]["auth.sequence"] = [{"credentials": request["auth"], "status": request["status"]}
                                                  for request in requests]
    return result


def navigation_output(url, body, status=200):
    return "### Result\n" + json.dumps({"url": url, "status": status, "body": body}) + "\n### Ran Playwright code\n"


class FakeProcess:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self.exit_code
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FlagsTests(unittest.TestCase):
    def test_h2_and_h3_flags_keep_proxy_and_resolver_on_loopback(self):
        for protocol in ("h2", "h3"):
            with self.subTest(protocol=protocol):
                flags = RUNNER.browser_flags(protocol, ready(protocol))
                self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", flags)
                self.assertIn("--proxy-server=" + ready(protocol)["proxy_url"], flags)
                self.assertIn("--ignore-certificate-errors-spki-list=" + ready(protocol)["spki"], flags)
                self.assertNotIn("--ignore-certificate-errors", flags)
                self.assertIn("--disable-background-networking", flags)
                self.assertIn("--disable-component-update", flags)
                self.assertIn("--disable-quic" if protocol == "h2" else "--enable-quic", flags)

    def test_remote_mismatched_or_malformed_ready_endpoints_are_rejected(self):
        changes = (
            {"endpoint": "203.0.113.7:443", "proxy_url": "https://203.0.113.7:443"},
            {"endpoint": "example.test:443", "proxy_url": "https://example.test:443"},
            {"endpoint": "0.0.0.0:5443", "proxy_url": "https://0.0.0.0:5443"},
            {"proxy_url": "https://127.0.0.1:5444"},
            {"proxy_url": "http://127.0.0.1:5443"},
            {"proxy_url": "https://user:pass@127.0.0.1:5443"},
            {"proxy_url": "https://127.0.0.1:5443/path"},
            {"protocol": "h3"}, {"spki": "invalid"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.browser_flags("h2", {**ready(), **change})

    def test_success_flags_resolve_only_named_proxy_to_loopback(self):
        for scenario in SUCCESS_SCENARIOS:
            with self.subTest(scenario=scenario):
                value = ready(scenario=scenario)
                self.assertEqual(RUNNER.validate_ready(value, "h2", scenario), value)
                flags = RUNNER.browser_flags("h2", value)
                self.assertIn("--proxy-server=https://proxy.baseline.invalid:5443", flags)
                self.assertIn("--host-resolver-rules=MAP proxy.baseline.invalid 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", flags)
                self.assertIn("--ignore-certificate-errors-spki-list=" + value["spki"], flags)
                self.assertNotIn("--ignore-certificate-errors", flags)
                self.assertIn("--disable-quic", flags)

    def test_success_ready_rejects_external_proxy_and_uncontrolled_origins(self):
        changes = (
            {"endpoint": "203.0.113.7:5443"}, {"endpoint": "0.0.0.0:5443"},
            {"endpoint": "localhost:5443"}, {"proxy_host": "external.invalid"},
            {"proxy_url": "https://external.invalid:5443"}, {"proxy_url": "https://127.0.0.1:5443"},
            {"proxy_url": "https://proxy.baseline.invalid:5444"},
            {"proxy_url": "https://baseline-user:baseline-pass@proxy.baseline.invalid:5443"},
            {"proxy_url": "https://proxy.baseline.invalid:5443/path"},
            {"proxy_url": "https://proxy.baseline.invalid:5443?target=external.invalid"},
            {"urls": ["https://external.invalid/", SUCCESS_URLS[1]]},
            {"urls": [SUCCESS_URLS[0], "http://two.baseline.invalid/two"]},
            {"urls": [SUCCESS_URLS[0], SUCCESS_URLS[0]]}, {"urls": SUCCESS_URLS[::-1]},
            {"urls": SUCCESS_URLS[:1]}, {"urls": SUCCESS_URLS + ["https://three.baseline.invalid/three"]},
            {"expected_bodies": []}, {"expected_bodies": ["one"]},
            {"expected_bodies": ["one", ""]}, {"expected_bodies": ["one", 2]},
            {"scenario": REJECT_SCENARIO}, {"protocol": "h3"}, {"spki": "invalid"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.validate_ready({**ready(scenario="h2_sni_reuse"), **change}, "h2", "h2_sni_reuse")

    def test_auth_ready_requires_only_public_fixture_credentials(self):
        for credentials in (None, {}, {"username": "baseline-user"},
                            {"username": "other", "password": "baseline-pass"},
                            {"username": "baseline-user", "password": "other"}):
            with self.subTest(credentials=credentials), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.validate_ready({**ready(scenario="h2_auth_reuse"), "test_credentials": credentials},
                                      "h2", "h2_auth_reuse")

    def test_success_ready_is_h2_only_and_requires_expected_scenario(self):
        for scenario in SUCCESS_SCENARIOS:
            with self.subTest(scenario=scenario), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.validate_ready(ready("h3", scenario), "h3", scenario)
        with self.assertRaises((ValueError, RuntimeError)):
            RUNNER.validate_ready(ready(scenario="h2_auth_reuse"), "h2", "h2_sni_reuse")


class NavigationTests(unittest.TestCase):
    def test_exact_200_response_returns_full_body_hash(self):
        body = "fixture body with trailing newline\n"
        result = RUNNER.parse_navigation(navigation_output(SUCCESS_URLS[0], body), SUCCESS_URLS[0], body)
        self.assertEqual(result, hashlib.sha256(body.encode()).hexdigest())

    def test_missing_partial_wrong_or_redirected_payload_is_rejected(self):
        body = "complete payload\n"
        results = [None, [], {}, {"url": SUCCESS_URLS[0], "status": 200},
                   {"url": SUCCESS_URLS[1], "status": 200, "body": body},
                   {"url": SUCCESS_URLS[0], "status": 200, "body": body[:-1]},
                   {"url": SUCCESS_URLS[0], "status": 200, "body": None}]
        results.extend({"url": SUCCESS_URLS[0], "status": status, "body": body}
                       for status in (None, 407, 502, 200.0, "200", True))
        for value in results:
            with self.subTest(value=value), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.parse_navigation("### Result\n" + json.dumps(value), SUCCESS_URLS[0], body)

    def test_cli_error_cannot_hide_behind_a_valid_result(self):
        valid = navigation_output(SUCCESS_URLS[0], "body")
        for text in ("### Error\nNavigation failed\n" + valid,
                     valid + "### Error\nNavigation failed\n", "not JSON", "### Result\n{broken"):
            with self.subTest(text=text), self.assertRaises((ValueError, RuntimeError)):
                RUNNER.parse_navigation(text, SUCCESS_URLS[0], "body")


class ValidateCaptureTests(unittest.TestCase):
    def test_successful_profiles_validate_for_both_actors(self):
        for scenario in SUCCESS_SCENARIOS:
            for actor in ("chrome", "moto"):
                with self.subTest(scenario=scenario, actor=actor):
                    RUNNER.validate_capture(profile(actor, scenario=scenario), actor, "h2", scenario)

    def test_success_evidence_cannot_claim_missing_payload_reuse_sni_or_auth(self):
        changes = (("completed_payloads", 0), ("completed_payloads", 2.0), ("successful_tunnels", True),
                   ("client_payloads_verified", False), ("client_payloads_verified", 1),
                   ("reused_physical_connection", False), ("server_name", "wrong.invalid"),
                   ("auth_required", False), ("auth_validated", 1), ("auth_challenges", 1))
        for field, value in changes:
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, RuntimeError)):
                captured = profile("moto", scenario="h2_auth_reuse")
                captured["evidence"][field] = value
                RUNNER.validate_capture(captured, "moto", "h2", "h2_auth_reuse")

    def test_success_capture_cannot_be_relabelled_as_another_scenario(self):
        with self.assertRaises((ValueError, RuntimeError)):
            RUNNER.validate_capture(profile("moto", scenario="h2_auth_reuse"), "moto", "h2", "h2_sni_reuse")

    def test_runner_rejects_success_capture_with_only_sni_and_auth_sequence(self):
        value = profile("moto", scenario="h2_sni_reuse")
        value["features"] = {field: value["features"][field] for field in ("tls.server_name", "auth.sequence")}
        with self.assertRaises(RuntimeError):
            RUNNER.validate_capture(value, "moto", "h2", "h2_sni_reuse")

    def test_runner_rejects_success_capture_with_changed_second_wire_user_agent(self):
        value = profile("moto", scenario="h2_sni_reuse")
        value["evidence"]["connections"][0]["wire_requests"][1]["user_agent"] = "changed-agent"
        with self.assertRaises(RuntimeError):
            RUNNER.validate_capture(value, "moto", "h2", "h2_sni_reuse")


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="moto-browser-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "capture"
        self.chrome = self.root / "Google Chrome for Testing"
        self.chrome.write_bytes(b"mock browser executable")
        self.args = argparse.Namespace(playwright_cli=self.root / "playwright-cli", chrome=self.chrome, headed=True)
        self.source = {"browser_version": "133.0.6943.141", "platform": "Darwin-arm64",
                       "executable_sha256": RUNNER.sha256(self.chrome),
                       "source_url": "https://storage.googleapis.com/chrome-for-testing-public/133.0.6943.141/mac-arm64/chrome-mac-arm64.zip"}
        self.protocol = "h2"
        self.actor = "chrome"
        self.capture_value = profile()
        self.ready_value = ready()
        self.process = FakeProcess()
        self.commands = []
        self.cli_version = "0.1.22"
        self.open_code = 0
        self.metadata_code = 0
        self.metadata_error = None
        self.close_code = 0
        self.close_error = None
        self.metadata_override = None
        self.metadata_output_prefix = ""
        self.write_capture = True
        self.launches = []
        self.navigation_commands = []
        self.navigation_results = {}
        self.proof_before_navigation = []
        self.open_output = "opened"

    def success_scenario(self, scenario="h2_sni_reuse"):
        self.args.scenario = scenario
        self.ready_value = ready(scenario=scenario)
        self.capture_value = profile(self.actor, scenario=scenario)

    def metadata(self):
        return {"version": {"product": "Chrome/133.0.6943.141", "protocolVersion": "1.3", "revision": "@mock-revision",
                            "userAgent": "Mozilla/5.0 Chrome/133.0.0.0 Safari/537.36"},
                "command": {"arguments": [str(self.chrome.resolve()), *RUNNER.browser_flags(self.protocol, self.ready_value),
                                          "--user-data-dir=/temporary/fresh-profile", "--remote-debugging-pipe"]}}

    def launch(self, command, **kwargs):
        self.launches.append((command, kwargs))
        RUNNER.write_json(self.directory / "ready.json", self.ready_value)
        if self.write_capture:
            RUNNER.write_json(self.directory / "capture.json", self.capture_value)
        return self.process

    def command(self, command, **_kwargs):
        self.commands.append(command)
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, self.cli_version + "\n")
        if "open" in command:
            return subprocess.CompletedProcess(command, self.open_code, self.open_output)
        if "run-code" in command:
            if "page.goto" in command[-1]:
                index = len(self.navigation_commands)
                self.navigation_commands.append(command)
                self.proof_before_navigation.append((self.directory / "client-proof.json").exists())
                default = (0, navigation_output(self.ready_value["urls"][index], self.ready_value["expected_bodies"][index]))
                code, output = self.navigation_results.get(index, default)
                return subprocess.CompletedProcess(command, code, output)
            if self.metadata_error:
                raise self.metadata_error
            value = self.metadata_override if self.metadata_override is not None else self.metadata()
            output = self.metadata_output_prefix + "### Result\n" + json.dumps(value) + "\n### Ran Playwright code\n```js\nmetadata\n```\n"
            return subprocess.CompletedProcess(command, self.metadata_code, output)
        if "goto" in command:
            return subprocess.CompletedProcess(command, 1, "ERR_TUNNEL_CONNECTION_FAILED")
        if "close" in command:
            if self.close_error:
                raise self.close_error
            return subprocess.CompletedProcess(command, self.close_code, "closed")
        self.fail("unexpected subprocess command")

    def invoke(self):
        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=self.launch), \
                mock.patch.object(RUNNER, "run", side_effect=self.command):
            return RUNNER.capture(self.root / "controller.test", self.directory, self.actor,
                                  self.protocol, self.args, self.source if self.actor == "chrome" else None)

    def test_valid_chrome_capture_has_provenance_and_closes_same_session(self):
        result = self.invoke()
        self.assertEqual(result, self.directory / "capture.json")
        captured = json.loads(result.read_text())
        self.assertEqual(captured["source"]["browser_version"], "133.0.6943.141")
        self.assertFalse(captured["source"]["headless"])
        manifest = json.loads((self.directory / "manifest.json").read_text())
        self.assertEqual(manifest["source"], captured["source"])
        self.assertEqual(captured["source"]["browser_metadata_sha256"], RUNNER.sha256(self.directory / "browser-metadata.log"))
        sessions = {part for command in self.commands for part in command if part.startswith("--session=")}
        self.assertEqual(len(sessions), 1)
        self.assertIn("close", self.commands[-1])
        config = json.loads((self.directory / "playwright-cli.json").read_text())
        self.assertEqual(config["browser"]["launchOptions"]["executablePath"], str(self.chrome.resolve()))
        self.assertTrue(config["browser"]["launchOptions"]["chromiumSandbox"])

    def test_moto_capture_never_starts_browser(self):
        self.actor = "moto"
        self.capture_value = profile("moto")
        self.assertEqual(self.invoke(), self.directory / "capture.json")
        self.assertEqual(self.commands, [])

    def test_custom_cli_records_observed_version_not_default_package_pin(self):
        self.cli_version = "0.1.23"
        captured = json.loads(self.invoke().read_text())
        self.assertEqual(captured["source"]["automation"], "Playwright CLI 0.1.23")

    def test_fresh_capture_directory_prevents_stale_output_reuse(self):
        self.directory.mkdir()
        RUNNER.write_json(self.directory / "capture.json", profile())
        with mock.patch.object(RUNNER.subprocess, "Popen") as popen, self.assertRaises(FileExistsError):
            RUNNER.capture(self.root / "controller.test", self.directory, self.actor,
                           self.protocol, self.args, self.source)
        popen.assert_not_called()

    def test_missing_capture_fails_even_when_fixture_exits_zero(self):
        self.write_capture = False
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertIn("close", self.commands[-1])

    def test_nonzero_fixture_exit_cannot_publish_capture_success(self):
        self.process.exit_code = 1
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertIn("close", self.commands[-1])

    def test_zero_exit_with_incomplete_capture_is_rejected(self):
        self.protocol = "h3"
        self.ready_value = ready("h3")
        self.capture_value = profile(protocol="h3")
        self.capture_value["features"] = {}
        self.capture_value["evidence"]["connect_received"] = False
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertIn("close", self.commands[-1])

    def test_zero_exit_with_wrong_capture_identity_is_rejected(self):
        for field, value in (("actor", "moto"), ("protocol", "h3"), ("scenario", "unrelated"), ("schema_version", True)):
            with self.subTest(field=field):
                self.directory = self.root / field
                self.capture_value = profile()
                self.capture_value[field] = value
                self.process = FakeProcess()
                with self.assertRaises(RuntimeError):
                    self.invoke()

    def test_moto_incomplete_capture_is_also_rejected_before_comparison(self):
        self.actor = "moto"
        self.capture_value = profile("moto")
        self.capture_value["evidence"]["connect_received"] = False
        with self.assertRaises(RuntimeError):
            self.invoke()

    def test_nonobject_capture_is_rejected_before_provenance_attachment(self):
        self.capture_value = []
        with self.assertRaises(RuntimeError):
            self.invoke()

    def test_failed_browser_metadata_is_not_accepted_as_provenance(self):
        self.metadata_code = 1
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertFalse(any("goto" in command for command in self.commands))
        self.assertIn("close", self.commands[-1])

    def test_malformed_browser_metadata_is_not_accepted_as_provenance(self):
        self.metadata_override = {"error": "Browser.getBrowserCommandLine requires --enable-automation"}
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertFalse(any("goto" in command for command in self.commands))

    def test_running_browser_version_must_match_requested_executable_version(self):
        self.metadata_override = self.metadata()
        self.metadata_override["version"]["product"] = "Chrome/134.0.6998.1"
        with self.assertRaises(RuntimeError):
            self.invoke()

    def test_running_browser_executable_and_proxy_flags_must_match(self):
        for change in ("executable", "proxy", "resolver"):
            with self.subTest(change=change):
                self.directory = self.root / change
                self.process = FakeProcess()
                self.metadata_override = self.metadata()
                arguments = self.metadata_override["command"]["arguments"]
                if change == "executable":
                    arguments[0] = "/another/browser"
                else:
                    prefix = "--proxy-server=" if change == "proxy" else "--host-resolver-rules="
                    arguments[:] = [argument for argument in arguments if not argument.startswith(prefix)]
                with self.assertRaises(RuntimeError):
                    self.invoke()

    def test_conflicting_effective_routing_flag_cannot_hide_behind_required_flag(self):
        for override in ("--proxy-server=https://203.0.113.7:443", "--host-resolver-rules=MAP * 203.0.113.7"):
            with self.subTest(override=override):
                self.directory = self.root / ("proxy-override" if "proxy-server" in override else "resolver-override")
                self.process = FakeProcess()
                self.metadata_override = self.metadata()
                self.metadata_override["command"]["arguments"].append(override)
                with self.assertRaises(RuntimeError):
                    self.invoke()

    def test_headed_capture_cannot_record_headless_process_as_headed(self):
        self.metadata_override = self.metadata()
        self.metadata_override["command"]["arguments"].append("--headless=new")
        self.metadata_override["version"]["userAgent"] = "Mozilla/5.0 HeadlessChrome/133.0.0.0 Safari/537.36"
        with self.assertRaises(RuntimeError):
            self.invoke()

    def test_open_failure_still_closes_browser_and_stops_fixture(self):
        self.open_code = 1
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertIn("close", self.commands[-1])
        self.assertTrue(self.process.terminated)

    def test_close_oserror_does_not_skip_fixture_cleanup(self):
        self.open_code = 1
        self.close_error = FileNotFoundError("mock CLI unavailable during close")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises((RuntimeError, OSError)):
            self.invoke()
        self.assertTrue(self.process.terminated)

    def test_unsuccessful_browser_close_prevents_success(self):
        self.close_code = 1
        with self.assertRaises(RuntimeError):
            self.invoke()

    def test_close_timeout_still_stops_running_fixture(self):
        self.open_code = 1
        self.close_error = subprocess.TimeoutExpired("close", 15)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(RuntimeError):
            self.invoke()
        self.assertTrue(self.process.terminated)

    def test_success_capture_verifies_two_responses_before_publishing_client_proof(self):
        self.success_scenario()
        result = self.invoke()
        self.assertEqual(result, self.directory / "capture.json")
        self.assertEqual(len(self.navigation_commands), 2)
        self.assertEqual(self.proof_before_navigation, [False, False])
        self.assertFalse(any("goto" in command for command in self.commands))
        for index, command in enumerate(self.navigation_commands):
            self.assertIn(json.dumps(SUCCESS_URLS[index]), command[-1])
            self.assertIn(".text()", command[-1])
        proof = json.loads((self.directory / "client-proof.json").read_text())
        self.assertEqual(proof, {"verified": True, "urls": SUCCESS_URLS,
                                 "body_sha256": [hashlib.sha256(body.encode()).hexdigest()
                                                 for body in self.ready_value["expected_bodies"]]})
        command, kwargs = self.launches[0]
        self.assertIn("-test.run=^TestBrowserBaselineH2Success$", command)
        self.assertEqual(kwargs["env"]["MOTO_BROWSER_SCENARIO"], "h2_sni_reuse")
        self.assertEqual(kwargs["env"]["MOTO_BROWSER_ACTOR"], "chrome")
        config = json.loads((self.directory / "playwright-cli.json").read_text())
        self.assertIs(config["browser"]["isolated"], True)
        self.assertEqual(config["browser"]["contextOptions"]["proxy"],
                         {"server": "https://proxy.baseline.invalid:5443"})
        self.assertEqual(self.commands[-1][-1], "close")

    def test_auth_success_uses_fixture_credentials_in_isolated_context(self):
        self.success_scenario("h2_auth_reuse")
        self.invoke()
        config = json.loads((self.directory / "playwright-cli.json").read_text())
        self.assertEqual(config["browser"]["contextOptions"]["proxy"], {
            "server": "https://proxy.baseline.invalid:5443", "username": "baseline-user", "password": "baseline-pass"})
        self.assertIs(config["browser"]["isolated"], True)
        self.assertEqual(self.launches[0][1]["env"]["MOTO_BROWSER_SCENARIO"], "h2_auth_reuse")
        self.assertEqual(len(self.navigation_commands), 2)
        self.assertTrue((self.directory / "client-proof.json").is_file())

    def test_failed_or_partial_navigation_never_publishes_client_proof(self):
        for index in (0, 1):
            for failure in ("exit", "error-marker", "partial-body", "wrong-url", "wrong-status"):
                with self.subTest(index=index, failure=failure):
                    self.directory = self.root / f"failure-{index}-{failure}"
                    self.process = FakeProcess()
                    self.navigation_commands = []
                    self.navigation_results = {}
                    self.proof_before_navigation = []
                    self.success_scenario()
                    url, body = SUCCESS_URLS[index], self.ready_value["expected_bodies"][index]
                    output = navigation_output(url, body)
                    code = 0
                    if failure == "exit":
                        code = 1
                    elif failure == "error-marker":
                        output += "### Error\npage.goto failed\n"
                    elif failure == "partial-body":
                        output = navigation_output(url, body[:-1])
                    elif failure == "wrong-url":
                        output = navigation_output("https://external.invalid/", body)
                    elif failure == "wrong-status":
                        output = navigation_output(url, body, 407)
                    self.navigation_results[index] = (code, output)
                    with self.assertRaises(RuntimeError):
                        self.invoke()
                    self.assertFalse((self.directory / "client-proof.json").exists())
                    self.assertFalse((self.directory / "manifest.json").exists())
                    self.assertEqual(len(self.navigation_commands), index + 1)
                    self.assertEqual(self.commands[-1][-1], "close")
                    self.assertTrue(self.process.terminated)

    def test_success_moto_capture_uses_success_fixture_without_starting_browser(self):
        self.actor = "moto"
        self.success_scenario("h2_auth_reuse")
        self.assertEqual(self.invoke(), self.directory / "capture.json")
        self.assertEqual(self.commands, [])
        self.assertIn("-test.run=^TestBrowserBaselineH2Success$", self.launches[0][0])
        self.assertFalse((self.directory / "client-proof.json").exists())

    def test_zero_exit_browser_open_error_marker_still_stops_owned_processes(self):
        self.success_scenario()
        self.open_output = "### Error\nBrowser launch failed\n"
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertEqual(self.navigation_commands, [])
        self.assertFalse((self.directory / "client-proof.json").exists())
        self.assertEqual(self.commands[-1][-1], "close")
        self.assertTrue(self.process.terminated)

    def test_zero_exit_metadata_error_marker_cannot_publish_success_proof(self):
        self.success_scenario()
        self.metadata_output_prefix = "### Error\nBrowser metadata command failed\n"
        with self.assertRaises(RuntimeError):
            self.invoke()
        self.assertEqual(self.navigation_commands, [])
        self.assertFalse((self.directory / "client-proof.json").exists())
        self.assertEqual(self.commands[-1][-1], "close")
        self.assertTrue(self.process.terminated)


class ProcessTests(unittest.TestCase):
    def test_stop_escalates_to_kill_after_terminate_timeout(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture", 5), 1]
        RUNNER.stop(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_stop_does_not_touch_already_exited_process(self):
        process = mock.Mock()
        process.poll.return_value = 0
        RUNNER.stop(process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()


class MainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="moto-browser-main-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.chrome = self.root / "chrome"
        self.chrome.write_bytes(b"mock chrome")
        self.version = "Google Chrome for Testing 133.0.6943.141"
        self.commands = []
        self.samples = []
        self.scenarios = []
        self.compare_code = 0

    def command(self, command, **_kwargs):
        self.commands.append(command)
        output = self.version if "--version" in command else ""
        code = self.compare_code if str(SCRIPT.with_name("browser_profile_compare.py")) in command else 0
        return subprocess.CompletedProcess(command, code, output)

    def capture(self, binary, directory, actor, protocol, args, source):
        self.samples.append((actor, protocol, args.headed))
        self.scenarios.append(args.scenario)
        directory.mkdir(parents=True)
        path = directory / "capture.json"
        RUNNER.write_json(path, profile(actor, protocol, args.scenario))
        return path

    def invoke(self, extra=None, capture=None):
        argv = [str(SCRIPT), "--output", str(self.output), "--samples", "1", *(extra or [])]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(RUNNER, "run", side_effect=self.command), \
                mock.patch.object(RUNNER, "capture", side_effect=capture or self.capture), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return RUNNER.main()

    def chrome_arguments(self):
        return ["--capture-chrome", "--chrome", str(self.chrome), "--headed", "--chrome-source-url",
                "https://storage.googleapis.com/chrome-for-testing-public/133.0.6943.141/mac-arm64/chrome-mac-arm64.zip"]

    def test_default_ci_mode_is_h2_only_and_requires_provenance(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.samples, [("moto", "h2", False)])
        comparison = next(command for command in self.commands if "--candidate" in command)
        self.assertIn("--require-provenance", comparison)
        self.assertIn("--policy", comparison)
        self.assertIn("chrome-133-h2.json", comparison[comparison.index("--baseline") + 1])
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertTrue(summary["success"])
        self.assertFalse(summary["browser_capture"])

    def test_comparison_failure_sets_summary_and_exit_failure(self):
        self.compare_code = 2
        self.assertEqual(self.invoke(), 1)
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertFalse(summary["success"])
        self.assertEqual(summary["results"][0]["comparison_exit"], 2)

    def test_incomplete_chrome_probe_is_saved_as_failure_not_captured(self):
        def incomplete(*_args, **_kwargs):
            raise RuntimeError("insufficient_evidence: Chrome H3 CONNECT was not received")

        self.assertEqual(self.invoke(self.chrome_arguments() + ["--protocol", "h3"], capture=incomplete), 1)
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertFalse(summary["success"])
        self.assertNotIn("captured_not_compared", json.dumps(summary))

    def test_capture_timeout_is_saved_as_failure(self):
        def timeout(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("fixture", 55)

        self.assertEqual(self.invoke(capture=timeout), 1)
        self.assertFalse(json.loads((self.output / "summary.json").read_text())["success"])

    def test_nonchrome_version_output_is_rejected_before_build(self):
        self.version = "Unrelated browser 133.0.6943.141"
        with self.assertRaises(SystemExit) as error:
            self.invoke(self.chrome_arguments())
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(any("test" in command for command in self.commands))

    def test_invalid_sample_count_is_rejected_before_processes(self):
        for samples in ("0", "21"):
            with self.subTest(samples=samples), self.assertRaises(SystemExit) as error:
                self.invoke(["--samples", samples])
            self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.commands, [])

    def test_each_success_scenario_selects_its_own_baseline_and_policy(self):
        for scenario in SUCCESS_SCENARIOS:
            with self.subTest(scenario=scenario):
                self.output = self.root / scenario
                self.commands = []
                self.scenarios = []
                self.assertEqual(self.invoke(["--scenario", scenario]), 0)
                self.assertEqual(self.scenarios, [scenario])
                comparison = next(command for command in self.commands if "--candidate" in command)
                suffix = scenario.removeprefix("h2_").replace("_", "-")
                self.assertEqual(Path(comparison[comparison.index("--baseline") + 1]).name,
                                 f"chrome-133-h2-{suffix}.json")
                self.assertEqual(Path(comparison[comparison.index("--policy") + 1]).name,
                                 f"h2-{suffix}-known-differences.json")
                summary = json.loads((self.output / "summary.json").read_text())
                self.assertTrue(summary["success"])
                self.assertEqual(summary["results"][0]["scenario"], scenario)

    def test_all_h2_scenarios_run_once_and_keep_evidence_in_distinct_directories(self):
        self.assertEqual(self.invoke(["--scenario", "all"]), 0)
        self.assertEqual(self.scenarios, [REJECT_SCENARIO, *SUCCESS_SCENARIOS])
        self.assertEqual(self.samples, [("moto", "h2", False)] * 3)
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertEqual([result["scenario"] for result in summary["results"]], self.scenarios)
        self.assertEqual(len({result["capture"] for result in summary["results"]}), 3)
        self.assertTrue(summary["success"])

    def test_all_chrome_scenarios_capture_without_comparing_or_promoting_baselines(self):
        self.assertEqual(self.invoke(self.chrome_arguments() + ["--scenario", "all"]), 0)
        self.assertEqual(self.scenarios, [REJECT_SCENARIO, *SUCCESS_SCENARIOS])
        self.assertEqual(self.samples, [("chrome", "h2", True)] * 3)
        self.assertFalse(any("--candidate" in command for command in self.commands))
        summary = json.loads((self.output / "summary.json").read_text())
        self.assertTrue(summary["browser_capture"])
        self.assertEqual([result["status"] for result in summary["results"]], ["captured_not_compared"] * 3)

    def test_success_and_all_scenarios_reject_h3_before_starting_processes(self):
        for scenario in (*SUCCESS_SCENARIOS, "all"):
            for protocol in ("h3", "both"):
                with self.subTest(scenario=scenario, protocol=protocol), self.assertRaises(SystemExit) as error:
                    self.invoke(["--scenario", scenario, "--protocol", protocol])
                self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.samples, [])

    def test_unknown_scenario_rejected_before_starting_processes(self):
        with self.assertRaises(SystemExit) as error:
            self.invoke(["--scenario", "unknown"])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.commands, [])


if __name__ == "__main__":
    unittest.main()
