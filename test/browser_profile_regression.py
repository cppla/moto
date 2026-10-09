#!/usr/bin/env python3
"""Loopback-only wire regression; real Chrome capture is an explicit opt-in.

Default mode needs Go and Python only. Browser profiles, plaintext test captures,
and test executables stay in the ignored output/playwright directory. This does
not contact configured Moto targets or change the running Moto instance.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test/testdata/browser_profile"
PLAYWRIGHT_VERSION = "0.1.22"
DEFAULT_SCENARIO = "connect_rejected_after_headers"
SUCCESS_SCENARIOS = ("h2_sni_reuse", "h2_auth_reuse")
SUCCESS_URLS = ["https://one.baseline.invalid/one", "https://two.baseline.invalid/two"]
_COMPARE_SPEC = importlib.util.spec_from_file_location(
    "moto_browser_profile_compare", Path(__file__).with_name("browser_profile_compare.py"))
_COMPARE = importlib.util.module_from_spec(_COMPARE_SPEC)
_COMPARE_SPEC.loader.exec_module(_COMPARE)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command: list[str], *, cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def read_ready(directory: Path, process: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            return json.loads((directory / "ready.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            if process.poll() is not None:
                break
            time.sleep(0.05)
    raise RuntimeError(f"fixture did not become ready; see {directory / 'server.log'}")


def validate_ready(ready: dict, protocol: str, scenario: str = DEFAULT_SCENARIO) -> dict:
    try:
        proxy = urlsplit(ready["proxy_url"])
        endpoint = urlsplit("https://" + ready["endpoint"])
        expected_scheme = "https" if protocol == "h2" else "quic"
        if (ready["protocol"] != protocol or proxy.scheme != expected_scheme
                or proxy.username or proxy.password or proxy.path or proxy.query or proxy.fragment
                or endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment
                or not ipaddress.ip_address(endpoint.hostname).is_loopback
                or not proxy.port or endpoint.port != proxy.port
                or len(base64.b64decode(ready["spki"], validate=True)) != 32):
            raise ValueError("inconsistent loopback fixture metadata")
        if scenario == DEFAULT_SCENARIO:
            if ready["endpoint"] != proxy.netloc:
                raise ValueError("proxy must be the literal loopback endpoint")
        elif scenario in SUCCESS_SCENARIOS:
            if (protocol != "h2" or ready.get("scenario") != scenario
                    or proxy.hostname != "proxy.baseline.invalid"
                    or ready.get("proxy_host") != proxy.hostname
                    or endpoint.hostname != "127.0.0.1"
                    or ready.get("urls") != SUCCESS_URLS
                    or not isinstance(ready.get("expected_bodies"), list)
                    or len(ready["expected_bodies"]) != 2
                    or not all(isinstance(body, str) and 0 < len(body) <= 4096
                               for body in ready["expected_bodies"])):
                raise ValueError("invalid closed-loop success fixture")
            if (scenario == "h2_auth_reuse" and ready.get("test_credentials") != {
                    "username": "baseline-user", "password": "baseline-pass"}):
                raise ValueError("only public fixture credentials are allowed")
        else:
            raise ValueError("unknown capture scenario")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise RuntimeError("invalid loopback fixture readiness") from error
    return ready


def validate_capture(value: dict, actor: str, protocol: str,
                     scenario: str = DEFAULT_SCENARIO) -> None:
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or value.get("actor") != actor
            or value.get("protocol") != protocol
            or value.get("scenario") != scenario
            or not isinstance(value.get("features"), dict) or not value["features"]
            or not isinstance(value.get("evidence"), dict)
            or value["evidence"].get("connect_received") is not True):
        raise RuntimeError("insufficient evidence: complete CONNECT capture required")
    evidence = value["evidence"]
    if scenario == DEFAULT_SCENARIO:
        if type(evidence.get("response_status")) is not int or evidence["response_status"] != 502:
            raise RuntimeError("insufficient evidence: rejected CONNECT capture required")
    elif scenario in SUCCESS_SCENARIOS:
        # Use the same target/stream/authentication evidence gate for new browser
        # captures and offline comparisons, so their definitions cannot drift.
        _, issues = _COMPARE.validate_capture(value, "baseline" if actor == "chrome" else "candidate")
        if issues:
            raise RuntimeError("insufficient evidence: " + json.dumps(issues, sort_keys=True))
    else:
        raise RuntimeError("unknown capture scenario")


def parse_navigation(text: str, url: str, expected_body: str) -> str:
    try:
        if "### Error" in text:
            raise ValueError("browser reported navigation failure")
        value, _ = json.JSONDecoder().raw_decode(text.split("### Result\n", 1)[1].lstrip())
        if (value.get("url") != url or type(value.get("status")) is not int
                or value["status"] != 200 or value.get("body") != expected_body):
            raise ValueError("browser did not receive the expected complete response")
        return hashlib.sha256(value["body"].encode("utf-8")).hexdigest()
    except (IndexError, KeyError, TypeError, ValueError, AttributeError) as error:
        raise RuntimeError("could not verify Chrome response payload") from error


def parse_browser_metadata(text: str, source: dict, chrome: Path) -> dict:
    try:
        if "### Error" in text:
            raise ValueError("browser reported metadata failure")
        value, _ = json.JSONDecoder().raw_decode(text.split("### Result\n", 1)[1].lstrip())
        version = value["version"]
        arguments = value["command"]["arguments"]
        if (version["product"] != "Chrome/" + source["browser_version"]
                or not isinstance(arguments, list) or not arguments
                or not all(isinstance(item, str) for item in arguments)
                or Path(arguments[0]).resolve() != chrome.resolve()
                or not any(item.startswith("--user-data-dir=") for item in arguments)
                or "--enable-automation" not in arguments
                or "--no-sandbox" in arguments):
            raise ValueError("unexpected browser process or arguments")
        # Keep the complete effective flags, but not host-specific profile paths.
        flags = ["--user-data-dir=<isolated-temporary-profile>" if item.startswith("--user-data-dir=")
                 else item for item in arguments[1:]]
        return {"effective_flags": flags, "browser_product": version["product"],
                "browser_revision": version["revision"], "browser_user_agent": version.get("userAgent", "")}
    except (IndexError, KeyError, TypeError, ValueError, AttributeError) as error:
        raise RuntimeError("could not verify running Chrome provenance") from error


def browser_flags(protocol: str, ready: dict) -> list[str]:
    scenario = ready.get("scenario", DEFAULT_SCENARIO)
    validate_ready(ready, protocol, scenario)
    resolver = "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"
    if scenario in SUCCESS_SCENARIOS:
        resolver = "MAP proxy.baseline.invalid 127.0.0.1, " + resolver
    flags = [
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--no-first-run",
        "--no-default-browser-check",
        "--enable-automation",
        "--host-resolver-rules=" + resolver,
        f"--proxy-server={ready['proxy_url']}",
        f"--ignore-certificate-errors-spki-list={ready['spki']}",
    ]
    if protocol == "h3":
        flags += ["--enable-quic", f"--origin-to-force-quic-on={ready['endpoint']}"]
    else:
        flags += ["--disable-quic"]
    return flags


def capture(binary: Path, directory: Path, actor: str, protocol: str,
            args: argparse.Namespace, source: dict | None) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    scenario = getattr(args, "scenario", DEFAULT_SCENARIO)
    success_scenario = scenario in SUCCESS_SCENARIOS
    env = os.environ.copy()
    env.update(MOTO_BROWSER_CAPTURE_DIR=str(directory), MOTO_BROWSER_ACTOR=actor,
               MOTO_BROWSER_SCENARIO=scenario)
    test_name = "H2Success" if success_scenario else protocol.upper()
    command = [str(binary), "-test.v", "-test.count=1", "-test.timeout=120s",
               f"-test.run=^TestBrowserBaseline{test_name}$"]
    with (directory / "server.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=log)
        session = "moto-baseline-" + uuid.uuid4().hex[:12]
        cli = ([str(args.playwright_cli.resolve())] if args.playwright_cli else
               ["npx", "--yes", f"--package=@playwright/cli@{PLAYWRIGHT_VERSION}", "playwright-cli"])
        browser_started = False
        try:
            ready = validate_ready(read_ready(directory, process), protocol, scenario)
            if actor == "chrome":
                automation_version = run(cli + ["--version"], cwd=directory, timeout=15)
                if automation_version.returncode or not re.fullmatch(r"\d+\.\d+\.\d+\s*", automation_version.stdout):
                    raise RuntimeError("could not verify Playwright CLI version")
                flags = browser_flags(protocol, ready)
                config = {"browser": {"launchOptions": {
                    "executablePath": str(args.chrome.resolve()),
                    "headless": not args.headed,
                    "chromiumSandbox": True,
                    "args": flags,
                }}}
                if success_scenario:
                    context_proxy = {"server": ready["proxy_url"]}
                    if scenario == "h2_auth_reuse":
                        context_proxy.update(ready["test_credentials"])
                    config["browser"].update(isolated=True, contextOptions={"proxy": context_proxy})
                config_path = directory / "playwright-cli.json"
                write_json(config_path, config)
                prefix = cli + [f"--session={session}"]
                browser_started = True
                opened = run(prefix + ["open", "about:blank", f"--config={config_path}"], cwd=directory, timeout=35)
                (directory / "browser-open.log").write_text(opened.stdout)
                if opened.returncode or "### Error" in opened.stdout:
                    raise RuntimeError(f"Chrome launch failed; see {directory / 'browser-open.log'}")
                # CDP metadata only: no page script, header/UA override, or TLS modification.
                metadata = run(prefix + ["run-code", "async page => { const s = await page.context().newCDPSession(page); return {version: await s.send('Browser.getVersion'), command: await s.send('Browser.getBrowserCommandLine')}; }"], cwd=directory, timeout=15)
                (directory / "browser-metadata.log").write_text(metadata.stdout)
                if metadata.returncode:
                    raise RuntimeError("could not obtain running Chrome metadata")
                verified_metadata = parse_browser_metadata(metadata.stdout, source or {}, args.chrome)
                if not set(flags).issubset(verified_metadata["effective_flags"]):
                    raise RuntimeError("running Chrome lacks required loopback capture flags")
                effective = verified_metadata["effective_flags"]
                for flag in flags:
                    if "=" in flag:
                        prefix_flag = flag.split("=", 1)[0] + "="
                        if [item for item in effective if item.startswith(prefix_flag)] != [flag]:
                            raise RuntimeError("running Chrome has conflicting capture flags")
                if ("--ignore-certificate-errors" in effective
                        or any(item.startswith("--user-agent=") for item in effective)
                        or (args.headed and (any(item.startswith("--headless") for item in effective)
                                             or "HeadlessChrome" in verified_metadata["browser_user_agent"]))):
                    raise RuntimeError("running Chrome does not match the requested unmodified headed profile")
                if success_scenario:
                    hashes = []
                    for index, (url, body) in enumerate(zip(ready["urls"], ready["expected_bodies"]), 1):
                        code = ("async page => { const r = await page.goto(" + json.dumps(url)
                                + ", {waitUntil:'domcontentloaded', timeout:20000}); "
                                + "return {url:r.url(), status:r.status(), body:await r.text()}; }")
                        navigated = run(prefix + ["run-code", code], cwd=directory, timeout=30)
                        (directory / f"browser-navigation-{index}.log").write_text(navigated.stdout)
                        if navigated.returncode:
                            raise RuntimeError("Chrome successful CONNECT navigation failed")
                        hashes.append(parse_navigation(navigated.stdout, url, body))
                    write_json(directory / "client-proof.json", {
                        "verified": True, "urls": ready["urls"], "body_sha256": hashes})
                else:
                    navigated = run(prefix + ["goto", "https://baseline.invalid/"], cwd=directory, timeout=40)
                    (directory / "browser-navigation.log").write_text(navigated.stdout)
                    # A rejected CONNECT fails navigation; only the wire capture
                    # determines whether comparable protocol evidence was obtained.
                manifest = dict(source or {})
                manifest.update(verified_metadata)
                manifest.update(captured_at=datetime.now(timezone.utc).isoformat(),
                                flags=flags, headless=not args.headed,
                                automation=f"Playwright CLI {automation_version.stdout.strip()}",
                                browser_metadata_sha256=sha256(directory / "browser-metadata.log"))
                write_json(directory / "manifest.json", {"source": manifest})
            process.wait(timeout=95 if success_scenario else 55)
            capture_path = directory / "capture.json"
            if not capture_path.is_file():
                raise RuntimeError(f"no capture (fixture exit {process.returncode}); see {directory / 'server.log'}")
            if actor == "chrome":
                value = json.loads(capture_path.read_text())
                if not isinstance(value, dict):
                    raise RuntimeError("invalid capture: expected JSON object")
                value["source"] = manifest
                write_json(capture_path, value)
            if process.returncode:
                raise RuntimeError(f"incomplete capture; see {directory / 'server.log'}")
            validate_capture(json.loads(capture_path.read_text()), actor, protocol, scenario)
            return capture_path
        finally:
            cleanup_error = None
            try:
                if browser_started:
                    closed = run(cli + [f"--session={session}", "close"], cwd=directory, timeout=15)
                    (directory / "browser-close.log").write_text(closed.stdout)
                    if closed.returncode or "### Error" in closed.stdout:
                        cleanup_error = RuntimeError(f"could not close owned browser session {session}")
            except (OSError, subprocess.TimeoutExpired) as error:
                cleanup_error = RuntimeError(f"close owned browser session {session} manually: {error}")
            finally:
                stop(process)
            if cleanup_error is not None:
                if sys.exc_info()[0] is None:
                    raise cleanup_error
                print(f"WARNING: {cleanup_error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--protocol", choices=["h2", "h3", "both"], default="h2",
                        help="H2 has a captured baseline; H3 is an opt-in coverage probe")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--scenario", choices=[DEFAULT_SCENARIO, *SUCCESS_SCENARIOS, "all"],
                        default=DEFAULT_SCENARIO, help="H2 scenario; all includes rejected and successful tunnels")
    parser.add_argument("--capture-chrome", action="store_true")
    parser.add_argument("--chrome", type=Path, help="isolated Chrome for Testing executable")
    parser.add_argument("--chrome-source-url", help="exact official download URL for provenance")
    parser.add_argument("--playwright-cli", type=Path, help="optional installed CLI or wrapper")
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.samples <= 20:
        parser.error("--samples must be 1..20")
    if args.scenario != DEFAULT_SCENARIO and args.protocol != "h2":
        parser.error("successful scenarios require --protocol h2")
    if args.capture_chrome and (not args.chrome or not args.chrome_source_url):
        parser.error("browser capture requires --chrome and --chrome-source-url")
    source = None
    if args.capture_chrome:
        version_result = run([str(args.chrome.resolve()), "--version"], cwd=ROOT, timeout=10)
        match = re.fullmatch(r"Google Chrome for Testing (\d+\.\d+\.\d+\.\d+)\s*", version_result.stdout)
        if version_result.returncode or not match:
            parser.error("could not verify Chrome version")
        source = {"browser_version": match.group(1),
                  "platform": f"{platform.system()}-{platform.machine()}",
                  "executable_sha256": sha256(args.chrome),
                  "source_url": args.chrome_source_url,
                  "fixture_commit": run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip(),
                  "fixture_worktree_dirty": bool(run(["git", "status", "--porcelain"], cwd=ROOT).stdout.strip())}
    output = (args.output or ROOT / "output/playwright" / ("browser-baseline-" + datetime.now().strftime("%Y%m%d-%H%M%S"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / "controller.test"
    built = run([args.go, "test", "-c", "-o", str(binary), "./controller"], cwd=ROOT)
    (output / "build.log").write_text(built.stdout)
    if built.returncode:
        print(f"Build failed; see {output / 'build.log'}", file=sys.stderr)
        return 1
    protocols = ["h2", "h3"] if args.protocol == "both" else [args.protocol]
    results = []
    failed = False
    scenarios = [DEFAULT_SCENARIO, *SUCCESS_SCENARIOS] if args.scenario == "all" else [args.scenario]
    cases = [(protocol, scenario) for protocol in protocols for scenario in scenarios]
    for protocol, scenario in cases:
        args.scenario = scenario
        suffix = "" if scenario == DEFAULT_SCENARIO else "-" + scenario.removeprefix("h2_").replace("_", "-")
        for sample in range(1, args.samples + 1):
            actor = "chrome" if args.capture_chrome else "moto"
            directory = output / f"{protocol}{suffix}-{actor}-{sample}"
            print(f"Capturing {protocol} {scenario} {actor} sample {sample}/{args.samples}", flush=True)
            try:
                candidate = capture(binary, directory, actor, protocol, args, source)
                if args.capture_chrome:
                    results.append({"capture": str(candidate), "scenario": scenario, "status": "captured_not_compared"})
                    continue
                comparison = run([sys.executable, "-B", str(ROOT / "test/browser_profile_compare.py"),
                                  "--baseline", str(FIXTURES / f"chrome-133-{protocol}{suffix}.json"),
                                  "--candidate", str(candidate), "--require-provenance",
                                  "--policy", str(FIXTURES / f"{protocol}{suffix}-known-differences.json"),
                                  "--json-output", str(directory / "comparison.json")], cwd=ROOT)
                (directory / "comparison.log").write_text(comparison.stdout)
                print(comparison.stdout.strip(), flush=True)
                failed |= comparison.returncode != 0
                results.append({"capture": str(candidate), "scenario": scenario, "comparison_exit": comparison.returncode})
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                failed = True
                print(str(error), file=sys.stderr)
                results.append({"directory": str(directory), "error": str(error)})
    write_json(output / "summary.json", {"schema_version": 1, "success": not failed,
                                         "browser_capture": args.capture_chrome, "results": results,
                                         "claim": "bounded wire regression; not browser indistinguishability"})
    print(f"Evidence: {output}")
    return int(failed)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"browser regression: {error}", file=sys.stderr)
        raise SystemExit(1)
