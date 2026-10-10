#!/usr/bin/env python3
"""Check managed dependency pins offline, or retain original upstream queries."""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
POLICY = Path("security/dependency-baselines.json")
IMPORTER = Path("internal/browserhttp2/update_upstream.py")
DATABASE = "https://vuln.go.dev"
IDENTITIES = {
    "utls": ("github.com/refraction-networking/utls", "github.com/cppla/utls", "github.com/refraction-networking/utls"),
    "quic": ("github.com/apernet/quic-go", "github.com/cppla/quic-go", "github.com/quic-go/quic-go"),
    "xnet": ("golang.org/x/net", None, "golang.org/x/net"),
}
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-(?:0\.)?[0-9]{14}-[0-9a-f]{12})?")
PSEUDO_VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-(?:0\.)?[0-9]{14}-[0-9a-f]{12}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-JSON number: {value}")


DECODER = json.JSONDecoder(object_pairs_hook=unique_object, parse_constant=reject_constant)


def json_document(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), f"invalid {label} fields")


def valid_version(value, label, pseudo=False):
    pattern = PSEUDO_VERSION if pseudo else VERSION
    require(isinstance(value, str) and pattern.fullmatch(value), f"invalid exact version: {label}")


def read_policy(root):
    policy = json_document((root / POLICY).read_text(encoding="utf-8"))
    exact_keys(policy, {"schema_version", "scanner_version", "dependencies"}, "policy")
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1, "unsupported policy schema")
    valid_version(policy["scanner_version"], "scanner")
    dependencies = policy["dependencies"]
    require(isinstance(dependencies, list) and len(dependencies) == 3, "require all three managed baselines")
    seen = set()
    for entry in dependencies:
        require(isinstance(entry, dict), "invalid dependency entry")
        identity = entry.get("id")
        require(isinstance(identity, str) and identity in IDENTITIES and identity not in seen, "invalid or duplicate baseline id")
        seen.add(identity)
        module, replacement, advisory = IDENTITIES[identity]
        fields = {"id", "module", "version", "advisory", "replacement" if replacement else "copied_source"}
        exact_keys(entry, fields, identity)
        require(entry["module"] == module, f"unexpected module identity: {identity}")
        valid_version(entry["version"], identity)
        exact_keys(entry["advisory"], {"module", "version"}, f"{identity} advisory")
        require(entry["advisory"]["module"] == advisory, f"unexpected original advisory identity: {identity}")
        valid_version(entry["advisory"]["version"], f"{identity} advisory")
        if identity != "quic":
            require(entry["advisory"]["version"] == entry["version"], f"advisory baseline drift: {identity}")
        if replacement:
            exact_keys(entry["replacement"], {"module", "version"}, f"{identity} replacement")
            require(entry["replacement"]["module"] == replacement, f"unexpected replacement identity: {identity}")
            valid_version(entry["replacement"]["version"], f"{identity} replacement", pseudo=True)
        else:
            copied = entry["copied_source"]
            exact_keys(copied, {"version", "archive_sha256"}, "copied source")
            require(copied["version"] == entry["version"], "copied x/net version drift")
            require(isinstance(copied["archive_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", copied["archive_sha256"]), "invalid copied source hash")
    return policy


def check_module_document(document, policy):
    require(isinstance(document, dict), "invalid go.mod JSON")
    requires = document.get("Require") or []
    replacements = document.get("Replace") or []
    for entry in policy["dependencies"]:
        module = entry["module"]
        selected = [item for item in requires if item.get("Path") == module]
        require(len(selected) == 1 and selected[0].get("Version") == entry["version"], f"go.mod baseline drift: {module}")
        require(not any(item.get("Old", {}).get("Path", "").startswith(module + "/") for item in replacements), f"managed submodule replacement bypass: {module}")
        selected_replacements = [item for item in replacements if item.get("Old", {}).get("Path") == module]
        expected = entry.get("replacement")
        if expected:
            require(len(selected_replacements) == 1, f"require one global replacement: {module}")
            item = selected_replacements[0]
            require(not item["Old"].get("Version") and item.get("New") == {
                "Path": expected["module"], "Version": expected["version"],
            }, f"replacement must match exact remote pin: {module}")
            require(not any(item.get("Path") == expected["module"] or item.get("Path", "").startswith(expected["module"] + "/") for item in requires), f"duplicate replacement module identity: {module}")
            for item in replacements:
                old, new = item.get("Old", {}), item.get("New", {})
                require(old.get("Path") != expected["module"] and not old.get("Path", "").startswith(expected["module"] + "/"), f"replacement identity must not be replaced: {module}")
                if new.get("Path") == expected["module"] or new.get("Path", "").startswith(expected["module"] + "/"):
                    require(old.get("Path") == module and new.get("Path") == expected["module"], f"replacement reused by another module: {module}")
        else:
            require(not selected_replacements, "copied x/net baseline must not be replaced")
        require(not any(item.get("Path", "").startswith(module + "/") for item in requires), f"managed submodule bypass: {module}")


def check_boundary(root, policy, go="go"):
    # Go's own parser handles quoted module paths and duplicate directives.
    # No dependency lookup, source execution, module update or toolchain download.
    result = subprocess.run(
        [go, "mod", "edit", "-json"], cwd=root,
        env={**os.environ, "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off"},
        text=True, capture_output=True, timeout=30,
    )
    require(result.returncode == 0, "Go could not parse go.mod offline")
    check_module_document(json_document(result.stdout), policy)
    tree = ast.parse((root / IMPORTER).read_text(encoding="utf-8"))
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"VERSION", "ZIP_SHA256"}:
                    require(target.id not in constants, "duplicate importer baseline constant")
                    constants[target.id] = ast.literal_eval(node.value)
    copied = next(item for item in policy["dependencies"] if item["id"] == "xnet")["copied_source"]
    require(constants == {"VERSION": copied["version"], "ZIP_SHA256": copied["archive_sha256"]}, "copied x/net importer differs from reviewed baseline")


def parse_query(text, entry, scanner_version):
    require(0 < len(text.encode("utf-8")) <= 32 << 20, "empty or oversized query output")
    messages = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = DECODER.raw_decode(text, offset)
        require(isinstance(value, dict) and len(value) == 1, "invalid query message")
        messages.append(value)
    require(messages and set(messages[0]) == {"config"}, "query must start with configuration")
    config = messages[0]["config"]
    require(isinstance(config, dict), "invalid query configuration")
    expected = {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": scanner_version, "scan_mode": "query", "db": DATABASE}
    require(all(config.get(key) == value for key, value in expected.items()), "unexpected scanner, database or query mode")
    require(isinstance(config.get("db_last_modified"), str), "query database freshness metadata missing")
    datetime.fromisoformat(config["db_last_modified"].replace("Z", "+00:00"))
    advisories = []
    for message in messages[1:]:
        kind, value = next(iter(message.items()))
        require(isinstance(value, dict), "invalid query message body")
        if kind == "progress":
            require(isinstance(value.get("message"), str), "invalid query progress")
        elif kind == "osv":
            identity = value.get("id")
            require(isinstance(identity, str) and re.fullmatch(r"GO-[0-9]{4}-[0-9]+", identity), "invalid advisory id")
            require(identity not in advisories, "duplicate advisory id")
            affected = value.get("affected")
            require(isinstance(affected, list) and any(
                isinstance(item, dict) and isinstance(item.get("package"), dict)
                and item["package"].get("name") == entry["advisory"]["module"]
                and item["package"].get("ecosystem") == "Go"
                for item in affected
            ), "advisory does not identify the queried upstream module")
            advisories.append(identity)
        else:
            raise ValueError(f"unexpected message in query stream: {kind}")
    return sorted(advisories), config


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def query_upstreams(root, output, go="go"):
    output.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="upstream-", dir=output))
    report = {"schema_version": 1, "status": "failed", "queries": [],
              "started_at": datetime.now(timezone.utc).isoformat(),
              "scope": "original upstream advisory candidates; not fork reachability"}
    try:
        policy = read_policy(root)
        write_json(evidence / "baselines.json", policy)
        check_boundary(root, policy, go)
        report["go_mod_sha256"] = hashlib.sha256((root / "go.mod").read_bytes()).hexdigest()
        tool_directory = (root / "bin/tools/dependency-security").resolve()
        tool_directory.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "GOTOOLCHAIN": "local", "GOWORK": "off", "GOBIN": str(tool_directory)}
        scanner = tool_directory / ("govulncheck.exe" if os.name == "nt" else "govulncheck")
        with (evidence / "tool-install.stdout").open("wb") as stdout, (evidence / "tool-install.stderr").open("wb") as stderr:
            installed = subprocess.run([go, "install", "golang.org/x/vuln/cmd/govulncheck@" + policy["scanner_version"]],
                                       cwd=root, env=environment, stdout=stdout, stderr=stderr, timeout=180)
        require(installed.returncode == 0, "pinned scanner installation failed; see retained tool-install.stderr")
        failed = False
        for entry in policy["dependencies"]:
            query = entry["advisory"]["module"] + "@" + entry["advisory"]["version"]
            result = {"id": entry["id"], "query": query, "status": "failed"}
            report["queries"].append(result)
            raw = evidence / (entry["id"] + ".json")
            try:
                with raw.open("wb") as stdout, (evidence / (entry["id"] + ".stderr")).open("wb") as stderr:
                    completed = subprocess.run([str(scanner), "-db", DATABASE, "-mode=query", "-json", query],
                                               cwd=root, env=environment, stdout=stdout, stderr=stderr, timeout=90)
                result["exit_code"] = completed.returncode
                require(completed.returncode == 0, "upstream query failed")
                identities, config = parse_query(raw.read_text(encoding="utf-8"), entry, policy["scanner_version"])
                result.update(advisories=identities, scanner=config,
                              status="review_required" if identities else "no_candidates")
                failed |= bool(identities)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                result["error"] = str(error)
                failed = True
            finally:
                if raw.is_file():
                    result["raw_sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
            print(f"{entry['id']}: {result['status']}" + (" " + ", ".join(result.get("advisories", [])) if result.get("advisories") else ""))
        report["status"] = "review_required_or_failed" if failed else "no_candidates"
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        write_json(evidence / "summary.json", report)
        print(f"Upstream advisory evidence: {evidence}")
    return 0 if report["status"] == "no_candidates" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "query"))
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", type=Path, default=ROOT / "bin/security-advisories")
    args = parser.parse_args()
    try:
        if args.command == "query":
            return query_upstreams(ROOT, args.output.resolve(), args.go)
        check_boundary(ROOT, read_policy(ROOT), args.go)
        print("Managed dependency baselines and replacements match.")
        return 0
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as error:
        print(f"Dependency security check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
