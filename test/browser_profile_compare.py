#!/usr/bin/env python3
"""Compare captured Chrome and Moto profiles without making network requests.

Exit codes: 0 matched/known differences, 1 regression, 2 insufficient evidence.
Feature names are opaque keys; arrays remain ordered and no TLS/QUIC fields are
normalized here. Known differences match only their complete, exact value pair.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


SCENARIO = "connect_rejected_after_headers"
H2_SUCCESS_SCENARIOS = ("h2_sni_reuse", "h2_auth_reuse")
SCENARIOS = (SCENARIO, *H2_SUCCESS_SCENARIOS)
H2_PROXY_SERVER_NAME = "proxy.baseline.invalid"
H2_AUTHORITIES = ("one.baseline.invalid:443", "two.baseline.invalid:443")
H2_SUCCESS_LIST_FEATURES = (
    "tls.alpn", "tls.cipher_suites", "tls.extension_ids", "tls.key_share_groups",
    "tls.signature_algorithms", "tls.supported_groups", "tls.supported_versions", "h2.settings",
    "connect.first.header_names", "connect.second.header_names",
    "connect.first.hpack_representations", "connect.second.hpack_representations", "auth.sequence",
)
H2_SUCCESS_REQUIRED_FEATURES = (*H2_SUCCESS_LIST_FEATURES, "tls.server_name",
                                "h2.connection_window_increment", "connect.user_agent",
                                "connect.reused_physical_connection")
EXIT_CODES = {"matched": 0, "known_differences": 0,
              "regression": 1, "insufficient_evidence": 2}


def json_equal(left: object, right: object) -> bool:
    """JSON semantic equality, without Python's True == 1 shortcut."""
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys()
                and all(json_equal(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return len(left) == len(right) and all(map(json_equal, left, right))
    return left == right


def json_issues(value: object, path: str = "") -> list[str]:
    if value is None or type(value) in (str, bool, int):
        return []
    if isinstance(value, float):
        return [] if math.isfinite(value) else [path + ": non-finite number"]
    if isinstance(value, list):
        return [issue for index, item in enumerate(value)
                for issue in json_issues(item, f"{path}/{index}")]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return [issue for key, item in value.items()
                for issue in json_issues(item, path + "/" + pointer_escape(key))]
    return [path + ": invalid JSON value"]


def pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def changed_paths(left: object, right: object, path: str = "") -> list[str]:
    """Return JSON pointers within a changed feature, including missing keys."""
    if json_equal(left, right):
        return []
    if isinstance(left, dict) and isinstance(right, dict):
        changes = []
        for key in sorted(left.keys() | right.keys()):
            child = path + "/" + pointer_escape(key)
            changes.extend([child] if key not in left or key not in right
                           else changed_paths(left[key], right[key], child))
        return changes
    if isinstance(left, list) and isinstance(right, list):
        changes = []
        for index in range(max(len(left), len(right))):
            child = f"{path}/{index}"
            changes.extend([child] if index >= len(left) or index >= len(right)
                           else changed_paths(left[index], right[index], child))
        return changes
    return [path]


def load_json(path: Path) -> object:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("non-finite JSON number")

    data = json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if json_issues(data):
        raise ValueError("invalid or non-finite JSON value")
    return data


def validate_h2_success_trace(data: dict, issue) -> None:
    """Bind summary claims to ordered server requests and decoded H2 streams."""
    evidence, features = data["evidence"], data["features"]
    requests, connections = evidence.get("requests"), evidence.get("connections")
    if not isinstance(requests, list) or not 2 <= len(requests) <= 128:
        issue("evidence.requests", "bounded ordered request evidence is required")
        return
    if not isinstance(connections, list) or not 1 <= len(connections) <= 16:
        issue("evidence.connections", "bounded physical connection evidence is required")
        return
    by_id, wire_by_stream = {}, {}
    for connection in connections:
        if (not isinstance(connection, dict) or type(connection.get("id")) is not int
                or connection["id"] <= 0 or connection["id"] in by_id):
            issue("evidence.connections", "physical connection IDs must be unique positive integers")
            return
        by_id[connection["id"]] = connection
        wire_requests = connection.get("wire_requests", [])
        if not isinstance(wire_requests, list):
            issue("evidence.connections", "decoded wire requests must be a list")
            return
        for wire in wire_requests:
            if (not isinstance(wire, dict) or type(wire.get("stream_id")) is not int
                    or not 0 < wire["stream_id"] < 2 ** 31 or wire["stream_id"] % 2 != 1):
                issue("evidence.connections", "client CONNECT stream IDs must be positive odd integers")
                return
            key = (connection["id"], wire["stream_id"])
            if key in wire_by_stream:
                issue("evidence.connections", "decoded CONNECT streams must be unique within each connection")
                return
            wire_by_stream[key] = wire
    controlled, used_streams = [], set()
    for request in requests:
        if not isinstance(request, dict):
            issue("evidence.requests", "request evidence must contain JSON objects")
            return
        if request.get("method") != "CONNECT" or request.get("authority") not in H2_AUTHORITIES:
            if (type(request.get("status")) is not int or request["status"] != 403
                    or request.get("payload_completed") is not False):
                issue("evidence.requests", "requests outside the fixture targets must be denied without payload")
            continue
        controlled.append(request)
        if (type(request.get("connection_id")) is not int or request["connection_id"] <= 0
                or type(request.get("stream_id")) is not int or request["stream_id"] <= 0):
            issue("evidence.requests", "controlled requests require positive integer connection and stream IDs")
            return
        key = (request["connection_id"], request["stream_id"])
        wire = wire_by_stream.get(key)
        if (key in used_streams or wire is None or wire.get("authority") != request["authority"]
                or wire.get("auth") != request.get("auth")):
            issue("evidence.requests", "controlled request must match its unique decoded connection/stream, authority and credentials")
        used_streams.add(key)
        if request.get("error"):
            issue("evidence.requests", "controlled requests must complete without errors")
    auth_required = data["scenario"] == "h2_auth_reuse"
    challenges = controlled[:-2]
    successful = controlled[-2:]
    if len(successful) != 2:
        issue("evidence.requests", "two ordered successful origin requests are required")
        return
    if len(challenges) != evidence.get("auth_challenges"):
        issue("evidence.auth_challenges", "challenge count must match the ordered controlled requests")
    for request in challenges:
        if (not auth_required or data.get("actor") != "chrome"
                or request.get("authority") != H2_AUTHORITIES[0] or request.get("auth") != "none"
                or type(request.get("status")) is not int or request["status"] != 407
                or request.get("payload_completed") is not False):
            issue("evidence.requests", "only initial unauthenticated first-origin challenges are permitted")
    for index, request in enumerate(successful):
        host = H2_AUTHORITIES[index].removesuffix(":443")
        if (request.get("authority") != H2_AUTHORITIES[index]
                or request.get("auth") != ("valid" if auth_required else "none")
                or type(request.get("status")) is not int or request["status"] != 200
                or request.get("payload_completed") is not True
                or request.get("origin_method") != "GET" or request.get("origin_host") != host
                or request.get("origin_path") != ("/one" if index == 0 else "/two")
                or type(request.get("response_bytes")) is not int or request["response_bytes"] <= 0):
            issue("evidence.requests", "each ordered origin must have a complete, verified successful payload")
    first, second = successful
    if (first["connection_id"] != second["connection_id"] or first["stream_id"] >= second["stream_id"]):
        issue("evidence.reused_physical_connection", "successful origins must use increasing streams on the same physical connection")
    connection = by_id.get(first["connection_id"], {})
    if (connection.get("server_name") != H2_PROXY_SERVER_NAME or connection.get("negotiated_protocol") != "h2"
            or connection.get("error") or connection.get("wire_parse_error")):
        issue("evidence.connections", "the reused connection must have the expected SNI, H2 negotiation and decoded wire evidence")
    for index, request in enumerate(successful):
        wire = wire_by_stream.get((request["connection_id"], request["stream_id"]), {})
        prefix = "connect.first." if index == 0 else "connect.second."
        for field in ("header_names", "hpack_representations"):
            if not json_equal(features.get(prefix + field), wire.get(field)):
                issue("features." + prefix + field, "feature must match the corresponding successful decoded CONNECT stream")
        if not json_equal(features.get("connect.user_agent"), wire.get("user_agent")):
            issue("features.connect.user_agent", "both successful decoded CONNECT streams must retain the captured User-Agent")
    sequence = [{"credentials": request.get("auth"), "status": request.get("status")} for request in controlled]
    if not json_equal(features.get("auth.sequence"), sequence):
        issue("features.auth.sequence", "authentication feature must exactly retain the controlled request sequence")


def validate_capture(data: object, role: str) -> tuple[dict, list[dict]]:
    issues = []

    def issue(field, reason):
        issues.append({"field": f"{role}.{field}", "reason": reason})

    if not isinstance(data, dict):
        issue("capture", "capture must be a JSON object")
        return {}, issues
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        issue("schema_version", "expected schema_version 1")
    expected_actor = "chrome" if role == "baseline" else "moto"
    if data.get("actor") != expected_actor:
        issue("actor", f"expected actor {expected_actor}")
    if data.get("protocol") not in ("h2", "h3"):
        issue("protocol", "expected h2 or h3")
    scenario = data.get("scenario")
    if scenario not in SCENARIOS:
        issue("scenario", "expected a supported capture scenario: " + ", ".join(SCENARIOS))
    evidence = data.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("connect_received") is not True:
        issue("evidence.connect_received", "server must confirm receipt of CONNECT headers")
    if scenario in H2_SUCCESS_SCENARIOS:
        if data.get("protocol") != "h2":
            issue("protocol", "successful H2 reuse scenarios require protocol h2")
        evidence = evidence if isinstance(evidence, dict) else {}
        for field, expected in (("response_status", 200), ("successful_tunnels", 2),
                                ("completed_payloads", 2)):
            if type(evidence.get(field)) is not int or evidence[field] != expected:
                issue("evidence." + field, f"expected integer {expected}")
        if evidence.get("reused_physical_connection") is not True:
            issue("evidence.reused_physical_connection", "both completed tunnels must reuse a physical connection")
        if evidence.get("client_payloads_verified") is not True:
            issue("evidence.client_payloads_verified", "client must verify both complete response payloads")
        if evidence.get("server_name") != H2_PROXY_SERVER_NAME:
            issue("evidence.server_name", f"expected {H2_PROXY_SERVER_NAME}")
        auth_required = scenario == "h2_auth_reuse"
        if evidence.get("auth_required") is not auth_required:
            issue("evidence.auth_required", f"expected boolean {str(auth_required).lower()} for {scenario}")
        expected_validated = 2 if auth_required else 0
        if type(evidence.get("auth_validated")) is not int or evidence["auth_validated"] != expected_validated:
            issue("evidence.auth_validated", f"expected integer {expected_validated} for {expected_actor}")
        challenges = evidence.get("auth_challenges")
        if auth_required and expected_actor == "chrome":
            if type(challenges) is not int or not 1 <= challenges <= 8:
                issue("evidence.auth_challenges", "expected 1..8 initial Chrome challenge responses")
        elif type(challenges) is not int or challenges != 0:
            issue("evidence.auth_challenges", f"expected integer 0 for {expected_actor}")
    features = data.get("features")
    if not isinstance(features, dict) or not features:
        issue("features", "nonempty captured features are required")
        return {}, issues
    if scenario in H2_SUCCESS_SCENARIOS and features.get("tls.server_name") != H2_PROXY_SERVER_NAME:
        issue("features.tls.server_name", f"expected {H2_PROXY_SERVER_NAME}")
    if scenario in H2_SUCCESS_SCENARIOS:
        for field in H2_SUCCESS_REQUIRED_FEATURES:
            if field not in features:
                issue("features." + field, "required successful H2 capture feature is missing")
        for field in H2_SUCCESS_LIST_FEATURES:
            if field in features and (not isinstance(features[field], list) or not features[field]):
                issue("features." + field, "required successful H2 capture feature must be a nonempty list")
        if (type(features.get("h2.connection_window_increment")) is not int
                or features["h2.connection_window_increment"] < 0):
            issue("features.h2.connection_window_increment", "captured connection window increment must be a nonnegative integer")
        if not isinstance(features.get("connect.user_agent"), str) or not features["connect.user_agent"].strip():
            issue("features.connect.user_agent", "a captured User-Agent is required")
        if features.get("connect.reused_physical_connection") is not True:
            issue("features.connect.reused_physical_connection", "successful H2 reuse feature must be boolean true")
    if scenario in H2_SUCCESS_SCENARIOS and isinstance(data.get("evidence"), dict):
        validate_h2_success_trace(data, issue)
    clean = {}
    for field, value in features.items():
        if not isinstance(field, str) or not field.strip() or field != field.strip():
            issue("features", "feature names must be nonempty strings without surrounding whitespace")
            continue
        errors = json_issues(value)
        if errors:
            issue(f"features.{field}", "; ".join(errors))
        else:
            clean[field] = value
    return clean, issues


def validate_source(source: object) -> list[dict]:
    """Check provenance metadata's structure; this does not attest its truth."""
    issues = []

    def issue(field, reason):
        issues.append({"field": f"baseline.source.{field}", "reason": reason})

    if not isinstance(source, dict):
        issue("metadata", "baseline source provenance is required")
        return issues
    version = source.get("browser_version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
        issue("browser_version", "an exact four-part browser version is required")
    if not isinstance(source.get("platform"), str) or not source["platform"].strip():
        issue("platform", "a nonempty platform is required")
    digest = source.get("executable_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        issue("executable_sha256", "a 64-character SHA-256 digest is required")
    try:
        url = urlsplit(source.get("source_url", ""))
        valid_url = url.scheme == "https" and bool(url.hostname) and not url.username and not url.password
    except (TypeError, ValueError, AttributeError):
        valid_url = False
    if not valid_url:
        issue("source_url", "an HTTPS browser source URL without credentials is required")
    try:
        timestamp = datetime.fromisoformat(source.get("captured_at", "").replace("Z", "+00:00"))
        valid_timestamp = timestamp.tzinfo is not None and timestamp.utcoffset() is not None
    except (TypeError, ValueError, AttributeError):
        valid_timestamp = False
    if not valid_timestamp:
        issue("captured_at", "an ISO-8601 capture timestamp with timezone is required")
    flags = source.get("flags")
    if not isinstance(flags, list) or not all(isinstance(flag, str) and flag.strip() for flag in flags):
        issue("flags", "capture flags must be a list of nonempty strings (possibly empty)")
    return issues


def validate_policy(policy: object) -> tuple[dict, list[str]]:
    if policy is None:
        return {}, []
    if not isinstance(policy, dict):
        return {}, ["policy must be a JSON object"]
    errors = []
    if set(policy) - {"schema_version", "allowed_differences"}:
        errors.append("policy contains unknown top-level fields")
    if type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
        errors.append("policy schema_version must be 1")
    rules = policy.get("allowed_differences")
    if not isinstance(rules, dict):
        return {}, errors + ["allowed_differences must be an object"]
    valid = {}
    for field, rule in rules.items():
        if not isinstance(field, str) or not field.strip() or field != field.strip():
            errors.append("policy feature names must be nonempty strings without surrounding whitespace")
        elif not isinstance(rule, dict) or set(rule) != {"baseline", "candidate", "reason"}:
            errors.append(f"{field}: rule must contain exactly baseline, candidate, reason")
        elif not isinstance(rule["reason"], str) or not rule["reason"].strip():
            errors.append(f"{field}: rule reason must be nonempty")
        elif json_issues(rule["baseline"]) or json_issues(rule["candidate"]):
            errors.append(f"{field}: rule contains an invalid JSON value")
        elif json_equal(rule["baseline"], rule["candidate"]):
            errors.append(f"{field}: rule must describe different values")
        else:
            valid[field] = rule
    return valid, errors


def compare_profiles(baseline: object, candidate: object, policy: object = None, *,
                     require_provenance: bool = False, manifest: object = None) -> dict:
    """Return a complete report, including failures for missing/invalid evidence."""
    old, baseline_issues = validate_capture(baseline, "baseline")
    new, candidate_issues = validate_capture(candidate, "candidate")
    rules, policy_errors = validate_policy(policy)
    report = {"schema_version": 1, "status": "insufficient_evidence", "exit_code": 2,
              "protocol": baseline.get("protocol") if isinstance(baseline, dict) else None,
              "scenario": baseline.get("scenario") if isinstance(baseline, dict) else None,
              "matched_fields": [], "known_differences": [],
              "differences": [], "missing_fields": [],
              "unverified": baseline_issues + candidate_issues, "policy_errors": policy_errors}
    if (isinstance(baseline, dict) and isinstance(candidate, dict)
            and baseline.get("protocol") != candidate.get("protocol")):
        report["unverified"].append({"field": "protocol", "reason": "baseline and candidate protocols differ"})
    if (isinstance(baseline, dict) and isinstance(candidate, dict)
            and baseline.get("scenario") != candidate.get("scenario")):
        report["unverified"].append({"field": "scenario", "reason": "baseline and candidate scenarios differ"})
    if require_provenance or manifest is not None:
        source = baseline.get("source") if isinstance(baseline, dict) else None
        if manifest is not None:
            manifest_source = manifest.get("source") if isinstance(manifest, dict) else None
            if source is not None and not json_equal(source, manifest_source):
                report["unverified"].append({"field": "baseline.source", "reason": "manifest and embedded source metadata differ"})
            source = manifest_source
        report["unverified"].extend(validate_source(source))
    fields = old.keys() | new.keys()
    for field in sorted(rules.keys() - fields):
        report["policy_errors"].append(f"{field}: policy refers to an uncaptured feature")
    for field in sorted(fields):
        if field not in old or field not in new:
            report["missing_fields"].append({"field": field, "missing_from": "baseline" if field not in old else "candidate"})
            continue
        if json_equal(old[field], new[field]):
            report["matched_fields"].append(field)
            if field in rules:
                report["policy_errors"].append(f"{field}: stale policy rule; captured values now match")
            continue
        difference = {"field": field, "baseline": old[field], "candidate": new[field],
                      "changed_paths": changed_paths(old[field], new[field])}
        rule = rules.get(field)
        if rule and json_equal(rule["baseline"], old[field]) and json_equal(rule["candidate"], new[field]):
            difference["reason"] = rule["reason"]
            report["known_differences"].append(difference)
        else:
            difference["reason"] = "policy value pair changed" if rule else "difference is not allowlisted"
            report["differences"].append(difference)
    if report["unverified"] or report["missing_fields"]:
        status = "insufficient_evidence"
    elif report["differences"] or report["policy_errors"]:
        status = "regression"
    elif report["known_differences"]:
        status = "known_differences"
    else:
        status = "matched"
    report.update(status=status, exit_code=EXIT_CODES[status])
    return report


def print_report(report: dict) -> None:
    print(f"{report['status']}: {len(report['matched_fields'])} matched, "
          f"{len(report['known_differences'])} known differences, "
          f"{len(report['differences'])} regressions, "
          f"{len(report['missing_fields'])} missing, {len(report['unverified'])} unverified")
    for label, key in (("matched", "matched_fields"), ("known", "known_differences"),
                       ("different", "differences"), ("missing", "missing_fields"),
                       ("unverified", "unverified")):
        for item in report[key]:
            if isinstance(item, str):
                print(f"  {label}: {item}")
            else:
                detail = item.get("reason", "missing from " + item.get("missing_from", ""))
                print(f"  {label}: {item['field']} ({detail})")
    for error in report["policy_errors"]:
        print(f"  policy error: {error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="captured Chrome profile JSON")
    parser.add_argument("--candidate", type=Path, required=True, help="captured Moto profile JSON")
    parser.add_argument("--policy", type=Path, help="exact known-difference policy JSON")
    parser.add_argument("--json-output", type=Path, help="write the complete comparison report")
    parser.add_argument("--require-provenance", action="store_true", help="validate baseline source metadata")
    parser.add_argument("--manifest", type=Path, help="baseline manifest JSON containing a source object")
    args = parser.parse_args(argv)
    loaded = {}
    failures = []
    for role in ("baseline", "candidate", "policy", "manifest"):
        path = getattr(args, role)
        if path is None:
            loaded[role] = None
            continue
        try:
            loaded[role] = load_json(path)
            if role in ("policy", "manifest") and loaded[role] is None:
                raise ValueError("explicit policy or manifest cannot be null")
        except (OSError, UnicodeError, ValueError) as exc:
            loaded[role] = None
            failures.append({"field": role, "reason": f"could not read valid JSON: {type(exc).__name__}"})
    report = compare_profiles(loaded["baseline"], loaded["candidate"], loaded["policy"],
                              require_provenance=args.require_provenance, manifest=loaded["manifest"])
    if failures:
        report["unverified"].extend(failures)
        report.update(status="insufficient_evidence", exit_code=2)
    if args.json_output:
        inputs = (args.baseline, args.candidate, args.policy, args.manifest)
        if any(path is not None and path.resolve() == args.json_output.resolve() for path in inputs):
            print("refusing to overwrite an input with --json-output", file=sys.stderr)
            return 2
        try:
            args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"could not write JSON report: {type(exc).__name__}", file=sys.stderr)
            return 2
    print_report(report)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
