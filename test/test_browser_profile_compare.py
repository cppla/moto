#!/usr/bin/env python3
"""Offline tests for strict browser profile evidence and comparison policy."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("browser_profile_compare.py")
SPEC = importlib.util.spec_from_file_location("browser_profile_compare", SCRIPT)
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def capture(actor="chrome", protocol="h2", features=None):
    return {"schema_version": 1, "actor": actor, "protocol": protocol,
            "scenario": COMPARE.SCENARIO, "features": features if features is not None else {
                "tls.extension_ids": [0, 10, 13, 16, 43],
                "h2.settings": [{"id": 1, "value": 65536}, {"id": 4, "value": 6291456}]},
            "evidence": {"connect_received": True}}


def h2_success_capture(actor="chrome", scenario="h2_sni_reuse", challenges=None):
    result = capture(actor)
    result["scenario"] = scenario
    result["features"]["tls.server_name"] = COMPARE.H2_PROXY_SERVER_NAME
    result["features"].update({"tls.alpn": ["h2", "http/1.1"], "tls.cipher_suites": ["0x1301"],
                               "tls.key_share_groups": [{"group": "0x001d", "key_exchange_bytes": 32}],
                               "tls.signature_algorithms": ["0x0403"], "tls.supported_groups": ["0x001d"],
                               "tls.supported_versions": ["0x0304"], "h2.connection_window_increment": 15663105,
                               "connect.user_agent": "fixture-chrome-133", "connect.reused_physical_connection": True})
    result["evidence"].update(response_status=200, successful_tunnels=2, completed_payloads=2,
                              reused_physical_connection=True, server_name=COMPARE.H2_PROXY_SERVER_NAME,
                              client_payloads_verified=True, auth_required=scenario == "h2_auth_reuse",
                              auth_validated=0, auth_challenges=0)
    if scenario == "h2_auth_reuse":
        result["evidence"].update(auth_validated=2, auth_challenges=1 if actor == "chrome" else 0)
    if challenges is not None:
        result["evidence"]["auth_challenges"] = challenges
    requests = [{"connection_id": 1, "stream_id": index * 2 + 1, "method": "CONNECT",
                 "authority": "one.baseline.invalid:443", "auth": "none", "status": 407,
                 "payload_completed": False} for index in range(result["evidence"]["auth_challenges"])]
    for host, path in (("one.baseline.invalid", "/one"), ("two.baseline.invalid", "/two")):
        requests.append({"connection_id": 1, "stream_id": len(requests) * 2 + 1, "method": "CONNECT",
                         "authority": host + ":443", "auth": "valid" if scenario == "h2_auth_reuse" else "none",
                         "status": 200, "payload_completed": True, "origin_method": "GET", "origin_host": host,
                         "origin_path": path, "response_bytes": 117})
    result["evidence"]["requests"] = requests
    result["evidence"]["connections"] = [{"id": 1, "server_name": COMPARE.H2_PROXY_SERVER_NAME,
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


def policy(field="h2.settings", baseline=1, candidate=2):
    return {"schema_version": 1, "allowed_differences": {
        field: {"baseline": baseline, "candidate": candidate, "reason": "documented transport setting"}}}


def source():
    return {"browser_version": "141.0.7390.65", "platform": "mac-arm64",
            "executable_sha256": "a" * 64,
            "source_url": "https://storage.googleapis.com/chrome-for-testing-public/141.0.7390.65/mac-arm64/chrome-mac-arm64.zip",
            "captured_at": "2026-10-09T12:00:00+08:00", "flags": ["--headless=new"]}


class ComparisonTests(unittest.TestCase):
    def compare(self, baseline=None, candidate=None, **kwargs):
        return COMPARE.compare_profiles(capture() if baseline is None else baseline,
                                        capture("moto") if candidate is None else candidate, **kwargs)

    def test_identical_features_match_in_sorted_order(self):
        result = self.compare()
        self.assertEqual((result["status"], result["exit_code"]), ("matched", 0))
        self.assertEqual(result["matched_fields"], ["h2.settings", "tls.extension_ids"])

    def test_h3_profiles_are_supported(self):
        result = self.compare(capture(protocol="h3"), capture("moto", protocol="h3"))
        self.assertEqual(result["status"], "matched")

    def test_json_objects_ignore_key_order_but_preserve_array_order(self):
        old = capture(features={"data": {"one": 1, "two": [2, 3]}})
        new = capture("moto", features={"data": {"two": [2.0, 3], "one": 1.0}})
        self.assertEqual(self.compare(old, new)["status"], "matched")
        new["features"]["data"]["two"].reverse()
        result = self.compare(old, new)
        self.assertEqual(result["status"], "regression")
        self.assertEqual(result["differences"][0]["changed_paths"], ["/two/0", "/two/1"])

    def test_tls_extension_arrays_are_not_normalized(self):
        new = capture("moto")
        new["features"]["tls.extension_ids"].reverse()
        self.assertEqual(self.compare(candidate=new)["status"], "regression")

    def test_nested_changes_and_missing_nested_keys_are_reported(self):
        old = capture(features={"nested": {"a/b": [{"v": 1}, {"gone": True}]}})
        new = capture("moto", features={"nested": {"a/b": [{"v": 2}, {"new": True}]}})
        difference = self.compare(old, new)["differences"][0]
        self.assertEqual(difference["changed_paths"], ["/a~1b/0/v", "/a~1b/1/gone", "/a~1b/1/new"])
        self.assertEqual(difference["baseline"], old["features"]["nested"])

    def test_boolean_is_not_equal_to_json_number(self):
        for old, new in ((True, 1), (False, 0), ({"v": True}, {"v": 1}), ([True], [1])):
            with self.subTest(old=old, new=new):
                result = self.compare(capture(features={"v": old}), capture("moto", features={"v": new}))
                self.assertEqual(result["status"], "regression")

    def test_exact_known_difference_pair_passes_and_keeps_evidence(self):
        result = self.compare(capture(features={"h2.settings": 1}),
                              capture("moto", features={"h2.settings": 2}), policy=policy())
        self.assertEqual((result["status"], result["exit_code"]), ("known_differences", 0))
        self.assertEqual(result["known_differences"][0]["reason"], "documented transport setting")
        self.assertEqual(result["differences"], [])

    def test_policy_locks_both_values_including_nested_content(self):
        rule = policy("v", {"a": [1, 2]}, {"a": [3, 4]})
        for old, new in (({"a": [1, 9]}, {"a": [3, 4]}),
                         ({"a": [1, 2]}, {"a": [3, 9]}),
                         ({"a": [1, 2], "new": 7}, {"a": [3, 4]})):
            with self.subTest(old=old, new=new):
                result = self.compare(capture(features={"v": old}), capture("moto", features={"v": new}), policy=rule)
                self.assertEqual((result["status"], result["exit_code"]), ("regression", 1))
                self.assertEqual(result["differences"][0]["reason"], "policy value pair changed")

    def test_unallowlisted_difference_fails_alongside_known_difference(self):
        result = self.compare(capture(features={"h2.settings": 1, "new": "x"}),
                              capture("moto", features={"h2.settings": 2, "new": "y"}), policy=policy())
        self.assertEqual(result["status"], "regression")
        self.assertEqual(len(result["known_differences"]), 1)
        self.assertEqual(result["differences"][0]["field"], "new")

    def test_missing_feature_on_either_side_is_insufficient_evidence(self):
        for missing_from in ("baseline", "candidate"):
            with self.subTest(missing_from=missing_from):
                old, new = capture(), capture("moto")
                target = old if missing_from == "baseline" else new
                del target["features"]["h2.settings"]
                result = self.compare(old, new)
                self.assertEqual((result["status"], result["exit_code"]), ("insufficient_evidence", 2))
                self.assertEqual(result["missing_fields"], [{"field": "h2.settings", "missing_from": missing_from}])

    def test_missing_is_not_null(self):
        old, new = capture(), capture("moto")
        old["features"]["null_feature"] = None
        self.assertEqual(self.compare(old, new)["status"], "insufficient_evidence")
        new["features"]["null_feature"] = None
        self.assertEqual(self.compare(old, new)["status"], "matched")

    def test_policy_cannot_allow_missing_feature(self):
        result = self.compare(capture(features={"v": 1, "x": 4}), capture("moto", features={"x": 4}),
                              policy=policy("v", 1, None))
        self.assertEqual(result["status"], "insufficient_evidence")

    def test_empty_missing_or_invalid_features_cannot_pass(self):
        for features in ({}, [], None, {"": 1}, {" bad ": 1}, {"v": float("nan")}, {"v": float("inf")}):
            with self.subTest(features=features):
                old, new = capture(), capture("moto")
                old["features"] = new["features"] = features
                self.assertEqual(self.compare(old, new)["status"], "insufficient_evidence")
        self.assertEqual(COMPARE.compare_profiles(None, None)["status"], "insufficient_evidence")

    def test_spoofed_roles_invalid_schema_and_scenario_fail(self):
        for field, value in (("actor", "moto"), ("schema_version", True), ("schema_version", 2),
                             ("schema_version", 1.0), ("scenario", "other"), ("protocol", "h1")):
            with self.subTest(field=field, value=value):
                old = capture()
                old[field] = value
                self.assertEqual(self.compare(baseline=old)["status"], "insufficient_evidence")
        self.assertEqual(self.compare(candidate=capture())["status"], "insufficient_evidence")

    def test_protocols_must_match(self):
        result = self.compare(candidate=capture("moto", protocol="h3"))
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertTrue(any(issue["field"] == "protocol" for issue in result["unverified"]))

    def test_capture_must_confirm_connect_headers_as_boolean_true(self):
        for evidence in ({}, None, [], {"connect_received": False}, {"connect_received": 1}, {"connect_received": "true"}):
            with self.subTest(evidence=evidence):
                new = capture("moto")
                new["evidence"] = evidence
                self.assertEqual(self.compare(candidate=new)["status"], "insufficient_evidence")

    def test_insufficient_evidence_takes_precedence_over_regressions(self):
        new = capture("moto", features={"h2.settings": 9})
        result = self.compare(candidate=new)
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(len(result["differences"]), 1)

    def test_policy_unknown_top_level_or_rule_fields_fail(self):
        for extra in ("top", "rule"):
            with self.subTest(extra=extra):
                rule = policy()
                if extra == "top":
                    rule["ignore_all"] = True
                else:
                    rule["allowed_differences"]["h2.settings"]["ignore"] = True
                result = self.compare(capture(features={"h2.settings": 1}),
                                      capture("moto", features={"h2.settings": 2}), policy=rule)
                self.assertEqual(result["status"], "regression")
                self.assertTrue(result["policy_errors"])

    def test_invalid_policy_schema_and_values_fail(self):
        bad_policies = [[], {}, {"schema_version": True, "allowed_differences": {}},
                        {"schema_version": 1, "allowed_differences": []}, policy(baseline=1, candidate=1)]
        for reason in ("", " ", None):
            rule = policy()
            rule["allowed_differences"]["h2.settings"]["reason"] = reason
            bad_policies.append(rule)
        rule = policy()
        del rule["allowed_differences"]["h2.settings"]["baseline"]
        bad_policies.append(rule)
        for rule in bad_policies:
            with self.subTest(policy=rule):
                result = self.compare(policy=rule)
                self.assertEqual(result["status"], "regression")
                self.assertTrue(result["policy_errors"])

    def test_unknown_or_stale_policy_features_fail(self):
        for rule in (policy("does.not.exist"), policy()):
            with self.subTest(rule=rule):
                result = self.compare(policy=rule)
                self.assertEqual(result["status"], "regression")
                self.assertTrue(result["policy_errors"])

    def test_valid_embedded_or_external_provenance_passes(self):
        old = capture()
        old["source"] = source()
        self.assertEqual(self.compare(baseline=old, require_provenance=True)["status"], "matched")
        self.assertEqual(self.compare(require_provenance=True, manifest={"source": source()})["status"], "matched")
        self.assertEqual(self.compare(baseline=old, manifest={"source": source()})["status"], "matched")

    def test_provenance_required_only_when_requested(self):
        self.assertEqual(self.compare()["status"], "matched")
        self.assertEqual(self.compare(require_provenance=True)["status"], "insufficient_evidence")
        self.assertEqual(self.compare(manifest={})["status"], "insufficient_evidence")

    def test_invalid_source_metadata_cannot_pass(self):
        for key, value in (("browser_version", "latest"), ("browser_version", "141"),
                           ("platform", ""), ("executable_sha256", "a" * 63),
                           ("executable_sha256", "g" * 64), ("source_url", "http://example.test/chrome"),
                           ("source_url", "https://user:password@example.test/chrome"),
                           ("source_url", "https://"), ("captured_at", "2026-10-09"),
                           ("captured_at", "yesterday"), ("flags", "--headless"), ("flags", [""])):
            with self.subTest(key=key, value=value):
                old = capture()
                old["source"] = source()
                old["source"][key] = value
                result = self.compare(baseline=old, require_provenance=True)
                self.assertEqual(result["status"], "insufficient_evidence")
                self.assertIn("baseline.source." + key, [issue["field"] for issue in result["unverified"]])

    def test_manifest_cannot_conflict_with_embedded_provenance(self):
        old = capture()
        old["source"] = source()
        manifest = {"source": source()}
        manifest["source"]["browser_version"] = "141.0.7390.99"
        self.assertEqual(self.compare(baseline=old, manifest=manifest)["status"], "insufficient_evidence")


class H2SuccessComparisonTests(unittest.TestCase):
    def assert_insufficient(self, baseline, candidate, field):
        result = COMPARE.compare_profiles(baseline, candidate)
        self.assertEqual((result["status"], result["exit_code"]), ("insufficient_evidence", 2))
        self.assertIn(field, [issue["field"] for issue in result["unverified"]])
        return result

    def test_complete_success_scenarios_pass_with_accurate_scenario(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            with self.subTest(scenario=scenario):
                old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                rule = policy("auth.sequence", old["features"]["auth.sequence"], new["features"]["auth.sequence"]) if scenario == "h2_auth_reuse" else None
                result = COMPARE.compare_profiles(old, new, rule)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["status"], "known_differences" if rule else "matched")
                self.assertEqual(result["scenario"], scenario)

    def test_success_requires_all_server_evidence_even_when_features_match(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            for role in ("baseline", "candidate"):
                evidence = h2_success_capture(scenario=scenario)["evidence"]
                for field in evidence:
                    with self.subTest(scenario=scenario, role=role, missing=field):
                        old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                        del (old if role == "baseline" else new)["evidence"][field]
                        self.assert_insufficient(old, new, role + ".evidence." + field)

    def test_success_counts_require_exact_integers(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            for field, values in (("response_status", (502, 200.0, "200", True)),
                                  ("successful_tunnels", (0, 1, 3, 2.0, "2", True)),
                                  ("completed_payloads", (0, 1, 3, 2.0, "2", True))):
                for value in values:
                    with self.subTest(scenario=scenario, field=field, value=value):
                        old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                        new["evidence"][field] = value
                        self.assert_insufficient(old, new, "candidate.evidence." + field)

    def test_connect_headers_and_200_without_completed_payload_cannot_pass(self):
        old, new = h2_success_capture(), h2_success_capture("moto")
        new["evidence"]["completed_payloads"] = 0
        result = self.assert_insufficient(old, new, "candidate.evidence.completed_payloads")
        self.assertEqual(result["differences"], [])
        self.assertEqual(result["matched_fields"], sorted(old["features"]))

    def test_two_tunnels_without_physical_connection_reuse_cannot_pass(self):
        for value in (False, 1, "true", None):
            with self.subTest(value=value):
                old, new = h2_success_capture(), h2_success_capture("moto")
                new["evidence"]["reused_physical_connection"] = value
                self.assert_insufficient(old, new, "candidate.evidence.reused_physical_connection")

    def test_server_payloads_without_client_verification_cannot_pass(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            for value in (False, 1, "true", None):
                with self.subTest(scenario=scenario, value=value):
                    old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                    new["evidence"]["client_payloads_verified"] = value
                    self.assert_insufficient(old, new, "candidate.evidence.client_payloads_verified")

    def test_matching_wrong_or_missing_sni_cannot_pass(self):
        for value in ("", "localhost", "wrong.baseline.invalid", None):
            for location, key in (("evidence", "server_name"), ("features", "tls.server_name")):
                with self.subTest(value=value, location=location):
                    old, new = h2_success_capture(), h2_success_capture("moto")
                    for profile in (old, new):
                        if value is None:
                            del profile[location][key]
                        else:
                            profile[location][key] = value
                    self.assert_insufficient(old, new, "candidate." + location + "." + key)

    def test_success_scenarios_reject_h3_even_if_both_protocols_match(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            with self.subTest(scenario=scenario):
                old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                old["protocol"] = new["protocol"] = "h3"
                self.assert_insufficient(old, new, "candidate.protocol")

    def test_missing_unknown_and_mixed_scenarios_cannot_pass(self):
        for scenario in (None, "", "future_scenario", [], {}):
            with self.subTest(scenario=scenario):
                old, new = h2_success_capture(), h2_success_capture("moto")
                for profile in (old, new):
                    if scenario is None:
                        del profile["scenario"]
                    else:
                        profile["scenario"] = scenario
                self.assert_insufficient(old, new, "candidate.scenario")
        self.assert_insufficient(h2_success_capture(), h2_success_capture("moto", "h2_auth_reuse"), "scenario")
        self.assert_insufficient(capture(), h2_success_capture("moto"), "scenario")

    def test_auth_requirement_must_match_scenario_as_boolean(self):
        for scenario in COMPARE.H2_SUCCESS_SCENARIOS:
            for value in (None, "true", 0, 1, scenario != "h2_auth_reuse"):
                with self.subTest(scenario=scenario, value=value):
                    old, new = h2_success_capture(scenario=scenario), h2_success_capture("moto", scenario)
                    new["evidence"]["auth_required"] = value
                    self.assert_insufficient(old, new, "candidate.evidence.auth_required")

    def test_auth_success_requires_validated_credentials_for_both_tunnels(self):
        for value in (None, 0, 1, 3, 2.0, "2", True):
            with self.subTest(value=value):
                old, new = h2_success_capture(scenario="h2_auth_reuse"), h2_success_capture("moto", "h2_auth_reuse")
                new["evidence"]["auth_validated"] = value
                self.assert_insufficient(old, new, "candidate.evidence.auth_validated")

    def test_auth_challenges_preserve_actor_specific_behavior(self):
        for role, value in (("baseline", 0), ("baseline", 9), ("baseline", True),
                            ("candidate", 1), ("candidate", 0.0), ("candidate", False)):
            with self.subTest(role=role, value=value):
                old, new = h2_success_capture(scenario="h2_auth_reuse"), h2_success_capture("moto", "h2_auth_reuse")
                (old if role == "baseline" else new)["evidence"]["auth_challenges"] = value
                self.assert_insufficient(old, new, role + ".evidence.auth_challenges")

    def test_unauthenticated_scenario_requires_zero_auth_events(self):
        for field in ("auth_validated", "auth_challenges"):
            for value in (1, 2, 0.0, False, "0", None):
                with self.subTest(field=field, value=value):
                    old, new = h2_success_capture(), h2_success_capture("moto")
                    new["evidence"][field] = value
                    self.assert_insufficient(old, new, "candidate.evidence." + field)

    def test_auth_feature_difference_requires_its_exact_documented_pair(self):
        old, new = h2_success_capture(scenario="h2_auth_reuse"), h2_success_capture("moto", "h2_auth_reuse")
        old["features"]["auth.sequence"] = [{"credentials": "none", "status": 407},
                                              {"credentials": "valid", "status": 200},
                                              {"credentials": "valid", "status": 200}]
        new["features"]["auth.sequence"] = [{"credentials": "valid", "status": 200},
                                              {"credentials": "valid", "status": 200}]
        self.assertEqual(COMPARE.compare_profiles(old, new)["status"], "regression")
        rule = policy("auth.sequence", old["features"]["auth.sequence"], new["features"]["auth.sequence"])
        rule["allowed_differences"]["auth.sequence"]["reason"] = "Chrome challenges once; Moto sends credentials preemptively"
        result = COMPARE.compare_profiles(old, new, rule)
        self.assertEqual((result["status"], result["exit_code"]), ("known_differences", 0))
        self.assertEqual(result["known_differences"][0]["baseline"], old["features"]["auth.sequence"])
        self.assertEqual(result["known_differences"][0]["candidate"], new["features"]["auth.sequence"])
        rule["allowed_differences"]["auth.sequence"]["candidate"] = [{"credentials": "invalid", "status": 407}]
        result = COMPARE.compare_profiles(old, new, rule)
        self.assertEqual((result["status"], result["exit_code"]), ("regression", 1))
        self.assertEqual(result["differences"][0]["reason"], "policy value pair changed")

    def test_auth_policy_cannot_excuse_missing_completed_payloads(self):
        old, new = h2_success_capture(scenario="h2_auth_reuse"), h2_success_capture("moto", "h2_auth_reuse")
        old["features"]["auth.sequence"] = [{"credentials": "none", "status": 407},
                                              {"credentials": "valid", "status": 200},
                                              {"credentials": "valid", "status": 200}]
        new["features"]["auth.sequence"] = [{"credentials": "valid", "status": 200},
                                              {"credentials": "valid", "status": 200}]
        del new["evidence"]["completed_payloads"]
        result = COMPARE.compare_profiles(old, new, policy("auth.sequence", old["features"]["auth.sequence"],
                                                          new["features"]["auth.sequence"]))
        self.assertEqual((result["status"], result["exit_code"]), ("insufficient_evidence", 2))
        self.assertEqual(len(result["known_differences"]), 1)

    def test_multiple_initial_challenges_are_retained_under_exact_policy(self):
        for count in (1, 2, 8):
            with self.subTest(challenges=count):
                old = h2_success_capture(scenario="h2_auth_reuse", challenges=count)
                new = h2_success_capture("moto", "h2_auth_reuse")
                rule = policy("auth.sequence", old["features"]["auth.sequence"], new["features"]["auth.sequence"])
                result = COMPARE.compare_profiles(old, new, rule)
                self.assertEqual((result["status"], result["exit_code"]), ("known_differences", 0))
                self.assertEqual(len(result["known_differences"][0]["baseline"]), count + 2)

    def test_auth_count_cannot_disagree_with_the_request_sequence(self):
        old = h2_success_capture(scenario="h2_auth_reuse", challenges=2)
        old["evidence"]["auth_challenges"] = 1
        self.assert_insufficient(old, h2_success_capture("moto", "h2_auth_reuse"), "baseline.evidence.auth_challenges")

    def test_second_origin_challenge_or_challenge_after_success_cannot_pass(self):
        for change in ("second-origin-challenge", "challenge-after-success", "invalid-credentials"):
            with self.subTest(change=change):
                old = h2_success_capture(scenario="h2_auth_reuse", challenges=2)
                requests = old["evidence"]["requests"]
                if change == "second-origin-challenge":
                    requests[1]["authority"] = "two.baseline.invalid:443"
                    old["evidence"]["connections"][0]["wire_requests"][1]["authority"] = requests[1]["authority"]
                elif change == "challenge-after-success":
                    requests[1], requests[2] = requests[2], requests[1]
                else:
                    requests[0]["auth"] = "invalid"
                    old["evidence"]["connections"][0]["wire_requests"][0]["auth"] = "invalid"
                old["features"]["auth.sequence"] = [{"credentials": row["auth"], "status": row["status"]} for row in requests]
                self.assert_insufficient(old, h2_success_capture("moto", "h2_auth_reuse"), "baseline.evidence.requests")

    def test_request_must_bind_to_the_same_captured_connection_stream_and_authority(self):
        for field, value in (("connection_id", 2), ("connection_id", True), ("stream_id", 7),
                             ("stream_id", True), ("authority", "two.baseline.invalid:443"),
                             ("auth", "invalid")):
            with self.subTest(field=field, value=value):
                old, new = h2_success_capture(), h2_success_capture("moto")
                new["evidence"]["requests"][0][field] = value
                self.assert_insufficient(old, new, "candidate.evidence.requests")

    def test_successful_requests_on_different_connections_are_not_reuse(self):
        old, new = h2_success_capture(), h2_success_capture("moto")
        connection = new["evidence"]["connections"][0]
        new["evidence"]["connections"].append({**connection, "id": 2, "wire_requests": [connection["wire_requests"][1]]})
        connection["wire_requests"] = connection["wire_requests"][:1]
        new["evidence"]["requests"][1]["connection_id"] = 2
        self.assert_insufficient(old, new, "candidate.evidence.reused_physical_connection")

    def test_reused_stream_or_reversed_stream_order_cannot_pass(self):
        for streams in ((1, 1), (3, 1)):
            with self.subTest(streams=streams):
                old, new = h2_success_capture(), h2_success_capture("moto")
                for index, stream in enumerate(streams):
                    new["evidence"]["requests"][index]["stream_id"] = stream
                    new["evidence"]["connections"][0]["wire_requests"][index]["stream_id"] = stream
                result = COMPARE.compare_profiles(old, new)
                self.assertEqual((result["status"], result["exit_code"]), ("insufficient_evidence", 2))

    def test_actual_reused_connection_must_prove_sni_and_h2(self):
        for field, value in (("server_name", "wrong.invalid"), ("negotiated_protocol", "http/1.1"),
                             ("error", "TLS error"), ("wire_parse_error", "truncated capture")):
            with self.subTest(field=field):
                old, new = h2_success_capture(), h2_success_capture("moto")
                new["evidence"]["connections"][0][field] = value
                self.assert_insufficient(old, new, "candidate.evidence.connections")

    def test_origin_payload_evidence_must_identify_actual_bytes_and_target(self):
        for field, value in (("origin_method", "POST"), ("origin_host", "wrong.invalid"),
                             ("origin_path", "/wrong"), ("response_bytes", 0),
                             ("response_bytes", True), ("response_bytes", 117.0),
                             ("payload_completed", False), ("payload_completed", 1), ("error", "truncated")):
            with self.subTest(field=field, value=value):
                old, new = h2_success_capture(), h2_success_capture("moto")
                new["evidence"]["requests"][0][field] = value
                self.assert_insufficient(old, new, "candidate.evidence.requests")

    def test_denied_background_requests_are_retained_but_not_auth_sequence(self):
        for status, completed in ((403, False), (200, True), (403, True)):
            with self.subTest(status=status, completed=completed):
                old, new = h2_success_capture(), h2_success_capture("moto")
                background = {"connection_id": 2, "stream_id": 1, "method": "CONNECT",
                              "authority": "background.invalid:443", "auth": "none", "status": status,
                              "payload_completed": completed}
                new["evidence"]["requests"].insert(0, background)
                result = COMPARE.compare_profiles(old, new)
                self.assertEqual(result["status"], "matched" if status == 403 and not completed else "insufficient_evidence")

    def test_auth_sequence_feature_cannot_omit_a_captured_challenge(self):
        old = h2_success_capture(scenario="h2_auth_reuse", challenges=2)
        old["features"]["auth.sequence"] = old["features"]["auth.sequence"][1:]
        self.assert_insufficient(old, h2_success_capture("moto", "h2_auth_reuse"), "baseline.features.auth.sequence")

    def test_missing_actor_in_auth_capture_fails_without_raising(self):
        old = h2_success_capture(scenario="h2_auth_reuse")
        del old["actor"]
        self.assert_insufficient(old, h2_success_capture("moto", "h2_auth_reuse"), "baseline.actor")

    def test_every_required_success_feature_is_needed_even_if_both_sides_omit_it(self):
        self.assertEqual(len(COMPARE.H2_SUCCESS_REQUIRED_FEATURES), 17)
        for field in COMPARE.H2_SUCCESS_REQUIRED_FEATURES:
            with self.subTest(field=field):
                old, new = h2_success_capture(), h2_success_capture("moto")
                del old["features"][field]
                del new["features"][field]
                result = self.assert_insufficient(old, new, "candidate.features." + field)
                self.assertEqual(result["differences"], [])

    def test_success_list_features_cannot_be_present_but_empty_or_null(self):
        for field in COMPARE.H2_SUCCESS_LIST_FEATURES:
            for value in ([], None, "captured"):
                with self.subTest(field=field, value=value):
                    old, new = h2_success_capture(), h2_success_capture("moto")
                    old["features"][field] = new["features"][field] = value
                    self.assert_insufficient(old, new, "candidate.features." + field)

    def test_matching_features_cannot_hide_changed_successful_wire_headers_or_hpack(self):
        for index, name in enumerate(("first", "second")):
            for field in ("header_names", "hpack_representations"):
                with self.subTest(request=name, field=field):
                    old, new = h2_success_capture(), h2_success_capture("moto")
                    new["evidence"]["connections"][0]["wire_requests"][index][field] = ["different"]
                    self.assert_insufficient(old, new, f"candidate.features.connect.{name}.{field}")

    def test_both_successful_wire_user_agents_must_match_the_captured_feature(self):
        for index in (0, 1):
            with self.subTest(request=index):
                old, new = h2_success_capture(), h2_success_capture("moto")
                new["evidence"]["connections"][0]["wire_requests"][index]["user_agent"] = "changed-agent"
                self.assert_insufficient(old, new, "candidate.features.connect.user_agent")

    def test_success_reuse_feature_must_be_true_even_when_both_sides_match(self):
        for value in (False, 1, "true", None):
            with self.subTest(value=value):
                old, new = h2_success_capture(), h2_success_capture("moto")
                old["features"]["connect.reused_physical_connection"] = value
                new["features"]["connect.reused_physical_connection"] = value
                self.assert_insufficient(old, new, "candidate.features.connect.reused_physical_connection")

    def test_success_scenarios_still_compare_additional_opaque_features(self):
        old, new = h2_success_capture(), h2_success_capture("moto")
        old["features"]["additional.feature"] = {"nested": [1, 2]}
        new["features"]["additional.feature"] = {"nested": [1, 2]}
        self.assertEqual(COMPARE.compare_profiles(old, new)["status"], "matched")
        new["features"]["additional.feature"] = {"nested": [1, 3]}
        self.assertEqual(COMPARE.compare_profiles(old, new)["status"], "regression")
        rule = policy("additional.feature", {"nested": [1, 2]}, {"nested": [1, 3]})
        self.assertEqual(COMPARE.compare_profiles(old, new, rule)["status"], "known_differences")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="moto-browser-profile-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline = self.root / "baseline.json"
        self.candidate = self.root / "candidate.json"
        self.report = self.root / "report.json"
        self.baseline.write_text(json.dumps(capture()), encoding="utf-8")
        self.candidate.write_text(json.dumps(capture("moto")), encoding="utf-8")
        self.args = ["--baseline", str(self.baseline), "--candidate", str(self.candidate),
                     "--json-output", str(self.report)]

    def invoke(self, extra=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = COMPARE.main(self.args + (extra or []))
        return code, output.getvalue(), json.loads(self.report.read_text(encoding="utf-8"))

    def test_cli_writes_json_and_returns_matching_exit_codes(self):
        for status, features, evidence, expected in (
                ("matched", capture()["features"], True, 0),
                ("regression", {**capture()["features"], "h2.settings": 7}, True, 1),
                ("insufficient_evidence", capture()["features"], False, 2)):
            with self.subTest(status=status):
                new = capture("moto", features=features)
                new["evidence"]["connect_received"] = evidence
                self.candidate.write_text(json.dumps(new), encoding="utf-8")
                code, output, report = self.invoke()
                self.assertEqual((code, report["exit_code"]), (expected, expected))
                self.assertEqual(report["status"], status)
                self.assertTrue(output.startswith(status + ":"))

    def test_cli_known_difference_returns_zero(self):
        self.baseline.write_text(json.dumps(capture(features={"h2.settings": 1})), encoding="utf-8")
        self.candidate.write_text(json.dumps(capture("moto", features={"h2.settings": 2})), encoding="utf-8")
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy()), encoding="utf-8")
        code, output, report = self.invoke(["--policy", str(policy_path)])
        self.assertEqual((code, report["status"]), (0, "known_differences"))
        self.assertIn("known: h2.settings", output)

    def test_cli_malformed_missing_duplicate_and_nonfinite_input_fail_closed(self):
        for raw in ("{broken", '{"actor":"chrome","actor":"moto"}', '{"x":NaN}', '{"x":1e999}', "[]"):
            with self.subTest(raw=raw):
                self.baseline.write_text(raw, encoding="utf-8")
                code, _, report = self.invoke()
                self.assertEqual((code, report["status"]), (2, "insufficient_evidence"))
        self.baseline.unlink()
        self.assertEqual(self.invoke()[0], 2)

    def test_cli_unreadable_policy_or_manifest_cannot_disappear(self):
        for flag in ("--policy", "--manifest"):
            with self.subTest(flag=flag):
                code, _, report = self.invoke([flag, str(self.root / "missing.json")])
                self.assertEqual((code, report["status"]), (2, "insufficient_evidence"))

    def test_cli_explicit_null_policy_or_manifest_cannot_disappear(self):
        null_file = self.root / "null.json"
        null_file.write_text("null", encoding="utf-8")
        for flag in ("--policy", "--manifest"):
            with self.subTest(flag=flag):
                code, _, report = self.invoke([flag, str(null_file)])
                self.assertEqual((code, report["status"]), (2, "insufficient_evidence"))

    def test_cli_provenance_manifest_flag(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"source": source()}), encoding="utf-8")
        self.assertEqual(self.invoke(["--require-provenance"])[0], 2)
        self.assertEqual(self.invoke(["--require-provenance", "--manifest", str(manifest)])[0], 0)

    def test_cli_refuses_to_overwrite_input(self):
        original = self.baseline.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            code = COMPARE.main(self.args + ["--json-output", str(self.baseline)])
        self.assertEqual(code, 2)
        self.assertEqual(self.baseline.read_bytes(), original)

    def test_cli_reports_output_write_failure(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = COMPARE.main(self.args + ["--json-output", str(self.root / "absent" / "report.json")])
        self.assertEqual(code, 2)

    def test_actual_process_exit_and_summary(self):
        run = subprocess.run([sys.executable, str(SCRIPT), *self.args], capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("matched: 2 matched", run.stdout)
        self.candidate.write_text("{}", encoding="utf-8")
        run = subprocess.run([sys.executable, str(SCRIPT), *self.args], capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("insufficient_evidence", run.stdout)


if __name__ == "__main__":
    unittest.main()
