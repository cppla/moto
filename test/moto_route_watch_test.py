#!/usr/bin/env python3

"""Focused tests for moto-route-watch.py without third-party dependencies."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("moto-route-watch.py")
SPEC = importlib.util.spec_from_file_location("moto_route_watch", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
WATCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WATCH
SPEC.loader.exec_module(WATCH)


def metrics_body(
    *,
    h3_active: int = 2,
    h3_upload: int = 0,
    h3_download: int = 0,
    h2_active: int = 1,
    h2_upload: int = 0,
    h2_download: int = 0,
) -> str:
    return f"""
# HELP {WATCH.ACTIVE_METRIC} Active tunnels.
# TYPE {WATCH.ACTIVE_METRIC} gauge
{WATCH.ACTIVE_METRIC}{{rule="mixed",target="h3.example:443",protocol="h3"}} {h3_active}
{WATCH.ACTIVE_METRIC}{{rule="mixed",target="h2.example:443",protocol="h2"}} {h2_active}
# HELP {WATCH.PAYLOAD_METRIC} Payload bytes.
# TYPE {WATCH.PAYLOAD_METRIC} counter
{WATCH.PAYLOAD_METRIC}{{rule="mixed",target="h3.example:443",protocol="h3",direction="client_to_target"}} {h3_upload}
{WATCH.PAYLOAD_METRIC}{{rule="mixed",target="h3.example:443",protocol="h3",direction="target_to_client"}} {h3_download}
{WATCH.PAYLOAD_METRIC}{{rule="mixed",target="h2.example:443",protocol="h2",direction="client_to_target"}} {h2_upload}
{WATCH.PAYLOAD_METRIC}{{rule="mixed",target="h2.example:443",protocol="h2",direction="target_to_client"}} {h2_download}
# HELP {WATCH.LAST_SUCCESS_METRIC} Last success.
# TYPE {WATCH.LAST_SUCCESS_METRIC} gauge
{WATCH.LAST_SUCCESS_METRIC}{{rule="mixed",target="h3.example:443",protocol="h3"}} 100
{WATCH.LAST_SUCCESS_METRIC}{{rule="mixed",target="h2.example:443",protocol="h2"}} 90
"""


def h3_health_body(
    *,
    target: str = "h3.example:443",
    rotation_promoted: int = 0,
    rule_opened: int = 0,
    target_cooldown: int = 0,
    rule_cooldown: int = 0,
    serving_loss: float = 0.01,
) -> str:
    transport_samples = {
        "moto_connect_proxy_h3_transports": (1, 1),
        "moto_connect_proxy_h3_active_tunnels": (2, 5),
        "moto_connect_proxy_h3_smoothed_rtt_seconds": (0.10, 1.0),
        "moto_connect_proxy_h3_baseline_rtt_seconds": (0.05, 0.04),
        "moto_connect_proxy_h3_loss_ratio": (serving_loss, 0.50),
        "moto_connect_proxy_h3_blocked_writes": (0, 10),
        "moto_connect_proxy_h3_oldest_blocked_write_seconds": (0, 8),
        "moto_connect_proxy_h3_payload_bytes_per_second": (50000, 100),
        "moto_connect_proxy_h3_healthy_payload_bytes_per_second": (60000, 50000),
    }
    lines = []
    for metric, (serving, draining) in transport_samples.items():
        lines.extend(
            [
                f"# TYPE {metric} gauge",
                f'{metric}{{target="{target}",state="serving",health="healthy"}} {serving}',
                f'{metric}{{target="{target}",state="draining",health="degraded"}} {draining}',
            ]
        )
    target_samples = {
        "moto_connect_proxy_h3_degradation_strikes": 1,
        "moto_connect_proxy_h3_protocol_penalty_seconds": 2,
        "moto_connect_proxy_h3_cooldown_active": target_cooldown,
        "moto_connect_proxy_h3_cooldown_remaining_seconds": 45 if target_cooldown else 0,
        "moto_connect_proxy_h3_half_open": 0,
        "moto_connect_proxy_h3_boost_canary_in_flight": 0,
        "moto_connect_proxy_h3_fallback_pending": 0,
    }
    for metric, value in target_samples.items():
        lines.extend([f"# TYPE {metric} gauge", f'{metric}{{target="{target}"}} {value}'])
    rule_samples = {
        "moto_connect_proxy_h3_rule_cooldown_active": rule_cooldown,
        "moto_connect_proxy_h3_rule_cooldown_remaining_seconds": 120 if rule_cooldown else 0,
        "moto_connect_proxy_h3_rule_fallback_validation_active": 0,
        "moto_connect_proxy_h3_rule_probe_due": 0,
        "moto_connect_proxy_h3_rule_probe_in_flight": 0,
        "moto_connect_proxy_h3_rule_probation_active": 0,
        "moto_connect_proxy_h3_rule_probation_healthy_samples": 0,
        "moto_connect_proxy_h3_rule_probation_payload_bytes": 0,
        "moto_connect_proxy_h3_rule_probation_packets_sent": 0,
    }
    for metric, value in rule_samples.items():
        lines.extend([f"# TYPE {metric} gauge", f'{metric}{{rule="mixed"}} {value}'])
    lines.extend(
        [
            f"# TYPE {WATCH.H3_ROTATION_METRIC} gauge",
            f'{WATCH.H3_ROTATION_METRIC}{{target="{target}",reason="sustained_signals",outcome="promoted"}} {rotation_promoted}',
            f"# TYPE {WATCH.H3_RULE_EVENT_METRIC} gauge",
            f'{WATCH.H3_RULE_EVENT_METRIC}{{rule="mixed",outcome="opened"}} {rule_opened}',
        ]
    )
    return "\n".join(lines) + "\n"


def attempt_metrics_body(
    *,
    h3_attempts: int = 0,
    h3_successes: int = 0,
    h3_canceled: int = 0,
    h3_failures: int = 0,
    h3_last_attempt: int = 0,
    h2_attempts: int = 0,
    h2_successes: int = 0,
    h2_canceled: int = 0,
    h2_failures: int = 0,
    h2_last_attempt: int = 0,
    h2_circuit_open: int = 0,
    h3_consecutive_failures: int = 0,
    h2_consecutive_failures: int = 0,
) -> str:
    targets = {
        "h3.example:443": {
            "attempts": h3_attempts,
            "successes": h3_successes,
            "canceled": h3_canceled,
            "failures": h3_failures,
            "consecutive_failures": h3_consecutive_failures,
            "last_attempt": h3_last_attempt,
            "ewma": 0.12,
            "circuit_open": 0,
        },
        "h2.example:443": {
            "attempts": h2_attempts,
            "successes": h2_successes,
            "canceled": h2_canceled,
            "failures": h2_failures,
            "consecutive_failures": h2_consecutive_failures,
            "last_attempt": h2_last_attempt,
            "ewma": 0.18,
            "circuit_open": h2_circuit_open,
        },
    }
    lines = []
    for metric in WATCH.ROUTE_ATTEMPT_METRICS:
        lines.append(f"# TYPE {metric} gauge")
    for metric in WATCH.DIAL_ATTEMPT_METRICS:
        lines.append(f"# TYPE {metric} counter")
    for target, values in targets.items():
        labels = f'rule="mixed",mode="boost",target="{target}"'
        lines.extend(
            [
                f'moto_route_latency_ewma_seconds{{{labels}}} {values["ewma"]}',
                f'moto_route_observed{{{labels}}} 1',
                f'moto_route_consecutive_failures{{{labels}}} {values["consecutive_failures"]}',
                f'moto_route_circuit_open{{{labels}}} {values["circuit_open"]}',
                f'moto_route_half_open{{{labels}}} 0',
                f'moto_route_last_attempt_timestamp_seconds{{{labels}}} {values["last_attempt"]}',
                f'moto_active_health_unhealthy{{{labels}}} 0',
            ]
        )
        dial_labels = f'rule="mixed",target="{target}"'
        lines.extend(
            [
                f'moto_dial_attempts_total{{{dial_labels}}} {values["attempts"]}',
                f'moto_dial_success_total{{{dial_labels}}} {values["successes"]}',
                f'moto_dial_canceled_total{{{dial_labels}}} {values["canceled"]}',
                f'moto_dial_failures_total{{{dial_labels}}} {values["failures"]}',
            ]
        )
    return "\n".join(lines) + "\n"


def route(
    key: WATCH.RouteKey,
    rate: float,
    *,
    status: str = "transmitting",
    active: int = 1,
    share: float = 50.0,
) -> WATCH.RouteView:
    return WATCH.RouteView(
        key=key,
        active_tunnels=active,
        bytes_per_second=rate,
        upload_bytes_per_second=0.0,
        download_bytes_per_second=rate,
        other_bytes_per_second=0.0,
        last_success_timestamp_seconds=100.0,
        status=status,
        instant_bytes_per_second=rate,
        instant_download_bytes_per_second=rate,
        traffic_share_percent=share,
    )


class RouteWatchTest(unittest.TestCase):
    def test_build_view_selects_route_with_meaningful_payload_growth(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body(h3_upload=100, h3_download=200, h2_upload=50),
            monotonic_time=10.0,
            wall_time=1000.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(h3_upload=20100, h3_download=40200, h2_upload=50),
            monotonic_time=12.0,
            wall_time=1002.0,
        )

        view = WATCH.build_view(current, baseline, baseline)

        self.assertEqual(view.state, "transmitting")
        self.assertEqual(view.window_seconds, 2.0)
        self.assertIsNotNone(view.raw_dominant)
        assert view.raw_dominant is not None
        self.assertEqual(view.raw_dominant.key, ("mixed", "h3.example:443", "h3"))
        self.assertEqual(view.raw_dominant.upload_bytes_per_second, 10000.0)
        self.assertEqual(view.raw_dominant.download_bytes_per_second, 20000.0)
        self.assertEqual(view.raw_dominant.instant_bytes_per_second, 30000.0)
        self.assertAlmostEqual(view.raw_dominant.traffic_share_percent or 0.0, 100.0)

    def test_sub_threshold_bytes_are_trickle_not_transmission(self) -> None:
        baseline = WATCH.parse_metrics(metrics_body(), 1.0, 100.0)
        current = WATCH.parse_metrics(metrics_body(h3_download=1686), 3.0, 102.0)

        view = WATCH.build_view(current, baseline, baseline, min_rate=4096.0)

        self.assertEqual(view.state, "trickle")
        assert view.raw_dominant is not None
        self.assertEqual(view.raw_dominant.bytes_per_second, 843.0)
        self.assertEqual(view.raw_dominant.status, "trickle")

    def test_active_tunnels_without_growth_are_idle(self) -> None:
        baseline = WATCH.parse_metrics(metrics_body(), 1.0, 100.0)
        current = WATCH.parse_metrics(metrics_body(), 3.0, 102.0)

        view = WATCH.build_view(current, baseline, baseline)

        self.assertEqual(view.state, "idle")
        self.assertIsNotNone(view.raw_dominant)
        self.assertTrue(all(item.status == "idle" for item in view.routes))
        self.assertTrue(all(item.traffic_share_percent is None for item in view.routes))

    def test_average_and_instant_rates_use_distinct_baselines(self) -> None:
        average_baseline = WATCH.parse_metrics(metrics_body(), 0.0, 100.0)
        instant_baseline = WATCH.parse_metrics(metrics_body(h3_download=1000), 8.0, 108.0)
        current = WATCH.parse_metrics(metrics_body(h3_download=5000), 10.0, 110.0)

        view = WATCH.build_view(current, average_baseline, instant_baseline, min_rate=1000.0)

        assert view.raw_dominant is not None
        self.assertEqual(view.raw_dominant.bytes_per_second, 500.0)
        self.assertEqual(view.raw_dominant.instant_bytes_per_second, 2000.0)
        self.assertEqual(view.state, "transmitting")

    def test_observed_leader_follows_current_traffic_not_stale_average(self) -> None:
        average_baseline = WATCH.parse_metrics(metrics_body(), 0.0, 100.0)
        instant_baseline = WATCH.parse_metrics(
            metrics_body(h3_download=1000000),
            8.0,
            108.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(h3_download=1000000, h2_download=200000),
            10.0,
            110.0,
        )

        view = WATCH.build_view(
            current,
            average_baseline,
            instant_baseline,
            min_rate=4096.0,
        )

        assert view.raw_dominant is not None
        self.assertEqual(view.raw_dominant.key[2], "h2")
        self.assertEqual(view.raw_dominant.instant_bytes_per_second, 100000.0)
        routes = {item.key[2]: item for item in view.routes}
        self.assertEqual(routes["h3"].status, "recent_activity")
        self.assertEqual(routes["h3"].instant_bytes_per_second, 0.0)

        tracker = WATCH.DominantTracker(selected=routes["h3"].key)
        decision = WATCH.select_dominant(tracker, view, 10.0, 3, 1.5, 0.0)
        self.assertEqual(decision.pending, routes["h2"].key)
        self.assertEqual(decision.pending_samples, 1)

    def test_traffic_share_uses_real_average_payload(self) -> None:
        baseline = WATCH.parse_metrics(metrics_body(), 0.0, 100.0)
        current = WATCH.parse_metrics(
            metrics_body(h3_download=75000, h2_download=25000),
            10.0,
            110.0,
        )

        view = WATCH.build_view(current, baseline, baseline, min_rate=0.0)
        shares = {item.key[2]: item.traffic_share_percent for item in view.routes}

        self.assertAlmostEqual(shares["h3"] or 0.0, 75.0)
        self.assertAlmostEqual(shares["h2"] or 0.0, 25.0)

    def test_counter_reset_never_produces_negative_rate(self) -> None:
        self.assertEqual(WATCH.counter_rate(20.0, 100.0, 2.0), 10.0)
        self.assertEqual(WATCH.counter_delta(20.0, 100.0), 20.0)

    def test_subsecond_window_is_not_rendered_as_zero(self) -> None:
        self.assertEqual(WATCH.format_seconds(0.1), "0.1s")

    def test_switch_ratio_rejects_values_below_one(self) -> None:
        with self.assertRaises(WATCH.argparse.ArgumentTypeError):
            WATCH.ratio_float("0.9")

    def test_main_route_requires_three_qualified_samples_to_switch(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        selected = route(h3, 100.0, share=25.0)
        candidate = route(h2, 300.0, share=75.0)
        view = WATCH.WatchView("transmitting", candidate, [candidate, selected], 10.0, 2.0)
        tracker = WATCH.DominantTracker(selected=h3)

        first = WATCH.select_dominant(tracker, view, 10.0, 3, 1.5, 0.0)
        second = WATCH.select_dominant(tracker, view, 12.0, 3, 1.5, 0.0)
        third = WATCH.select_dominant(tracker, view, 14.0, 3, 1.5, 0.0)

        self.assertEqual(first.pending_samples, 1)
        self.assertEqual(second.pending_samples, 2)
        self.assertEqual(first.dominant.key, h3)
        self.assertEqual(third.transition, (h3, h2))
        self.assertEqual(third.dominant.key, h2)

    def test_collecting_sample_does_not_seed_a_guessed_main_route(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        guessed = route(h3, 0.0, status="collecting", active=20)
        tracker = WATCH.DominantTracker()

        collecting = WATCH.WatchView("collecting", guessed, [guessed], 0.0, 0.0)
        first = WATCH.select_dominant(tracker, collecting, 1.0, 3, 1.5, 10.0)

        self.assertEqual(first.dominant.key, h3)
        self.assertIsNone(tracker.selected)

        actual = route(h2, 10000.0)
        transmitting = WATCH.WatchView("transmitting", actual, [actual], 2.0, 2.0)
        second = WATCH.select_dominant(tracker, transmitting, 3.0, 3, 1.5, 10.0)

        self.assertEqual(second.dominant.key, h2)
        self.assertEqual(tracker.selected, h2)
        self.assertIsNone(second.transition)

    def test_trickle_traffic_never_moves_confirmed_route(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        selected = route(h3, 100.0, status="trickle")
        observed = route(h2, 843.0, status="trickle")
        view = WATCH.WatchView("trickle", observed, [observed, selected], 10.0, 2.0)
        tracker = WATCH.DominantTracker(selected=h3)

        decision = WATCH.select_dominant(tracker, view, 10.0, 3, 1.5, 0.0)

        self.assertEqual(decision.dominant.key, h3)
        self.assertIsNone(decision.pending)
        self.assertIsNone(decision.transition)

    def test_inactive_confirmed_route_switches_immediately(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        observed = route(h2, 10000.0)
        view = WATCH.WatchView("transmitting", observed, [observed], 10.0, 2.0)
        tracker = WATCH.DominantTracker(selected=h3)

        decision = WATCH.select_dominant(tracker, view, 20.0, 3, 1.5, 10.0)

        self.assertEqual(decision.transition, (h3, h2))
        self.assertEqual(decision.dominant.key, h2)

    def test_inactive_route_does_not_report_switch_to_trickle(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        observed = route(h2, 843.0, status="trickle")
        view = WATCH.WatchView("trickle", observed, [observed], 10.0, 2.0)
        tracker = WATCH.DominantTracker(selected=h3)

        decision = WATCH.select_dominant(tracker, view, 20.0, 3, 1.5, 10.0)

        self.assertEqual(decision.dominant.key, h2)
        self.assertIsNone(decision.transition)

    def test_switch_cooldown_prevents_immediate_route_flap(self) -> None:
        h3 = ("mixed", "h3.example:443", "h3")
        h2 = ("mixed", "h2.example:443", "h2")
        selected = route(h2, 100.0)
        candidate = route(h3, 300.0)
        view = WATCH.WatchView("transmitting", candidate, [candidate, selected], 10.0, 2.0)
        tracker = WATCH.DominantTracker(selected=h2, last_switch_monotonic=20.0)

        decision = WATCH.select_dominant(tracker, view, 25.0, 3, 1.5, 10.0)

        self.assertEqual(decision.dominant.key, h2)
        self.assertIsNone(decision.pending)

    def test_h3_serving_health_is_not_polluted_by_degraded_draining_slot(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body() + h3_health_body(rotation_promoted=4, rule_opened=1),
            10.0,
            100.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(h3_download=20000)
            + h3_health_body(rotation_promoted=5, rule_opened=2),
            12.0,
            102.0,
        )

        view = WATCH.build_view(current, baseline, baseline, min_rate=0.0)
        assert view.raw_dominant is not None
        health = view.raw_dominant.h3_health
        assert health is not None

        self.assertEqual(health.status, "healthy")
        self.assertEqual(health.transport_health, "healthy")
        self.assertEqual(health.smoothed_rtt_seconds, 0.10)
        self.assertEqual(health.loss_ratio, 0.01)
        self.assertEqual(health.blocked_writes, 0)
        self.assertEqual(health.transport_states, {"draining": 1, "serving": 1})
        self.assertEqual(health.degraded_draining_tunnels, 5)
        self.assertEqual(len(health.transport_groups), 2)
        self.assertEqual(health.rotation_events, 1)
        self.assertEqual(health.rule_breaker_events, 1)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.print_h3_health(health, color=False)
        self.assertIn("5 条退化隧道仍在排空", output.getvalue())

        selection = WATCH.DominantSelection(view.raw_dominant, None, None, 0)
        snapshot = WATCH.snapshot_dict(
            "http://127.0.0.1:9090/metrics",
            current,
            view,
            selection,
            4096.0,
            10.0,
            3,
        )
        self.assertEqual(
            snapshot["h3_events_since_last_scrape"]["targets"]["h3.example:443"]["count"],
            1,
        )
        self.assertEqual(
            snapshot["h3_events_since_last_scrape"]["rules"]["mixed"]["count"],
            1,
        )
        self.assertNotIn("rotation_events_since_last_scrape", snapshot["dominant"]["h3_health"])

    def test_h3_events_survive_after_all_visible_routes_close(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body(h3_active=0, h2_active=0)
            + h3_health_body(rotation_promoted=7, rule_opened=3),
            10.0,
            100.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(h3_active=0, h2_active=0)
            + h3_health_body(rotation_promoted=8, rule_opened=4),
            12.0,
            102.0,
        )

        view = WATCH.build_view(current, baseline, baseline, min_rate=0.0)
        self.assertEqual(view.routes, [])
        selection = WATCH.DominantSelection(None, None, None, 0)
        snapshot = WATCH.snapshot_dict(
            "http://127.0.0.1:9090/metrics",
            current,
            view,
            selection,
            4096.0,
            10.0,
            3,
        )

        self.assertEqual(
            snapshot["h3_events_since_last_scrape"]["targets"]["h3.example:443"],
            {
                "count": 1,
                "details": {"sustained_signals/promoted": 1},
            },
        )
        self.assertEqual(
            snapshot["h3_events_since_last_scrape"]["rules"]["mixed"],
            {"count": 1, "details": {"opened": 1}},
        )

    def test_h2_route_explains_h3_target_and_rule_cooldown(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body(h3_active=0) + h3_health_body(target="h2.example:443"),
            10.0,
            100.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(h3_active=0, h2_download=20000)
            + h3_health_body(
                target="h2.example:443",
                target_cooldown=1,
                rule_cooldown=1,
            ),
            12.0,
            102.0,
        )

        view = WATCH.build_view(current, baseline, baseline, min_rate=0.0)
        assert view.raw_dominant is not None
        health = view.raw_dominant.h3_health
        assert health is not None

        self.assertEqual(view.raw_dominant.key[2], "h2")
        self.assertEqual(health.status, "cooldown")
        self.assertTrue(health.cooldown_active)
        self.assertTrue(health.rule_cooldown_active)

    def test_zero_loss_does_not_claim_the_sample_was_sufficient(self) -> None:
        sample = WATCH.parse_metrics(
            metrics_body() + h3_health_body(serving_loss=0.0),
            10.0,
            100.0,
        )
        health = WATCH.aggregate_h3_health(
            sample,
            None,
            "h3.example:443",
            "mixed",
            "h3",
        )
        assert health is not None
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.print_h3_health(health, color=False)

        self.assertIn("丢包 未见（样本量可能不足）", output.getvalue())

    def test_optional_h3_metrics_can_be_absent(self) -> None:
        sample = WATCH.parse_metrics(metrics_body(), 1.0, 100.0)
        view = WATCH.build_view(sample, None)

        self.assertTrue(all(item.h3_health is None for item in view.routes))

    def test_recent_attempt_window_uses_existing_route_and_dial_metrics(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body()
            + attempt_metrics_body(
                h3_attempts=10,
                h3_successes=7,
                h3_canceled=2,
                h3_failures=1,
                h3_last_attempt=100,
                h2_attempts=5,
                h2_successes=3,
                h2_canceled=1,
                h2_failures=1,
                h2_last_attempt=90,
            ),
            10.0,
            100.0,
        )
        current = WATCH.parse_metrics(
            metrics_body()
            + attempt_metrics_body(
                h3_attempts=14,
                h3_successes=10,
                h3_canceled=3,
                h3_failures=1,
                h3_last_attempt=218,
                h2_attempts=7,
                h2_successes=4,
                h2_canceled=1,
                h2_failures=2,
                h2_last_attempt=200,
                h2_circuit_open=1,
            ),
            130.0,
            220.0,
        )

        attempts = WATCH.build_attempt_window(current, baseline)
        by_target = {target.target: target for target in attempts.targets}

        self.assertTrue(attempts.supported)
        self.assertEqual(attempts.window_seconds, 120.0)
        self.assertEqual(attempts.attempted_targets, 2)
        self.assertEqual(by_target["h3.example:443"].attempts, 4)
        self.assertEqual(by_target["h3.example:443"].successes, 3)
        self.assertEqual(by_target["h3.example:443"].canceled, 1)
        self.assertEqual(by_target["h3.example:443"].failures, 0)
        self.assertEqual(by_target["h3.example:443"].latency_ewma_seconds, 0.12)
        self.assertEqual(by_target["h3.example:443"].status, "healthy")
        self.assertEqual(by_target["h2.example:443"].status, "circuit_open")

    def test_failed_target_is_kept_even_without_a_successful_tunnel_series(self) -> None:
        def failed_target_body(attempts: int, failures: int, last_attempt: int) -> str:
            route_labels = 'rule="mixed",mode="boost",target="failed.example:443"'
            dial_labels = 'rule="mixed",target="failed.example:443"'
            return "\n".join(
                [
                    f'moto_route_observed{{{route_labels}}} 1',
                    f'moto_route_consecutive_failures{{{route_labels}}} {failures}',
                    f'moto_route_circuit_open{{{route_labels}}} 0',
                    f'moto_route_half_open{{{route_labels}}} 0',
                    f'moto_route_last_attempt_timestamp_seconds{{{route_labels}}} {last_attempt}',
                    f'moto_active_health_unhealthy{{{route_labels}}} 0',
                    f'moto_dial_attempts_total{{{dial_labels}}} {attempts}',
                    f'moto_dial_failures_total{{{dial_labels}}} {failures}',
                ]
            ) + "\n"

        baseline = WATCH.parse_metrics(
            metrics_body()
            + attempt_metrics_body()
            + failed_target_body(1, 1, 100),
            10.0,
            100.0,
        )
        current = WATCH.parse_metrics(
            metrics_body()
            + attempt_metrics_body()
            + failed_target_body(2, 2, 110),
            20.0,
            110.0,
        )

        attempts = WATCH.build_attempt_window(current, baseline)
        by_target = {target.target: target for target in attempts.targets}

        self.assertIn("failed.example:443", by_target)
        self.assertEqual(by_target["failed.example:443"].attempts, 1)
        self.assertEqual(by_target["failed.example:443"].failures, 1)
        self.assertEqual(by_target["failed.example:443"].status, "failing")

    def test_recent_attempt_metrics_are_optional_for_older_moto(self) -> None:
        sample = WATCH.parse_metrics(metrics_body(), 1.0, 100.0)
        attempts = WATCH.build_attempt_window(sample, None)

        self.assertFalse(attempts.supported)
        self.assertEqual(attempts.targets, [])

    def test_human_output_separates_active_routes_from_attempt_evidence(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body() + attempt_metrics_body(h3_attempts=10, h3_successes=8),
            1.0,
            100.0,
        )
        current_sample = WATCH.parse_metrics(
            metrics_body(h3_download=20000)
            + attempt_metrics_body(
                h3_attempts=12,
                h3_successes=9,
                h3_canceled=1,
                h3_last_attempt=101,
            ),
            3.0,
            102.0,
        )
        view = WATCH.build_view(current_sample, baseline, baseline, min_rate=0.0)
        attempts = WATCH.build_attempt_window(current_sample, baseline)
        assert view.raw_dominant is not None
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.print_human(
                "http://127.0.0.1:9090/metrics",
                current_sample,
                view,
                WATCH.DominantSelection(view.raw_dominant, None, None, 0),
                10.0,
                3,
                attempts=attempts,
                attempt_window_target=120.0,
            )

        rendered = output.getvalue()
        self.assertIn("当前承载（活动隧道与 payload）", rendered)
        self.assertIn("最近目标尝试（参竞证据）", rendered)
        self.assertIn("成功”是目标尝试成功，不等于最终 Winner", rendered)
        self.assertIn("取消”可能是竞速落败或父请求取消", rendered)

    def test_current_route_highlights_requested_values_in_green(self) -> None:
        current = route(
            ("SOCKS5 to H3/H2", "2.example.com:443", "h3"),
            843.0,
            status="trickle",
            active=16,
            share=100.0,
        )
        view = WATCH.WatchView("trickle", current, [current], 10.0, 2.0)
        selection = WATCH.DominantSelection(current, None, None, 0)
        sample = WATCH.Sample(monotonic_time=1.0, wall_time=100.0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.print_human(
                "http://127.0.0.1:9090/metrics",
                sample,
                view,
                selection,
                10.0,
                3,
                color=True,
            )

        current_line = next(
            line for line in output.getvalue().splitlines() if line.startswith("当前主线路:")
        )
        self.assertIn("\033[32mH3  2.example.com:443\033[0m", current_line)
        self.assertIn("总速率 \033[32m843 B/s\033[0m", current_line)
        self.assertIn("活动隧道 \033[32m16\033[0m", current_line)
        self.assertIn("微量后台流量", output.getvalue())

    def test_json_v2_preserves_rate_alias_and_contains_no_ansi(self) -> None:
        current = route(("mixed", "h3.example:443", "h3"), 10000.0, share=100.0)
        view = WATCH.WatchView("transmitting", current, [current], 10.0, 2.0)
        selection = WATCH.DominantSelection(current, None, None, 0)
        sample = WATCH.Sample(monotonic_time=10.0, wall_time=100.0)

        encoded = json.dumps(
            WATCH.snapshot_dict(
                "http://127.0.0.1:9090/metrics",
                sample,
                view,
                selection,
                4096.0,
                10.0,
                3,
            ),
            ensure_ascii=False,
        )
        decoded = json.loads(encoded)

        self.assertEqual(decoded["schema_version"], 2)
        self.assertEqual(decoded["dominant"]["bytes_per_second"], 10000.0)
        self.assertEqual(decoded["dominant"]["average_bytes_per_second"], 10000.0)
        self.assertFalse(decoded["recent_target_attempts"]["available"])
        self.assertNotIn("\033", encoded)

    def test_json_v2_adds_recent_attempts_without_breaking_schema(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body() + attempt_metrics_body(h3_attempts=10, h3_successes=8),
            1.0,
            100.0,
        )
        current_sample = WATCH.parse_metrics(
            metrics_body()
            + attempt_metrics_body(
                h3_attempts=12,
                h3_successes=9,
                h3_canceled=1,
                h3_last_attempt=101,
            ),
            3.0,
            102.0,
        )
        view = WATCH.build_view(current_sample, baseline, baseline)
        attempts = WATCH.build_attempt_window(current_sample, baseline)
        assert view.raw_dominant is not None

        snapshot = WATCH.snapshot_dict(
            "http://127.0.0.1:9090/metrics",
            current_sample,
            view,
            WATCH.DominantSelection(view.raw_dominant, None, None, 0),
            4096.0,
            10.0,
            3,
            attempts,
            120.0,
        )

        self.assertEqual(snapshot["schema_version"], 2)
        recent = snapshot["recent_target_attempts"]
        self.assertTrue(recent["available"])
        self.assertEqual(recent["attempted_targets"], 1)
        targets = {target["target"]: target for target in recent["targets"]}
        self.assertEqual(targets["h3.example:443"]["attempts"], 2)
        self.assertEqual(targets["h3.example:443"]["successes"], 1)
        self.assertEqual(targets["h3.example:443"]["canceled"], 1)
        self.assertIn("does not prove", recent["semantics"]["success"])

    def test_json_error_uses_the_same_top_level_contract(self) -> None:
        args = WATCH.parse_args(["--json"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.emit_error(args, WATCH.WatchError("boom"), allow_clear=False)

        decoded = json.loads(output.getvalue())
        self.assertEqual(decoded["schema_version"], 2)
        self.assertEqual(decoded["state"], "error")
        self.assertIsNone(decoded["dominant"])
        self.assertIsNone(decoded["observed_leader"])
        self.assertEqual(decoded["routes"], [])
        self.assertEqual(decoded["aggregate"]["active_tunnels"], 0)
        self.assertFalse(decoded["recent_target_attempts"]["available"])

    def test_missing_required_metric_fails_clearly(self) -> None:
        body = metrics_body().replace(WATCH.LAST_SUCCESS_METRIC, "removed_metric")
        with self.assertRaisesRegex(WATCH.WatchError, WATCH.LAST_SUCCESS_METRIC):
            WATCH.parse_metrics(body, 1.0, 1.0)

    def test_prometheus_label_escapes_are_decoded(self) -> None:
        labels = WATCH.parse_labels(r'rule="line\nname",target="a\\b:443",protocol="h3"')
        self.assertEqual(labels["rule"], "line\nname")
        self.assertEqual(labels["target"], r"a\b:443")


if __name__ == "__main__":
    unittest.main()
