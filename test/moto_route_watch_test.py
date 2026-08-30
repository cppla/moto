#!/usr/bin/env python3

"""Focused tests for moto-route-watch.py without third-party dependencies."""

from __future__ import annotations

import contextlib
import importlib.util
import io
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


class RouteWatchTest(unittest.TestCase):
    def test_build_view_selects_route_with_real_payload_growth(self) -> None:
        baseline = WATCH.parse_metrics(
            metrics_body(h3_upload=100, h3_download=200, h2_upload=50),
            monotonic_time=10.0,
            wall_time=1000.0,
        )
        current = WATCH.parse_metrics(
            metrics_body(
                h3_upload=300,
                h3_download=600,
                h2_upload=50,
            ),
            monotonic_time=12.0,
            wall_time=1002.0,
        )

        state, dominant, routes, elapsed = WATCH.build_view(current, baseline)

        self.assertEqual(state, "transmitting")
        self.assertEqual(elapsed, 2.0)
        self.assertIsNotNone(dominant)
        assert dominant is not None
        self.assertEqual(dominant.key, ("mixed", "h3.example:443", "h3"))
        self.assertEqual(dominant.upload_bytes_per_second, 100.0)
        self.assertEqual(dominant.download_bytes_per_second, 200.0)
        self.assertEqual(dominant.bytes_per_second, 300.0)
        self.assertEqual(len(routes), 2)

    def test_active_tunnels_without_growth_are_idle(self) -> None:
        baseline = WATCH.parse_metrics(metrics_body(), 1.0, 100.0)
        current = WATCH.parse_metrics(metrics_body(), 3.0, 102.0)

        state, dominant, routes, _elapsed = WATCH.build_view(current, baseline)

        self.assertEqual(state, "idle")
        self.assertIsNotNone(dominant)
        self.assertTrue(all(route.status == "idle" for route in routes))

    def test_counter_reset_never_produces_negative_rate(self) -> None:
        self.assertEqual(WATCH.counter_rate(20.0, 100.0, 2.0), 10.0)

    def test_transmitting_route_change_emits_one_transition(self) -> None:
        previous = ("mixed", "h3.example:443", "h3")
        current = WATCH.RouteView(
            key=("mixed", "h2.example:443", "h2"),
            active_tunnels=1,
            bytes_per_second=100.0,
            upload_bytes_per_second=0.0,
            download_bytes_per_second=100.0,
            other_bytes_per_second=0.0,
            last_success_timestamp_seconds=100.0,
            status="transmitting",
        )

        transition, next_dominant = WATCH.select_transition(previous, "transmitting", current)

        self.assertEqual(transition, (previous, current.key))
        self.assertEqual(next_dominant, current.key)
        _transition, next_after_close = WATCH.select_transition(next_dominant, "no_active_tunnels", None)
        self.assertIsNone(next_after_close)

    def test_current_route_highlights_requested_values_in_green(self) -> None:
        route = WATCH.RouteView(
            key=("SOCKS5 to H3/H2", "2.example.com:443", "h3"),
            active_tunnels=16,
            bytes_per_second=843.0,
            upload_bytes_per_second=0.0,
            download_bytes_per_second=843.0,
            other_bytes_per_second=0.0,
            last_success_timestamp_seconds=100.0,
            status="transmitting",
        )
        sample = WATCH.Sample(monotonic_time=1.0, wall_time=100.0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            WATCH.print_human(
                "http://127.0.0.1:9090/metrics",
                sample,
                "transmitting",
                route,
                [route],
                2.0,
                None,
                color=True,
            )

        current_line = next(
            line for line in output.getvalue().splitlines() if line.startswith("当前主线路:")
        )
        self.assertIn("\033[32mH3  2.example.com:443\033[0m", current_line)
        self.assertIn("总速率 \033[32m843 B/s\033[0m", current_line)
        self.assertIn("活动隧道 \033[32m16\033[0m", current_line)

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
