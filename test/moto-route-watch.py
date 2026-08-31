#!/usr/bin/env python3

"""Observe Moto's active H2/H3 routes through its Prometheus metrics."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple


ACTIVE_METRIC = "moto_connect_proxy_active_tunnels"
PAYLOAD_METRIC = "moto_connect_proxy_payload_bytes_total"
LAST_SUCCESS_METRIC = "moto_connect_proxy_last_success_timestamp_seconds"
REQUIRED_METRICS = (ACTIVE_METRIC, PAYLOAD_METRIC, LAST_SUCCESS_METRIC)

H3_TRANSPORT_METRICS = {
    "moto_connect_proxy_h3_transports": "transports",
    "moto_connect_proxy_h3_active_tunnels": "active_tunnels",
    "moto_connect_proxy_h3_smoothed_rtt_seconds": "smoothed_rtt_seconds",
    "moto_connect_proxy_h3_baseline_rtt_seconds": "baseline_rtt_seconds",
    "moto_connect_proxy_h3_loss_ratio": "loss_ratio",
    "moto_connect_proxy_h3_blocked_writes": "blocked_writes",
    "moto_connect_proxy_h3_oldest_blocked_write_seconds": "oldest_blocked_write_seconds",
    "moto_connect_proxy_h3_payload_bytes_per_second": "payload_bytes_per_second",
    "moto_connect_proxy_h3_healthy_payload_bytes_per_second": "healthy_payload_bytes_per_second",
}
H3_TARGET_METRICS = {
    "moto_connect_proxy_h3_degradation_strikes": "degradation_strikes",
    "moto_connect_proxy_h3_protocol_penalty_seconds": "protocol_penalty_seconds",
    "moto_connect_proxy_h3_cooldown_active": "cooldown_active",
    "moto_connect_proxy_h3_cooldown_remaining_seconds": "cooldown_remaining_seconds",
    "moto_connect_proxy_h3_half_open": "half_open",
    "moto_connect_proxy_h3_boost_canary_in_flight": "boost_canary_in_flight",
    "moto_connect_proxy_h3_fallback_pending": "fallback_pending",
}
H3_RULE_METRICS = {
    "moto_connect_proxy_h3_rule_cooldown_active": "cooldown_active",
    "moto_connect_proxy_h3_rule_cooldown_remaining_seconds": "cooldown_remaining_seconds",
    "moto_connect_proxy_h3_rule_fallback_validation_active": "fallback_validation_active",
    "moto_connect_proxy_h3_rule_probe_due": "probe_due",
    "moto_connect_proxy_h3_rule_probe_in_flight": "probe_in_flight",
    "moto_connect_proxy_h3_rule_probation_active": "probation_active",
    "moto_connect_proxy_h3_rule_probation_healthy_samples": "probation_healthy_samples",
    "moto_connect_proxy_h3_rule_probation_payload_bytes": "probation_payload_bytes",
    "moto_connect_proxy_h3_rule_probation_packets_sent": "probation_packets_sent",
}
H3_ROTATION_METRIC = "moto_connect_proxy_h3_rotation_events"
H3_RULE_EVENT_METRIC = "moto_connect_proxy_h3_rule_breaker_events"
OPTIONAL_METRICS = tuple(
    list(H3_TRANSPORT_METRICS)
    + list(H3_TARGET_METRICS)
    + list(H3_RULE_METRICS)
    + [H3_ROTATION_METRIC, H3_RULE_EVENT_METRIC]
)
WATCHED_METRICS = REQUIRED_METRICS + OPTIONAL_METRICS

DEFAULT_MIN_RATE = 4 * 1024.0
DEFAULT_SWITCH_SAMPLES = 3
DEFAULT_SWITCH_RATIO = 1.5
DEFAULT_SWITCH_COOLDOWN = 10.0
MAX_METRICS_BYTES = 16 * 1024 * 1024

RouteKey = Tuple[str, str, str]
PayloadKey = Tuple[RouteKey, str]
RouteTransition = Tuple[RouteKey, RouteKey]
H3TransportKey = Tuple[str, str, str]
H3RotationKey = Tuple[str, str, str]
H3RuleEventKey = Tuple[str, str]


class WatchError(RuntimeError):
    pass


@dataclass
class Sample:
    monotonic_time: float
    wall_time: float
    active: Dict[RouteKey, float] = field(default_factory=dict)
    payload: Dict[PayloadKey, float] = field(default_factory=dict)
    last_success: Dict[RouteKey, float] = field(default_factory=dict)
    h3_transport: Dict[H3TransportKey, Dict[str, float]] = field(default_factory=dict)
    h3_target: Dict[str, Dict[str, float]] = field(default_factory=dict)
    h3_rule: Dict[str, Dict[str, float]] = field(default_factory=dict)
    h3_rotations: Dict[H3RotationKey, float] = field(default_factory=dict)
    h3_rule_events: Dict[H3RuleEventKey, float] = field(default_factory=dict)
    available_metrics: Set[str] = field(default_factory=set)


@dataclass
class H3HealthView:
    target: str
    status: str
    target_status: str
    rule_status: str
    transport_health: str
    transport_states: Dict[str, int]
    transport_groups: List[Dict[str, object]]
    transports: int
    active_tunnels: int
    degraded_draining_tunnels: int
    suspect_draining_tunnels: int
    smoothed_rtt_seconds: float
    baseline_rtt_seconds: float
    loss_ratio: float
    blocked_writes: int
    oldest_blocked_write_seconds: float
    payload_bytes_per_second: float
    healthy_payload_bytes_per_second: float
    degradation_strikes: int
    protocol_penalty_seconds: float
    cooldown_active: bool
    cooldown_remaining_seconds: float
    half_open: bool
    boost_canary_in_flight: bool
    fallback_pending: bool
    rule_cooldown_active: bool
    rule_cooldown_remaining_seconds: float
    rule_fallback_validation_active: bool
    rule_probe_due: bool
    rule_probe_in_flight: bool
    rule_probation_active: bool
    rule_probation_healthy_samples: int
    rule_probation_payload_bytes: int
    rule_probation_packets_sent: int
    rotation_events: int
    rotation_details: Dict[str, int]
    rule_breaker_events: int
    rule_breaker_details: Dict[str, int]
    signals_sampled: bool


@dataclass
class RouteView:
    key: RouteKey
    active_tunnels: int
    bytes_per_second: float
    upload_bytes_per_second: float
    download_bytes_per_second: float
    other_bytes_per_second: float
    last_success_timestamp_seconds: float
    status: str
    instant_bytes_per_second: float = 0.0
    instant_upload_bytes_per_second: float = 0.0
    instant_download_bytes_per_second: float = 0.0
    traffic_share_percent: Optional[float] = None
    h3_health: Optional[H3HealthView] = None


@dataclass
class WatchView:
    state: str
    raw_dominant: Optional[RouteView]
    routes: List[RouteView]
    window_seconds: float
    instant_seconds: float
    h3_target_events: Dict[str, Dict[str, int]] = field(default_factory=dict)
    h3_rule_events: Dict[str, Dict[str, int]] = field(default_factory=dict)


@dataclass
class DominantTracker:
    selected: Optional[RouteKey] = None
    candidate: Optional[RouteKey] = None
    candidate_samples: int = 0
    last_switch_monotonic: float = 0.0


@dataclass
class DominantSelection:
    dominant: Optional[RouteView]
    transition: Optional[RouteTransition]
    pending: Optional[RouteKey]
    pending_samples: int


METRIC_LINE_RE = re.compile(
    r"^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?$"
)
DECLARATION_RE = re.compile(r"^#\s+(?:HELP|TYPE)\s+([A-Za-z_:][A-Za-z0-9_:]*)\b")


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be a number: {value!r}") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be a number: {value!r}") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than or equal to zero")
    return parsed


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be an integer: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be an integer greater than zero")
    return parsed


def ratio_float(value: str) -> float:
    parsed = positive_float(value)
    if parsed < 1.0:
        raise argparse.ArgumentTypeError("must be greater than or equal to 1")
    return parsed


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="moto-route-watch.py",
        description=(
            "Observe Moto's current H2/H3 routes from its Prometheus metrics endpoint. "
            "The default mode refreshes continuously."
        ),
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("MOTO_METRICS_URL", "http://127.0.0.1:9090/metrics"),
        help="metrics URL (default: %(default)s; env: MOTO_METRICS_URL)",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=2.0,
        help="seconds between scrapes (default: %(default)s)",
    )
    parser.add_argument(
        "--window",
        type=positive_float,
        default=10.0,
        help="maximum byte-rate window in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=3.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--min-rate",
        type=non_negative_float,
        default=DEFAULT_MIN_RATE,
        help=(
            "minimum current-sample payload bytes/s considered real transmission; "
            "smaller rates are marked as trickle (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--switch-samples",
        type=positive_int,
        default=DEFAULT_SWITCH_SAMPLES,
        help="consecutive leading samples required before changing the main route (default: %(default)s)",
    )
    parser.add_argument(
        "--switch-ratio",
        type=ratio_float,
        default=DEFAULT_SWITCH_RATIO,
        help="candidate/current instant-rate ratio required for a route switch (default: %(default)s)",
    )
    parser.add_argument(
        "--switch-cooldown",
        type=non_negative_float,
        default=DEFAULT_SWITCH_COOLDOWN,
        help="minimum seconds between confirmed route switches (default: %(default)s)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="take two scrapes, print one measured snapshot, and exit",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON (one object per line in watch mode)",
    )
    parser.add_argument(
        "--no-clear",
        action="store_true",
        help="do not clear an interactive terminal between watch snapshots",
    )
    args = parser.parse_args(argv)
    if args.window < args.interval:
        parser.error("--window must be greater than or equal to --interval")
    return args


def decode_prometheus_escape(char: str) -> str:
    if char == "n":
        return "\n"
    if char in ('"', "\\"):
        return char
    # Prometheus only defines \\, \", and \n. Preserve unknown escapes so a
    # future exporter extension cannot silently change a route label.
    return "\\" + char


def parse_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    index = 0
    length = len(raw)
    while index < length:
        while index < length and raw[index].isspace():
            index += 1
        name_start = index
        while index < length and (raw[index].isalnum() or raw[index] in "_:"):
            index += 1
        name = raw[name_start:index]
        if not name:
            raise WatchError(f"invalid Prometheus label set: {raw!r}")
        while index < length and raw[index].isspace():
            index += 1
        if index >= length or raw[index] != "=":
            raise WatchError(f"invalid Prometheus label assignment: {raw!r}")
        index += 1
        while index < length and raw[index].isspace():
            index += 1
        if index >= length or raw[index] != '"':
            raise WatchError(f"invalid Prometheus label value: {raw!r}")
        index += 1
        value: List[str] = []
        while index < length:
            char = raw[index]
            index += 1
            if char == '"':
                break
            if char == "\\":
                if index >= length:
                    raise WatchError(f"unterminated Prometheus escape: {raw!r}")
                value.append(decode_prometheus_escape(raw[index]))
                index += 1
            else:
                value.append(char)
        else:
            raise WatchError(f"unterminated Prometheus label value: {raw!r}")
        labels[name] = "".join(value)
        while index < length and raw[index].isspace():
            index += 1
        if index == length:
            break
        if raw[index] != ",":
            raise WatchError(f"invalid Prometheus label separator: {raw!r}")
        index += 1
    return labels


def finite_metric_value(raw: str, metric: str) -> Optional[float]:
    try:
        value = float(raw)
    except ValueError as exc:
        raise WatchError(f"invalid value for {metric}: {raw!r}") from exc
    if not math.isfinite(value):
        return None
    return value


def route_key(labels: Mapping[str, str], metric: str) -> RouteKey:
    missing = [name for name in ("rule", "target", "protocol") if not labels.get(name)]
    if missing:
        raise WatchError(f"{metric} sample is missing labels: {', '.join(missing)}")
    return labels["rule"], labels["target"], labels["protocol"].lower()


def required_label(labels: Mapping[str, str], metric: str, name: str) -> str:
    value = labels.get(name, "")
    if not value:
        raise WatchError(f"{metric} sample is missing label: {name}")
    return value


def parse_metrics(body: str, monotonic_time: float, wall_time: float) -> Sample:
    declared: Set[str] = set()
    parsed_names: Set[str] = set()
    sample = Sample(monotonic_time=monotonic_time, wall_time=wall_time)

    for line_number, raw_line in enumerate(body.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        declaration = DECLARATION_RE.match(line)
        if declaration:
            declared.add(declaration.group(1))
            continue
        if line.startswith("#"):
            continue
        match = METRIC_LINE_RE.match(line)
        if not match:
            # Ignore unrelated exporter syntax, but never silently ignore a
            # malformed route or H3 health metric.
            if any(line.startswith(name) for name in WATCHED_METRICS):
                raise WatchError(f"invalid route metric at line {line_number}: {line!r}")
            continue
        metric, raw_labels, raw_value = match.groups()
        if metric not in WATCHED_METRICS:
            continue
        parsed_names.add(metric)
        labels = parse_labels(raw_labels or "")
        value = finite_metric_value(raw_value, metric)
        if value is None:
            continue
        value = max(0.0, value)

        if metric in REQUIRED_METRICS:
            key = route_key(labels, metric)
        if metric == ACTIVE_METRIC:
            sample.active[key] = sample.active.get(key, 0.0) + value
        elif metric == PAYLOAD_METRIC:
            direction = labels.get("direction", "")
            if not direction:
                raise WatchError(f"{PAYLOAD_METRIC} sample is missing label: direction")
            payload_key = key, direction
            sample.payload[payload_key] = sample.payload.get(payload_key, 0.0) + value
        elif metric == LAST_SUCCESS_METRIC:
            sample.last_success[key] = max(sample.last_success.get(key, 0.0), value)
        elif metric in H3_TRANSPORT_METRICS:
            transport_key = (
                required_label(labels, metric, "target"),
                required_label(labels, metric, "state"),
                required_label(labels, metric, "health"),
            )
            values = sample.h3_transport.setdefault(transport_key, {})
            values[H3_TRANSPORT_METRICS[metric]] = value
        elif metric in H3_TARGET_METRICS:
            target = required_label(labels, metric, "target")
            values = sample.h3_target.setdefault(target, {})
            values[H3_TARGET_METRICS[metric]] = value
        elif metric in H3_RULE_METRICS:
            rule = required_label(labels, metric, "rule")
            values = sample.h3_rule.setdefault(rule, {})
            values[H3_RULE_METRICS[metric]] = value
        elif metric == H3_ROTATION_METRIC:
            rotation_key = (
                required_label(labels, metric, "target"),
                required_label(labels, metric, "reason"),
                required_label(labels, metric, "outcome"),
            )
            sample.h3_rotations[rotation_key] = value
        elif metric == H3_RULE_EVENT_METRIC:
            event_key = (
                required_label(labels, metric, "rule"),
                required_label(labels, metric, "outcome"),
            )
            sample.h3_rule_events[event_key] = value

    available = declared | parsed_names
    missing_metrics = [name for name in REQUIRED_METRICS if name not in available]
    if missing_metrics:
        raise WatchError(
            "metrics endpoint does not expose the required Moto route metrics: "
            + ", ".join(missing_metrics)
            + "; update/restart Moto with route metrics enabled"
        )
    sample.available_metrics = available
    return sample


def fetch_sample(url: str, timeout: float) -> Sample:
    request = urllib.request.Request(
        url,
        headers={"Accept": "text/plain", "User-Agent": "moto-route-watch/1"},
    )
    started = time.monotonic()
    try:
        # Metrics normally lives on loopback. Bypass HTTP(S)_PROXY so a local
        # scrape cannot accidentally leave the host or fail in a desktop proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise WatchError(f"metrics endpoint returned HTTP {status}")
            raw_body = response.read(MAX_METRICS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise WatchError(f"metrics endpoint returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise WatchError(f"cannot reach metrics endpoint {url}: {reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise WatchError(f"cannot reach metrics endpoint {url}: {exc}") from exc
    if len(raw_body) > MAX_METRICS_BYTES:
        raise WatchError(f"metrics response exceeds {MAX_METRICS_BYTES // (1024 * 1024)} MiB")
    try:
        body = raw_body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WatchError("metrics response is not valid UTF-8") from exc
    return parse_metrics(body, started, time.time())


def counter_rate(current: float, previous: float, elapsed: float) -> float:
    if current >= previous:
        delta = current - previous
    else:
        # A Moto restart or counter reset occurred inside the observed window.
        delta = current
    return max(0.0, delta / elapsed)


def counter_delta(current: float, previous: float) -> float:
    if current >= previous:
        return current - previous
    return current


def payload_rates(current: Sample, baseline: Optional[Sample]) -> Tuple[Dict[PayloadKey, float], float]:
    if baseline is None:
        return {}, 0.0
    elapsed = current.monotonic_time - baseline.monotonic_time
    if elapsed <= 0:
        return {}, 0.0
    rates: Dict[PayloadKey, float] = {}
    for payload_key, current_value in current.payload.items():
        rates[payload_key] = counter_rate(
            current_value,
            baseline.payload.get(payload_key, 0.0),
            elapsed,
        )
    return rates, elapsed


def boolean_metric(values: Mapping[str, float], name: str) -> bool:
    return values.get(name, 0.0) >= 0.5


def h3_event_deltas(
    current: Sample,
    event_baseline: Optional[Sample],
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, Dict[str, int]]]:
    target_events: Dict[str, Dict[str, int]] = {}
    rule_events: Dict[str, Dict[str, int]] = {}
    if event_baseline is None:
        return target_events, rule_events
    for rotation_key, current_value in current.h3_rotations.items():
        target, reason, outcome = rotation_key
        delta = int(
            round(
                counter_delta(
                    current_value,
                    event_baseline.h3_rotations.get(rotation_key, 0.0),
                )
            )
        )
        if delta > 0:
            detail = f"{reason}/{outcome}"
            details = target_events.setdefault(target, {})
            details[detail] = details.get(detail, 0) + delta
    for event_key, current_value in current.h3_rule_events.items():
        rule, outcome = event_key
        delta = int(
            round(
                counter_delta(
                    current_value,
                    event_baseline.h3_rule_events.get(event_key, 0.0),
                )
            )
        )
        if delta > 0:
            details = rule_events.setdefault(rule, {})
            details[outcome] = details.get(outcome, 0) + delta
    return target_events, rule_events


def aggregate_h3_health(
    current: Sample,
    event_baseline: Optional[Sample],
    target: str,
    rule: str,
    protocol: str,
) -> Optional[H3HealthView]:
    groups = [
        (key, values)
        for key, values in current.h3_transport.items()
        if key[0] == target
    ]
    target_values = current.h3_target.get(target, {})
    rule_values = current.h3_rule.get(rule, {})
    optional_supported = any(metric in current.available_metrics for metric in OPTIONAL_METRICS)
    if (
        not groups
        and not target_values
        and not rule_values
        and (protocol != "h3" or not optional_supported)
    ):
        return None

    transport_states: Dict[str, int] = {}
    transport_groups: List[Dict[str, object]] = []
    transports = 0
    active_tunnels = 0
    degraded_draining_tunnels = 0
    suspect_draining_tunnels = 0
    for (_group_target, state, health), values in sorted(groups, key=lambda item: item[0]):
        count = max(0, int(round(values.get("transports", 0.0))))
        tunnels = max(0, int(round(values.get("active_tunnels", 0.0))))
        transports += count
        transport_states[state] = transport_states.get(state, 0) + count
        active_tunnels += tunnels
        if state == "draining" and health == "degraded":
            degraded_draining_tunnels += tunnels
        elif state == "draining" and health == "suspect":
            suspect_draining_tunnels += tunnels
        transport_groups.append(
            {
                "state": state,
                "health": health,
                "transports": count,
                "active_tunnels": tunnels,
                "smoothed_rtt_seconds": values.get("smoothed_rtt_seconds", 0.0),
                "baseline_rtt_seconds": values.get("baseline_rtt_seconds", 0.0),
                "loss_ratio": values.get("loss_ratio", 0.0),
                "blocked_writes": max(0, int(round(values.get("blocked_writes", 0.0)))),
                "oldest_blocked_write_seconds": values.get(
                    "oldest_blocked_write_seconds",
                    0.0,
                ),
                "payload_bytes_per_second": values.get("payload_bytes_per_second", 0.0),
                "healthy_payload_bytes_per_second": values.get(
                    "healthy_payload_bytes_per_second",
                    0.0,
                ),
            }
        )

    serving_groups = [
        (key, values)
        for key, values in groups
        if values.get("transports", 0.0) > 0 and key[1] == "serving"
    ]
    signal_groups = serving_groups
    if not signal_groups:
        signal_groups = [
            (key, values)
            for key, values in groups
            if values.get("transports", 0.0) > 0
            and values.get("active_tunnels", 0.0) > 0
        ]
    if not signal_groups:
        signal_groups = groups

    healths = {key[2] for key, _values in signal_groups}
    if "degraded" in healths:
        transport_health = "degraded"
    elif "suspect" in healths:
        transport_health = "suspect"
    elif "healthy" in healths:
        transport_health = "healthy"
    else:
        transport_health = "unknown"

    smoothed_rtt = max(
        (values.get("smoothed_rtt_seconds", 0.0) for _key, values in signal_groups),
        default=0.0,
    )
    baselines = [
        values.get("baseline_rtt_seconds", 0.0)
        for _key, values in signal_groups
        if values.get("baseline_rtt_seconds", 0.0) > 0
    ]
    baseline_rtt = min(baselines, default=0.0)
    loss_ratio = max(
        (values.get("loss_ratio", 0.0) for _key, values in signal_groups),
        default=0.0,
    )
    blocked_writes = sum(
        max(0, int(round(values.get("blocked_writes", 0.0))))
        for _key, values in signal_groups
    )
    oldest_blocked = max(
        (values.get("oldest_blocked_write_seconds", 0.0) for _key, values in signal_groups),
        default=0.0,
    )
    payload_rate = sum(
        values.get("payload_bytes_per_second", 0.0)
        for _key, values in signal_groups
    )
    healthy_payload_rate = sum(
        values.get("healthy_payload_bytes_per_second", 0.0)
        for _key, values in signal_groups
    )

    target_events, rule_events = h3_event_deltas(current, event_baseline)
    rotation_details = target_events.get(target, {})
    rotation_events = sum(rotation_details.values())
    rule_breaker_details = rule_events.get(rule, {})
    rule_breaker_events = sum(rule_breaker_details.values())

    cooldown_active = boolean_metric(target_values, "cooldown_active")
    half_open = boolean_metric(target_values, "half_open")
    boost_canary = boolean_metric(target_values, "boost_canary_in_flight")
    fallback_pending = boolean_metric(target_values, "fallback_pending")
    rule_cooldown = boolean_metric(rule_values, "cooldown_active")
    rule_validation = boolean_metric(rule_values, "fallback_validation_active")
    rule_probe_due = boolean_metric(rule_values, "probe_due")
    rule_probe_in_flight = boolean_metric(rule_values, "probe_in_flight")
    rule_probation = boolean_metric(rule_values, "probation_active")
    signals_sampled = any(
        values.get("smoothed_rtt_seconds", 0.0) > 0
        or values.get("baseline_rtt_seconds", 0.0) > 0
        or values.get("payload_bytes_per_second", 0.0) > 0
        or values.get("healthy_payload_bytes_per_second", 0.0) > 0
        or values.get("loss_ratio", 0.0) > 0
        or values.get("blocked_writes", 0.0) > 0
        for _key, values in signal_groups
    )

    if cooldown_active:
        target_status = "cooldown"
    elif (
        half_open
        or boost_canary
        or fallback_pending
    ):
        target_status = "recovering"
    elif transport_health == "degraded":
        target_status = "degraded"
    elif transport_health == "suspect":
        target_status = "suspect"
    elif transport_health == "healthy" and signals_sampled:
        target_status = "healthy"
    else:
        target_status = "unknown"

    if rule_cooldown:
        rule_status = "cooldown"
    elif rule_validation:
        rule_status = "validating_h2"
    elif rule_probe_in_flight:
        rule_status = "probe_in_flight"
    elif rule_probation:
        rule_status = "probation"
    elif rule_probe_due:
        rule_status = "probe_due"
    else:
        rule_status = "idle"

    if rule_status == "cooldown" or target_status == "cooldown":
        status = "cooldown"
    elif rule_status != "idle" or target_status == "recovering":
        status = "recovering"
    else:
        status = target_status

    return H3HealthView(
        target=target,
        status=status,
        target_status=target_status,
        rule_status=rule_status,
        transport_health=transport_health,
        transport_states=transport_states,
        transport_groups=transport_groups,
        transports=transports,
        active_tunnels=active_tunnels,
        degraded_draining_tunnels=degraded_draining_tunnels,
        suspect_draining_tunnels=suspect_draining_tunnels,
        smoothed_rtt_seconds=smoothed_rtt,
        baseline_rtt_seconds=baseline_rtt,
        loss_ratio=loss_ratio,
        blocked_writes=blocked_writes,
        oldest_blocked_write_seconds=oldest_blocked,
        payload_bytes_per_second=payload_rate,
        healthy_payload_bytes_per_second=healthy_payload_rate,
        degradation_strikes=max(0, int(round(target_values.get("degradation_strikes", 0.0)))),
        protocol_penalty_seconds=target_values.get("protocol_penalty_seconds", 0.0),
        cooldown_active=cooldown_active,
        cooldown_remaining_seconds=target_values.get("cooldown_remaining_seconds", 0.0),
        half_open=half_open,
        boost_canary_in_flight=boost_canary,
        fallback_pending=fallback_pending,
        rule_cooldown_active=rule_cooldown,
        rule_cooldown_remaining_seconds=rule_values.get("cooldown_remaining_seconds", 0.0),
        rule_fallback_validation_active=rule_validation,
        rule_probe_due=rule_probe_due,
        rule_probe_in_flight=rule_probe_in_flight,
        rule_probation_active=rule_probation,
        rule_probation_healthy_samples=max(
            0,
            int(round(rule_values.get("probation_healthy_samples", 0.0))),
        ),
        rule_probation_payload_bytes=max(
            0,
            int(round(rule_values.get("probation_payload_bytes", 0.0))),
        ),
        rule_probation_packets_sent=max(
            0,
            int(round(rule_values.get("probation_packets_sent", 0.0))),
        ),
        rotation_events=rotation_events,
        rotation_details=rotation_details,
        rule_breaker_events=rule_breaker_events,
        rule_breaker_details=rule_breaker_details,
        signals_sampled=signals_sampled,
    )


def build_view(
    current: Sample,
    baseline: Optional[Sample],
    instant_baseline: Optional[Sample] = None,
    min_rate: float = DEFAULT_MIN_RATE,
) -> WatchView:
    event_baseline = instant_baseline if instant_baseline is not None else baseline
    rates, elapsed = payload_rates(current, baseline)
    instant_rates, instant_elapsed = payload_rates(
        current,
        event_baseline,
    )
    target_events, rule_events = h3_event_deltas(current, event_baseline)

    keys: Set[RouteKey] = (
        set(current.active)
        | {route for route, _direction in current.payload}
        | set(current.last_success)
    )
    views: List[RouteView] = []
    for key in keys:
        per_direction = {
            direction: rate
            for (route, direction), rate in rates.items()
            if route == key
        }
        upload = per_direction.get("client_to_target", 0.0)
        download = per_direction.get("target_to_client", 0.0)
        other = sum(
            rate
            for direction, rate in per_direction.items()
            if direction not in ("client_to_target", "target_to_client")
        )
        total = upload + download + other
        instant_per_direction = {
            direction: rate
            for (route, direction), rate in instant_rates.items()
            if route == key
        }
        instant_upload = instant_per_direction.get("client_to_target", 0.0)
        instant_download = instant_per_direction.get("target_to_client", 0.0)
        instant_total = sum(instant_per_direction.values())
        tunnels = max(0, int(round(current.active.get(key, 0.0))))
        if tunnels > 0:
            if baseline is None:
                status = "collecting"
            elif instant_total > 0 and (min_rate == 0 or instant_total >= min_rate):
                status = "transmitting"
            elif total > 0 and (min_rate == 0 or total >= min_rate):
                status = "recent_activity"
            elif instant_total > 0 or total > 0:
                status = "trickle"
            else:
                status = "idle"
        elif total > 0:
            status = "recently_closed"
        else:
            status = "inactive"
        rule, target, protocol = key
        views.append(
            RouteView(
                key=key,
                active_tunnels=tunnels,
                bytes_per_second=total,
                upload_bytes_per_second=upload,
                download_bytes_per_second=download,
                other_bytes_per_second=other,
                instant_bytes_per_second=instant_total,
                instant_upload_bytes_per_second=instant_upload,
                instant_download_bytes_per_second=instant_download,
                traffic_share_percent=None,
                last_success_timestamp_seconds=current.last_success.get(key, 0.0),
                status=status,
                h3_health=aggregate_h3_health(
                    current,
                    event_baseline,
                    target,
                    rule,
                    protocol,
                ),
            )
        )

    active_views = [view for view in views if view.active_tunnels > 0]
    total_visible_rate = sum(view.bytes_per_second for view in views if view.bytes_per_second > 0)
    if total_visible_rate > 0:
        for view in views:
            if view.bytes_per_second > 0:
                view.traffic_share_percent = view.bytes_per_second * 100.0 / total_visible_rate

    raw_dominant = max(
        active_views,
        key=lambda view: (
            view.status == "transmitting",
            view.instant_bytes_per_second,
            view.bytes_per_second,
            view.active_tunnels,
            view.last_success_timestamp_seconds,
            view.key,
        ),
        default=None,
    )
    if not active_views:
        state = "no_active_tunnels"
    elif baseline is None:
        state = "collecting"
    elif any(view.status == "transmitting" for view in active_views):
        state = "transmitting"
    elif any(view.status == "recent_activity" for view in active_views):
        state = "recent_activity"
    elif any(view.status == "trickle" for view in active_views):
        state = "trickle"
    else:
        state = "idle"

    visible = [view for view in views if view.active_tunnels > 0 or view.bytes_per_second > 0]
    visible.sort(
        key=lambda view: (
            view.active_tunnels <= 0,
            -view.instant_bytes_per_second,
            -view.bytes_per_second,
            -view.active_tunnels,
            view.key,
        )
    )
    return WatchView(
        state=state,
        raw_dominant=raw_dominant,
        routes=visible,
        window_seconds=max(0.0, elapsed),
        instant_seconds=max(0.0, instant_elapsed),
        h3_target_events=target_events,
        h3_rule_events=rule_events,
    )


def format_rate(value: float) -> str:
    units = ("B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s")
    scaled = max(0.0, value)
    for unit in units:
        if scaled < 1024.0 or unit == units[-1]:
            if unit == "B/s":
                return f"{scaled:.0f} {unit}"
            return f"{scaled:.2f} {unit}"
        scaled /= 1024.0
    return f"{scaled:.2f} TiB/s"


def format_timestamp(timestamp: float) -> str:
    if timestamp <= 0:
        return "-"
    try:
        return dt.datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "-"


def terminal_color_enabled() -> bool:
    return (
        sys.stdout.isatty()
        and os.environ.get("TERM", "") != "dumb"
        and "NO_COLOR" not in os.environ
    )


def terminal_style(value: str, code: str, enabled: bool) -> str:
    if not enabled:
        return value
    return f"\033[{code}m{value}\033[0m"


def green(value: str, enabled: bool) -> str:
    return terminal_style(value, "32", enabled)


def yellow(value: str, enabled: bool) -> str:
    return terminal_style(value, "33", enabled)


def red(value: str, enabled: bool) -> str:
    return terminal_style(value, "31", enabled)


def cyan(value: str, enabled: bool) -> str:
    return terminal_style(value, "36", enabled)


def h3_health_to_dict(health: H3HealthView) -> Dict[str, object]:
    return {
        "target": health.target,
        "status": health.status,
        "target_status": health.target_status,
        "rule_status": health.rule_status,
        "transport_health": health.transport_health,
        "transport_states": health.transport_states,
        "transport_groups": health.transport_groups,
        "transports": health.transports,
        "active_tunnels": health.active_tunnels,
        "degraded_draining_tunnels": health.degraded_draining_tunnels,
        "suspect_draining_tunnels": health.suspect_draining_tunnels,
        "signals_sampled": health.signals_sampled,
        "smoothed_rtt_seconds": round(health.smoothed_rtt_seconds, 6),
        "baseline_rtt_seconds": round(health.baseline_rtt_seconds, 6),
        "loss_ratio": round(health.loss_ratio, 6),
        "blocked_writes": health.blocked_writes,
        "oldest_blocked_write_seconds": round(health.oldest_blocked_write_seconds, 6),
        "payload_bytes_per_second": round(health.payload_bytes_per_second, 3),
        "healthy_payload_bytes_per_second": round(
            health.healthy_payload_bytes_per_second,
            3,
        ),
        "degradation_strikes": health.degradation_strikes,
        "protocol_penalty_seconds": round(health.protocol_penalty_seconds, 3),
        "cooldown_active": health.cooldown_active,
        "cooldown_remaining_seconds": round(health.cooldown_remaining_seconds, 3),
        "half_open": health.half_open,
        "boost_canary_in_flight": health.boost_canary_in_flight,
        "fallback_pending": health.fallback_pending,
        "rule_cooldown_active": health.rule_cooldown_active,
        "rule_cooldown_remaining_seconds": round(
            health.rule_cooldown_remaining_seconds,
            3,
        ),
        "rule_fallback_validation_active": health.rule_fallback_validation_active,
        "rule_probe_due": health.rule_probe_due,
        "rule_probe_in_flight": health.rule_probe_in_flight,
        "rule_probation_active": health.rule_probation_active,
        "rule_probation_healthy_samples": health.rule_probation_healthy_samples,
        "rule_probation_payload_bytes": health.rule_probation_payload_bytes,
        "rule_probation_packets_sent": health.rule_probation_packets_sent,
    }


def route_to_dict(
    view: RouteView,
    dominant_key: Optional[RouteKey] = None,
    candidate_key: Optional[RouteKey] = None,
) -> Dict[str, object]:
    rule, target, protocol = view.key
    return {
        "rule": rule,
        "target": target,
        "protocol": protocol,
        "active_tunnels": view.active_tunnels,
        "bytes_per_second": round(view.bytes_per_second, 3),
        "upload_bytes_per_second": round(view.upload_bytes_per_second, 3),
        "download_bytes_per_second": round(view.download_bytes_per_second, 3),
        "other_bytes_per_second": round(view.other_bytes_per_second, 3),
        "average_bytes_per_second": round(view.bytes_per_second, 3),
        "average_upload_bytes_per_second": round(view.upload_bytes_per_second, 3),
        "average_download_bytes_per_second": round(view.download_bytes_per_second, 3),
        "instant_bytes_per_second": round(view.instant_bytes_per_second, 3),
        "instant_upload_bytes_per_second": round(view.instant_upload_bytes_per_second, 3),
        "instant_download_bytes_per_second": round(view.instant_download_bytes_per_second, 3),
        "traffic_share_percent": (
            round(view.traffic_share_percent, 3)
            if view.traffic_share_percent is not None
            else None
        ),
        "window_payload_share_percent": (
            round(view.traffic_share_percent, 3)
            if view.traffic_share_percent is not None
            else None
        ),
        "meaningful_traffic": view.status == "transmitting",
        "last_success_timestamp_seconds": view.last_success_timestamp_seconds,
        "last_success": format_timestamp(view.last_success_timestamp_seconds),
        "status": view.status,
        "is_dominant": view.key == dominant_key,
        "is_candidate": view.key == candidate_key,
        "h3_health": h3_health_to_dict(view.h3_health) if view.h3_health else None,
    }


def route_key_to_dict(key: RouteKey) -> Dict[str, str]:
    rule, target, protocol = key
    return {"rule": rule, "target": target, "protocol": protocol}


def transition_to_dict(transition: Optional[RouteTransition]) -> Optional[Dict[str, object]]:
    if transition is None:
        return None
    previous, current = transition
    return {"from": route_key_to_dict(previous), "to": route_key_to_dict(current)}


def reset_candidate(tracker: DominantTracker) -> None:
    tracker.candidate = None
    tracker.candidate_samples = 0


def route_lookup(routes: Iterable[RouteView]) -> Dict[RouteKey, RouteView]:
    return {route.key: route for route in routes}


def select_dominant(
    tracker: DominantTracker,
    view: WatchView,
    now: float,
    switch_samples: int,
    switch_ratio: float,
    switch_cooldown: float,
) -> DominantSelection:
    active = {
        route.key: route
        for route in view.routes
        if route.active_tunnels > 0
    }
    raw = view.raw_dominant
    if not active or raw is None:
        tracker.selected = None
        reset_candidate(tracker)
        return DominantSelection(None, None, None, 0)

    if tracker.selected is None:
        if view.state == "collecting":
            return DominantSelection(raw, None, None, 0)
        tracker.selected = raw.key
        reset_candidate(tracker)
        return DominantSelection(raw, None, None, 0)

    selected = active.get(tracker.selected)
    if selected is None:
        previous = tracker.selected
        tracker.selected = raw.key
        reset_candidate(tracker)
        if raw.status == "transmitting":
            tracker.last_switch_monotonic = now
            return DominantSelection(raw, (previous, raw.key), None, 0)
        # Keep showing the only active route, but do not call idle or trickle
        # bytes a confirmed traffic switch.
        return DominantSelection(raw, None, None, 0)

    if raw.key == tracker.selected:
        reset_candidate(tracker)
        return DominantSelection(selected, None, None, 0)

    # Idle and sub-threshold background bytes are informative, but never move
    # the confirmed main route. They otherwise make browser keepalives look
    # like rapid H3/H2 route changes.
    if view.state != "transmitting" or raw.status != "transmitting":
        reset_candidate(tracker)
        return DominantSelection(selected, None, None, 0)

    if (
        tracker.last_switch_monotonic > 0
        and now - tracker.last_switch_monotonic < switch_cooldown
    ):
        reset_candidate(tracker)
        return DominantSelection(selected, None, None, 0)

    required_rate = selected.instant_bytes_per_second * switch_ratio
    if raw.instant_bytes_per_second < required_rate:
        reset_candidate(tracker)
        return DominantSelection(selected, None, None, 0)

    if tracker.candidate == raw.key:
        tracker.candidate_samples += 1
    else:
        tracker.candidate = raw.key
        tracker.candidate_samples = 1

    if tracker.candidate_samples < switch_samples:
        return DominantSelection(
            selected,
            None,
            tracker.candidate,
            tracker.candidate_samples,
        )

    previous = tracker.selected
    tracker.selected = raw.key
    tracker.last_switch_monotonic = now
    reset_candidate(tracker)
    return DominantSelection(raw, (previous, raw.key), None, 0)


def snapshot_dict(
    url: str,
    sample: Sample,
    view: WatchView,
    selection: DominantSelection,
    min_rate: float,
    average_window_target: float,
    switch_samples: int,
) -> Dict[str, object]:
    routes = list(view.routes)
    dominant_key = selection.dominant.key if selection.dominant else None
    average_ready = view.window_seconds >= average_window_target * 0.9
    pending = None
    if selection.pending is not None:
        pending = {
            "route": route_key_to_dict(selection.pending),
            "samples": selection.pending_samples,
            "required_samples": switch_samples,
        }
    target_events: Dict[str, Dict[str, object]] = {
        target: {
            "count": sum(details.values()),
            "details": details,
        }
        for target, details in sorted(view.h3_target_events.items())
    }
    rule_events: Dict[str, Dict[str, object]] = {
        rule: {
            "count": sum(details.values()),
            "details": details,
        }
        for rule, details in sorted(view.h3_rule_events.items())
    }
    return {
        "schema_version": 2,
        "timestamp": format_timestamp(sample.wall_time),
        "url": url,
        "state": view.state,
        "traffic_threshold_bytes_per_second": min_rate,
        "instant_window_seconds": round(view.instant_seconds, 3),
        "average_window_seconds": round(view.window_seconds, 3),
        "average_window_target_seconds": average_window_target,
        "average_window_ready": average_ready,
        # Compatibility alias retained for consumers of the first watcher.
        "sample_window_seconds": round(view.window_seconds, 3),
        "aggregate": {
            "active_tunnels": sum(route.active_tunnels for route in routes),
            "instant_bytes_per_second": round(
                sum(route.instant_bytes_per_second for route in routes),
                3,
            ),
            "average_bytes_per_second": round(
                sum(route.bytes_per_second for route in routes),
                3,
            ),
        },
        "dominant": (
            route_to_dict(selection.dominant, dominant_key, selection.pending)
            if selection.dominant
            else None
        ),
        "observed_leader": (
            route_to_dict(view.raw_dominant, dominant_key, selection.pending)
            if view.raw_dominant
            else None
        ),
        "switch_pending": pending,
        "transition": transition_to_dict(selection.transition),
        "h3_events_since_last_scrape": {
            "targets": target_events,
            "rules": rule_events,
        },
        "routes": [
            route_to_dict(route, dominant_key, selection.pending)
            for route in routes
        ],
    }


def format_share(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.1f}%"


def format_seconds(value: float) -> str:
    if value <= 0:
        return "0s"
    if value < 10:
        return f"{value:.1f}s"
    if value >= 3600:
        hours = int(value) // 3600
        minutes = int(value) % 3600 // 60
        return f"{hours}h{minutes:02d}m"
    if value >= 60:
        minutes = int(value) // 60
        seconds = int(value) % 60
        return f"{minutes}m{seconds:02d}s"
    return f"{value:.0f}s"


def h3_status_text(status: str, color: bool) -> str:
    labels = {
        "healthy": ("健康", green),
        "suspect": ("观察中", yellow),
        "degraded": ("持续退化", red),
        "recovering": ("恢复探测", cyan),
        "cooldown": ("冷却中，新连接优先 H2", red),
        "unknown": ("等待有效采样", yellow),
    }
    label, painter = labels.get(status, (status, yellow))
    return painter(label, color)


def print_h3_health(health: H3HealthView, color: bool) -> None:
    states = ", ".join(
        f"{state}={count}"
        for state, count in sorted(health.transport_states.items())
        if count > 0
    )
    summary = f"H3 状态: {h3_status_text(health.target_status, color)}"
    if states:
        summary += f"  连接池 {states}"
    print(summary)
    if health.degraded_draining_tunnels > 0:
        print(
            "H3 旧隧道: "
            + red(
                f"{health.degraded_draining_tunnels} 条退化隧道仍在排空",
                color,
            )
        )
    elif health.suspect_draining_tunnels > 0:
        print(
            "H3 旧隧道: "
            + yellow(
                f"{health.suspect_draining_tunnels} 条可疑隧道仍在排空",
                color,
            )
        )

    signals: List[str] = []
    if health.signals_sampled:
        if health.smoothed_rtt_seconds > 0:
            signals.append(f"RTT {health.smoothed_rtt_seconds * 1000:.0f}ms")
        if health.baseline_rtt_seconds > 0:
            signals.append(f"基线 {health.baseline_rtt_seconds * 1000:.0f}ms")
        if health.loss_ratio > 0:
            signals.append(f"丢包 {health.loss_ratio * 100:.2f}%")
        else:
            signals.append("丢包 未见（样本量可能不足）")
        signals.append(f"阻塞写入 {health.blocked_writes}")
        if health.oldest_blocked_write_seconds > 0:
            signals.append(f"最久阻塞 {format_seconds(health.oldest_blocked_write_seconds)}")
    if signals:
        print("H3 质量: " + "  ".join(signals))

    policy: List[str] = []
    if health.cooldown_active:
        policy.append(f"目标冷却剩余 {format_seconds(health.cooldown_remaining_seconds)}")
    if health.half_open:
        policy.append("目标半开探测中")
    if health.fallback_pending:
        policy.append("正在验证 H2")
    if health.boost_canary_in_flight:
        policy.append("轮换候选验证中")
    if health.rule_cooldown_active:
        policy.append(f"规则冷却剩余 {format_seconds(health.rule_cooldown_remaining_seconds)}")
    if health.rule_fallback_validation_active:
        policy.append("规则正在验证 H2")
    if health.rule_probe_due:
        policy.append("规则可执行 H3 探测")
    if health.rule_probe_in_flight:
        policy.append("规则 H3 探测连接建立中")
    if health.rule_probation_active:
        policy.append(
            f"规则 H3 恢复观察中（健康样本 {health.rule_probation_healthy_samples}）"
        )
    if policy:
        policy_text = "  ".join(policy)
        if health.cooldown_active or health.rule_cooldown_active:
            policy_text = red(policy_text, color)
        else:
            policy_text = cyan(policy_text, color)
        print("H3 策略: " + policy_text)
    if health.rotation_events or health.rule_breaker_events:
        print(
            "H3 事件: "
            f"连接轮换 +{health.rotation_events}  "
            f"规则状态 +{health.rule_breaker_events}"
        )


def print_human(
    url: str,
    sample: Sample,
    view: WatchView,
    selection: DominantSelection,
    average_window_target: float,
    switch_samples: int,
    color: bool = False,
) -> None:
    labels = {
        "collecting": "采样中",
        "transmitting": "正在传输",
        "recent_activity": "最近有传输，当前已静止",
        "trickle": "微量后台流量",
        "idle": "隧道空闲",
        "no_active_tunnels": "无活动隧道",
    }
    print(f"Moto 路线观测  {format_timestamp(sample.wall_time)}")
    print(f"Metrics: {url}")
    print(
        f"状态: {labels.get(view.state, view.state)}  "
        f"瞬时窗口 {view.instant_seconds:.1f}s  "
        f"平均窗口 {view.window_seconds:.1f}s/{format_seconds(average_window_target)}"
    )
    if selection.transition is not None:
        previous, current = selection.transition
        print(
            f"线路切换: {previous[2].upper()} {previous[1]} / {previous[0]}"
            f"  ->  {current[2].upper()} {current[1]} / {current[0]}"
        )
    if selection.dominant is not None:
        dominant = selection.dominant
        rule, target, protocol = dominant.key
        route_label = green(f"{protocol.upper()}  {target}", color)
        rate_label = green(format_rate(dominant.bytes_per_second), color)
        instant_label = green(format_rate(dominant.instant_bytes_per_second), color)
        share_label = green(format_share(dominant.traffic_share_percent), color)
        tunnel_label = green(str(dominant.active_tunnels), color)
        print(
            f"当前主线路: {route_label}  "
            f"瞬时 {instant_label}  "
            f"总速率 {rate_label}  "
            f"窗口占比 {share_label}  "
            f"活动隧道 {tunnel_label}  规则 {rule}"
        )
        if dominant.h3_health is not None:
            print_h3_health(dominant.h3_health, color)
    elif view.state == "no_active_tunnels":
        print("当前没有活动的 H2/H3 隧道。")

    if selection.pending is not None:
        pending = route_lookup(view.routes).get(selection.pending)
        if pending is not None:
            rule, target, protocol = pending.key
            print(
                f"候选线路: {yellow(f'{protocol.upper()}  {target}', color)}  "
                f"切换确认 {selection.pending_samples}/{switch_samples}  规则 {rule}"
            )

    if view.state == "collecting":
        print("正在收集 byte-rate 基线；下一次采样后显示吞吐。")
    elif view.state == "recent_activity":
        print("平均窗口仍有历史流量，但最近一次采样没有达到传输阈值。")
    elif view.state == "trickle":
        print("仅检测到低于阈值的后台流量，不触发主线路切换。")
    elif view.state == "idle":
        print("活动隧道仍存在，但观测窗口内 payload 字节没有增长。")

    if not view.routes:
        return
    print()
    print(
        "协议 | 活动 |       瞬时 |     平均速率 | 窗口占比 | 状态            | 目标 / 规则"
    )
    print("-" * 116)
    for route in view.routes:
        rule, target, protocol = route.key
        print(
            f"{protocol.upper():<4} | {route.active_tunnels:>4} | "
            f"{format_rate(route.instant_bytes_per_second):>10} | "
            f"{format_rate(route.bytes_per_second):>12} | "
            f"{format_share(route.traffic_share_percent):>6} | "
            f"{route.status:<15} | {target} / {rule}"
        )


def emit_snapshot(
    args: argparse.Namespace,
    sample: Sample,
    baseline: Optional[Sample],
    instant_baseline: Optional[Sample],
    tracker: DominantTracker,
    allow_clear: bool,
) -> None:
    view = build_view(
        sample,
        baseline,
        instant_baseline=instant_baseline,
        min_rate=args.min_rate,
    )
    selection = select_dominant(
        tracker,
        view,
        sample.monotonic_time,
        args.switch_samples,
        args.switch_ratio,
        args.switch_cooldown,
    )
    if args.json:
        print(
            json.dumps(
                snapshot_dict(
                    args.url,
                    sample,
                    view,
                    selection,
                    args.min_rate,
                    args.window,
                    args.switch_samples,
                ),
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            flush=True,
        )
    else:
        if allow_clear and sys.stdout.isatty() and not args.no_clear:
            print("\033[2J\033[H", end="")
        print_human(
            args.url,
            sample,
            view,
            selection,
            args.window,
            args.switch_samples,
            color=terminal_color_enabled(),
        )
        print(flush=True)


def emit_error(args: argparse.Namespace, error: Exception, allow_clear: bool) -> None:
    if args.json:
        print(
            json.dumps(
                {
                    "schema_version": 2,
                    "timestamp": format_timestamp(time.time()),
                    "url": args.url,
                    "state": "error",
                    "error": str(error),
                    "traffic_threshold_bytes_per_second": args.min_rate,
                    "instant_window_seconds": 0.0,
                    "average_window_seconds": 0.0,
                    "average_window_target_seconds": args.window,
                    "average_window_ready": False,
                    "sample_window_seconds": 0.0,
                    "aggregate": {
                        "active_tunnels": 0,
                        "instant_bytes_per_second": 0.0,
                        "average_bytes_per_second": 0.0,
                    },
                    "dominant": None,
                    "observed_leader": None,
                    "switch_pending": None,
                    "transition": None,
                    "h3_events_since_last_scrape": {
                        "targets": {},
                        "rules": {},
                    },
                    "routes": [],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            flush=True,
        )
        return
    if allow_clear and sys.stdout.isatty() and not args.no_clear:
        print("\033[2J\033[H", end="")
    print(f"moto-route-watch.py: {error}", file=sys.stderr, flush=True)


def run_once(args: argparse.Namespace) -> int:
    try:
        baseline = fetch_sample(args.url, args.timeout)
        time.sleep(args.interval)
        current = fetch_sample(args.url, args.timeout)
    except WatchError as exc:
        emit_error(args, exc, allow_clear=False)
        return 2
    emit_snapshot(
        args,
        current,
        baseline,
        instant_baseline=baseline,
        tracker=DominantTracker(),
        allow_clear=False,
    )
    return 0


def run_watch(args: argparse.Namespace) -> int:
    history: collections.deque[Sample] = collections.deque()
    tracker = DominantTracker()
    while True:
        cycle_started = time.monotonic()
        try:
            current = fetch_sample(args.url, args.timeout)
            history.append(current)
            while (
                len(history) > 1
                and current.monotonic_time - history[0].monotonic_time > args.window
            ):
                history.popleft()
            baseline = history[0] if len(history) > 1 else None
            instant_baseline = history[-2] if len(history) > 1 else None
            emit_snapshot(
                args,
                current,
                baseline,
                instant_baseline,
                tracker,
                allow_clear=True,
            )
        except WatchError as exc:
            emit_error(args, exc, allow_clear=True)
            # Do not calculate a byte-rate across an observability outage.
            history.clear()
            tracker = DominantTracker()
        remaining = args.interval - (time.monotonic() - cycle_started)
        if remaining > 0:
            time.sleep(remaining)


def configure_utf8_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("_", "-")
        reconfigure = getattr(stream, "reconfigure", None)
        if encoding not in ("utf-8", "utf8") and callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (LookupError, OSError):
                pass


def main(argv: List[str]) -> int:
    configure_utf8_output()
    args = parse_args(argv)
    try:
        return run_once(args) if args.once else run_watch(args)
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
