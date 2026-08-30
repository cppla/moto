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
MAX_METRICS_BYTES = 16 * 1024 * 1024

RouteKey = Tuple[str, str, str]
PayloadKey = Tuple[RouteKey, str]
RouteTransition = Tuple[RouteKey, RouteKey]


class WatchError(RuntimeError):
    pass


@dataclass
class Sample:
    monotonic_time: float
    wall_time: float
    active: Dict[RouteKey, float] = field(default_factory=dict)
    payload: Dict[PayloadKey, float] = field(default_factory=dict)
    last_success: Dict[RouteKey, float] = field(default_factory=dict)


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
            # malformed unified route metric.
            if any(line.startswith(name) for name in REQUIRED_METRICS):
                raise WatchError(f"invalid route metric at line {line_number}: {line!r}")
            continue
        metric, raw_labels, raw_value = match.groups()
        if metric not in REQUIRED_METRICS:
            continue
        parsed_names.add(metric)
        labels = parse_labels(raw_labels or "")
        key = route_key(labels, metric)
        value = finite_metric_value(raw_value, metric)
        if value is None:
            continue

        if metric == ACTIVE_METRIC:
            sample.active[key] = sample.active.get(key, 0.0) + max(0.0, value)
        elif metric == PAYLOAD_METRIC:
            direction = labels.get("direction", "")
            if not direction:
                raise WatchError(f"{PAYLOAD_METRIC} sample is missing label: direction")
            payload_key = key, direction
            sample.payload[payload_key] = sample.payload.get(payload_key, 0.0) + max(0.0, value)
        elif metric == LAST_SUCCESS_METRIC:
            sample.last_success[key] = max(sample.last_success.get(key, 0.0), value)

    available = declared | parsed_names
    missing_metrics = [name for name in REQUIRED_METRICS if name not in available]
    if missing_metrics:
        raise WatchError(
            "metrics endpoint does not expose the required Moto route metrics: "
            + ", ".join(missing_metrics)
            + "; update/restart Moto with route metrics enabled"
        )
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


def build_view(
    current: Sample, baseline: Optional[Sample]
) -> Tuple[str, Optional[RouteView], List[RouteView], float]:
    elapsed = 0.0
    rates: Dict[PayloadKey, float] = {}
    if baseline is not None:
        elapsed = current.monotonic_time - baseline.monotonic_time
        if elapsed > 0:
            for payload_key, current_value in current.payload.items():
                previous_value = baseline.payload.get(payload_key, 0.0)
                rates[payload_key] = counter_rate(current_value, previous_value, elapsed)

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
        tunnels = max(0, int(round(current.active.get(key, 0.0))))
        if tunnels > 0:
            status = "transmitting" if total > 0 else ("collecting" if baseline is None else "idle")
        elif total > 0:
            status = "recently_closed"
        else:
            status = "inactive"
        views.append(
            RouteView(
                key=key,
                active_tunnels=tunnels,
                bytes_per_second=total,
                upload_bytes_per_second=upload,
                download_bytes_per_second=download,
                other_bytes_per_second=other,
                last_success_timestamp_seconds=current.last_success.get(key, 0.0),
                status=status,
            )
        )

    active_views = [view for view in views if view.active_tunnels > 0]
    dominant = max(
        active_views,
        key=lambda view: (
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
    elif any(view.bytes_per_second > 0 for view in active_views):
        state = "transmitting"
    else:
        state = "idle"

    visible = [view for view in views if view.active_tunnels > 0 or view.bytes_per_second > 0]
    visible.sort(
        key=lambda view: (
            view.active_tunnels <= 0,
            -view.bytes_per_second,
            -view.active_tunnels,
            view.key,
        )
    )
    return state, dominant, visible, max(0.0, elapsed)


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


def green(value: str, enabled: bool) -> str:
    if not enabled:
        return value
    return f"\033[32m{value}\033[0m"


def route_to_dict(view: RouteView) -> Dict[str, object]:
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
        "last_success_timestamp_seconds": view.last_success_timestamp_seconds,
        "last_success": format_timestamp(view.last_success_timestamp_seconds),
        "status": view.status,
    }


def route_key_to_dict(key: RouteKey) -> Dict[str, str]:
    rule, target, protocol = key
    return {"rule": rule, "target": target, "protocol": protocol}


def transition_to_dict(transition: Optional[RouteTransition]) -> Optional[Dict[str, object]]:
    if transition is None:
        return None
    previous, current = transition
    return {"from": route_key_to_dict(previous), "to": route_key_to_dict(current)}


def select_transition(
    previous_dominant: Optional[RouteKey],
    state: str,
    dominant: Optional[RouteView],
) -> Tuple[Optional[RouteTransition], Optional[RouteKey]]:
    current_dominant = dominant.key if state == "transmitting" and dominant is not None else None
    transition = None
    if previous_dominant is not None and current_dominant is not None and previous_dominant != current_dominant:
        transition = previous_dominant, current_dominant
    if state == "no_active_tunnels":
        return transition, None
    return transition, current_dominant if current_dominant is not None else previous_dominant


def snapshot_dict(
    url: str,
    sample: Sample,
    state: str,
    dominant: Optional[RouteView],
    routes: Iterable[RouteView],
    elapsed: float,
    transition: Optional[RouteTransition],
) -> Dict[str, object]:
    return {
        "timestamp": format_timestamp(sample.wall_time),
        "url": url,
        "state": state,
        "sample_window_seconds": round(elapsed, 3),
        "dominant": route_to_dict(dominant) if dominant else None,
        "transition": transition_to_dict(transition),
        "routes": [route_to_dict(route) for route in routes],
    }


def print_human(
    url: str,
    sample: Sample,
    state: str,
    dominant: Optional[RouteView],
    routes: List[RouteView],
    elapsed: float,
    transition: Optional[RouteTransition],
    color: bool = False,
) -> None:
    labels = {
        "collecting": "采样中",
        "transmitting": "正在传输",
        "idle": "隧道空闲",
        "no_active_tunnels": "无活动隧道",
    }
    print(f"Moto 路线观测  {format_timestamp(sample.wall_time)}")
    print(f"Metrics: {url}")
    print(f"状态: {labels.get(state, state)}  速率窗口: {elapsed:.1f}s")
    if transition is not None:
        previous, current = transition
        print(
            f"线路切换: {previous[2].upper()} {previous[1]} / {previous[0]}"
            f"  ->  {current[2].upper()} {current[1]} / {current[0]}"
        )
    if dominant is not None:
        rule, target, protocol = dominant.key
        route_label = green(f"{protocol.upper()}  {target}", color)
        rate_label = green(format_rate(dominant.bytes_per_second), color)
        tunnel_label = green(str(dominant.active_tunnels), color)
        print(
            f"当前主线路: {route_label}  "
            f"总速率 {rate_label}  "
            f"活动隧道 {tunnel_label}  规则 {rule}"
        )
    elif state == "no_active_tunnels":
        print("当前没有活动的 H2/H3 隧道。")

    if state == "collecting":
        print("正在收集 byte-rate 基线；下一次采样后显示吞吐。")
    elif state == "idle":
        print("活动隧道仍存在，但观测窗口内 payload 字节没有增长。")

    if not routes:
        return
    print()
    print(
        f"{'协议':<6} {'活动':>5} {'上行':>12} {'下行':>12} "
        f"{'总速率':>12}  {'状态':<15} {'目标 / 规则'}"
    )
    print("-" * 110)
    for route in routes:
        rule, target, protocol = route.key
        print(
            f"{protocol.upper():<6} {route.active_tunnels:>5} "
            f"{format_rate(route.upload_bytes_per_second):>12} "
            f"{format_rate(route.download_bytes_per_second):>12} "
            f"{format_rate(route.bytes_per_second):>12}  "
            f"{route.status:<15} {target} / {rule}"
        )


def emit_snapshot(
    args: argparse.Namespace,
    sample: Sample,
    baseline: Optional[Sample],
    allow_clear: bool,
    previous_dominant: Optional[RouteKey] = None,
) -> Optional[RouteKey]:
    state, dominant, routes, elapsed = build_view(sample, baseline)
    transition, next_dominant = select_transition(previous_dominant, state, dominant)
    if args.json:
        print(
            json.dumps(
                snapshot_dict(args.url, sample, state, dominant, routes, elapsed, transition),
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
            state,
            dominant,
            routes,
            elapsed,
            transition,
            color=terminal_color_enabled(),
        )
        print(flush=True)
    return next_dominant


def emit_error(args: argparse.Namespace, error: Exception, allow_clear: bool) -> None:
    if args.json:
        print(
            json.dumps(
                {
                    "timestamp": format_timestamp(time.time()),
                    "url": args.url,
                    "state": "error",
                    "error": str(error),
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
    emit_snapshot(args, current, baseline, allow_clear=False)
    return 0


def run_watch(args: argparse.Namespace) -> int:
    history: collections.deque[Sample] = collections.deque()
    previous_dominant: Optional[RouteKey] = None
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
            previous_dominant = emit_snapshot(
                args,
                current,
                baseline,
                allow_clear=True,
                previous_dominant=previous_dominant,
            )
        except WatchError as exc:
            emit_error(args, exc, allow_clear=True)
            # Do not calculate a byte-rate across an observability outage.
            history.clear()
            previous_dominant = None
        remaining = args.interval - (time.monotonic() - cycle_started)
        if remaining > 0:
            time.sleep(remaining)


def main(argv: List[str]) -> int:
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
