#!/usr/bin/env python3
import asyncio
import argparse
import time
import statistics
import json
import random
import sys
from collections import Counter, defaultdict
from typing import Optional, List, Dict, Any

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 84
TARGET_HOST = "www.baidu.com"
TARGET_PORT = 80
HTTP_REQ_TEMPLATE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: prewarm-test/0.1\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode()

class Result:
    __slots__ = (
        "ok","error","connect_ms","first_byte_ms","total_ms","status","phase"
    )
    def __init__(self, ok: bool, error: Optional[str], connect_ms: float,
                 first_byte_ms: float, total_ms: float, status: Optional[int], phase: str):
        self.ok = ok
        self.error = error
        self.connect_ms = connect_ms
        self.first_byte_ms = first_byte_ms
        self.total_ms = total_ms
        self.status = status
        self.phase = phase

async def socks5_http_get(timeout: float, phase: str) -> Result:
    start = time.monotonic()
    reader = writer = None
    try:
        # 连接到本地 SOCKS5
        conn_begin = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(PROXY_HOST, PROXY_PORT),
            timeout=timeout
        )
        # SOCKS5 greeting
        writer.write(b"\x05\x01\x00")  # VER=5, NMETHODS=1, METHOD=0(no auth)
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp != b"\x05\x00":
            raise RuntimeError(f"socks5 greet resp invalid: {resp!r}")

        # CONNECT 请求
        host_bytes = TARGET_HOST.encode()
        pkt = bytearray()
        pkt += b"\x05"          # VER
        pkt += b"\x01"          # CMD=CONNECT
        pkt += b"\x00"          # RSV
        pkt += b"\x03"          # ATYP=DOMAIN
        pkt += bytes([len(host_bytes)])
        pkt += host_bytes
        pkt += TARGET_PORT.to_bytes(2, "big")
        writer.write(pkt)
        await writer.drain()
        # 应答：VER REP RSV ATYP ...   最少 10 字节 (域名长度可能不同)
        ver_rep = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if len(ver_rep) != 4 or ver_rep[1] != 0x00:
            raise RuntimeError(f"socks5 connect failed: {ver_rep!r}")
        atyp = ver_rep[3]
        if atyp == 1:  # IPv4
            await asyncio.wait_for(reader.readexactly(4+2), timeout=timeout)
        elif atyp == 3:
            ln = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(ln[0] + 2), timeout=timeout)
        elif atyp == 4:  # IPv6
            await asyncio.wait_for(reader.readexactly(16+2), timeout=timeout)
        else:
            raise RuntimeError(f"socks5 atyp unsupported: {atyp}")

        connect_done = time.monotonic()
        connect_ms = (connect_done - conn_begin) * 1000.0

        # 发起 HTTP 请求
        writer.write(HTTP_REQ_TEMPLATE.replace(b"{host}", TARGET_HOST.encode()))
        await writer.drain()

        # 首字节
        first_chunk = await asyncio.wait_for(reader.read(1), timeout=timeout)
        if not first_chunk:
            raise RuntimeError("empty first byte")
        first_byte_ms = (time.monotonic() - start) * 1000.0

        # 读剩余响应（简单读取到 EOF）
        buf = bytearray(first_chunk)
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                raise RuntimeError("read timeout")
            if not chunk:
                break
            buf += chunk
            if len(buf) > 64 * 1024:
                # 不需要整站大 body，适度截断
                break

        total_ms = (time.monotonic() - start) * 1000.0
        # 简单解析状态码
        status = None
        try:
            head = bytes(buf.split(b"\r\n", 1)[0])
            if head.startswith(b"HTTP/"):
                parts = head.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status = int(parts[1])
        except Exception:
            pass

        return Result(True, None, connect_ms, first_byte_ms, total_ms, status, phase)
    except Exception as e:
        total_ms = (time.monotonic() - start) * 1000.0
        return Result(False, str(e), 0.0, 0.0, total_ms, None, phase)
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

def percentiles(values: List[float], ps=(50,90,95,99)) -> Dict[int,float]:
    if not values:
        return {p: 0.0 for p in ps}
    s = sorted(values)
    out = {}
    n = len(s)
    for p in ps:
        k = int(round((p/100.0)*(n-1)))
        out[p] = s[k]
    return out

async def run_phase(phase_name: str, concurrency: int, total: int,
                    timeout: float, jitter: float, results: List[Result]):
    sem = asyncio.Semaphore(concurrency)
    started = 0

    async def worker(idx: int):
        nonlocal started
        async with sem:
            if jitter > 0:
                await asyncio.sleep(random.random()*jitter)
            res = await socks5_http_get(timeout, phase_name)
            results.append(res)

    tasks = []
    for i in range(total):
        started += 1
        tasks.append(asyncio.create_task(worker(i)))
    await asyncio.gather(*tasks)

def summarize(results: List[Result]):
    ok = [r for r in results if r.ok]
    fail = [r for r in results if not r.ok]

    connect_ms = [r.connect_ms for r in ok]
    fb_ms = [r.first_byte_ms for r in ok]
    total_ms = [r.total_ms for r in ok]

    codes = Counter(r.status for r in ok if r.status is not None)
    errors = Counter(r.error for r in fail)

    def fmt_dist(c: Counter, top=5):
        return ", ".join(f"{k}:{v}" for k,v in c.most_common(top)) or "-"

    def fmt_perc(vals, name):
        p = percentiles(vals)
        return f"{name} p50={p[50]:.1f} p90={p[90]:.1f} p95={p[95]:.1f} p99={p[99]:.1f}"

    lines = []
    lines.append(f"Total={len(results)} OK={len(ok)} Fail={len(fail)} "
                 f"SuccessRate={ (len(ok)/len(results)*100 if results else 0):.2f}%")
    if ok:
        lines.append(fmt_perc(connect_ms, "Connect(ms)"))
        lines.append(fmt_perc(fb_ms, "FirstByte(ms)"))
        lines.append(fmt_perc(total_ms, "Total(ms)"))
    lines.append(f"HTTP Codes: {fmt_dist(codes)}")
    if fail:
        lines.append(f"Errors: {fmt_dist(errors)}")
    # 按 phase 汇总
    by_phase = defaultdict(list)
    for r in results:
        by_phase[r.phase].append(r)
    if len(by_phase) > 1:
        lines.append("Per-Phase Success:")
        for ph, lst in by_phase.items():
            o = sum(1 for x in lst if x.ok)
            lines.append(f"  {ph}: {o}/{len(lst)} = {o/len(lst)*100:.1f}%")
    return "\n".join(lines)

def parse_args():
    ap = argparse.ArgumentParser(description="SOCKS5 concurrency test for dynamic prewarm observation")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-c","--concurrency", type=int, help="固定并发数")
    g.add_argument("-r","--ramp", help="分阶段并发列表, 例如: 50,100,200")
    ap.add_argument("-t","--total", type=int, help="总请求数（固定并发模式必须）")
    ap.add_argument("--per-stage", type=int, help="每个阶段请求数（ramp 模式必须）")
    ap.add_argument("--timeout", type=float, default=5.0, help="单请求超时秒")
    ap.add_argument("--jitter", type=float, default=0.0, help="启动抖动最大秒 (0~1 小幅随机延迟)")
    ap.add_argument("--save", help="保存所有结果为 JSON 文件")
    ap.add_argument("--seed", type=int, help="随机种子")
    return ap.parse_args()

def print_header():
    print("="*70)
    print(" SOCKS5 High Concurrency Test (observe server prewarm scaling) ")
    print("="*70)

async def main():
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    print_header()
    results: List[Result] = []
    t0 = time.monotonic()

    if args.concurrency:
        if not args.total:
            print("--total 必须指定（固定并发模式）", file=sys.stderr)
            sys.exit(1)
        print(f"[Phase single] concurrency={args.concurrency} total={args.total}")
        await run_phase("phase1", args.concurrency, args.total,
                        args.timeout, args.jitter, results)
    else:
        # ramp 模式
        stages = [int(x.strip()) for x in args.ramp.split(",") if x.strip()]
        if not stages:
            print("无效 ramp 列表", file=sys.stderr)
            sys.exit(1)
        if not args.per_stage:
            print("--per-stage 必须指定（ramp 模式）", file=sys.stderr)
            sys.exit(1)
        for i, c in enumerate(stages, 1):
            print(f"[Phase {i}] concurrency={c} total={args.per_stage}")
            await run_phase(f"phase{i}", c, args.per_stage,
                            args.timeout, args.jitter, results)

    elapsed = time.monotonic() - t0
    print("\n=== Summary ===")
    print(summarize(results))
    print(f"Elapsed: {elapsed:.2f}s  Approx QPS: {len(results)/elapsed:.1f}")

    if args.save:
        out = []
        for r in results:
            out.append({
                "ok": r.ok,
                "error": r.error,
                "connect_ms": r.connect_ms,
                "first_byte_ms": r.first_byte_ms,
                "total_ms": r.total_ms,
                "status": r.status,
                "phase": r.phase
            })
        with open(args.save, "w") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"Saved JSON results -> {args.save}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)

# 较小并发测试：
# python3 bench.py -c 50 -t 500
# ramp 模式：
# python3 bench.py -r 50,100,200,400 --per-stage 400