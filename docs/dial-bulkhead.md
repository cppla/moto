# 拨号隔离舱

Moto 对前台新建上游连接设置 Server 级双层并发上限：全局最多 256 个真实拨号，同一配置目标最多 64 个。容量不足时最多等待 250 ms；热重载前后的 generation 共用同一份额度，避免重载瞬间放大并发。

预热连接命中不占前台额度。预热补池与 Boost 懒刷新非阻塞地共用 32 个 Server 级后台拨号槽，主动健康检查另受 32 个进程级探测槽约束，因此后台维护不能耗尽前台额度。

隔离舱等待发生在领取线路 attempt 之前。本地容量超时或等待期间的 context 取消不会更新线路 EWMA 或连续失败，不会打开熔断、占用半开探针或清除 Boost winner。全局额度已满时 Moto 直接结束本次连接；若只是当前目标达到 64 个拨号而全局仍有余量，`normal`/`regex`/`tls`/`roundrobin` 对其他已配置目标只做立即准入，Boost 则允许已经在途的独立候选完成。这些路径不会为其他目标再新增一轮 250 ms 排队。

启用 Boost `hedge` 时，延迟计时从缓存线路通过隔离舱准入、即将真实拨号时开始。延迟备用仍受相同前台额度约束，但只做非阻塞准入；拿不到容量时记录 `skipped_capacity`，已经运行的缓存主线路继续等待，不会新增 250 ms 排队者。若主线路随后明确失败，该目标会作为必要 fallback 恢复普通的有界准入等待。剩余规则期限不足以容纳本次延迟时记录 `skipped_deadline`，不建立计时器。

## 指标与验证

对应 Prometheus 指标：

- `moto_dial_bulkhead_in_flight`
- `moto_dial_bulkhead_waiting`
- `moto_dial_bulkhead_target_in_flight`
- `moto_dial_bulkhead_wait_seconds`
- `moto_dial_bulkhead_rejected_total`
- `moto_boost_hedge_events_total{outcome="skipped_capacity"}`
- `moto_boost_hedge_events_total{outcome="skipped_deadline"}`

压测应覆盖全局和单目标上限、等待超时、调用方取消、热重载共享额度，以及预热命中不占前台额度。验证时同时观察成功率、p50/p95/p99、CPU、RSS、FD 和上述隔离舱指标，避免只比较单次峰值吞吐。
