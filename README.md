<p align="center">
  <img src="docs/assets/moto-logo.png" alt="Moto 加速摩托与网络线路 Logo" width="480">
</p>

<h1 align="center">Moto</h1>

<p align="center"><strong>在不断变化的网络里，自动找到更值得走的 TCP 路径。</strong></p>

<p align="center">
  <a href="https://github.com/cppla/moto/actions/workflows/ci.yml"><img src="https://github.com/cppla/moto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/cppla/moto" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/cppla/moto" alt="License"></a>
</p>

Moto 是轻量级、自适应的 TCP 网关。应用只连接一个稳定入口，Moto 根据真实拨号延迟、近期故障和转发规则，从多个上游、隧道或跨地域节点中动态选路。

## 为什么是 Moto？

- **自适应选路：** 顺序故障切换、首包与 TLS SNI/ALPN 分类、EWMA 延迟学习、Top-2 竞速、主动健康检查、熔断和恢复探测都在一个进程内完成。
- **协议透明：** 不终止 TLS、不改写流量，也不要求接入 SDK；HTTP(S)、WebSocket、SSH、SOCKS5 和私有 TCP 协议均可直接使用。
- **高效转发：** 稳定字节流直接交给 `io.Copy`；Linux 上符合条件的 TCP→TCP 路径通常由 Go 运行时自动使用 `splice(2)` 零拷贝，不支持时自动回退。
- **轻而可靠：** 单个 Go 二进制加一份 JSON 即可运行，同时内置严格配置校验、资源上限、访问控制、Prometheus 指标、优雅退出和跨平台发布。

## 30 秒启动

```bash
git clone https://github.com/cppla/moto.git
cd moto

# 校验配置，不监听端口
go run . --config config/setting.json --check-config

# 启动
go run . --config config/setting.json
```

配置路径优先级为 `--config`、`MOTO_CONFIG`、`config/setting.json`。Unix 下发送 `SIGHUP` 会校验并原子切换规则：旧连接继续使用旧规则，新连接只使用新规则；解析、校验或新端口绑定失败时继续运行原配置。最多允许 8 个旧 generation 同时排空，达到上限会拒绝下一次重载；Windows、日志或 metrics 监听变更需要重启。收到 `SIGINT` 或 `SIGTERM` 后，Moto 停止接收新连接，并为现有连接保留最多 10 秒的优雅退出时间。

## 工作方式

```mermaid
flowchart LR
    C[Client] --> M[Moto]
    M -->|每条连接选择一个| W[当前 Target]
    M -. 故障切换 / 周期探索 .-> S[其他 Targets]
```

## 运行模式

| 模式 | 行为 |
| --- | --- |
| `normal` | 按配置顺序连接目标，直到成功 |
| `regex` | 在最多 4 KiB 的客户端首包中匹配规则，再转发完整字节流 |
| `boost` | 按 EWMA 评分竞速 Top-2 目标，缓存胜出线路并定期探索；可选自适应延迟备用拨号 |
| `roundrobin` | 按规则独立轮询；单个目标失败时回退到竞速选择 |
| `tls` | 解析 ClientHello 的 SNI/ALPN 选路，再原样转发 TLS 字节流 |

<details>
<summary><strong>选路、熔断与预热细节</strong></summary>

域名由 Go TCP Dialer 处理，并支持 IPv4/IPv6 快速回退。每条线路记录拨号延迟 EWMA；连续三次拨号失败或连接准备、首包写入等可明确归因于上游的失败后，线路进入 5 秒熔断冷却，重复失败时最长增加到 60 秒。冷却结束只允许一个半开探针，竞速取消的败者不会被误记为故障。稳定转发使用 `io.Copy`，其错误无法可靠区分客户端和上游，因此只进入日志与指标，不参与熔断；这类故障由后续拨号和主动健康检查发现。

`boost` 冷缓存仍然只同时竞速 Top-2。配置 `hedge` 后，热缓存先拨缓存线路；若它在 `clamp(2 × EWMA, minDelay, maxDelay)` 内未完成，再启动一个备用目标，同时在途数仍不超过 2。缓存线路明确失败时不等待延迟，立即补齐备用目标。Hedge 计时从缓存线路通过健康、熔断和前台隔离舱准入后开始；延迟备用只使用立即可得的拨号额度，拿不到时保留主线路且不新增排队者。若主线路随后失败，备用会转为必要故障切换并恢复正常的有界准入等待。省略 `hedge` 完全保留原来的单线路热缓存行为。

Hedge 只竞速 Moto 到上游的 TCP 建连与连接准备，不观察 SOCKS CONNECT、应用首字节或已建立连接的传输速度。命中预热连接时 TCP 建连已经完成，因此该请求通常不会再启动 Hedge；两者分别优化“已有可用连接”和“新建连接尾延迟”，收益不能直接相加。

预热池默认关闭。启用后，每个目标最多 4 个并发补充拨号、进程最多 32 个、单份配置最多 256 个唯一预热目标。Unix 会用非消费式 `MSG_PEEK` 拒绝已收到 FIN/RST 的空闲连接；无法安全探测的平台使用新连接。`MSG_PEEK` 只能判断 TCP 是否已明确关闭，不能识别“socket 仍 open，但应用会话已过期”；启用前必须在同一条连接上等待接近 30 秒后完成真实协议请求，不能只测 TCP connect。线路熔断时旧池会被清空并暂停补充。

前台新建上游连接经过 Server 级拨号隔离舱：同时最多 256 个真实拨号、同一配置目标最多 64 个，额度不足时最多等待 250 ms。热重载前后的 generation 共用同一份额度；预热连接命中不占前台额度，预热补池与 Boost 懒刷新合计使用 32 个独立后台拨号槽，主动健康检查另有 32 个探测槽。本地额度超时不会更新线路失败或抢占半开探针；全局容量已满时立即结束，仅单目标容量已满且全局仍有余量时，才会对其他已配置目标做无排队的立即准入尝试。详见 [拨号隔离舱](docs/dial-bulkhead.md)。

</details>

<details>
<summary><strong>首包正则示例与限制</strong></summary>

| 协议 | JSON 中的正则表达式 |
| --- | --- |
| HTTP | `^(GET|POST|HEAD|DELETE|PUT|PATCH|CONNECT|OPTIONS|TRACE) ` |
| TLS | `^\\x16\\x03` |
| RDP | `^\\x03\\x00\\x00` |
| SOCKS5 | `^\\x05` |

TCP 是字节流，不保证一次读取就是完整数据包。Moto 会增量读取并在任一规则匹配后停止分类。`regex` 只适合客户端先发送数据的协议；常见 SSH 客户端会等待服务端 banner，VNC、FTP、MySQL 也是服务端先握手，这些协议应使用 `normal`、`boost` 或 `roundrobin` 直接转发。

</details>

## 配置

```json
{
  "log": {
    "level": "info",
    "path": ""
  },
  "metrics": {
    "enabled": true,
    "listen": "127.0.0.1:9090"
  },
  "rules": [
    {
      "name": "web",
      "listen": "127.0.0.1:8080",
      "mode": "boost",
      "prewarm": false,
      "timeout": 3000,
      "hedge": {
        "minDelay": 25,
        "maxDelay": 250
      },
      "allowlist": ["127.0.0.0/8", "::1/128"],
      "targets": [
        { "address": "server-a.example.com:443" },
        { "address": "server-b.example.com:443" }
      ]
    }
  ]
}
```

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | 无 | `normal`、`regex`、`boost`、`roundrobin` 或 `tls` |
| `timeout` | `regex` 为 500 ms；其余为 3 s | 拨号或首包决策期限，不限制已建立连接的寿命 |
| `prewarm` | `false` | 仅在上游允许业务握手前保持空闲 TCP 时启用 |
| `hedge` | 关闭 | 仅用于至少两个唯一目标的 `boost`；空对象默认延迟范围 25–250 ms，且 `maxDelay` 必须小于规则 `timeout` |
| `healthCheck` | 关闭 | 可选 TCP 或明文 HTTP 主动探测，达到阈值后暂时排除目标 |
| `proxyProtocol` | 关闭 | 从可信 CIDR 接收 PROXY v1/v2，或向上游发送 v1/v2 |
| `allowlist` | 空 | CIDR 来源白名单；空值允许所有有效地址 |
| `blacklist` | 空 | 兼容旧配置的精确 IP 拒绝表 |
| `maxConnections` | `4096` | 单规则连接上限 |
| `maxConnectionsPerIP` | `256` | 单 IP、单规则连接上限 |
| `metrics` | 关闭 | 启用时默认监听 `127.0.0.1:9090` |

配置采用严格校验：未知字段、重复 JSON 键、字段名大小写变体、未知模式、重复规则名或监听地址、非法 CIDR、空目标和非法正则都会阻止启动。所有监听地址会先一次性绑定，任一端口失败都不会留下部分服务继续运行。

<details>
<summary><strong>TLS、健康检查与 PROXY protocol 示例</strong></summary>

```json
{
  "name": "tls-edge",
  "listen": "127.0.0.1:8443",
  "mode": "tls",
  "timeout": 3000,
  "healthCheck": {
    "type": "tcp",
    "interval": 10000,
    "timeout": 2000,
    "failureThreshold": 3,
    "successThreshold": 2
  },
  "proxyProtocol": {
    "accept": true,
    "trustedCIDRs": ["127.0.0.0/8"],
    "send": "v2"
  },
  "targets": [
    {
      "address": "127.0.0.1:9443",
      "serverNames": ["api.example.com", "*.edge.example.com"],
      "alpn": ["h2", "http/1.1"]
    },
    { "address": "127.0.0.1:9444" }
  ]
}
```

`tls` 不解密流量；`serverNames` 支持精确名称和单标签 `*.` 通配符，`alpn` 为精确匹配，未配置匹配条件的目标是 fallback。

`healthCheck` 的时长单位均为毫秒：`interval` 默认 10 秒、范围 250 毫秒到 10 分钟；`timeout` 默认取 2 秒与 interval 的较小值、范围 50 毫秒到 30 秒且不得超过 interval；失败/恢复阈值默认 3/2，范围均为 1–20。HTTP 检查的 `path` 默认 `/`、只接受最长 2 KiB 的 origin-form，状态码默认接受 200–399，可配置在 100–599 内；不跟随重定向。单份配置最多启用 1,024 个 rule-target 检查任务，进程同时探测不超过 32 个目标。

`trustedCIDRs` 只校验直连 Moto 的上一跳；`proxyProtocol.accept: true` 要求可信上一跳的每条连接都以完整、合法的 PROXY v1/v2 头开始，非可信来源、缺失或畸形头都会被拒绝。`send` 可为 `v1` 或 `v2`；启用 outbound PROXY 时不能同时启用 `prewarm`，因为建池时还不知道客户端地址。

</details>

## 安全与可观测

- 示例配置只监听 `127.0.0.1` 并关闭预热，但各模式已启用 TCP 健康检查；启动后仍会周期连接配置的外部目标，部署前必须替换为自己的上游。
- 进程最多同时处理 4,096 条客户端连接；若监听公网地址，应同时配置精确 `allowlist`，并使用防火墙或安全组限制来源。
- Moto 是透明 TCP 转发器，不替代 TLS、应用认证或网络访问控制；观测端点只能监听数字形式的 loopback 地址。

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/metrics
```

`healthz` 表示进程可响应，`readyz` 只在全部转发监听器就绪且未进入关闭流程时成功。Prometheus 指标覆盖 goroutine、连接数、转发字节与错误、拨号成功率与耗时、拨号隔离舱当前占用/等待/拒绝/等待耗时、Boost 缓存与 Hedge 调度/胜出/延迟/决策耗时、线路 EWMA/熔断、主动健康状态、预热池及当前/排空中的配置 generation。

## WebSocket

Moto 在 TCP 层透明支持 `ws://` 和 `wss://`。HTTP Upgrade、TLS 握手和 WebSocket 帧不会被改写，已建立会话也不受规则 `timeout` 限制；通用四种模式均有 Upgrade、文本帧、Ping/Pong 和长连接端到端测试，`tls` 模式另有真实 ClientHello 分片与原字节重放测试。

长连接会持续占用连接额度，并在 Moto 关闭超过 10 秒后被强制断开。`regex` 只能检查明文 WS 握手前 4 KiB；WSS 的 Host 和路径已加密，但 `tls` 模式可按 SNI/ALPN 分流。WebSocket 规则建议保持 `prewarm: false`。

## 构建与验证

项目要求 Go 1.25.13 或更高的兼容版本。

```bash
# 完整本地门禁
make check

# 与 CI 等价，并交叉构建 Linux、macOS 和 Windows
make ci

# 生成带版本信息的当前平台二进制
make build
./bin/moto --version
```

<details>
<summary><strong>Docker 与 systemd</strong></summary>

Docker 镜像以非 root 用户运行，并从 `/etc/moto/setting.json` 读取挂载的配置；TCP 网关在 Linux 上通常直接使用 host network：

```bash
docker build -t moto:local .
docker run --rm --network host \
  -v "$PWD/config/setting.json:/etc/moto/setting.json:ro" \
  moto:local
```

systemd unit 使用动态用户、只读系统目录和最小网络能力，`systemctl reload moto` 会发送 `SIGHUP`：

```bash
make build
sudo install -m 0755 bin/moto /usr/local/bin/moto
sudo install -d -m 0755 /etc/moto
sudo install -m 0644 config/setting.json /etc/moto/setting.json
sudo install -m 0644 packaging/moto.service /etc/systemd/system/moto.service
sudo systemctl daemon-reload
sudo systemctl enable --now moto
```

</details>

CI 覆盖格式、模块完整性、测试、race、vet、staticcheck、可达漏洞、示例配置、TLS/PROXY/热重载端到端测试和四种通用模式的本机闭环 smoke。推送 `v*` tag 会先通过完整门禁，再生成可复现的多平台压缩包、CycloneDX SBOM、SHA-256 校验文件和自动 release notes；归档内含二进制、README、LICENSE、示例配置和 systemd unit。

<details>
<summary><strong>本地回归与性能采样</strong></summary>

完全本地的回归门禁不访问外网，会报告直连、启动初期（输出中保留名称 `cold`，但同一阶段后续请求会逐渐变热）和热态的成功吞吐与 p50/p95/p99，并采样 CPU、RSS、FD 和 goroutine。这是功能与回归 smoke，不是绝对容量结论：

```bash
python3 test/bench.py --self-contained --mode boost \
  --concurrency 50 --total 500 --warmup 50 \
  --min-success-rate 99 --save /tmp/moto-bench.json
```

大流量双向转发另有逐字节校验的直连/代理同负载基准；它会同时采样 CPU、RSS、FD，并可在 Linux 网络命名空间中加入延迟、抖动、丢包和带宽限制：

```bash
python3 test/bulk_relay_bench.py --direction both \
  --concurrency 4 --connections 8 \
  --bytes-per-direction 256MiB \
  --min-success-rate 100 --save /tmp/moto-bulk.json
```

正式 A/B 应至少重复 5 轮，在相同预热条件下交替默认顺序与 `--proxy-first`，报告中位数、离散程度和全部原始结果。自包含 fixture 与负载生成器共享 Python 进程，适合回归和相对对比；绝对容量测试应把客户端、Moto 和上游分离并绑定 CPU。

Linux 的 `splice` 每个转发方向会占用一根内核 pipe，因此一条双向连接除客户端、上游 socket 外还需要 4 个 pipe FD。按进程 4,096 条连接上限部署时，建议 `LimitNOFILE`/`ulimit -n` 至少为 65,536；随仓库提供的 systemd unit 已配置更高上限。高并发大流量测试应同时观察 FD、RSS 和内核 pipe 内存，而不只看吞吐。

SOCKS5 外部场景也可参数化运行：

```bash
python3 test/bench.py \
  --proxy-host 127.0.0.1 --proxy-port 84 \
  --target-host www.baidu.com --target-port 80 \
  --concurrency 50 --total 500 \
  --min-success-rate 99
```

生产性能评估应同时记录直连基线、成功率、p50/p95/p99 和资源峰值，不能只比较单次最快延迟。

跨地域且有丢包的 Linux 链路可单独 A/B 测试 BBR 等拥塞控制算法，但它们是宿主机或网络命名空间级的全局策略。Moto 不会在进程内加载内核模块或修改 `sysctl`；上线前应使用与业务方向、RTT、丢包率和带宽相同的可回滚测试验证收益。

</details>

## 参考

- [better way for tcp relay](https://hostloc.com/thread-969397-1-1.html)
- [switcher](https://github.com/crabkun/switcher)
