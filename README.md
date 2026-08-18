# Moto

Moto 是一个轻量级、自适应的 TCP 网关：把多个上游地址组合成一个本地入口，提供故障切换、首包分类、线路竞速和轮询分流。

## 运行模式

| 模式 | 行为 |
| --- | --- |
| `normal` | 按配置顺序连接目标，直到成功 |
| `regex` | 在最多 4 KiB 的客户端首包中匹配规则，再转发完整字节流 |
| `boost` | 按 EWMA 评分竞速 Top-2 目标，缓存胜出线路并定期探索其他线路 |
| `roundrobin` | 按规则独立轮询；单个目标失败时回退到竞速选择 |

域名拨号交给 Go TCP Dialer 处理 IPv4/IPv6 快速回退。可选预热池用于降低已知目标的后续建连时间；线路重新验证始终使用新连接，避免把池命中速度误认为线路速度。每条线路记录拨号延迟 EWMA；连续三次拨号失败或可明确归因于上游的转发失败后进入 5 秒熔断冷却，重复失败时指数增长到最多 60 秒，冷却结束仅允许一个半开探针。竞速取消的败者不会被误记为故障。

预热受三层硬限制：每个目标最多 4 个并发补充拨号、进程最多 32 个并发预热拨号、单份配置最多 256 个唯一预热目标。Unix 在取用空闲连接前通过不消费数据的 `MSG_PEEK` 探测 socket，已收到 FIN/RST 或状态不确定的连接不会交给请求；Windows 及尚未实现安全探测的平台会保守禁用复用并使用新连接。线路熔断期间还会清空旧连接并暂停补充，避免后台任务绕过故障保护。预热仍是面向已知兼容协议的可选优化，不应替代新建连接的端到端健康验证。

## 安全默认

示例配置只监听 `127.0.0.1`，并限制每规则连接数和单 IP 连接数；服务进程另有 4,096 条客户端连接的硬上限。若要监听公网地址，请同时配置精确的 `allowlist`，并在主机防火墙或安全组中再次限制来源。

Moto 是透明 TCP 转发器，本身不替代 TLS、应用层认证或网络访问控制。

示例配置默认关闭所有规则的预热，不会仅因启动就主动连接外部 `targets`。只有确认上游协议允许 TCP 连接在发送业务数据前保持空闲时，才应显式设置 `prewarm: true`。

观测端点也只允许配置为数字形式的 loopback 地址，配置成公网地址或主机名会直接校验失败。

## 运行

```bash
# 启动前只检查配置；不会监听端口
go run . --config config/setting.json --check-config

# 启动
go run . --config config/setting.json
```

配置路径优先级为 `--config`、`MOTO_CONFIG`、`config/setting.json`。收到 `SIGINT` 或 `SIGTERM` 后，Moto 会停止接受新连接；现有连接最多获得 10 秒的优雅退出窗口，随后其处理上下文和 socket 会被强制关闭。

## 配置

```json
{
  "log": {
    "level": "info",
    "path": "./moto.log"
  },
  "metrics": {
    "enabled": true,
    "listen": "127.0.0.1:9090"
  },
  "rules": [
    {
      "name": "web-failover",
      "listen": "127.0.0.1:8080",
      "mode": "normal",
      "prewarm": false,
      "timeout": 3000,
      "allowlist": ["127.0.0.0/8", "::1/128"],
      "maxConnections": 4096,
      "maxConnectionsPerIP": 1024,
      "blacklist": null,
      "targets": [
        { "address": "server-a.example.com:80" },
        { "address": "server-b.example.com:80" }
      ]
    }
  ]
}
```

配置加载采用严格校验：未知字段、未知模式、重复规则名、重复监听地址、非法 CIDR、空目标和非法正则都会阻止进程启动。所有监听地址会先一次性绑定；任意端口绑定失败时，不会留下部分规则继续运行。

`timeout` 单位为毫秒：在 `normal` 模式中是整组目标的拨号期限；在 `regex` 模式中分别限制首包分类和匹配后整组目标的拨号（两个阶段各自计时）；在 `boost` 及轮询回退中是竞速决策期限。省略或设为 `0` 时，正则模式默认 500 毫秒，其余模式默认 3 秒。

## WebSocket

Moto 在 TCP 层透明支持 `ws://` 和 `wss://`：HTTP Upgrade/TLS 握手及后续 WebSocket 帧都不会被解析或改写，连接建立后的会话时长也不受上述拨号或首包 `timeout` 限制。仓库的端到端测试覆盖四种运行模式下的 Upgrade、文本帧回显、Ping/Pong，以及超过规则超时后继续传输。

WebSocket 长连接会持续占用全局、规则和单 IP 的连接额度。Moto 关闭时仍遵循 10 秒优雅退出窗口，届时尚未结束的连接会被强制关闭，因此客户端应实现断线重连。

`regex` 模式只能检查明文 WS 握手前 4 KiB；若要按 `Host`、路径或 `Upgrade: websocket` 分流，表达式必须等待对应 Header 到达，不能只写会提前命中的通用 `^GET`。WSS 握手经过 TLS 加密，Moto 不终止 TLS，也不能从中读取 HTTP Host/Path；这类分流需要专门的 SNI 解析或在 Moto 前终止 TLS。WebSocket 规则建议默认保持 `prewarm: false`，除非已确认上游允许业务握手前的空闲 TCP 连接。

## 健康检查与指标

启用 `metrics` 后提供三个仅本机可访问的 HTTP 端点：

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/metrics
```

`healthz` 表示进程仍能响应；`readyz` 只在全部转发监听器启动且尚未进入关闭流程时返回成功。Prometheus 文本指标包含 goroutine 数量、连接接收/拒绝/活跃数、双向转发字节和错误、拨号成功率与耗时、Boost 缓存命中、线路 EWMA/熔断状态，以及预热池 idle/warming 数量。省略 `metrics` 或设置 `enabled: false` 时不会启动观测端口；启用但省略 `listen` 时默认使用 `127.0.0.1:9090`。

### 首包匹配示例

| 协议 | JSON 中的正则表达式 |
| --- | --- |
| HTTP | `^(GET|POST|HEAD|DELETE|PUT|CONNECT|OPTIONS|TRACE)` |
| SSH | `^SSH` |
| TLS | `^\\x16\\x03` |
| RDP | `^\\x03\\x00\\x00` |
| SOCKS5 | `^\\x05` |

TCP 是字节流，不保证一次读取就是一个完整“数据包”。Moto 会增量读取并在任一规则匹配后立即停止分类。该模式仍只适用于客户端先发送数据的协议；VNC、FTP、MySQL 等服务端先握手协议不能依靠客户端首包区分。TLS 域名分流更适合后续增加专门的 SNI 解析，而不是维护复杂二进制正则。

## 构建与验证

项目要求 Go 1.25.13 或更高的兼容版本；使用 `GOTOOLCHAIN=auto` 时 Go 命令会自动选择该补丁工具链。

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...

# 完整本地分析门禁（含 workflow、模块完整性、staticcheck、govulncheck、示例配置、脚本语法与四模式本机闭环 smoke）
make check

# 与 CI 等价：在上述门禁后再构建四个平台产物
make ci

# 带版本、提交和构建时间信息的二进制
make build
./bin/moto --version
```

CI 固定使用 Go 1.25.13，并覆盖格式、模块完整性、测试、vet、race、staticcheck、可达漏洞、示例配置、四种模式的本机闭环基准门禁，以及 Linux amd64/arm64、macOS arm64、Windows amd64 构建。推送符合语义版本的 `v*` tag 会生成可复现的多平台压缩包、每个平台对应且时间归一化的 CycloneDX SBOM、SHA-256 校验文件和自动 release notes。

完全本地的回归门禁会自动启动临时 HTTP 上游和 Moto，不访问外网；它分别报告直连、冷态、热态的吞吐与 p50/p95/p99，并采样 Moto 的 CPU、RSS、FD 和 goroutine 峰值：

```bash
python3 test/bench.py --self-contained --mode boost \
  --concurrency 50 --total 500 --warmup 50 \
  --min-success-rate 99 --save /tmp/moto-bench.json
```

SOCKS5 场景的并发检查脚本支持参数化地址和成功率门禁：

```bash
python3 test/bench.py \
  --proxy-host 127.0.0.1 --proxy-port 84 \
  --target-host www.baidu.com --target-port 80 \
  --concurrency 50 --total 500 \
  --min-success-rate 99
```

生产性能结论应同时记录冷/热连接、直连基线、成功率、p50/p95/p99、CPU、RSS、FD 和 goroutine 数量，避免只比较单次最快延迟。

## 参考

- [better way for tcp relay](https://hostloc.com/thread-969397-1-1.html)
- [switcher](https://github.com/crabkun/switcher)
