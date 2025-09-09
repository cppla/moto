# Moto

端口转发、正则匹配[端口复用]转发、智能加速、轮询加速。支持零拷贝转发与弱网加速（多隧道复用 + 自适应多倍发送 + 选择性重传）。high-speed motorcycle，可以上高速的摩托车🏍️～

## 特性
- 四种模式：normal / regex / boost / roundrobin
- 弱网加速：
  - 持久多隧道（TCP/QUIC）+ 多路复用，避免频繁建连
  - 上行可多倍重复（1~5x）；下行禁用重复，采用 NACK 选择性重传
  - 自适应倍率：根据观测丢包率动态选择 1~5 倍；无需手动设置 duplication
  - 健康度优选：基于 RTT/抖动（EWMA）选择更健康的隧道作为主路径
  - 可选 QUIC 传输：更低时延与抗抖动（基于 UDP，需放行 UDP 端口）
- 正则端口复用：基于首包正则，按协议特征路由不同后端

## 模式说明
- normal：按 targets 顺序逐一尝试，首个连通即转发
- regex：读取首包，在 `targets[].regexp` 中匹配成功者即转发
- boost：对所有 targets 并发拨号，谁先连上用谁
- roundrobin：轮询选择一个 target，失败可回落至 boost

以上四种模式在“启用加速器 client 角色”时，实际对后端的连接通过“复用流”走持久隧道，由“加速器 server 角色”代拨目标，达到复用与弱网加速效果。

## 自适应发包倍率（默认映射）
- 丢包率 < 0.5%  -> 1x
- 丢包率 < 5%    -> 2x
- 丢包率 < 10%   -> 3x
- 丢包率 < 20%   -> 4x
- 丢包率 ≥ 20%   -> 5x

说明：系统在固定时间窗内统计“发送帧数 vs 收到 ACK 帧数”估算丢包率，并按映射选择新的倍率；仅上行重复生效，下行通过 NACK 选择性重传。倍率上限为 5。

## 配置（片段）
```json
{
  "accelerator": {
    "enabled": true,
  "role": "client",
  "remotes": ["1.2.3.4:9900", "2.3.4.5:9900"],
  "tunnels": 3,
  "duplication": 0,
  "frameSize": 32768,
  "transport": "tcp"
  },
  "lossAdaptation": {
    "enabled": true,
    "windowSeconds": 10,
    "probeIntervalMs": 1000,
    "rules": [
      {"lossBelow": 0.5,  "dup": 1},
      {"lossBelow": 5,    "dup": 2},
      {"lossBelow": 10,   "dup": 3},
      {"lossBelow": 20,   "dup": 4},
      {"lossBelow": 101,  "dup": 5}
    ]
  }
}
```
- 启用自适应后无需手动设置 tunnels/duplication，系统会根据映射选择发送倍率，并基于 RTT/抖动择优隧道。

## 运行与帮助
- 加速服务器（server 侧）：
  - `accelerator.enabled=true`，`role=server`，`listen=":9900"`
- 加速客户端（client 侧）：
  - `accelerator.enabled=true`，`role=client`，`remotes=["<server-ip-1>:9900","<server-ip-2>:9900"]`
  - 四种转发规则仍在客户端监听入口；出站改走隧道复用流
- 查看帮助：
```bash
./moto --help
```

## QUIC 模式快速上手

示例配置（服务端）：
```json
{
  "accelerator": {
    "enabled": true,
    "role": "server",
    "listen": ":9900",
    "tunnels": 3,
    "frameSize": 32768,
    "transport": "quic"
  },
  "rules": []
}
```

示例配置（客户端，本地回环）：
```json
{
  "accelerator": {
    "enabled": true,
    "role": "client",
    "remotes": ["127.0.0.1:9900"],
    "tunnels": 3,
    "frameSize": 32768,
    "transport": "quic"
  },
  "rules": [
    {
      "name": "loopback",
      "listen": ":18080",
      "mode": "normal",
      "targets": [{"address": "127.0.0.1:18081"}],
      "timeout": 3000
    }
  ]
}
```

本地验证（一个终端运行 server，一个终端运行 client，再起一个目标服务）：
- 放行/可用 UDP 9900（QUIC 使用 UDP）。
- 分别以 `--config` 指向上述 JSON 运行，两侧都打印出 “server/client tunnel up (quic)” 日志后，用 `nc` 向客户端监听端口发数据，在目标侧能看到收到的数据。

## 多路径最佳实践（remotes）
- 选择“不同网络路径”的远端：
  - 不同机房/地域/运营商/ASN；或同城不同出口。
  - 端口也可区分（如 9900/9901/443/8443），以穿越不同中间设备策略。
- 客户端 `tunnels` 建议与 `remotes` 数量一致或更大，系统会对隧道轮询分配远端。
- 健康度优选已内置（RTT/抖动 EWMA），主路径优先更健康隧道；弱网下可保留自适应重复，小丢包主要靠选择性重传（NACK）。
- 单路径或同瓶颈下重复意义有限，建议尽量创造真实多路径，否则保持 duplication=1 并依赖 NACK。

## QUIC/UDP 放行与注意事项
- 服务端需放行“监听端口的 UDP”（例如 9900/UDP）。
- 云厂商安全组/防火墙/NAT 设备需要同时允许 UDP；客户端侧一般为出站 UDP。
- 证书：当前内置自签名证书用于开发/内网；生产建议替换为正式证书并启用校验（后续将提供可配置校验策略）。
- 资源与内核：高并发场景可适当调大系统 UDP 缓冲（Linux: rmem_max/wmem_max），并关注 CPU/内存占用。

## 调参建议
- 良好网络：
  - duplication=1（或启用自适应但采用保守映射，已默认），frameSize=32768。
  - 下行不做重复（已内置禁用），以提升大对象下载吞吐。
- 弱网（随机/突发丢包）：
  - 保持自适应开启；主要依靠 NACK 修补，必要时提升 tunnels 并扩展 remotes。
- 极端弱网：
  - 可增加 remotes 数量构造更多路径；后续可考虑开启 FEC（如 8+1 XOR）功能。

## 验证清单
- 启动日志出现：
  - server: `ACC: server listening (tcp|quic)` 以及 `server tunnel up`（QUIC 模式下为 stream）。
  - client: `ACC: tunnel up`，并周期打印健康度/自适应调节 debug 日志。
- 业务连通：通过客户端规则监听端口发起连接，目标后端有流量，客户端日志可见 ACK/NACK 正常往返。


## 常见协议正则表达式
| 协议 | 正则 |
| --- | --- |
| HTTP | ^(GET|POST|HEAD|DELETE|PUT|CONNECT|OPTIONS|TRACE) |
| HTTP代理 | (^CONNECT)|(Proxy-Connection:) |

## 构建（Go 1.21+）
- linux：
```bash
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo
```
- macOS：
```bash
CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo
```
- windows：
```bash
CGO_ENABLED=0 GOOS=windows go build -a -installsuffix cgo
```

## 设计要点
- 帧协议（SYN/DATA/FIN/ACK/PING/PONG/NACK），支持乱序重组、重复去重与选择性重传
- 自适应窗口统计 sent/ack 估算丢包率，按规则设定 1..5 倍“上行重复”；下行禁用重复，靠 NACK 补丢
- 健康度：基于 RTT 与抖动的 EWMA 作为评分，优先选择更健康隧道

## 参考与致谢
- better way for tcp relay: https://hostloc.com/thread-969397-1-1.html
- switcher: https://github.com/crabkun/switcher
- JetBrains: 
  <a href="https://www.jetbrains.com/?from=cppla"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_square.png" width="100px"></a>
