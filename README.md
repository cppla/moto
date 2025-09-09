# Moto

端口转发、正则匹配[端口复用]转发、智能加速、轮询加速。支持零拷贝转发与弱网加速（多隧道复用 + 自适应多倍发送）。high-speed motorcycle，可以上高速的摩托车🏍️～

## 特性
- 四种模式：normal / regex / boost / roundrobin
- 弱网加速：
  - 持久多 TCP 隧道 + 多路复用，避免频繁建连
  - 双向“暴力发包”：上行/下行均可多倍重复发送（1~5x）
  - 自适应倍率：根据观测丢包率动态选择 1~5 倍；无需手动设置 duplication
  - 健康度优选：基于 RTT/抖动（EWMA）选择更健康的隧道作为主路径
- 正则端口复用：基于首包正则，按协议特征路由不同后端

## 模式说明
- normal：按 targets 顺序逐一尝试，首个连通即转发
- regex：读取首包，在 `targets[].regexp` 中匹配成功者即转发
- boost：对所有 targets 并发拨号，谁先连上用谁
- roundrobin：轮询选择一个 target，失败可回落至 boost

以上四种模式在“启用加速器 client 角色”时，实际对后端的连接通过“复用流”走持久隧道，由“加速器 server 角色”代拨目标，达到复用与弱网加速效果。

## 自适应发包倍率（默认映射）
- 丢包率 < 1%  -> 1x
- 丢包率 < 10% -> 2x
- 丢包率 < 20% -> 3x
- 丢包率 < 30% -> 4x
- 丢包率 ≥ 30% -> 5x

说明：系统在固定时间窗内统计“发送帧数 vs 收到 ACK 帧数”估算丢包率，并按映射选择新的倍率；上下行均生效。倍率上限为 5。

## 配置（片段）
```json
{
  "accelerator": {
    "enabled": true,
    "role": "client",
    "remote": "1.2.3.4:9900",
    "listen": ":9900",
    "tunnels": 0,
    "duplication": 0,
    "frameSize": 8192
  },
  "lossAdaptation": {
    "enabled": true,
    "windowSeconds": 10,
    "probeIntervalMs": 500,
    "rules": [
      {"lossBelow": 1,  "dup": 1},
      {"lossBelow": 10, "dup": 2},
      {"lossBelow": 20, "dup": 3},
      {"lossBelow": 30, "dup": 4},
      {"lossBelow": 101, "dup": 5}
    ]
  }
}
```
- 启用自适应后无需手动设置 tunnels/duplication，系统会根据映射选择发送倍率，并基于 RTT/抖动择优隧道。

## 运行与帮助
- 加速服务器（server 侧）：
  - `accelerator.enabled=true`，`role=server`，`listen=":9900"`
- 加速客户端（client 侧）：
  - `accelerator.enabled=true`，`role=client`，`remote="<server-ip>:9900"`
  - 四种转发规则仍在客户端监听入口；出站改走隧道复用流
- 查看帮助：
```bash
./moto --help
```

## 常见协议正则表达式
| 协议 | 正则 |
| --- | --- |
| HTTP | ^(GET|POST|HEAD|DELETE|PUT|CONNECT|OPTIONS|TRACE) |
| HTTP代理 | (^CONNECT)|(Proxy-Connection:) |

## 构建
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
- 帧协议（SYN/DATA/FIN/ACK/PING/PONG），支持乱序重组与重复去重
- 自适应窗口统计 sent/ack 估算丢包率，按规则设定 1..5 倍重复
- 健康度：基于 RTT 与抖动的 EWMA 作为评分，优先选择更健康隧道

## 参考与致谢
- better way for tcp relay: https://hostloc.com/thread-969397-1-1.html
- switcher: https://github.com/crabkun/switcher
- JetBrains: 
  <a href="https://www.jetbrains.com/?from=cppla"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_square.png" width="100px"></a>
