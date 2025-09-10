# Moto

轻量端口转发与单边加速。支持 normal / regex / boost / roundrobin 四种模式。

## 特性
- 单边加速（默认）：并发解析/拨号择先连通；写入按 ~1200B 分片并重复一次。
- 正则复用：按首包正则路由不同后端。

## 模式
- normal：按 targets 顺序逐一尝试，首个连通即转发。
- regex：读取首包，匹配 `targets[].regexp` 后转发。
- boost：对所有 targets 并发拨号，谁先连上用谁。
- roundrobin：轮询一个 target，失败可回落 boost。

目标为域名时会并发拨号并优先最先连通。

## 运行
```bash
go run ./run.go                         # 使用默认 config/setting.json
go run ./run.go --config config/setting.json
```
也可通过环境变量：`MOTO_CONFIG=/path/to/your.json`。

## 配置
仅需日志 log、限速/防护 wafs、转发规则 rules。示例见 `config/setting.json`。

## 构建（Go 1.21+）
```bash
go build ./...
```

## 常用正则
| 协议 | 正则 |
| --- | --- |
| HTTP | ^(GET|POST|HEAD|DELETE|PUT|CONNECT|OPTIONS|TRACE) |
| HTTP 代理 | (^CONNECT)|(Proxy-Connection:) |

## 参考
- better way for tcp relay: https://hostloc.com/thread-969397-1-1.html
- switcher: https://github.com/crabkun/switcher
- JetBrains: <a href="https://www.jetbrains.com/?from=cppla"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_square.png" width="100px"></a>
