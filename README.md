# Moto

端口转发、正则匹配[端口复用]转发、智能加速、轮询加速。TCP转发，零拷贝转发, 单边加速。
high-speed motorcycle，可以上高速的摩托车🏍️～

## 模式
- 普通模式[normal]：逐一连接目标地址，成功为止       
- 正则模式[regex]：利用正则匹配第一个数据报文来实现端口复用      
- 智能加速[boost]：多线路多TCP主动竞争最优TCP通道，大幅降低网络丢包、中断、切换、出口高低峰的影响!    
- 轮询模式[roundrobin]：分散连接到所有目标地址    

目标为域名时会并发拨号并优先最先连通。

## 演示，自动择路
```
`work from home(china telecom)`:
{"level":"debug","ts":"2022-06-08 12:17:59.444","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49751","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":79}
{"level":"debug","ts":"2022-06-08 12:18:05.050","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49774","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":81}
{"level":"debug","ts":"2022-06-08 12:18:05.493","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49783","targetAddr":"34.124.1.1 [美国 得克萨斯州] :85","decisionTime(ms)":75}
{"level":"debug","ts":"2022-06-08 12:18:05.838","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49792","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":84}
{"level":"debug","ts":"2022-06-08 12:18:09.176","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49810","targetAddr":"34.124.1.1 [美国 得克萨斯州] :85","decisionTime(ms)":81}

`in office(china unicom)`:
{"level":"debug","ts":"2022-06-09 19:24:43.216","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :63847","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":66}
{"level":"debug","ts":"2022-06-09 19:24:49.412","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :63878","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":49}
{"level":"debug","ts":"2022-06-09 19:27:07.666","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :64256","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":55}
```

## 运行
```bash
go run ./run.go                         # 使用默认 config/setting.json
go run ./run.go --config config/setting.json
```
也可通过环境变量：`MOTO_CONFIG=/path/to/your.json`。

## 配置
仅需日志 log、限速/防护 wafs、转发规则 rules。示例见 `config/setting.json`。

## 构建
```bash
# build 
go build ./...
# build for linux
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo

# build for macos
CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo

# build for windows
CGO_ENABLED=0 GOOS=windows go build -a -installsuffix cgo
```

## 常用正则
|协议|正则表达式|
| --- | ---|
|HTTP|^(GET\|POST\|HEAD\|DELETE\|PUT\|CONNECT\|OPTIONS\|TRACE)|
|SSH|^SSH|
|HTTPS(SSL)|^\x16\x03|
|RDP|^\x03\x00\x00|
|SOCKS5|^\x05|
|HTTP代理|(^CONNECT)\|(Proxy-Connection:)|

1、复制到JSON中记得注意特殊符号，例如^\\x16\\x03得改成^\\\\x16\\\\x03**     
2、正则模式的原理是根据客户端建立连接后第一个数据包的特征进行判断是什么协议，该方式不支持连接建立之后服务器主动握手的协议，例如VNC，FTP，MYSQL，被动SSH等。**

## 参考
- better way for tcp relay: https://hostloc.com/thread-969397-1-1.html
- switcher: https://github.com/crabkun/switcher
