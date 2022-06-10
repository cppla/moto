# Moto
high-speed motorcycle，可以上高速的摩托车🏍️～    
端口转发、正则匹配[端口复用]转发、智能加速、轮询加速。TCP转发，零拷贝转发。    

# Usage    
```diff
普通模式[normal]：逐一连接目标地址，成功为止       
正则模式[regex]：利用正则匹配第一个数据报文来实现端口复用      
智能加速[boost]：多线路多TCP主动竞争最优TCP通道，大幅降低网络丢包、中断、切换、出口高低峰的影响!    
轮询模式[roundrobin]：分散连接到所有目标地址    
```

#### 智能加速模式演示，自动择路    

```bash
`work from home(china telecom)`:
{"level":"debug","ts":"2022-06-08 12:17:59.444","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49751","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":79}
{"level":"debug","ts":"2022-06-08 12:18:05.050","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49774","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":81}
{"level":"debug","ts":"2022-06-08 12:18:05.493","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49783","targetAddr":"34.124.1.1 [美国 得克萨斯州] :85","decisionTime(ms)":75}
{"level":"debug","ts":"2022-06-08 12:18:05.838","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49792","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":84}
{"level":"debug","ts":"2022-06-08 12:18:05.838","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49790","targetAddr":"47.241.9.9 [新加坡 阿里云] :85","decisionTime(ms)":84}
{"level":"debug","ts":"2022-06-08 12:18:09.176","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :49810","targetAddr":"34.124.1.1 [美国 得克萨斯州] :85","decisionTime(ms)":81}

`in office(china unicom)`:
{"level":"debug","ts":"2022-06-09 19:24:43.216","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :63847","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":66}
{"level":"debug","ts":"2022-06-09 19:24:49.412","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :63878","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":49}
{"level":"debug","ts":"2022-06-09 19:24:57.356","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :63905","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":55}
{"level":"debug","ts":"2022-06-09 19:27:06.394","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :64245","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":51}
{"level":"debug","ts":"2022-06-09 19:27:07.666","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :64255","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":55}
{"level":"debug","ts":"2022-06-09 19:27:07.666","msg":"establish connection","ruleName":"智能加速","remoteAddr":"127.0.0.1 [本机地址] :64256","targetAddr":"119.28.5.2 [香港 腾讯云] :85","decisionTime(ms)":55}
```

#### 常见协议正则表达式      
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

# Example    
```
{
  "log": {
    "level": "info",
    "path": "./moto.log",
    "version": "1.0.0",
    "date": "2022-06-08"
  },
  "rules": [
    {
      "name": "普通模式",
      "listen": ":81",
      "mode": "normal",
      "timeout": 3000,
      "blacklist": null,
      "targets": [
        {
          "address": "1.1.1.1:85"
        },
        {
          "address": "2.2.2.2:85"
        }
      ]
    },
    {
      "name": "正则模式",
      "listen": ":82",
      "mode": "regex",
      "timeout": 3000,
      "blacklist": null,
      "targets": [
        {
          "regexp": "^(GET|POST|HEAD|DELETE|PUT|CONNECT|OPTIONS|TRACE)",
          "address": "1.1.1.1:80"
        },
        {
          "regexp": "^SSH",
          "address": "2.2.2.2:22"
        }
      ]
    },
    {
      "name": "智能加速",
      "listen": ":83",
      "mode": "boost",
      "timeout": 150,
      "blacklist": null,
      "targets": [
        {
          "address": "1.1.1.1:85"
        },
        {
          "address": "2.2.2.2:85"
        }
      ]
    },
    {
      "name": "轮询模式",
      "listen": ":84",
      "mode": "roundrobin",
      "timeout": 150,
      "blacklist": null,
      "targets": [
        {
          "address": "1.1.1.1:85"
        },
        {
          "address": "2.2.2.2:85"
        }
      ]
    }
  ]
}
```


# Build    
#### build for linux    

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo   

#### build for macos

CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo

#### build for windows 

CGO_ENABLED=0 GOOS=windows go build -a -installsuffix cgo    

# Make Better        

* todo
* better way for tcp relay: https://hostloc.com/thread-969397-1-1.html
* switcher: https://github.com/crabkun/switcher

# Jetbrains    

<a href="https://www.jetbrains.com/?from=cppla"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_square.png" width="100px"></a>
