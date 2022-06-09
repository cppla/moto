# Moto
high-speed motorcycle，可以上高速的摩托车🏍️～    
端口转发、正则匹配[端口复用]转发、智能加速、轮询加速。TCP转发，零拷贝转发。    

# Usage    
普通模式[normal]：逐一连接目标地址，成功为止       
正则模式[regex]：利用正则匹配第一个数据报文来实现端口复用      
<font color="red">智能加速[boost]：多线路多TCP主动竞争最优TCP通道，大幅降低丢包、中断、网络切换，网络出口高低峰的影响</font>     
轮询模式[roundrobin]：分散连接到所有目标地址    

#### 常见协议正则表达式      
|协议|正则表达式|
| --- | ---|
|HTTP|^(GET\|POST\|HEAD\|DELETE\|PUT\|CONNECT\|OPTIONS\|TRACE)|
|SSH|^SSH|
|HTTPS(SSL)|^\x16\x03|
|RDP|^\x03\x00\x00|
|SOCKS5|^\x05|
|HTTP代理|(^CONNECT)\|(Proxy-Connection:)|

**1、复制到JSON中记得注意特殊符号，例如^\\x16\\x03得改成^\\\\x16\\\\x03**     
**2、正则模式的原理是根据客户端建立连接后第一个数据包的特征进行判断是什么协议，该方式不支持连接建立之后服务器主动握手的协议，例如VNC，FTP，MYSQL，被动SSH等。**

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
