package controller

import (
	"moto/config"
	"moto/utils"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

var ipCache = cache.New(30*time.Second, 1*time.Minute)

// Listen 根据规则启动 TCP 监听，做基础限流并分发到对应模式。
func Listen(rule *config.Rule, wg *sync.WaitGroup) {
	defer wg.Done()
	initPrewarm(rule)
	//监听
	listener, err := net.Listen("tcp", rule.Listen)
	if err != nil {
		utils.Logger.Error(rule.Name + " failed to listen at " + rule.Listen)
		return
	}
	utils.Logger.Info(rule.Name + " listing at " + rule.Listen)
	for {
		//处理客户端连接
		conn, err := listener.Accept()
		if err != nil {
			utils.Logger.Error(rule.Name + " failed to accept at " + rule.Listen)
			time.Sleep(time.Second * 1)
			continue
		}
		//判断黑名单
		if len(rule.Blacklist) != 0 {
			clientIP := conn.RemoteAddr().String()
			clientIP = clientIP[0:strings.LastIndex(clientIP, ":")]
			if rule.Blacklist[clientIP] {
				utils.Logger.Info(rule.Name + " disconnected ip in blacklist: " + clientIP)
				conn.Close()
				continue
			}
		}
		//todo: WAF策略：限制单一IP 30秒内请求不能超过200次, no debug,wait fix
		clientIP := conn.RemoteAddr().String()
		clientIP = clientIP[0:strings.LastIndex(clientIP, ":")]
		if count, found := ipCache.Get(clientIP); found && count.(int) >= 200 {
			utils.Logger.Warn("WAF: too many requests from " + clientIP)
			conn.Close()
			continue
		} else {
			if found {
				ipCache.Increment(clientIP, 1)
			} else {
				ipCache.Set(clientIP, 1, cache.DefaultExpiration)
			}
		}
		//选择运行模式
		switch rule.Mode {
		case "normal":
			go HandleNormal(conn, rule)
		case "regex":
			go HandleRegexp(conn, rule)
		case "boost":
			go HandleBoost(conn, rule)
		case "roundrobin":
			go HandleRoundrobin(conn, rule)
		}
	}
}
