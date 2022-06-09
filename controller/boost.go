package controller

import (
	"go.uber.org/zap"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"
)

func HandleBoost(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	decusionBegin := time.Now()
	//智能选择最先连上的优质线路。 未用的TCP主动关闭连接。
	//决策时间超过timeout主动关闭，超过300ms🚀没有意义
	switchBetter := make(chan net.Conn)
	for _, v := range rule.Targets {
		go func(address string) {
			if tryGetQuickConn, err := net.Dial("tcp", address); err == nil {
				timeout := time.NewTimer(time.Millisecond * time.Duration(rule.Timeout))
				select {
				case switchBetter <- tryGetQuickConn:
				case <-timeout.C:
					tryGetQuickConn.Close()
				}
			}
		}(v.Address)
	}
	//全部连接失败： 最恶劣的情况，全部线路延迟大或中断。主动结束该TCP协程任务！
	var target net.Conn
	timeout := time.NewTimer(time.Millisecond * time.Duration(rule.Timeout))
	select {
	case target = <-switchBetter:
	case <-timeout.C:
		utils.Logger.Error("Boost Decision Failed！All Online Network Disconnect!",
			zap.String("ruleName", rule.Name))
		return
	}

	utils.Logger.Debug("establish connection",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()),
		zap.Int64("decisionTime(ms)", time.Now().Sub(decusionBegin).Milliseconds()))

	defer target.Close()

	go io.Copy(conn, target)
	io.Copy(target, conn)
}
