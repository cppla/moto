package controller

import (
	"context"
	"go.uber.org/zap"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"
)

func HandleBoost(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	decisionBegin := time.Now()
	//智能选择最先连上的优质线路。 未用的TCP主动关闭连接。
	//决策时间超过timeout主动关闭，超过300ms🚀没有意义
	//todo： 这里如何保持长久连接？
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switchBetter := make(chan net.Conn, 1)
	for _, v := range rule.Targets {
		go func(address string) {
			if tryGetQuickConn, err := net.Dial("tcp", address); err == nil {
				select {
				case switchBetter <- tryGetQuickConn:
				case <-ctx.Done():
					tryGetQuickConn.Close()
				}
			}
		}(v.Address)
	}
	//全部连接失败： 最恶劣的情况，全部线路延迟大或中断。
	var target net.Conn
	dtx, dance := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(rule.Timeout))
	defer dance()
	select {
	case target = <-switchBetter:
		cancel()
	case <-dtx.Done():
		utils.Logger.Error("Boost Decision Failed！All Online Network Disconnect!",
			zap.String("ruleName", rule.Name))
		return
	}

	utils.Logger.Debug("ESTABLISHED",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()),
		zap.Int64("decisionTime(ms)", time.Now().Sub(decisionBegin).Milliseconds()))

	defer target.Close()

	go func() {
		io.Copy(conn, target)
		conn.Close()
		target.Close()
	}()
	io.Copy(target, conn)
}
