package controller

import (
	"go.uber.org/zap"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"
)

var tcpCounter = 0

func HandleRoundrobin(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	v := rule.Targets[tcpCounter % len(rule.Targets)]
	if tcpCounter >= 100*len(rule.Targets) {
		tcpCounter = 1
	} else {
		tcpCounter += 1
	}

	roundrobinBegin := time.Now()
	target, err := net.Dial("tcp", v.Address)
	if err != nil {
		utils.Logger.Error("unable to establish connection, Smart switch boost mode",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.String("targetAddr", v.Address),
			zap.Int64("failedTime(ms)", time.Now().Sub(roundrobinBegin).Milliseconds()))
		HandleBoost(conn, rule)
		return
	}
	utils.Logger.Debug("establish connection",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()),
		zap.Int64("roundrobinTime(ms)", time.Now().Sub(roundrobinBegin).Milliseconds()))

	defer target.Close()

	go io.Copy(conn, target)
	io.Copy(target, conn)
}
