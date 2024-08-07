package controller

import (
	"go.uber.org/zap"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sync/atomic"
	"time"
)

var tcpCounter uint64

func HandleRoundrobin(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	index := atomic.AddUint64(&tcpCounter, 1) % uint64(len(rule.Targets))
	if tcpCounter >= 100*uint64(len(rule.Targets)) {
		atomic.StoreUint64(&tcpCounter, 1)
	}

	v := rule.Targets[index]

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

	go func() {
		io.Copy(conn, target)
		conn.Close()
		target.Close()
	}()
	io.Copy(target, conn)
}
