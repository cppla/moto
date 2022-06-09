package controller

import (
	"go.uber.org/zap"
	"io"
	"moto/config"
	"moto/utils"
	"net"
)

func HandleNormal(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	var target net.Conn
	//正常模式下挨个连接直到成功连接
	for _, v := range rule.Targets {
		c, err := net.Dial("tcp", v.Address)
		if err != nil {
			utils.Logger.Error("unable to establish connection, try next target",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", v.Address))
			continue
		}
		target = c
		break
	}
	if target == nil {
		utils.Logger.Error("all targets connected failed，so can't to handle connection",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", conn.RemoteAddr().String()))
		return
	}
	utils.Logger.Debug("establish connection",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()))

	defer target.Close()

	go io.Copy(conn, target)
	io.Copy(target, conn)
}
