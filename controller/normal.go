package controller

import (
	"io"
	"moto/config"
	"moto/utils"
	"net"

	"go.uber.org/zap"
)

func HandleNormal(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	var target net.Conn
	//正常模式下挨个连接直到成功连接
	for _, v := range rule.Targets {
		c, _, err := DialAccelerated(v.Address)
		if err != nil {
			utils.Logger.Error("无法建立连接，尝试下一个目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", v.Address))
			continue
		}
		target = c
		break
	}
	if target == nil {
		utils.Logger.Error("所有目标均连接失败，无法处理连接",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", conn.RemoteAddr().String()))
		return
	}
	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()))

	defer target.Close()

	go func() {
		io.Copy(conn, target)
		conn.Close()
		target.Close()
	}()
	io.Copy(target, conn)
}
