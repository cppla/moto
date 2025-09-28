package controller

import (
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

// HandleNormal 会依次尝试各个目标，并在成功的连接上挂载自适应的单边加速。
func HandleNormal(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	var target net.Conn
	//正常模式下挨个连接直到成功连接
	for _, v := range rule.Targets {
		c, err := outboundDial(v.Address)
		if err != nil {
			utils.Logger.Error("无法建立连接，尝试下一个目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", v.Address))
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
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
