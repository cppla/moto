package controller

import (
	"bytes"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

func HandleRegexp(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	//正则模式下需要客户端的第一个数据包判断特征，所以需要设置一个超时
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(rule.Timeout)))
	//获取第一个数据包
	firstPacket := new(bytes.Buffer)
	if _, err := io.CopyN(firstPacket, conn, 4096); err != nil {
		utils.Logger.Error("unable to handle connection, failed to get first packet",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.Error(err))
		return
	}

	var target net.Conn
	//挨个匹配正则
	for _, v := range rule.Targets {
		if !v.Re.Match(firstPacket.Bytes()) {
			continue
		}
		c, _, err := DialAccelerated(v.Address)
		if err != nil {
			utils.Logger.Error("unable to establish connection",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", v.Address))
			continue
		}
		target = c
		break
	}
	if target == nil {
		utils.Logger.Error("can't match target , so can't handle connection",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", conn.RemoteAddr().String()))
		return
	}

	utils.Logger.Debug("establish connection",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("targetAddr", target.RemoteAddr().String()))
	//匹配到了，去除掉刚才设定的超时
	conn.SetReadDeadline(time.Time{})
	//把第一个数据包发送给目标
	io.Copy(target, firstPacket)

	defer target.Close()

	go func() {
		io.Copy(conn, target)
		conn.Close()
		target.Close()
	}()
	io.Copy(target, conn)
}
