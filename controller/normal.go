package controller

import (
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

func HandleNormal(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	var target net.Conn
	//正常模式下挨个连接直到成功连接
	for _, v := range rule.Targets {
		c, usedAccel, err := DialAccelerated(v.Address)
		if err != nil {
			utils.Logger.Error("无法建立连接，尝试下一个目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.String("targetAddr", v.Address))
			continue
		}
		// 如果未使用加速器，启用轻量级单边写入加固（重复 + 小片）
		if !usedAccel {
			target = newOneSidedConn(c)
		} else {
			target = c
		}
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

// one-sided acceleration: duplicate small write fragments to mitigate random loss along the access hop.
// This is best-effort and only applies on client egress when server is not available.
type oneSidedConn struct {
	net.Conn
}

func newOneSidedConn(c net.Conn) net.Conn {
	// tcp tuning
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return &oneSidedConn{Conn: c}
}

func (o *oneSidedConn) Write(p []byte) (int, error) {
	// simple fragmentation: cap fragment to 1200 bytes to fit typical MTU, and duplicate on send
	const frag = 1200
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > frag {
			n = frag
		}
		chunk := p[written : written+n]
		// primary write
		if _, err := o.Conn.Write(chunk); err != nil {
			return written, err
		}
		// duplicate once with tiny delay to reduce collision
		time.Sleep(2 * time.Millisecond)
		_, _ = o.Conn.Write(chunk)
		written += n
	}
	return written, nil
}
