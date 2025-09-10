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
	enableDup bool
	dupBudget int           // bytes left for duplication (only first N bytes)
	ewmaBlock time.Duration // EWMA of write blocking time
	winBytes  int
	winChunks int
	lastAdj   time.Time
}

func newOneSidedConn(c net.Conn) net.Conn {
	// tcp tuning
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	// adaptive: if dial was very fast, disable duplication; else enable
	dup := true
	if hl, ok := c.(interface{ DialLatency() time.Duration }); ok {
		if hl.DialLatency() < 40*time.Millisecond {
			dup = false
		}
	}
	return &oneSidedConn{Conn: c, enableDup: dup, dupBudget: 64 * 1024, lastAdj: time.Now()}
}

func (o *oneSidedConn) Write(p []byte) (int, error) {
	// simple fragmentation: cap fragment to 1200 bytes to fit typical MTU, optional duplicate on send
	const frag = 1200
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > frag {
			n = frag
		}
		chunk := p[written : written+n]
		// primary write with blocking time measurement
		t0 := time.Now()
		if _, err := o.Conn.Write(chunk); err != nil {
			return written, err
		}
		dt := time.Since(t0)
		if o.ewmaBlock == 0 {
			o.ewmaBlock = dt
		} else {
			const alpha = 0.2
			o.ewmaBlock = time.Duration(alpha*float64(dt) + (1-alpha)*float64(o.ewmaBlock))
		}
		o.winBytes += n
		o.winChunks++
		// duplicate once with tiny delay to reduce collision (only if enabled and with budget)
		if o.enableDup && o.dupBudget > 0 {
			time.Sleep(2 * time.Millisecond)
			_, _ = o.Conn.Write(chunk)
			o.dupBudget -= len(chunk)
			if o.dupBudget < 0 {
				o.dupBudget = 0
			}
		}
		// periodic reassessment
		if time.Since(o.lastAdj) > 500*time.Millisecond || o.winChunks >= 32 {
			o.reassess()
		}
		written += n
	}
	return written, nil
}

// reassess toggles duplication based on EWMA of blocking time and adjusts budget.
func (o *oneSidedConn) reassess() {
	fast := 2 * time.Millisecond
	slow := 8 * time.Millisecond
	if o.ewmaBlock > 0 {
		if o.ewmaBlock <= fast {
			o.enableDup = false
			if o.dupBudget > 16*1024 {
				o.dupBudget -= 16 * 1024
			} else if o.dupBudget > 0 {
				o.dupBudget /= 2
			}
		} else if o.ewmaBlock >= slow {
			o.enableDup = true
			o.dupBudget += 32 * 1024
			if o.dupBudget > 256*1024 {
				o.dupBudget = 256 * 1024
			}
		}
	}
	o.winBytes = 0
	o.winChunks = 0
	o.lastAdj = time.Now()
}
