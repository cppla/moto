package controller

import (
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sort"
	"time"

	"go.uber.org/zap"
)

// HandleNormal 会依次尝试各个目标，并在成功的连接上挂载自适应的单边加速。
func HandleNormal(conn net.Conn, rule *config.Rule) {
	defer conn.Close()

	var target net.Conn
	//正常模式下挨个连接直到成功连接
	for _, v := range rule.Targets {
		c, usedAccel, err := outboundDial(v.Address)
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

// oneSidedConn 会在出站链路上做尽力复制，用来对抗随机丢包。
// 仅对限定预算内的小块数据做复制，并根据实时网络状况动态调节。
type oneSidedConn struct {
	net.Conn
	enableDup bool
	dupBudget int           // 剩余可复制的字节预算（仅前 N 字节）
	ewmaBlock time.Duration // 写阻塞耗时的指数滑动平均
	winBytes  int
	winChunks int
	lastAdj   time.Time
	blockHist [64]int64
	histCount int
	histIdx   int
	dupDelay  time.Duration
}

// newOneSidedConn 负责打开 TCP 保活参数，并根据拨号耗时决定是否启用复制。
func newOneSidedConn(c net.Conn) net.Conn {
	// TCP 参数调整
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	// 自适应策略：拨号超快就关闭复制，否则启用
	dup := true
	if hl, ok := c.(interface{ DialLatency() time.Duration }); ok {
		if hl.DialLatency() < 40*time.Millisecond {
			dup = false
		}
	}
	return &oneSidedConn{Conn: c, enableDup: dup, dupBudget: 64 * 1024, lastAdj: time.Now()}
}

// Write 会将数据拆成 MTU 友好的片段，并视情况在短延迟后发送副本。
func (o *oneSidedConn) Write(p []byte) (int, error) {
	// 简单分片：限制为 1200 字节以适配常见 MTU，并可选地发送副本
	const frag = 1200
	written := 0
	for written < len(p) {
		n := len(p) - written
		if n > frag {
			n = frag
		}
		chunk := p[written : written+n]
		// 主链路写入并记录阻塞耗时
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
		o.recordBlock(dt)
		o.winBytes += n
		o.winChunks++
		// 若启用了复制且尚有预算，则带自适应延迟发送一次副本，降低碰撞概率
		if o.enableDup && o.dupBudget > 0 {
			if o.dupDelay > 0 {
				time.Sleep(o.dupDelay)
			}
			_, _ = o.Conn.Write(chunk)
			o.dupBudget -= len(chunk)
			if o.dupBudget < 0 {
				o.dupBudget = 0
			}
		}
		// 周期性回顾当前窗口
		if time.Since(o.lastAdj) > 500*time.Millisecond || o.winChunks >= 32 {
			o.reassess()
		}
		written += n
	}
	return written, nil
}

// reassess 会依据写阻塞的 EWMA 来开关复制并调整预算。
func (o *oneSidedConn) reassess() {
	fast, slow := o.dynamicThresholds()
	prevDup := o.enableDup
	prevBudget := o.dupBudget
	prevDelay := o.dupDelay
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
	o.updateDupDelay(fast, slow)
	if prevDup != o.enableDup || prevBudget != o.dupBudget || prevDelay != o.dupDelay {
		utils.Logger.Debug("单边自适应",
			zap.Bool("dup", o.enableDup),
			zap.Int("budget", o.dupBudget),
			zap.Int64("blockEWMA_us", o.ewmaBlock.Microseconds()),
			zap.Int64("fast_us", fast.Microseconds()),
			zap.Int64("slow_us", slow.Microseconds()),
			zap.Int64("dupDelay_us", o.dupDelay.Microseconds()))
	}
	o.winBytes = 0
	o.winChunks = 0
	o.lastAdj = time.Now()
}

// recordBlock 将最新的阻塞耗时写入环形历史队列。
func (o *oneSidedConn) recordBlock(dt time.Duration) {
	val := dt.Microseconds()
	if val <= 0 {
		val = 1
	}
	o.blockHist[o.histIdx] = val
	if o.histCount < len(o.blockHist) {
		o.histCount++
	}
	o.histIdx = (o.histIdx + 1) % len(o.blockHist)
}

// dynamicThresholds 计算决定复制策略的快速/慢速分位阈值。
func (o *oneSidedConn) dynamicThresholds() (time.Duration, time.Duration) {
	if o.histCount == 0 {
		return 2 * time.Millisecond, 8 * time.Millisecond
	}
	tmp := make([]int64, o.histCount)
	base := o.histIdx - o.histCount
	size := len(o.blockHist)
	for i := 0; i < o.histCount; i++ {
		idx := base + i
		if idx < 0 {
			idx += size
		}
		tmp[i] = o.blockHist[idx]
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	fastIdx := o.histCount / 4
	slowIdx := (o.histCount * 3) / 4
	if fastIdx >= o.histCount {
		fastIdx = o.histCount - 1
	}
	if slowIdx >= o.histCount {
		slowIdx = o.histCount - 1
	}
	fastVal := tmp[fastIdx]
	slowVal := tmp[slowIdx]
	if fastVal < 1000 {
		fastVal = 1000
	}
	if slowVal < fastVal*2 {
		slowVal = fastVal * 2
	}
	if slowVal > fastVal*16 {
		slowVal = fastVal * 16
	}
	return time.Duration(fastVal) * time.Microsecond, time.Duration(slowVal) * time.Microsecond
}

// updateDupDelay 根据阈值调整副本延迟，以兼顾碰撞概率和响应速度。
func (o *oneSidedConn) updateDupDelay(fast, slow time.Duration) {
	if !o.enableDup {
		o.dupDelay = 0
		return
	}
	if o.ewmaBlock <= fast {
		o.dupDelay = 0
		return
	}
	const (
		minDelay = 500 * time.Microsecond
		maxDelay = 10 * time.Millisecond
	)
	if slow <= fast {
		// fallback防御：阈值异常时用最小延迟
		o.dupDelay = minDelay
		return
	}
	denom := slow - fast
	if denom <= 0 {
		o.dupDelay = minDelay
		return
	}
	if o.ewmaBlock >= slow {
		delay := slow / 2
		if delay < minDelay {
			delay = minDelay
		}
		if delay > maxDelay {
			delay = maxDelay
		}
		o.dupDelay = delay
		return
	}
	ratio := float64(o.ewmaBlock-fast) / float64(denom)
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	delay := time.Duration(ratio * float64(maxDelay))
	if delay > 0 && delay < minDelay {
		delay = minDelay
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	o.dupDelay = delay
}
