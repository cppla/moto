package controller

import (
	"net"
	"sync"
	"time"

	"moto/config"
	"moto/utils"

	"go.uber.org/zap"
)

// 每个目标默认预热连接数量。
const (
	prewarmDefaultSize = 1
	prewarmBoostSize   = 8
)

var prewarmPools sync.Map // 映射地址到对应的预热池

// prewarmPool 维护目标地址对应的一小撮预热 TCP 连接。
type prewarmPool struct {
	addr    string
	desired int

	mu      sync.Mutex
	idle    []net.Conn
	warming int
}

// initPrewarm 会为规则中的每个目标开启后台保温。
func initPrewarm(rule *config.Rule) {
	if !rule.Prewarm {
		return
	}
	desired := prewarmDefaultSize
	if rule.Mode == "boost" {
		desired = prewarmBoostSize
	}
	for _, target := range rule.Targets {
		ensurePrewarmPool(target.Address, desired)
	}
}

func ensurePrewarmPool(addr string, desired int) *prewarmPool {
	poolAny, _ := prewarmPools.LoadOrStore(addr, &prewarmPool{addr: addr, desired: desired})
	pool := poolAny.(*prewarmPool)
	pool.mu.Lock()
	if desired > pool.desired {
		pool.desired = desired
	}
	pool.ensureLocked()
	pool.mu.Unlock()
	return pool
}

// ensureLocked 会持续补齐预热连接直到达到期望值。
func (p *prewarmPool) ensureLocked() {
	need := p.desired - len(p.idle) - p.warming
	if need <= 0 {
		return
	}
	for i := 0; i < need; i++ {
		p.warming++
		go p.dialOne()
	}
}

// dialOne 拨号一个连接并加入空闲池。
func (p *prewarmPool) dialOne() {
	conn, err := DialFast(p.addr)
	if err != nil {
		utils.Logger.Warn("预热连接失败", zap.String("target", p.addr), zap.Error(err))
		time.Sleep(500 * time.Millisecond)
		p.mu.Lock()
		p.warming--
		if p.warming < 0 {
			p.warming = 0
		}
		p.ensureLocked()
		p.mu.Unlock()
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}
	p.mu.Lock()
	p.warming--
	p.idle = append(p.idle, conn)
	p.ensureLocked()
	p.mu.Unlock()
}

// acquirePrewarmed 优先从预热池取出可用连接。
func acquirePrewarmed(addr string) (net.Conn, bool) {
	poolAny, ok := prewarmPools.Load(addr)
	if !ok {
		return nil, false
	}
	pool := poolAny.(*prewarmPool)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	n := len(pool.idle)
	if n == 0 {
		pool.ensureLocked()
		return nil, false
	}
	conn := pool.idle[n-1]
	pool.idle = pool.idle[:n-1]
	pool.ensureLocked()
	return conn, true
}

// outboundDial 先尝试预热池，失败再发起新建连接。
// 之前返回 (conn, usedFlag, error)，由于当前不再区分来源，精简为 (conn, error)。
func outboundDial(addr string) (net.Conn, error) {
	if conn, ok := acquirePrewarmed(addr); ok {
		return conn, nil
	}
	c, err := DialFast(addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}
