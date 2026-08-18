package controller

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"moto/config"
	"moto/utils"

	"go.uber.org/zap"
)

const (
	prewarmInitialSize       = 4
	prewarmPerTargetMax      = 32
	prewarmMaxConcurrentDial = 4
	prewarmGlobalDialLimit   = 32
	prewarmIdleTTL           = 30 * time.Second
	prewarmRetryMin          = 100 * time.Millisecond
	prewarmRetryMax          = 5 * time.Second
	prewarmMaintenancePeriod = 250 * time.Millisecond
)

var (
	prewarmPoolsMu sync.Mutex
	prewarmPools   = make(map[string]*prewarmPool)
	prewarmDialSem = make(chan struct{}, prewarmGlobalDialLimit)
)

type idlePrewarmConn struct {
	conn      net.Conn
	idleSince time.Time
}

// prewarmPool maintains a bounded number of short-lived idle connections for
// one target. A single reconciler owns replenishment decisions, while warming
// tracks the small, bounded number of concurrent dials.
type prewarmPool struct {
	addr    string
	desired int

	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	dial   func(context.Context, string) (net.Conn, error)
	wg     sync.WaitGroup

	mu        sync.Mutex
	idle      []idlePrewarmConn
	rules     map[string]*config.Rule
	warming   int
	failures  int
	nextRetry time.Time
	stopped   bool
}

// initPrewarm 会为规则中的每个目标开启后台保温。
func initPrewarm(rule *config.Rule) {
	if rule == nil || !rule.Prewarm {
		return
	}
	if !prewarmReuseSupported {
		utils.Logger.Warn("当前平台不支持安全的预热连接复用，改用新连接",
			zap.String("ruleName", rule.Name))
		return
	}
	for _, target := range rule.Targets {
		ensurePrewarmPoolForRule(rule, target.Address, prewarmInitialSize)
	}
}

func clampPrewarmDesired(desired int) int {
	if desired < 1 {
		return 1
	}
	if desired > prewarmPerTargetMax {
		return prewarmPerTargetMax
	}
	return desired
}

func newPrewarmPool(addr string, desired int) *prewarmPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &prewarmPool{
		addr:    addr,
		desired: clampPrewarmDesired(desired),
		ctx:     ctx,
		cancel:  cancel,
		wake:    make(chan struct{}, 1),
		dial:    DialFastContext,
		rules:   make(map[string]*config.Rule),
	}
}

func (p *prewarmPool) start() {
	p.wg.Add(1)
	go p.maintain()
	p.signal()
}

func ensurePrewarmPoolForRule(rule *config.Rule, addr string, desired int) *prewarmPool {
	desired = clampPrewarmDesired(desired)
	prewarmPoolsMu.Lock()
	pool := prewarmPools[addr]
	if pool == nil {
		pool = newPrewarmPool(addr, desired)
		if rule != nil {
			pool.rules[boostRuleKey(rule)] = rule
		}
		prewarmPools[addr] = pool
		pool.start()
		prewarmPoolsMu.Unlock()
		return pool
	}
	prewarmPoolsMu.Unlock()

	pool.mu.Lock()
	if rule != nil {
		pool.rules[boostRuleKey(rule)] = rule
	}
	if desired > pool.desired {
		pool.desired = desired
	}
	pool.mu.Unlock()
	pool.signal()
	return pool
}

func (p *prewarmPool) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *prewarmPool) maintain() {
	defer p.wg.Done()
	ticker := time.NewTicker(prewarmMaintenancePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
		p.reconcile(time.Now())
	}
}

func (p *prewarmPool) reconcile(now time.Time) {
	var expired []net.Conn
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	kept := p.idle[:0]
	for _, idle := range p.idle {
		if now.Sub(idle.idleSince) >= prewarmIdleTTL {
			expired = append(expired, idle.conn)
			continue
		}
		kept = append(kept, idle)
	}
	p.idle = kept
	// An idle TCP connection predating an outage is not evidence that the path
	// recovered. Drain the shared target pool as soon as any associated rule has
	// an open circuit, and pause replenishment until foreground traffic completes
	// a fresh half-open probe.
	routeUnavailable := false
	for _, rule := range p.rules {
		if routeSnapshot(rule, p.addr, now).CircuitOpen {
			routeUnavailable = true
			break
		}
	}
	if routeUnavailable {
		for _, idle := range p.idle {
			expired = append(expired, idle.conn)
		}
		p.idle = nil
	}

	need := p.desired - len(p.idle) - p.warming
	capacity := prewarmMaxConcurrentDial - p.warming
	if need > capacity {
		need = capacity
	}
	if routeUnavailable || now.Before(p.nextRetry) || need < 0 {
		need = 0
	}
	reserved := 0
	for reserved < need {
		select {
		case prewarmDialSem <- struct{}{}:
			reserved++
		default:
			need = reserved
			goto slotsReserved
		}
	}
slotsReserved:
	need = reserved
	if need > 0 {
		p.warming += need
		p.wg.Add(need)
	}
	p.mu.Unlock()

	for _, conn := range expired {
		_ = conn.Close()
	}
	for i := 0; i < need; i++ {
		go p.dialOne()
	}
}

func prewarmBackoff(failures int) time.Duration {
	if failures <= 1 {
		return prewarmRetryMin
	}
	backoff := prewarmRetryMin
	for i := 1; i < failures && backoff < prewarmRetryMax; i++ {
		backoff *= 2
		if backoff >= prewarmRetryMax {
			return prewarmRetryMax
		}
	}
	return backoff
}

// dialOne adds at most one connection to the idle pool. Failures only update
// the next retry deadline; no retry goroutine sleeps or recursively respawns.
func (p *prewarmPool) dialOne() {
	defer p.wg.Done()
	defer func() { <-prewarmDialSem }()

	p.mu.Lock()
	rules := make([]*config.Rule, 0, len(p.rules))
	for _, rule := range p.rules {
		rules = append(rules, rule)
	}
	p.mu.Unlock()
	type trackedAttempt struct {
		rule    *config.Rule
		attempt routeAttempt
	}
	attempts := make([]trackedAttempt, 0, len(rules))
	started := time.Now()
	for _, rule := range rules {
		if routeSnapshot(rule, p.addr, started).CircuitOpen {
			continue
		}
		attempt, err := routeBegin(rule, p.addr, started)
		if err == nil {
			attempts = append(attempts, trackedAttempt{rule: rule, attempt: attempt})
		}
	}
	if len(rules) > 0 && len(attempts) == 0 {
		p.mu.Lock()
		p.warming--
		p.mu.Unlock()
		p.signal()
		return
	}

	var conn net.Conn
	err := p.ctx.Err()
	if err == nil {
		conn, err = p.dial(p.ctx, p.addr)
	}
	if err == nil && conn == nil {
		err = errors.New("prewarm dial returned a nil connection")
	}
	now := time.Now()
	latency := now.Sub(started)
	for _, tracked := range attempts {
		routeObserve(tracked.attempt, latency, err, now)
		metricDial(tracked.rule.Name, p.addr, latency, err)
	}

	p.mu.Lock()
	p.warming--
	if p.stopped {
		p.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	if err != nil {
		p.failures++
		p.nextRetry = now.Add(prewarmBackoff(p.failures))
		p.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		if p.ctx.Err() == nil {
			utils.Logger.Warn("预热连接失败", zap.String("target", p.addr), zap.Error(err))
		}
		return
	}
	p.failures = 0
	p.nextRetry = time.Time{}
	if len(p.idle) >= p.desired {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	p.idle = append(p.idle, idlePrewarmConn{conn: conn, idleSince: now})
	p.mu.Unlock()
	p.signal()
}

// acquirePrewarmed removes expired idle connections before returning the most
// recently established one.
func acquirePrewarmed(addr string) (net.Conn, bool) {
	prewarmPoolsMu.Lock()
	pool := prewarmPools[addr]
	prewarmPoolsMu.Unlock()
	if pool == nil {
		return nil, false
	}

	now := time.Now()
	var expired []net.Conn
	pool.mu.Lock()
	if pool.stopped {
		pool.mu.Unlock()
		return nil, false
	}
	kept := pool.idle[:0]
	for _, idle := range pool.idle {
		if now.Sub(idle.idleSince) >= prewarmIdleTTL {
			expired = append(expired, idle.conn)
			continue
		}
		kept = append(kept, idle)
	}
	pool.idle = kept
	var conn net.Conn
	for n := len(pool.idle); n > 0; n = len(pool.idle) {
		candidate := pool.idle[n-1].conn
		pool.idle = pool.idle[:n-1]
		if prewarmConnReusable(candidate) {
			conn = candidate
			break
		}
		expired = append(expired, candidate)
	}
	pool.mu.Unlock()
	for _, stale := range expired {
		_ = stale.Close()
	}
	pool.signal()
	return conn, conn != nil
}

func (p *prewarmPool) stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		p.wg.Wait()
		return
	}
	p.stopped = true
	idle := p.idle
	p.idle = nil
	p.cancel()
	p.mu.Unlock()
	for _, entry := range idle {
		_ = entry.conn.Close()
	}
	p.wg.Wait()
}

// shutdownPrewarm can be called repeatedly. It atomically detaches all pools,
// cancels replenishment, closes every idle connection, and waits for in-flight
// dials to observe cancellation.
func shutdownPrewarm() {
	prewarmPoolsMu.Lock()
	pools := make([]*prewarmPool, 0, len(prewarmPools))
	for addr, pool := range prewarmPools {
		delete(prewarmPools, addr)
		pools = append(pools, pool)
	}
	prewarmPoolsMu.Unlock()
	for _, pool := range pools {
		pool.stop()
	}
}

// outboundDial only consumes a pooled connection for rules that explicitly
// enabled prewarming. Other rules always establish a fresh connection, even if
// another rule happens to share the same target address.
func outboundDial(ctx context.Context, rule *config.Rule, addr string) (net.Conn, error) {
	conn, _, err := outboundDialRoute(ctx, rule, addr)
	return conn, err
}

func outboundDialRoute(ctx context.Context, rule *config.Rule, addr string) (net.Conn, routeAttempt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, routeAttempt{}, err
	}
	now := time.Now()
	snapshot := routeSnapshot(rule, addr, now)
	attempt, err := routeBegin(rule, addr, now)
	if err != nil {
		return nil, routeAttempt{}, err
	}
	// A half-open route must prove itself with a fresh TCP handshake. Reusing a
	// pooled socket would make an expired circuit look healthy without testing
	// the current network path.
	if rule != nil && rule.Prewarm && prewarmReuseSupported && !snapshot.ProbeRequired {
		if conn, ok := acquirePrewarmed(addr); ok {
			if err := ctx.Err(); err != nil {
				_ = conn.Close()
				return nil, attempt, err
			}
			return conn, attempt, nil
		}
	}
	started := time.Now()
	conn, err := DialFastContext(ctx, addr)
	if err == nil && conn == nil {
		err = errors.New("dial returned a nil connection")
	}
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	latency := time.Since(started)
	routeObserve(attempt, latency, err, time.Now())
	if rule != nil {
		metricDial(rule.Name, addr, latency, err)
	}
	return conn, attempt, err
}
