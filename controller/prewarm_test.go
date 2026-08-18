package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPrewarmBackoffIsBounded(t *testing.T) {
	if got := prewarmBackoff(1); got != prewarmRetryMin {
		t.Fatalf("first retry = %s, want %s", got, prewarmRetryMin)
	}
	if got := prewarmBackoff(100); got != prewarmRetryMax {
		t.Fatalf("large retry = %s, want capped %s", got, prewarmRetryMax)
	}
}

func TestPrewarmDesiredAndConcurrentDialsAreBounded(t *testing.T) {
	if got := clampPrewarmDesired(prewarmPerTargetMax + 100); got != prewarmPerTargetMax {
		t.Fatalf("desired size = %d, want capped %d", got, prewarmPerTargetMax)
	}

	pool := newPrewarmPool("unused.invalid:1", prewarmPerTargetMax+100)
	started := make(chan struct{}, prewarmMaxConcurrentDial+1)
	release := make(chan struct{})
	pool.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		started <- struct{}{}
		select {
		case <-release:
			return nil, errors.New("expected test failure")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	pool.start()
	defer pool.stop()
	defer close(release)

	for i := 0; i < prewarmMaxConcurrentDial; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d replenishment dials started", i)
		}
	}
	select {
	case <-started:
		t.Fatalf("more than %d replenishment dials started", prewarmMaxConcurrentDial)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPrewarmDialsAreGloballyBoundedAcrossPools(t *testing.T) {
	poolCount := prewarmGlobalDialLimit/prewarmMaxConcurrentDial + 2
	started := make(chan struct{}, poolCount*prewarmMaxConcurrentDial)
	release := make(chan struct{})
	pools := make([]*prewarmPool, 0, poolCount)
	var releaseOnce sync.Once
	cleanup := func() {
		releaseOnce.Do(func() { close(release) })
		for _, pool := range pools {
			pool.stop()
		}
	}
	defer cleanup()

	for i := 0; i < poolCount; i++ {
		pool := newPrewarmPool(fmt.Sprintf("global-limit-%d.invalid:1", i), prewarmPerTargetMax)
		pool.dial = func(ctx context.Context, _ string) (net.Conn, error) {
			started <- struct{}{}
			select {
			case <-release:
				return nil, errors.New("expected test failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		pools = append(pools, pool)
		pool.start()
	}

	for i := 0; i < prewarmGlobalDialLimit; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d global replenishment dials started", i)
		}
	}
	select {
	case <-started:
		t.Fatalf("more than %d global replenishment dials started", prewarmGlobalDialLimit)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPrewarmPausesWhileRouteCircuitIsOpen(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("prewarm-circuit", "127.0.0.1:1010", "upstream.invalid:1")
	rule.Prewarm = true
	now := time.Now()
	tripRoute(t, rule, rule.Targets[0].Address, now)

	pool := newPrewarmPool(rule.Targets[0].Address, prewarmInitialSize)
	pool.rules[boostRuleKey(rule)] = rule
	pool.reconcile(now.Add(time.Second))
	pool.mu.Lock()
	warming := pool.warming
	pool.mu.Unlock()
	if warming != 0 {
		t.Fatalf("prewarm started %d dials while route circuit was open", warming)
	}
	pool.stop()
}

func TestAcquirePrewarmedDropsExpiredConnection(t *testing.T) {
	shutdownPrewarm()
	defer shutdownPrewarm()

	conn, peer := net.Pipe()
	defer peer.Close()
	pool := newPrewarmPool("expired.test:1", 1)
	pool.idle = []idlePrewarmConn{{
		conn:      conn,
		idleSince: time.Now().Add(-prewarmIdleTTL - time.Second),
	}}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	if acquired, ok := acquirePrewarmed(pool.addr); ok || acquired != nil {
		t.Fatal("expired prewarmed connection should not be returned")
	}
	buffer := make([]byte, 1)
	if _, err := peer.Read(buffer); err == nil {
		t.Fatal("expired connection was not closed")
	}
}

func TestAcquirePrewarmedReturnsLiveTCPWithoutConsumingBufferedData(t *testing.T) {
	if !prewarmReuseSupported {
		t.Skip("safe prewarm reuse is disabled on this platform")
	}
	shutdownPrewarm()
	defer shutdownPrewarm()

	conn, peer := newTCPPair(t)
	defer peer.Close()
	if _, err := peer.Write([]byte("g")); err != nil {
		t.Fatal(err)
	}
	pool := newPrewarmPool("live.test:1", 1)
	pool.idle = []idlePrewarmConn{{conn: conn, idleSince: time.Now()}}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	acquired, ok := acquirePrewarmed(pool.addr)
	if !ok || acquired != conn {
		t.Fatalf("acquirePrewarmed() = (%v, %v), want live TCP connection", acquired, ok)
	}
	defer acquired.Close()
	if err := acquired.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := acquired.Read(got[:]); err != nil {
		t.Fatal(err)
	}
	if got[0] != 'g' {
		t.Fatalf("peek consumed or changed buffered byte: %q", got[:])
	}
}

func TestAcquirePrewarmedReturnsQuietLiveTCP(t *testing.T) {
	if !prewarmReuseSupported {
		t.Skip("safe prewarm reuse is disabled on this platform")
	}
	shutdownPrewarm()
	defer shutdownPrewarm()

	conn, peer := newTCPPair(t)
	defer peer.Close()
	pool := newPrewarmPool("quiet-live.test:1", 1)
	pool.idle = []idlePrewarmConn{{conn: conn, idleSince: time.Now()}}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	acquired, ok := acquirePrewarmed(pool.addr)
	if !ok || acquired != conn {
		t.Fatalf("acquirePrewarmed() = (%v, %v), want quiet live TCP connection", acquired, ok)
	}
	_ = acquired.Close()
}

func TestAcquirePrewarmedRejectsTCPWithPendingClose(t *testing.T) {
	shutdownPrewarm()
	defer shutdownPrewarm()

	conn, peer := newTCPPair(t)
	if tcpPeer, ok := peer.(*net.TCPConn); ok {
		_ = tcpPeer.SetLinger(0)
	}
	_ = peer.Close()
	deadline := time.Now().Add(2 * time.Second)
	for prewarmConnReusable(conn) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if prewarmConnReusable(conn) {
		_ = conn.Close()
		t.Fatal("closed peer was still reported reusable")
	}

	pool := newPrewarmPool("closed.test:1", 1)
	pool.idle = []idlePrewarmConn{{conn: conn, idleSince: time.Now()}}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()
	if acquired, ok := acquirePrewarmed(pool.addr); ok || acquired != nil {
		t.Fatalf("acquired visibly closed connection: %v", acquired)
	}
}

func TestUnsupportedPlatformDoesNotStartPrewarmPools(t *testing.T) {
	if prewarmReuseSupported {
		t.Skip("platform supports safe prewarm reuse")
	}
	shutdownPrewarm()
	defer shutdownPrewarm()
	rule := boostTestRule("unsupported-prewarm", "127.0.0.1:1018", "127.0.0.1:9")
	rule.Prewarm = true
	initPrewarm(rule)
	prewarmPoolsMu.Lock()
	count := len(prewarmPools)
	prewarmPoolsMu.Unlock()
	if count != 0 {
		t.Fatalf("unsupported platform started %d prewarm pools", count)
	}
}

func TestPrewarmDrainsIdleConnectionsWhileCircuitIsOpen(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("prewarm-drain", "127.0.0.1:1013", "upstream.invalid:1")
	rule.Prewarm = true
	now := time.Now()
	tripRoute(t, rule, rule.Targets[0].Address, now)

	conn, peer := net.Pipe()
	defer peer.Close()
	tracked := &boostTrackingConn{Conn: conn}
	pool := newPrewarmPool(rule.Targets[0].Address, 1)
	pool.rules[boostRuleKey(rule)] = rule
	pool.idle = []idlePrewarmConn{{conn: tracked, idleSince: now}}
	pool.reconcile(now.Add(time.Second))
	pool.mu.Lock()
	idle := len(pool.idle)
	warming := pool.warming
	pool.mu.Unlock()
	if idle != 0 || warming != 0 {
		t.Fatalf("open circuit left pool idle=%d warming=%d, want both zero", idle, warming)
	}
	if got := tracked.closes.Load(); got != 1 {
		t.Fatalf("connection drained from open circuit close count = %d, want 1", got)
	}
	pool.stop()
}

func TestRuleWithoutPrewarmNeverConsumesSharedPool(t *testing.T) {
	shutdownPrewarm()
	defer shutdownPrewarm()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	pooled, pooledPeer := net.Pipe()
	defer pooledPeer.Close()
	pool := newPrewarmPool(listener.Addr().String(), 1)
	pool.idle = []idlePrewarmConn{{conn: pooled, idleSince: time.Now()}}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	rule := &config.Rule{Prewarm: false}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := outboundDial(ctx, rule, listener.Addr().String())
	if err != nil {
		t.Fatalf("outboundDial: %v", err)
	}
	defer got.Close()
	if got == pooled {
		t.Fatal("non-prewarm rule consumed a pool created by another rule")
	}

	select {
	case backend := <-accepted:
		_ = backend.Close()
	case <-time.After(time.Second):
		t.Fatal("fresh outbound connection was not established")
	}
}

func TestShutdownPrewarmIsIdempotentAndClosesIdleConnections(t *testing.T) {
	shutdownPrewarm()
	conn, peer := net.Pipe()
	defer peer.Close()
	tracked := &boostTrackingConn{Conn: conn}
	pool := newPrewarmPool("shutdown.test:1", 1)
	pool.idle = []idlePrewarmConn{{conn: tracked, idleSince: time.Now()}}
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	shutdownPrewarm()
	shutdownPrewarm()
	if got := tracked.closes.Load(); got != 1 {
		t.Fatalf("idle connection close count = %d, want 1", got)
	}
	prewarmPoolsMu.Lock()
	remaining := len(prewarmPools)
	prewarmPoolsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("shutdown left %d prewarm pools", remaining)
	}
}
