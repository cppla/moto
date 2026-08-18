package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type boostTrackingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *boostTrackingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func boostTestRule(name, listen string, addresses ...string) *config.Rule {
	targets := make([]*config.Target, 0, len(addresses))
	for _, addr := range addresses {
		targets = append(targets, &config.Target{Address: addr})
	}
	return &config.Rule{
		Name:    name,
		Listen:  listen,
		Mode:    config.ModeBoost,
		Targets: targets,
		Timeout: 1000,
	}
}

func TestBoostRuleKeyIncludesRouteIdentity(t *testing.T) {
	base := boostTestRule("duplicate", "127.0.0.1:1001", "one:1", "two:2")
	differentListener := boostTestRule("duplicate", "127.0.0.1:1002", "one:1", "two:2")
	differentTargets := boostTestRule("duplicate", "127.0.0.1:1001", "one:1", "three:3")

	if boostRuleKey(base) == boostRuleKey(differentListener) {
		t.Fatal("rules with different listeners share a boost cache key")
	}
	if boostRuleKey(base) == boostRuleKey(differentTargets) {
		t.Fatal("rules with different target sets share a boost cache key")
	}
}

func TestRaceBoostTargetsClosesEveryLoser(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("race", "127.0.0.1:1001", "one:1", "two:2", "three:3")
	connections := make(map[string]*boostTrackingConn, len(rule.Targets))
	dialed := make(map[string]bool, 2)
	var dialedMu sync.Mutex
	peers := make([]net.Conn, 0, len(rule.Targets))
	for _, target := range rule.Targets {
		conn, peer := net.Pipe()
		connections[target.Address] = &boostTrackingConn{Conn: conn}
		peers = append(peers, peer)
	}
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	winner, err := raceBoostTargets(context.Background(), rule, func(_ context.Context, addr string) (net.Conn, error) {
		dialedMu.Lock()
		dialed[addr] = true
		dialedMu.Unlock()
		return connections[addr], nil
	})
	if err != nil {
		t.Fatalf("raceBoostTargets() error = %v", err)
	}

	open := 0
	for addr, conn := range connections {
		if !dialed[addr] {
			_ = conn.Close()
			continue
		}
		if conn.closes.Load() == 0 {
			open++
		}
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed targets = %d, want Top-2", len(dialed))
	}
	if open != 1 {
		t.Fatalf("open connections after race = %d, want exactly the winner", open)
	}
	if connections[winner.addr] != winner.conn {
		t.Fatalf("winner address %q does not identify the returned connection", winner.addr)
	}
	_ = winner.conn.Close()
}

func TestRaceBoostTargetsReturnsAsSoonAsAllTargetsFail(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("fail", "127.0.0.1:1001", "one:1", "two:2", "three:3")
	wantErr := errors.New("dial failed")

	start := time.Now()
	_, err := raceBoostTargets(context.Background(), rule, func(context.Context, string) (net.Conn, error) {
		return nil, wantErr
	})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("raceBoostTargets() error = %v, want wrapped dial error", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("all-failed race waited %s instead of returning immediately", elapsed)
	}
}

func TestRaceBoostTargetsContinuesAfterFirstBatchFails(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("batch-fallback", "127.0.0.1:1011", "one:1", "two:2", "three:3")
	var active atomic.Int32
	var maximum atomic.Int32
	var firstBatchStarted atomic.Int32
	releaseFirstBatch := make(chan struct{})
	var releaseOnce sync.Once
	dialed := make(map[string]int)
	var dialedMu sync.Mutex
	winningConn, winningPeer := net.Pipe()
	defer winningPeer.Close()

	winner, err := raceBoostTargets(context.Background(), rule, func(_ context.Context, addr string) (net.Conn, error) {
		dialedMu.Lock()
		dialed[addr]++
		dialedMu.Unlock()
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		if addr == "three:3" {
			return winningConn, nil
		}
		if firstBatchStarted.Add(1) == 2 {
			releaseOnce.Do(func() { close(releaseFirstBatch) })
		}
		<-releaseFirstBatch
		return nil, errors.New("first batch unavailable")
	})
	if err != nil {
		t.Fatalf("raceBoostTargets() error = %v", err)
	}
	defer winner.conn.Close()
	if winner.addr != "three:3" || winner.conn != winningConn {
		t.Fatalf("winner = %q (%T), want third target", winner.addr, winner.conn)
	}
	if got := maximum.Load(); got > 2 {
		t.Fatalf("maximum concurrent dials = %d, want at most 2", got)
	}
	for _, addr := range []string{"one:1", "two:2", "three:3"} {
		if dialed[addr] != 1 {
			t.Fatalf("dial count for %s = %d, want 1", addr, dialed[addr])
		}
	}
}

func TestRaceBoostTargetsRefillsFailedSlotBeforeSlowPeerCompletes(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("rolling-slot", "127.0.0.1:1014", "fast-fail:1", "slow:2", "replacement:3")
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	slowStarted := make(chan struct{})
	replacementStarted := make(chan struct{})
	var slowOnce sync.Once
	var replacementOnce sync.Once

	winner, err := raceBoostTargets(context.Background(), rule, func(ctx context.Context, addr string) (net.Conn, error) {
		switch addr {
		case "fast-fail:1":
			return nil, errors.New("unavailable")
		case "slow:2":
			slowOnce.Do(func() { close(slowStarted) })
			<-ctx.Done()
			return nil, ctx.Err()
		case "replacement:3":
			replacementOnce.Do(func() { close(replacementStarted) })
			return winnerConn, nil
		default:
			return nil, fmt.Errorf("unexpected target %s", addr)
		}
	})
	if err != nil {
		t.Fatalf("raceBoostTargets() error = %v", err)
	}
	defer winner.conn.Close()
	if winner.addr != "replacement:3" {
		t.Fatalf("winner = %q, want replacement:3", winner.addr)
	}
	select {
	case <-slowStarted:
	default:
		t.Fatal("slow peer was not part of the initial Top-2")
	}
	select {
	case <-replacementStarted:
	default:
		t.Fatal("failed slot was not refilled from the third target")
	}
}

func TestRaceBoostTargetsFillsSlotsAroundOpenAndHalfOpenRoutes(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("circuit-slot", "127.0.0.1:1012", "cooling:1", "probing:2", "healthy:3")
	now := time.Now()
	tripRoute(t, rule, "cooling:1", now)
	tripRoute(t, rule, "probing:2", now.Add(-routeInitialCooldown-time.Second))
	probe, err := routeBegin(rule, "probing:2", now)
	if err != nil {
		t.Fatalf("claim half-open probe: %v", err)
	}
	defer routeObserve(probe, 0, context.Canceled, time.Now())

	winningConn, winningPeer := net.Pipe()
	defer winningPeer.Close()
	var dialedMu sync.Mutex
	var dialed []string
	winner, err := raceBoostTargets(context.Background(), rule, func(_ context.Context, addr string) (net.Conn, error) {
		dialedMu.Lock()
		dialed = append(dialed, addr)
		dialedMu.Unlock()
		if addr != "healthy:3" {
			return nil, fmt.Errorf("unexpected dial to %s", addr)
		}
		return winningConn, nil
	})
	if err != nil {
		t.Fatalf("raceBoostTargets() error = %v", err)
	}
	defer winner.conn.Close()
	if winner.addr != "healthy:3" {
		t.Fatalf("winner = %q, want healthy:3", winner.addr)
	}
	if len(dialed) != 1 || dialed[0] != "healthy:3" {
		t.Fatalf("dialed targets = %v, want only healthy:3", dialed)
	}
}

func TestRaceBoostTargetsHonorsCancellation(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("cancel", "127.0.0.1:1001", "one:1", "two:2")
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, len(rule.Targets))
	done := make(chan error, 1)
	go func() {
		_, err := raceBoostTargets(ctx, rule, func(dialCtx context.Context, _ string) (net.Conn, error) {
			started <- struct{}{}
			<-dialCtx.Done()
			return nil, dialCtx.Err()
		})
		done <- err
	}()
	for range rule.Targets {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("raceBoostTargets() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("race did not stop after context cancellation")
	}
}

func TestBoostCacheHitDoesNotExtendRevalidationDeadline(t *testing.T) {
	resetRouteHealthForTest()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
		close(accepted)
	}()

	rule := boostTestRule("cache-ttl", "127.0.0.1:1009", listener.Addr().String())
	key := boostRuleKey(rule)
	expires := time.Now().Add(boostRevalidateAfter + 5*time.Second)
	boostWinnerCache.Lock()
	boostWinnerCache.entries[key] = boostWinnerEntry{addr: listener.Addr().String(), expires: expires}
	boostWinnerCache.Unlock()
	defer deleteBoostWinner(key)

	client, proxy := net.Pipe()
	done := make(chan struct{})
	go func() {
		HandleBoost(context.Background(), proxy, rule)
		close(done)
	}()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleBoost did not finish")
	}
	<-accepted

	_, ok, gotExpiry := loadBoostWinner(key)
	if !ok {
		t.Fatal("cache entry disappeared after a successful hit")
	}
	if !gotExpiry.Equal(expires) {
		t.Fatalf("cache expiry changed from %s to %s", expires, gotExpiry)
	}
}

func TestBoostWinnerEvictionOnlyUsesAttributedUpstreamFailures(t *testing.T) {
	clientReset := relayResult{
		ClientToTarget: relayDirectionResult{Err: errors.New("client reset")},
	}
	if upstreamRelayError(clientReset) != nil {
		t.Fatal("client failure would evict boost winner")
	}

	upstreamReset := relayResult{
		TargetToClient: relayDirectionResult{
			Err:             errors.New("upstream reset"),
			upstreamFailure: true,
		},
	}
	if upstreamRelayError(upstreamReset) == nil {
		t.Fatal("attributed upstream failure would retain boost winner")
	}
}

func TestRuntimeRoutingCleanupWaitsForLazyRevalidation(t *testing.T) {
	rule := boostTestRule("cleanup", "127.0.0.1:1019", "one:1", "two:2")
	key := boostRuleKey(rule)
	job := &boostRevalidation{done: make(chan struct{})}
	boostRevalidating.Store(key, job)
	storeBoostWinner(key, "one:1")

	done := make(chan struct{})
	go func() {
		clearRuntimeRoutingState([]*config.Rule{rule})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("routing cleanup returned before lazy revalidation completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(job.done)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("routing cleanup did not finish after lazy revalidation completed")
	}
	if _, ok, _ := loadBoostWinner(key); ok {
		t.Fatal("routing cleanup retained boost winner")
	}
	if _, ok := boostRevalidating.Load(key); ok {
		t.Fatal("routing cleanup retained revalidation entry")
	}
}
