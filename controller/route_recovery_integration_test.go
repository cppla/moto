package controller

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func acceptRouteRecoveryTestConn(listener net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	return accepted
}

func TestHandleBoostDueCircuitBypassesHealthyCachedWinner(t *testing.T) {
	recoveryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer recoveryListener.Close()
	cachedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cachedListener.Close()

	recoveryAccepted := acceptRouteRecoveryTestConn(recoveryListener)
	cachedAccepted := acceptRouteRecoveryTestConn(cachedListener)

	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"cached-circuit-recovery",
		"127.0.0.1:18122",
		recoveryListener.Addr().String(),
		cachedListener.Addr().String(),
	)
	now := time.Now()
	cachedAttempt, err := runtime.routes.begin(rule, cachedListener.Addr().String(), now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(cachedAttempt, 10*time.Millisecond, nil, now)
	failureAt := now.Add(-routeInitialCooldown - time.Second)
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, beginErr := runtime.routes.begin(rule, recoveryListener.Addr().String(), failureAt)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		routeObserve(attempt, time.Millisecond, errors.New("recovery fixture failure"), failureAt)
	}
	runtime.storeBoostWinner(boostRuleKey(rule), cachedListener.Addr().String())

	client, moto := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		runtime.handleBoost(ctx, moto, rule)
		close(done)
	}()

	var recoveryConnection net.Conn
	select {
	case recoveryConnection = <-recoveryAccepted:
	case connection := <-cachedAccepted:
		_ = connection.Close()
		t.Fatal("healthy cached winner was dialed before the due circuit recovery")
	case <-time.After(2 * time.Second):
		t.Fatal("due circuit recovery was not dialed")
	}
	defer recoveryConnection.Close()
	select {
	case connection := <-cachedAccepted:
		_ = connection.Close()
		t.Fatal("cached winner raced the in-flight circuit recovery")
	case <-time.After(50 * time.Millisecond):
	}

	deadline := time.Now().Add(time.Second)
	for {
		snapshot := runtime.routes.snapshot(rule, recoveryListener.Addr().String(), time.Now())
		if !snapshot.CircuitOpen && !snapshot.LastRecovery.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery route did not close its circuit: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	entry, ok := runtime.loadBoostWinnerToken(boostRuleKey(rule))
	if !ok || entry.addr != recoveryListener.Addr().String() {
		t.Fatalf("winner after recovery = %+v ok=%t", entry, ok)
	}

	_ = recoveryConnection.Close()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Boost handler did not stop after the recovered connection closed")
	}
}

func TestHandleBoostCircuitRecoveryDoesNotBlockCachedSibling(t *testing.T) {
	recoveryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer recoveryListener.Close()
	cachedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cachedListener.Close()
	recoveryAccepted := acceptRouteRecoveryTestConn(recoveryListener)
	cachedAccepted := acceptRouteRecoveryTestConn(cachedListener)

	bulkhead := newDialBulkhead(2, 1, 2*time.Second)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule(
		"cached-sibling-during-recovery",
		"127.0.0.1:18124",
		recoveryListener.Addr().String(),
		cachedListener.Addr().String(),
	)
	now := time.Now()
	cachedAttempt, err := runtime.routes.begin(rule, cachedListener.Addr().String(), now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(cachedAttempt, 10*time.Millisecond, nil, now)
	failureAt := now.Add(-routeInitialCooldown - time.Second)
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, beginErr := runtime.routes.begin(rule, recoveryListener.Addr().String(), failureAt)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		routeObserve(attempt, time.Millisecond, errors.New("recovery fixture failure"), failureAt)
	}
	runtime.storeBoostWinner(boostRuleKey(rule), cachedListener.Addr().String())
	holder, _, err := bulkhead.acquire(context.Background(), recoveryListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	holderReleased := false
	defer func() {
		if !holderReleased {
			holder.release()
		}
	}()

	ownerClient, ownerMoto := net.Pipe()
	defer ownerClient.Close()
	ownerDone := make(chan struct{})
	go func() {
		runtime.handleBoost(context.Background(), ownerMoto, rule)
		close(ownerDone)
	}()
	waitDeadline := time.Now().Add(time.Second)
	for bulkhead.snapshot().Waiting != 1 && time.Now().Before(waitDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bulkhead.snapshot().Waiting; got != 1 {
		t.Fatalf("recovery owner bulkhead waiters = %d, want 1", got)
	}

	siblingClient, siblingMoto := net.Pipe()
	defer siblingClient.Close()
	siblingDone := make(chan struct{})
	go func() {
		runtime.handleBoost(context.Background(), siblingMoto, rule)
		close(siblingDone)
	}()
	var cachedConnection net.Conn
	select {
	case cachedConnection = <-cachedAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("sibling waited behind the in-flight recovery instead of using cache")
	}
	defer cachedConnection.Close()
	select {
	case <-ownerDone:
		t.Fatal("cached sibling dial canceled the recovery owner")
	default:
	}
	holder.release()
	holderReleased = true
	var recoveryConnection net.Conn
	select {
	case recoveryConnection = <-recoveryAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery owner did not continue after target capacity was released")
	}
	defer recoveryConnection.Close()

	_ = cachedConnection.Close()
	_ = siblingClient.Close()
	select {
	case <-siblingDone:
	case <-time.After(time.Second):
		t.Fatal("cached sibling did not stop after its upstream closed")
	}
	select {
	case <-ownerDone:
		t.Fatal("cached sibling shutdown canceled the recovery owner")
	default:
	}

	_ = recoveryConnection.Close()
	_ = ownerClient.Close()
	select {
	case <-ownerDone:
	case <-time.After(time.Second):
		t.Fatal("recovery owner did not stop after its upstream closed")
	}
	snapshot := runtime.routes.snapshot(rule, recoveryListener.Addr().String(), time.Now())
	if snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.LastRecovery.IsZero() {
		t.Fatalf("recovery owner did not restore its target: %+v", snapshot)
	}
}

func TestCachedWinnerIsEvictedWhileItsTargetCircuitIsOpen(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("open-cached-route", "127.0.0.1:18123", "cached.example:443")
	now := time.Now()
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := runtime.routes.begin(rule, "cached.example:443", now)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, time.Millisecond, errors.New("route failed"), now)
	}
	runtime.storeBoostWinner(boostRuleKey(rule), "cached.example:443")

	if entry, ok := runtime.loadUsableBoostWinnerToken(boostRuleKey(rule), rule, now); ok {
		t.Fatalf("open-circuit cached winner remained usable: %+v", entry)
	}
	if entry, ok := runtime.loadBoostWinnerToken(boostRuleKey(rule)); ok {
		t.Fatalf("open-circuit cached winner was not evicted: %+v", entry)
	}
}

func TestHandleBoostCanceledRecoveryReleasesLeaseWithoutRouteFailure(t *testing.T) {
	bulkhead := newDialBulkhead(1, 1, 2*time.Second)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("canceled-circuit-recovery", "127.0.0.1:18125", "recovering.example:443")
	failureAt := time.Now().Add(-routeInitialCooldown - time.Second)
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := runtime.routes.begin(rule, "recovering.example:443", failureAt)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, time.Millisecond, errors.New("recovery fixture failure"), failureAt)
	}
	before := runtime.routes.snapshot(rule, "recovering.example:443", time.Now())
	holder, _, err := bulkhead.acquire(context.Background(), "recovering.example:443")
	if err != nil {
		t.Fatal(err)
	}
	holderReleased := false
	defer func() {
		if !holderReleased {
			holder.release()
		}
	}()

	client, moto := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.handleBoost(ctx, moto, rule)
		close(done)
	}()
	waitDeadline := time.Now().Add(time.Second)
	for bulkhead.snapshot().Waiting != 1 && time.Now().Before(waitDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bulkhead.snapshot().Waiting; got != 1 {
		t.Fatalf("recovery owner bulkhead waiters = %d, want 1", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled recovery owner did not stop")
	}
	holder.release()
	holderReleased = true

	runtime.routes.Lock()
	_, leaseRetained := runtime.routes.recovery[boostRuleKey(rule)]
	runtime.routes.Unlock()
	if leaseRetained {
		t.Fatal("canceled recovery retained its rule-wide lease")
	}
	after := runtime.routes.snapshot(rule, "recovering.example:443", time.Now())
	if after.HalfOpen || !after.CircuitOpen || after.ConsecutiveFailures != before.ConsecutiveFailures ||
		after.Cooldown != before.Cooldown || !after.LastAttempt.Equal(before.LastAttempt) {
		t.Fatalf("canceled pre-dial recovery changed route health: before=%+v after=%+v", before, after)
	}
}

func TestReachableHalfOpenResponseRecordsRouteRecovery(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := routeHealthTestRule("reachable.example:443")
	tripAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tripRouteInRegistry(t, registry, rule, "reachable.example:443", tripAt)
	recoveredAt := tripAt.Add(routeInitialCooldown)
	probe, err := registry.begin(rule, "reachable.example:443", recoveredAt)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(probe, time.Second, errRouteReachable, recoveredAt)

	snapshot := registry.snapshot(rule, "reachable.example:443", recoveredAt)
	if snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("reachable response did not recover route: %+v", snapshot)
	}
	if !snapshot.LastRecovery.Equal(recoveredAt) {
		t.Fatalf("last recovery = %s, want %s", snapshot.LastRecovery, recoveredAt)
	}
	if snapshot.HasEWMA {
		t.Fatalf("reachable non-tunnel response updated latency EWMA: %+v", snapshot)
	}
}
