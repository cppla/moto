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

func TestDialBulkheadCapacityErrorStopsModeRetryAmplification(t *testing.T) {
	tests := []struct {
		name string
		run  func(*routingRuntime, net.Conn, *config.Rule)
		mode string
	}{
		{
			name: "normal",
			mode: config.ModeNormal,
			run: func(runtime *routingRuntime, conn net.Conn, rule *config.Rule) {
				runtime.handleNormal(context.Background(), conn, rule)
			},
		},
		{
			name: "roundrobin",
			mode: config.ModeRoundRobin,
			run: func(runtime *routingRuntime, conn net.Conn, rule *config.Rule) {
				runtime.handleRoundrobin(context.Background(), conn, rule)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetProcessMetricsForTest()
			defer resetProcessMetricsForTest()
			bulkhead := newDialBulkhead(1, 1, 5*time.Millisecond)
			runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
			defer runtime.stopBackground()
			rule := &config.Rule{
				Name:    "no-retry-" + test.name,
				Mode:    test.mode,
				Timeout: 1000,
				Targets: []*config.Target{
					{Address: "first.invalid:1"},
					{Address: "second.invalid:2"},
					{Address: "third.invalid:3"},
				},
			}
			holder, _, err := bulkhead.acquire(context.Background(), "capacity-holder:443")
			if err != nil {
				t.Fatal(err)
			}

			motoSide, clientSide := net.Pipe()
			test.run(runtime, motoSide, rule)
			_ = clientSide.Close()
			holder.release()

			snapshot := processMetrics.snapshot()
			if len(snapshot.dialAttempts) != 0 {
				t.Fatalf("local capacity error reached real dial metrics: %+v", snapshot.dialAttempts)
			}
			firstKey := dialMetricKey{rule: rule.Name, target: rule.Targets[0].Address}
			if snapshot.dialBulkheadRejected[firstKey] != 1 || snapshot.dialBulkheadWaitCount[firstKey] != 1 {
				t.Fatalf("first target bulkhead metrics = rejected %d waits %d, want 1/1",
					snapshot.dialBulkheadRejected[firstKey], snapshot.dialBulkheadWaitCount[firstKey])
			}
			for _, target := range rule.Targets[1:] {
				key := dialMetricKey{rule: rule.Name, target: target.Address}
				if snapshot.dialBulkheadWaitCount[key] != 0 {
					t.Fatalf("capacity error amplified into target %s", target.Address)
				}
			}
			if _, exists := runtime.loadBoostWinnerToken(boostRuleKey(rule)); exists {
				t.Fatal("local saturation unexpectedly ran Boost fallback")
			}
		})
	}
}

func TestDialBulkheadPerTargetSaturationUsesHealthyNormalFallback(t *testing.T) {
	backend := newReloadEchoBackend(t, "capacity-fallback")
	bulkhead := newDialBulkhead(2, 1, 5*time.Millisecond)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	first := "saturated.example:443"
	rule := &config.Rule{
		Name:    "per-target-fallback",
		Mode:    config.ModeNormal,
		Timeout: 1000,
		Targets: []*config.Target{{Address: first}, {Address: backend.addr()}},
	}
	holder, _, err := bulkhead.acquire(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	motoSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		runtime.handleNormal(context.Background(), motoSide, rule)
		close(done)
	}()
	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	line := make([]byte, len("capacity-fallback\n"))
	if _, err := io.ReadFull(clientSide, line); err != nil {
		_ = clientSide.Close()
		t.Fatalf("read fallback greeting: %v", err)
	}
	if string(line) != "capacity-fallback\n" {
		t.Fatalf("fallback greeting = %q", line)
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("normal fallback relay did not stop")
	}
}

func TestBoostCachedTargetSaturationUsesTryOnlyHealthyFallback(t *testing.T) {
	backend := newReloadEchoBackend(t, "cached-capacity-fallback")
	bulkhead := newDialBulkhead(2, 1, 10*time.Millisecond)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	cached := "cached-saturated.example:443"
	rule := boostTestRule("cached-target-capacity", "127.0.0.1:19110", cached, backend.addr())
	holder, _, err := bulkhead.acquire(context.Background(), cached)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	var fallbackTryOnly atomic.Bool
	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		cached,
		func(ctx context.Context, dialRule *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			if addr == backend.addr() {
				fallbackTryOnly.Store(options.tryOnly)
			}
			return runtime.outboundDialRouteWithOptions(ctx, dialRule, addr, options.tryOnly, options.onStart)
		},
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("cached Boost fallback failed: %v", err)
	}
	defer outcome.winner.conn.Close()
	if outcome.winner.addr != backend.addr() || !outcome.fallbackStarted || outcome.cachedFailed {
		t.Fatalf("cached capacity outcome = %+v", outcome)
	}
	if !fallbackTryOnly.Load() {
		t.Fatal("cached target saturation did not switch the healthy fallback to try-only admission")
	}
	if snapshot := bulkhead.snapshot(); snapshot.Waiting != 0 || snapshot.Active != 1 {
		t.Fatalf("cached fallback amplified bulkhead waiters or leaked capacity: %+v", snapshot)
	}
}

func TestBoostTargetSaturationRefillsTryOnlyWithoutWaiter(t *testing.T) {
	bulkhead := newDialBulkhead(3, 1, 10*time.Millisecond)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule(
		"target-capacity-refill",
		"127.0.0.1:19111",
		"saturated:443",
		"hard-fail:443",
		"healthy:443",
	)
	holder, _, err := bulkhead.acquire(context.Background(), "saturated:443")
	if err != nil {
		t.Fatal(err)
	}

	hardFailStarted := make(chan struct{})
	releaseHardFail := make(chan struct{})
	hardFailReturned := make(chan struct{})
	healthyStarted := make(chan struct{})
	peerReady := make(chan net.Conn, 1)
	var active atomic.Int32
	var peak atomic.Int32
	var healthyTryOnly atomic.Bool
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		switch addr {
		case "hard-fail:443":
			close(hardFailStarted)
			select {
			case <-releaseHardFail:
				close(hardFailReturned)
				return nil, errors.New("hard failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "healthy:443":
			close(healthyStarted)
			select {
			case <-hardFailReturned:
				connection, peer := net.Pipe()
				peerReady <- peer
				return connection, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		default:
			return nil, fmt.Errorf("unexpected network dial to %s", addr)
		}
	}
	acquire := func(ctx context.Context, dialRule *config.Rule, addr string, tryOnly bool) (boostDialRelease, error) {
		if addr == "healthy:443" {
			healthyTryOnly.Store(tryOnly)
		}
		return runtime.acquireBoostTrafficDial(ctx, dialRule, addr, tryOnly)
	}

	type raceResult struct {
		winner dialResult
		err    error
	}
	done := make(chan raceResult, 1)
	go func() {
		winner, raceErr := runtime.raceBoostTargetsPreparedWithAdmission(
			context.Background(), rule, dial, nil, acquire,
		)
		done <- raceResult{winner: winner, err: raceErr}
	}()
	select {
	case <-hardFailStarted:
	case <-time.After(time.Second):
		holder.release()
		t.Fatal("initial hard-failing candidate did not start")
	}
	select {
	case <-healthyStarted:
	case <-time.After(time.Second):
		close(releaseHardFail)
		holder.release()
		t.Fatal("target-scoped saturation did not refill from the healthy candidate")
	}
	if !healthyTryOnly.Load() {
		close(releaseHardFail)
		holder.release()
		t.Fatal("post-saturation refill did not use try-only admission")
	}
	if snapshot := bulkhead.snapshot(); snapshot.Waiting != 0 {
		close(releaseHardFail)
		holder.release()
		t.Fatalf("post-saturation refill created a bulkhead waiter: %+v", snapshot)
	}
	close(releaseHardFail)

	var completed raceResult
	select {
	case completed = <-done:
	case <-time.After(2 * time.Second):
		holder.release()
		t.Fatal("Boost race did not finish")
	}
	if completed.err != nil || completed.winner.addr != "healthy:443" || completed.winner.conn == nil {
		holder.release()
		t.Fatalf("Boost refill result = %+v, error %v", completed.winner, completed.err)
	}
	_ = completed.winner.conn.Close()
	_ = (<-peerReady).Close()
	if got := peak.Load(); got > 2 {
		holder.release()
		t.Fatalf("Boost network dial concurrency peaked at %d, want at most 2", got)
	}
	holder.release()
	waitForDialBulkheadState(t, bulkhead, 0, 0)
}

func TestBoostCapacityErrorDoesNotCancelIndependentInflightCandidate(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("capacity-inflight", "127.0.0.1:19109", "limited:443", "winner:443")
	winnerDialStarted := make(chan struct{})
	releaseWinner := make(chan struct{})
	peers := make(chan net.Conn, 1)

	acquire := func(ctx context.Context, _ *config.Rule, target string, _ bool) (boostDialRelease, error) {
		if target == "limited:443" {
			select {
			case <-winnerDialStarted:
				return nil, &dialBulkheadError{
					target: target, saturated: true, scope: dialSaturationTarget,
				}
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return func() {}, nil
	}
	dial := func(ctx context.Context, target string) (net.Conn, error) {
		if target != "winner:443" {
			return nil, errors.New("limited target unexpectedly reached dial")
		}
		close(winnerDialStarted)
		select {
		case <-releaseWinner:
			connection, peer := net.Pipe()
			peers <- peer
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	type boostCapacityResult struct {
		winner dialResult
		err    error
	}
	result := make(chan boostCapacityResult, 1)
	go func() {
		winner, raceErr := runtime.raceBoostTargetsPreparedWithAdmission(
			context.Background(), rule, dial, nil, acquire,
		)
		result <- boostCapacityResult{winner: winner, err: raceErr}
	}()
	select {
	case <-winnerDialStarted:
	case <-time.After(time.Second):
		t.Fatal("independent Boost candidate did not start")
	}
	time.Sleep(20 * time.Millisecond)
	close(releaseWinner)
	select {
	case completed := <-result:
		if completed.err != nil || completed.winner.conn == nil || completed.winner.addr != "winner:443" {
			t.Fatalf("Boost canceled independent candidate: %v", completed.err)
		}
		_ = completed.winner.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Boost did not finish after independent candidate succeeded")
	}
	_ = (<-peers).Close()
}

func TestDialBulkheadBoostSaturationStopsBeforeNetworkAndFurtherTargets(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	bulkhead := newDialBulkhead(1, 1, 10*time.Millisecond)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-boost-stop", "127.0.0.1:19100", "one:1", "two:2", "three:3")
	holder, _, err := bulkhead.acquire(context.Background(), "capacity-holder:443")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	var actualDials atomic.Int32
	_, err = runtime.raceBoostTargets(context.Background(), rule, func(context.Context, string) (net.Conn, error) {
		actualDials.Add(1)
		return nil, errors.New("must not dial while capacity is full")
	})
	if !isDialBulkheadError(err) || !errors.Is(err, errDialBulkheadSaturated) {
		t.Fatalf("raceBoostTargets error = %v, want bulkhead saturation", err)
	}
	if got := actualDials.Load(); got != 0 {
		t.Fatalf("actual network dials = %d, want zero", got)
	}
	snapshot := processMetrics.snapshot()
	waits := uint64(0)
	for _, target := range rule.Targets {
		waits += snapshot.dialBulkheadWaitCount[dialMetricKey{rule: rule.Name, target: target.Address}]
	}
	if waits > 2 {
		t.Fatalf("Boost capacity failure queued %d targets, want at most initial Top-2", waits)
	}
}

func TestDialBulkheadCapsConcurrentBoostNetworkDials(t *testing.T) {
	bulkhead := newDialBulkhead(1, 1, time.Second)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-boost-cap", "127.0.0.1:19101", "one:1", "two:2", "three:3")

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var startOnce sync.Once
	var active atomic.Int32
	var peak atomic.Int32
	var calls atomic.Int32
	var peersMu sync.Mutex
	var peers []net.Conn
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		call := calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		if call == 1 {
			startOnce.Do(func() { close(firstStarted) })
			select {
			case <-releaseFirst:
				return nil, errors.New("first route unavailable")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		connection, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return connection, nil
	}
	type raceResult struct {
		winner dialResult
		err    error
	}
	result := make(chan raceResult, 1)
	go func() {
		winner, raceErr := runtime.raceBoostTargets(context.Background(), rule, dial)
		result <- raceResult{winner: winner, err: raceErr}
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first Boost dial did not start")
	}
	waitForDialBulkheadState(t, bulkhead, 1, 1)
	close(releaseFirst)

	var completed raceResult
	select {
	case completed = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("Boost race did not finish")
	}
	if completed.err != nil {
		t.Fatalf("Boost race error = %v", completed.err)
	}
	_ = completed.winner.conn.Close()
	peersMu.Lock()
	for _, peer := range peers {
		_ = peer.Close()
	}
	peersMu.Unlock()
	if got := peak.Load(); got != 1 {
		t.Fatalf("concurrent real Boost dials peaked at %d, want 1", got)
	}
	waitForDialBulkheadState(t, bulkhead, 0, 0)
}

func TestDialBulkheadSaturationPreservesCachedBoostWinner(t *testing.T) {
	bulkhead := newDialBulkhead(1, 1, 5*time.Millisecond)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-cache", "127.0.0.1:19102", "cached:443", "fallback:443")
	key := boostRuleKey(rule)
	token := runtime.storeBoostWinner(key, "cached:443")
	holder, _, err := bulkhead.acquire(context.Background(), "capacity-holder:443")
	if err != nil {
		t.Fatal(err)
	}

	motoSide, clientSide := net.Pipe()
	runtime.handleBoost(context.Background(), motoSide, rule)
	_ = clientSide.Close()
	holder.release()

	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != token.addr || entry.generation != token.generation {
		t.Fatalf("cached winner after local saturation = %+v, %v; want generation %d address %s",
			entry, ok, token.generation, token.addr)
	}
}

func TestDialBulkheadCapacityWaitDoesNotClaimHalfOpenProbe(t *testing.T) {
	bulkhead := newDialBulkhead(1, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-half-open", "127.0.0.1:19103", "recovering:443")
	target := rule.Targets[0].Address
	failureTime := time.Now().Add(-routeInitialCooldown - time.Second)
	for failure := 0; failure < routeFailureThreshold; failure++ {
		attempt, err := runtime.routes.begin(rule, target, failureTime)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, time.Millisecond, errors.New("route unavailable"), failureTime)
	}
	before := runtime.routes.snapshot(rule, target, time.Now())
	if !before.ProbeRequired || before.HalfOpen {
		t.Fatalf("route before capacity wait = %+v, want unclaimed half-open probe", before)
	}
	holder, _, err := bulkhead.acquire(context.Background(), "capacity-holder:443")
	if err != nil {
		t.Fatal(err)
	}
	_, attempt, err := runtime.outboundDialRoute(context.Background(), rule, target)
	if !isDialBulkheadError(err) || attempt.valid {
		t.Fatalf("capacity-limited half-open dial = attempt %+v, error %v", attempt, err)
	}
	after := runtime.routes.snapshot(rule, target, time.Now())
	if after.HalfOpen || !after.ProbeRequired || after.LastAttempt != before.LastAttempt ||
		after.ConsecutiveFailures != before.ConsecutiveFailures {
		t.Fatalf("capacity wait claimed or changed half-open route:\nbefore=%+v\nafter=%+v", before, after)
	}
	holder.release()
	replacement, err := runtime.routes.begin(rule, target, time.Now())
	if err != nil {
		t.Fatalf("replacement half-open probe was not available: %v", err)
	}
	routeObserve(replacement, time.Millisecond, context.Canceled, time.Now())
}

func TestDialBulkheadBoostWinnerCancelsBlockedProxyPrepare(t *testing.T) {
	bulkhead := newDialBulkhead(2, 2, time.Second)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-proxy-cancel", "127.0.0.1:19104", "blocked:443", "winner:443")
	blockedStarted := make(chan struct{})
	var blockedOnce sync.Once
	var peersMu sync.Mutex
	var peers []net.Conn
	dial := func(context.Context, string) (net.Conn, error) {
		connection, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return connection, nil
	}
	prepare := func(ctx context.Context, connection net.Conn, target string) error {
		if target == "winner:443" {
			select {
			case <-blockedStarted:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return writeProxyProtocolWithContext(ctx, connection, "test Boost", func() error {
			blockedOnce.Do(func() { close(blockedStarted) })
			_, err := connection.Write([]byte("blocked proxy header"))
			return err
		})
	}

	started := time.Now()
	winner, err := runtime.raceBoostTargetsPrepared(context.Background(), rule, dial, prepare)
	if err != nil {
		t.Fatalf("Boost race error = %v", err)
	}
	defer winner.conn.Close()
	if winner.addr != "winner:443" {
		t.Fatalf("Boost winner = %s, want winner:443", winner.addr)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Boost winner waited %s for canceled blocked prepare", elapsed)
	}
	peersMu.Lock()
	for _, peer := range peers {
		_ = peer.Close()
	}
	peersMu.Unlock()
	blocked := runtime.routes.snapshot(rule, "blocked:443", time.Now())
	if blocked.Observed || blocked.ConsecutiveFailures != 0 || blocked.CircuitOpen {
		t.Fatalf("canceled blocked prepare polluted route health: %+v", blocked)
	}
	waitForDialBulkheadState(t, bulkhead, 0, 0)
}

func TestDialBulkheadLazyRevalidationUsesIndependentBackgroundCapacity(t *testing.T) {
	backendA := newReloadEchoBackend(t, "lazy-a")
	backendB := newReloadEchoBackend(t, "lazy-b")
	backgroundDials := make(chan struct{}, 1)
	foregroundDials := newDialBulkhead(1, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(backgroundDials, foregroundDials)
	defer runtime.stopBackground()
	rule := boostTestRule("bulkhead-lazy-background", "127.0.0.1:19105", backendA.addr(), backendB.addr())
	holder, _, err := foregroundDials.acquire(context.Background(), "foreground-holder:443")
	if err != nil {
		t.Fatal(err)
	}

	key := boostRuleKey(rule)
	runtime.lazyRevalidate(context.Background(), rule, key)
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || (entry.addr != backendA.addr() && entry.addr != backendB.addr()) {
		holder.release()
		t.Fatalf("lazy revalidation did not use independent background capacity: %+v, %v", entry, ok)
	}
	if snapshot := foregroundDials.snapshot(); snapshot.Active != 1 || snapshot.Waiting != 0 ||
		snapshot.ActiveByTarget["foreground-holder:443"] != 1 {
		holder.release()
		t.Fatalf("lazy revalidation consumed foreground capacity: %+v", snapshot)
	}
	holder.release()
	waitForDialBulkheadState(t, foregroundDials, 0, 0)

	// Conversely, a full maintenance budget must not prevent a real request
	// from using its separately reserved foreground allowance.
	backgroundDials <- struct{}{}
	foreground, err := runtime.acquireTrafficDial(context.Background(), rule, backendA.addr())
	if err != nil {
		<-backgroundDials
		t.Fatalf("full background budget blocked foreground dial admission: %v", err)
	}
	foreground.release()
	<-backgroundDials
}
