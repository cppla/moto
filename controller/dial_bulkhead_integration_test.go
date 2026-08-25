package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"testing"
	"time"
)

type runtimeDialPermitResult struct {
	permit *dialPermit
	err    error
}

func acquireRuntimeDialAsync(ctx context.Context, runtime *routingRuntime, rule *config.Rule, target string) <-chan runtimeDialPermitResult {
	result := make(chan runtimeDialPermitResult, 1)
	go func() {
		permit, err := runtime.acquireTrafficDial(ctx, rule, target)
		result <- runtimeDialPermitResult{permit: permit, err: err}
	}()
	return result
}

func receiveRuntimeDialPermit(t *testing.T, result <-chan runtimeDialPermitResult) runtimeDialPermitResult {
	t.Helper()
	select {
	case acquired := <-result:
		return acquired
	case <-time.After(2 * time.Second):
		t.Fatal("routing runtime did not finish acquiring dial capacity")
		return runtimeDialPermitResult{}
	}
}

func TestDialBulkheadOutboundSaturationDoesNotTouchNetworkRouteOrDialMetrics(t *testing.T) {
	resetProcessMetricsForTest()
	t.Cleanup(resetProcessMetricsForTest)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acceptResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if conn != nil {
			_ = conn.Close()
			acceptResult <- errors.New("backend accepted an unexpected foreground dial")
			return
		}
		acceptResult <- acceptErr
	}()

	target := listener.Addr().String()
	rule := &config.Rule{
		Name:    "bulkhead-neutral",
		Listen:  "127.0.0.1:19001",
		Mode:    config.ModeNormal,
		Targets: []*config.Target{{Address: target}},
	}
	bulkhead := newDialBulkhead(1, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	t.Cleanup(runtime.stopBackground)

	holder, _, err := bulkhead.acquire(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	// Start with non-zero route and dial state so the test detects both creation
	// of a new attempt and mutation of an existing failure streak.
	baselineTime := time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC)
	attempt, err := runtime.routes.begin(rule, target, baselineTime)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(attempt, 10*time.Millisecond, errors.New("baseline route failure"), baselineTime)
	beforeRoute := runtime.routes.snapshot(rule, target, baselineTime)

	metricDial(rule.Name, target, 5*time.Millisecond, nil)
	metricDial(rule.Name, target, 7*time.Millisecond, errors.New("baseline metric failure"))
	metricKey := dialMetricKey{rule: rule.Name, target: target}
	beforeMetrics := processMetrics.snapshot()

	conn, gotAttempt, dialErr := runtime.outboundDialRoute(context.Background(), rule, target)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("saturated outbound path returned a network connection")
	}
	if gotAttempt.valid {
		t.Fatal("saturated outbound path claimed a route attempt before network dialing")
	}
	if !errors.Is(dialErr, errDialBulkheadSaturated) || !isDialBulkheadError(dialErr) {
		t.Fatalf("outboundDialRoute error = %v, want local bulkhead saturation", dialErr)
	}

	afterRoute := runtime.routes.snapshot(rule, target, time.Now())
	if afterRoute != beforeRoute {
		t.Fatalf("capacity rejection changed route state:\nbefore=%+v\nafter=%+v", beforeRoute, afterRoute)
	}
	afterMetrics := processMetrics.snapshot()
	if afterMetrics.dialAttempts[metricKey] != beforeMetrics.dialAttempts[metricKey] ||
		afterMetrics.dialSuccess[metricKey] != beforeMetrics.dialSuccess[metricKey] ||
		afterMetrics.dialFailures[metricKey] != beforeMetrics.dialFailures[metricKey] ||
		afterMetrics.dialCanceled[metricKey] != beforeMetrics.dialCanceled[metricKey] ||
		afterMetrics.dialLatencyNanos[metricKey] != beforeMetrics.dialLatencyNanos[metricKey] ||
		afterMetrics.dialLatencyCount[metricKey] != beforeMetrics.dialLatencyCount[metricKey] {
		t.Fatalf("capacity rejection changed network dial metrics:\nbefore=%+v\nafter=%+v", beforeMetrics, afterMetrics)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case acceptErr := <-acceptResult:
		if !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("backend accept result = %v, want listener closure without a dial", acceptErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend accept did not stop after listener closure")
	}
}

func TestDialBulkheadSharedAcrossRoutingRuntimes(t *testing.T) {
	tests := []struct {
		name           string
		globalLimit    int
		perTargetLimit int
		heldTarget     string
		waitingTarget  string
	}{
		{
			name:           "global limit",
			globalLimit:    1,
			perTargetLimit: 1,
			heldTarget:     "generation-one:443",
			waitingTarget:  "generation-two:443",
		},
		{
			name:           "per-target limit",
			globalLimit:    2,
			perTargetLimit: 1,
			heldTarget:     "shared-target:443",
			waitingTarget:  "shared-target:443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetProcessMetricsForTest()
			defer resetProcessMetricsForTest()

			shared := newDialBulkhead(test.globalLimit, test.perTargetLimit, time.Second)
			sharedPrewarm := make(chan struct{}, 1)
			oldRuntime := newRoutingRuntimeWithDialResources(sharedPrewarm, shared)
			newRuntime := newRoutingRuntimeWithDialResources(sharedPrewarm, shared)
			defer oldRuntime.stopBackground()
			defer newRuntime.stopBackground()
			if oldRuntime.trafficDials != shared || newRuntime.trafficDials != shared {
				t.Fatal("routing generations did not retain the shared dial bulkhead")
			}

			oldRule := &config.Rule{Name: "old-generation", Mode: config.ModeNormal}
			newRule := &config.Rule{Name: "new-generation", Mode: config.ModeNormal}
			holder, err := oldRuntime.acquireTrafficDial(context.Background(), oldRule, test.heldTarget)
			if err != nil {
				t.Fatal(err)
			}
			waiting := acquireRuntimeDialAsync(context.Background(), newRuntime, newRule, test.waitingTarget)
			snapshot := waitForDialBulkheadState(t, shared, 1, 1)
			if snapshot.ActiveByTarget[test.heldTarget] != 1 {
				t.Fatalf("old generation active target state = %+v", snapshot.ActiveByTarget)
			}

			holder.release()
			acquired := receiveRuntimeDialPermit(t, waiting)
			if acquired.err != nil || acquired.permit == nil {
				t.Fatalf("new generation acquire after old release = (%v, %v)", acquired.permit, acquired.err)
			}
			snapshot = waitForDialBulkheadState(t, shared, 1, 0)
			if snapshot.ActiveByTarget[test.waitingTarget] != 1 {
				t.Fatalf("new generation target state = %+v", snapshot.ActiveByTarget)
			}
			acquired.permit.release()
			snapshot = waitForDialBulkheadState(t, shared, 0, 0)
			if len(snapshot.ActiveByTarget) != 0 {
				t.Fatalf("shared generation test retained target state: %+v", snapshot.ActiveByTarget)
			}
		})
	}
}

func TestDialBulkheadReloadGenerationsShareServerCapacity(t *testing.T) {
	listen := unusedReloadAddress(t)
	server, err := NewServer([]*config.Rule{reloadRule("bulkhead-old", listen, "old-target:443")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	shared := newDialBulkhead(1, 1, time.Second)
	server.trafficDials = shared
	oldGeneration := server.current.Load()
	oldGeneration.runtime.trafficDials = shared
	holder, err := oldGeneration.runtime.acquireTrafficDial(context.Background(), oldGeneration.rules[0], "shared-target:443")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := server.ReloadRules(context.Background(), []*config.Rule{
		reloadRule("bulkhead-new", listen, "new-target:443"),
	}); err != nil {
		holder.release()
		t.Fatal(err)
	}
	newGeneration := server.current.Load()
	if newGeneration == oldGeneration || newGeneration.runtime.trafficDials != shared || server.trafficDials != shared {
		holder.release()
		t.Fatal("reload generation did not retain the Server-shared dial bulkhead")
	}
	waiting := acquireRuntimeDialAsync(context.Background(), newGeneration.runtime, newGeneration.rules[0], "shared-target:443")
	waitForDialBulkheadState(t, shared, 1, 1)
	holder.release()
	acquired := receiveRuntimeDialPermit(t, waiting)
	if acquired.err != nil || acquired.permit == nil {
		t.Fatalf("new generation did not acquire released old-generation capacity: (%v, %v)", acquired.permit, acquired.err)
	}
	acquired.permit.release()
	waitForDialBulkheadState(t, shared, 0, 0)
}

func TestDialBulkheadPrewarmHitBypassesFullForegroundCapacity(t *testing.T) {
	if !prewarmReuseSupported {
		t.Skip("safe prewarm reuse is disabled on this platform")
	}
	resetProcessMetricsForTest()
	t.Cleanup(resetProcessMetricsForTest)

	bulkhead := newDialBulkhead(1, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	t.Cleanup(runtime.stopBackground)
	target := "prewarmed-target.test:443"
	rule := &config.Rule{
		Name:    "prewarm-bypass",
		Listen:  "127.0.0.1:19002",
		Mode:    config.ModeNormal,
		Prewarm: true,
		Targets: []*config.Target{{Address: target}},
	}

	pooled, peer := newTCPPair(t)
	defer peer.Close()
	pool := runtime.prewarm.newPool(target, 1)
	pool.idle = []idlePrewarmConn{{conn: pooled, idleSince: time.Now()}}
	runtime.prewarm.mu.Lock()
	runtime.prewarm.pools[target] = pool
	runtime.prewarm.mu.Unlock()

	holder, _, err := bulkhead.acquire(context.Background(), "foreground-holder:443")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()
	if snapshot := bulkhead.snapshot(); snapshot.Active != 1 || snapshot.Waiting != 0 {
		t.Fatalf("full foreground capacity snapshot = %+v", snapshot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired, attempt, err := runtime.outboundDialRoute(ctx, rule, target)
	if err != nil {
		t.Fatalf("prewarm hit waited for foreground dial capacity: %v", err)
	}
	if acquired != pooled {
		if acquired != nil {
			_ = acquired.Close()
		}
		t.Fatalf("outboundDialRoute returned %v, want the prewarmed connection", acquired)
	}
	if !attempt.valid {
		_ = acquired.Close()
		t.Fatal("prewarm hit did not receive a route-attribution attempt")
	}
	if snapshot := bulkhead.snapshot(); snapshot.Active != 1 || snapshot.Waiting != 0 || snapshot.ActiveByTarget["foreground-holder:443"] != 1 {
		_ = acquired.Close()
		t.Fatalf("prewarm hit changed foreground bulkhead accounting: %+v", snapshot)
	}
	_ = acquired.Close()

	holder.release()
	snapshot := waitForDialBulkheadState(t, bulkhead, 0, 0)
	if len(snapshot.ActiveByTarget) != 0 {
		t.Fatalf("prewarm test retained foreground target state: %+v", snapshot.ActiveByTarget)
	}
}
