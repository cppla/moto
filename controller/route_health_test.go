package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetRouteHealthForTest() {
	routeHealth.Lock()
	routeHealth.states = make(map[routeHealthKey]*routeHealthState)
	routeHealth.nextAttempt = 0
	routeHealth.Unlock()
}

func observeRoute(t *testing.T, rule *config.Rule, addr string, latency time.Duration, err error, now time.Time) {
	t.Helper()
	attempt, beginErr := routeBegin(rule, addr, now)
	if beginErr != nil {
		t.Fatalf("routeBegin(%q): %v", addr, beginErr)
	}
	routeObserve(attempt, latency, err, now)
}

func routeHealthTestRule(addresses ...string) *config.Rule {
	targets := make([]*config.Target, 0, len(addresses))
	for _, address := range addresses {
		targets = append(targets, &config.Target{Address: address})
	}
	return &config.Rule{
		Name:    "route-health-test",
		Listen:  "127.0.0.1:10000",
		Mode:    config.ModeBoost,
		Targets: targets,
	}
}

func tripRoute(t *testing.T, rule *config.Rule, addr string, now time.Time) {
	t.Helper()
	for i := 0; i < routeFailureThreshold; i++ {
		attempt, err := routeBegin(rule, addr, now)
		if err != nil {
			t.Fatalf("routeBegin() before failure %d: %v", i+1, err)
		}
		routeObserve(attempt, time.Duration(i+1)*time.Millisecond, errors.New("dial failed"), now)
	}
}

func TestRouteHealthTripsAfterThreeConsecutiveFailures(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	tripRoute(t, rule, "one:1", now)

	snapshot := routeSnapshot(rule, "one:1", now)
	if !snapshot.Observed || !snapshot.CircuitOpen {
		t.Fatalf("snapshot after trip = %+v, want observed open circuit", snapshot)
	}
	if snapshot.ConsecutiveFailures != routeFailureThreshold {
		t.Fatalf("failures = %d, want %d", snapshot.ConsecutiveFailures, routeFailureThreshold)
	}
	if snapshot.Cooldown != 5*time.Second || !snapshot.OpenUntil.Equal(now.Add(5*time.Second)) {
		t.Fatalf("cooldown snapshot = %+v, want five seconds", snapshot)
	}
	if _, err := routeBegin(rule, "one:1", now.Add(4999*time.Millisecond)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("routeBegin() during cooldown = %v, want ErrCircuitOpen", err)
	}
	if targets := selectRouteTargets(rule, 1, now.Add(time.Second)); len(targets) != 0 {
		t.Fatalf("selector returned cooling target: %+v", targets)
	}
}

func TestRouteHealthAllowsOnlyOneConcurrentHalfOpenProbe(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 1, 0, 0, time.UTC)
	tripRoute(t, rule, "one:1", now)
	probeTime := now.Add(routeInitialCooldown)
	if snapshot := routeSnapshot(rule, "one:1", probeTime); !snapshot.ProbeRequired {
		t.Fatalf("snapshot at cooldown expiry = %+v, want required probe", snapshot)
	}

	const callers = 32
	start := make(chan struct{})
	var ready sync.WaitGroup
	var done sync.WaitGroup
	var admitted atomic.Int32
	var rejected atomic.Int32
	ready.Add(callers)
	done.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			_, err := routeBegin(rule, "one:1", probeTime)
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, ErrCircuitOpen):
				rejected.Add(1)
			default:
				t.Errorf("routeBegin() error = %v", err)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted half-open probes = %d, want 1", got)
	}
	if got := rejected.Load(); got != callers-1 {
		t.Fatalf("rejected half-open probes = %d, want %d", got, callers-1)
	}
	if snapshot := routeSnapshot(rule, "one:1", probeTime); !snapshot.HalfOpen {
		t.Fatalf("snapshot = %+v, want half-open probe in flight", snapshot)
	}
}

func TestRouteHealthCooldownCapsAtOneMinute(t *testing.T) {
	tests := []struct {
		previous time.Duration
		want     time.Duration
	}{
		{previous: 0, want: 5 * time.Second},
		{previous: 5 * time.Second, want: 10 * time.Second},
		{previous: 10 * time.Second, want: 20 * time.Second},
		{previous: 20 * time.Second, want: 40 * time.Second},
		{previous: 40 * time.Second, want: 60 * time.Second},
		{previous: 60 * time.Second, want: 60 * time.Second},
	}
	for _, test := range tests {
		if got := nextRouteCooldown(test.previous); got != test.want {
			t.Errorf("nextRouteCooldown(%s) = %s, want %s", test.previous, got, test.want)
		}
	}
}

func TestRouteHealthProbeBackoffAndRecovery(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 2, 0, 0, time.UTC)
	tripRoute(t, rule, "one:1", now)

	firstProbe := now.Add(5 * time.Second)
	firstAttempt, err := routeBegin(rule, "one:1", firstProbe)
	if err != nil {
		t.Fatalf("first half-open routeBegin() = %v", err)
	}
	routeObserve(firstAttempt, 50*time.Millisecond, errors.New("probe failed"), firstProbe)
	snapshot := routeSnapshot(rule, "one:1", firstProbe)
	if snapshot.Cooldown != 10*time.Second || !snapshot.OpenUntil.Equal(firstProbe.Add(10*time.Second)) {
		t.Fatalf("snapshot after failed probe = %+v, want ten-second cooldown", snapshot)
	}

	secondProbe := firstProbe.Add(10 * time.Second)
	secondAttempt, err := routeBegin(rule, "one:1", secondProbe)
	if err != nil {
		t.Fatalf("second half-open routeBegin() = %v", err)
	}
	routeObserve(secondAttempt, 40*time.Millisecond, nil, secondProbe)
	snapshot = routeSnapshot(rule, "one:1", secondProbe)
	if snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("snapshot after recovery = %+v, want closed healthy route", snapshot)
	}
	if snapshot.EWMA != 40*time.Millisecond {
		t.Fatalf("EWMA after recovery = %s, want 40ms", snapshot.EWMA)
	}
	if _, err := routeBegin(rule, "one:1", secondProbe); err != nil {
		t.Fatalf("routeBegin() after recovery = %v", err)
	}
}

func TestRouteHealthCancelledProbeIsNeutralAndReleasesClaim(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 2, 30, 0, time.UTC)
	tripRoute(t, rule, "one:1", now)
	probeTime := now.Add(routeInitialCooldown)
	probeAttempt, err := routeBegin(rule, "one:1", probeTime)
	if err != nil {
		t.Fatalf("half-open routeBegin() = %v", err)
	}
	routeObserve(probeAttempt, time.Second, context.Canceled, probeTime)

	snapshot := routeSnapshot(rule, "one:1", probeTime)
	if snapshot.HalfOpen || !snapshot.ProbeRequired {
		t.Fatalf("snapshot after cancelled probe = %+v, want a new probe", snapshot)
	}
	if snapshot.ConsecutiveFailures != routeFailureThreshold || snapshot.Cooldown != routeInitialCooldown {
		t.Fatalf("cancelled probe changed failure state: %+v", snapshot)
	}
	if _, err := routeBegin(rule, "one:1", probeTime); err != nil {
		t.Fatalf("replacement half-open routeBegin() = %v", err)
	}
}

func TestRouteHealthIgnoresOutOfOrderPreCircuitResults(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 2, 45, 0, time.UTC)

	stale := make([]routeAttempt, 4)
	for i := range stale {
		attempt, err := routeBegin(rule, "one:1", now)
		if err != nil {
			t.Fatal(err)
		}
		stale[i] = attempt
	}
	tripRoute(t, rule, "one:1", now)

	firstProbeTime := now.Add(routeInitialCooldown)
	firstProbe, err := routeBegin(rule, "one:1", firstProbeTime)
	if err != nil {
		t.Fatal(err)
	}
	// A cancelled attempt that predates the circuit must not release the probe.
	routeObserve(stale[0], time.Second, context.Canceled, firstProbeTime)
	if snapshot := routeSnapshot(rule, "one:1", firstProbeTime); !snapshot.HalfOpen {
		t.Fatalf("stale cancellation released half-open probe: %+v", snapshot)
	}
	routeObserve(firstProbe, 50*time.Millisecond, errors.New("probe failed"), firstProbeTime)

	// A late success from before the circuit opened must not bypass cooldown.
	routeObserve(stale[1], 2*time.Second, nil, firstProbeTime.Add(time.Second))
	if snapshot := routeSnapshot(rule, "one:1", firstProbeTime.Add(time.Second)); !snapshot.CircuitOpen || snapshot.Cooldown != 10*time.Second {
		t.Fatalf("stale success changed open circuit: %+v", snapshot)
	}

	secondProbeTime := firstProbeTime.Add(10 * time.Second)
	secondProbe, err := routeBegin(rule, "one:1", secondProbeTime)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(secondProbe, 25*time.Millisecond, nil, secondProbeTime)
	for _, attempt := range stale[2:] {
		routeObserve(attempt, 3*time.Second, errors.New("stale failure"), secondProbeTime.Add(time.Second))
	}
	if snapshot := routeSnapshot(rule, "one:1", secondProbeTime.Add(time.Second)); snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("stale failures changed recovered circuit: %+v", snapshot)
	}
}

func TestRouteHealthEWMAAndCancellation(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 3, 0, 0, time.UTC)
	observeRoute(t, rule, "one:1", 100*time.Millisecond, nil, now)
	observeRoute(t, rule, "one:1", 200*time.Millisecond, nil, now.Add(time.Second))

	before := routeSnapshot(rule, "one:1", now.Add(time.Second))
	if before.EWMA != 120*time.Millisecond {
		t.Fatalf("EWMA = %s, want 120ms", before.EWMA)
	}
	cancelledAttempt, err := routeBegin(rule, "one:1", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(cancelledAttempt, time.Second, fmt.Errorf("race loser: %w", context.Canceled), now.Add(2*time.Second))
	after := routeSnapshot(rule, "one:1", now.Add(2*time.Second))
	if after.EWMA != before.EWMA || after.ConsecutiveFailures != before.ConsecutiveFailures ||
		after.CircuitOpen != before.CircuitOpen || after.HalfOpen != before.HalfOpen {
		t.Fatalf("cancellation changed route outcome state: before=%+v after=%+v", before, after)
	}
	if !after.LastAttempt.Equal(now.Add(2 * time.Second)) {
		t.Fatalf("last attempt = %s, want cancelled attempt start", after.LastAttempt)
	}
}

func TestRouteRelayFailuresTripAndSuccessfulTrafficResets(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 3, 30, 0, time.UTC)
	upstreamErr := &net.OpError{Op: "write", Net: "tcp", Err: errors.New("connection reset")}

	for i := 0; i < routeFailureThreshold; i++ {
		attempt, err := routeBegin(rule, "one:1", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, 10*time.Millisecond, nil, now.Add(time.Duration(i)*time.Second))
		routeReportFailure(attempt, upstreamErr, now.Add(time.Duration(i)*time.Second))
	}
	if snapshot := routeSnapshot(rule, "one:1", now.Add(2*time.Second)); !snapshot.CircuitOpen || snapshot.ConsecutiveFailures != routeFailureThreshold {
		t.Fatalf("relay failures did not trip route: %+v", snapshot)
	}

	probeTime := now.Add(2*time.Second + routeInitialCooldown)
	probe, err := routeBegin(rule, "one:1", probeTime)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(probe, 10*time.Millisecond, nil, probeTime)
	routeReportSuccess(probe)

	next, err := routeBegin(rule, "one:1", probeTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(next, 10*time.Millisecond, nil, probeTime.Add(time.Second))
	routeReportFailure(next, upstreamErr, probeTime.Add(time.Second))
	if snapshot := routeSnapshot(rule, "one:1", probeTime.Add(time.Second)); snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 1 {
		t.Fatalf("successful relay did not reset failure streak: %+v", snapshot)
	}
}

func TestRouteRelaySuccessClearsDialFailureStreakForPooledConnection(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 3, 45, 0, time.UTC)
	for i := 0; i < routeFailureThreshold-1; i++ {
		observeRoute(t, rule, "one:1", 10*time.Millisecond, errors.New("replenishment failed"), now.Add(time.Duration(i)*time.Second))
	}

	pooledAttempt, err := routeBegin(rule, "one:1", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	// Pooled connections intentionally have no routeObserve call. Successful
	// traffic is their proof of health.
	routeReportSuccess(pooledAttempt)
	if snapshot := routeSnapshot(rule, "one:1", now.Add(2*time.Second)); snapshot.ConsecutiveFailures != 0 || snapshot.CircuitOpen {
		t.Fatalf("successful pooled traffic did not reset failures: %+v", snapshot)
	}

	observeRoute(t, rule, "one:1", 10*time.Millisecond, errors.New("later failure"), now.Add(3*time.Second))
	if snapshot := routeSnapshot(rule, "one:1", now.Add(3*time.Second)); snapshot.ConsecutiveFailures != 1 || snapshot.CircuitOpen {
		t.Fatalf("later failure was not a fresh streak: %+v", snapshot)
	}
}

func TestSelectRouteTargetsExploresThenRanksTopTwo(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("slow:1", "fast:1", "new-one:1", "new-two:1")
	now := time.Date(2026, 8, 18, 10, 4, 0, 0, time.UTC)
	observeRoute(t, rule, "slow:1", 100*time.Millisecond, nil, now)
	observeRoute(t, rule, "fast:1", 20*time.Millisecond, nil, now)

	selected := selectRouteTargets(rule, 2, now)
	assertRouteAddresses(t, selected, "fast:1", "new-one:1")

	observeRoute(t, rule, "new-one:1", 40*time.Millisecond, nil, now)
	observeRoute(t, rule, "new-two:1", 60*time.Millisecond, nil, now)
	selected = selectRouteTargets(rule, 2, now)
	assertRouteAddresses(t, selected, "fast:1", "new-one:1")

	selected = selectRouteTargets(rule, 2, now.Add(routeExplorationAfter))
	assertRouteAddresses(t, selected, "fast:1", "slow:1")

	// A recent failure penalizes an otherwise fast route without opening it.
	observeRoute(t, rule, "fast:1", 5*time.Millisecond, errors.New("temporary failure"), now)
	selected = selectRouteTargets(rule, 2, now)
	assertRouteAddresses(t, selected, "new-one:1", "new-two:1")
}

func TestSelectRouteTargetsKeepsBestAndRotatesUnobserved(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("best:1", "cancelled:1", "new-one:1", "new-two:1")
	now := time.Date(2026, 8, 18, 10, 5, 0, 0, time.UTC)
	observeRoute(t, rule, "best:1", 10*time.Millisecond, nil, now)

	cancelled, err := routeBegin(rule, "cancelled:1", now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(cancelled, 10*time.Millisecond, context.Canceled, now)
	assertRouteAddresses(t, selectRouteTargets(rule, 2, now), "best:1", "new-one:1")

	newOne, err := routeBegin(rule, "new-one:1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(newOne, 10*time.Millisecond, context.Canceled, now.Add(time.Second))
	assertRouteAddresses(t, selectRouteTargets(rule, 2, now.Add(time.Second)), "best:1", "new-two:1")

	newTwo, err := routeBegin(rule, "new-two:1", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(newTwo, 10*time.Millisecond, context.Canceled, now.Add(2*time.Second))
	assertRouteAddresses(t, selectRouteTargets(rule, 2, now.Add(2*time.Second)), "best:1", "cancelled:1")
}

func assertRouteAddresses(t *testing.T, targets []*config.Target, want ...string) {
	t.Helper()
	if len(targets) != len(want) {
		t.Fatalf("selected %d targets, want %d", len(targets), len(want))
	}
	for i, target := range targets {
		if target.Address != want[i] {
			t.Fatalf("target[%d] = %q, want %q", i, target.Address, want[i])
		}
	}
}
