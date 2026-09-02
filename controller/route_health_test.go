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

func tripRouteInRegistry(
	t *testing.T,
	registry *routeHealthRegistry,
	rule *config.Rule,
	addr string,
	now time.Time,
) {
	t.Helper()
	for i := 0; i < routeFailureThreshold; i++ {
		attempt, err := registry.begin(rule, addr, now)
		if err != nil {
			t.Fatalf("registry.begin() before failure %d: %v", i+1, err)
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

func TestRouteHealthRecordsOnlySuccessfulHalfOpenRecovery(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)

	ordinary, err := registry.begin(rule, "one:1", now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(ordinary, 20*time.Millisecond, nil, now)
	if snapshot := registry.snapshot(rule, "one:1", now); !snapshot.LastRecovery.IsZero() {
		t.Fatalf("ordinary success recorded recovery time %s", snapshot.LastRecovery)
	}

	tripAt := now.Add(time.Second)
	tripRouteInRegistry(t, registry, rule, "one:1", tripAt)
	recoveredAt := tripAt.Add(routeInitialCooldown)
	probe, err := registry.begin(rule, "one:1", recoveredAt)
	if err != nil {
		t.Fatalf("begin half-open recovery: %v", err)
	}
	routeObserve(probe, 30*time.Millisecond, nil, recoveredAt)
	snapshot := registry.snapshot(rule, "one:1", recoveredAt)
	if snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("successful half-open did not recover route: %+v", snapshot)
	}
	if !snapshot.LastRecovery.Equal(recoveredAt) {
		t.Fatalf("last recovery = %s, want %s", snapshot.LastRecovery, recoveredAt)
	}

	regularAt := recoveredAt.Add(time.Second)
	regular, err := registry.begin(rule, "one:1", regularAt)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(regular, 15*time.Millisecond, nil, regularAt)
	if snapshot = registry.snapshot(rule, "one:1", regularAt); !snapshot.LastRecovery.Equal(recoveredAt) {
		t.Fatalf("ordinary success overwrote recovery time: got %s want %s", snapshot.LastRecovery, recoveredAt)
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

func TestRouteReachableObservationClearsFailuresWithoutUpdatingEWMA(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 2, 35, 0, time.UTC)
	observeRoute(t, rule, "one:1", 25*time.Millisecond, nil, now)

	relayAttempt, err := routeBegin(rule, "one:1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(relayAttempt, 30*time.Millisecond, nil, now.Add(time.Second))
	routeReportFailure(relayAttempt, errors.New("relay failed"), now.Add(time.Second))
	observeRoute(t, rule, "one:1", 40*time.Millisecond, errors.New("dial failed"), now.Add(2*time.Second))
	before := routeSnapshot(rule, "one:1", now.Add(2*time.Second))
	if before.ConsecutiveFailures != 1 || before.EWMA != 26*time.Millisecond {
		t.Fatalf("snapshot before reachable response = %+v, want one failure and 26ms EWMA", before)
	}

	reachableAttempt, err := routeBegin(rule, "one:1", now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(
		reachableAttempt,
		2*time.Second,
		fmt.Errorf("CONNECT returned a destination error: %w", errRouteReachable),
		now.Add(3*time.Second),
	)
	after := routeSnapshot(rule, "one:1", now.Add(3*time.Second))
	if after.ConsecutiveFailures != 0 || after.CircuitOpen || after.HalfOpen ||
		!after.OpenUntil.IsZero() || after.Cooldown != 0 {
		t.Fatalf("reachable response did not clear route failure state: %+v", after)
	}
	if after.EWMA != before.EWMA || after.HasEWMA != before.HasEWMA {
		t.Fatalf("reachable response changed EWMA: before=%+v after=%+v", before, after)
	}
}

func TestRouteReachableHalfOpenProbeRecoversCircuit(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("one:1")
	now := time.Date(2026, 8, 18, 10, 2, 40, 0, time.UTC)
	observeRoute(t, rule, "one:1", 20*time.Millisecond, nil, now)

	staleAttempt, err := routeBegin(rule, "one:1", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	tripRoute(t, rule, "one:1", now.Add(2*time.Second))
	probeTime := now.Add(2*time.Second + routeInitialCooldown)
	probe, err := routeBegin(rule, "one:1", probeTime)
	if err != nil {
		t.Fatalf("half-open routeBegin() = %v", err)
	}
	routeObserve(probe, 3*time.Second, fmt.Errorf("HTTP 503 service unavailable: %w", errRouteReachable), probeTime)

	snapshot := routeSnapshot(rule, "one:1", probeTime)
	if snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.ProbeRequired ||
		snapshot.ConsecutiveFailures != 0 || !snapshot.OpenUntil.IsZero() || snapshot.Cooldown != 0 {
		t.Fatalf("reachable half-open response did not recover route: %+v", snapshot)
	}
	if snapshot.EWMA != 20*time.Millisecond {
		t.Fatalf("reachable half-open response EWMA = %s, want existing 20ms", snapshot.EWMA)
	}

	// An attempt admitted before the circuit opened must not undo the recovery.
	routeObserve(staleAttempt, time.Second, errors.New("late transport failure"), probeTime.Add(time.Second))
	if snapshot = routeSnapshot(rule, "one:1", probeTime.Add(time.Second)); snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("stale failure changed reachable recovery: %+v", snapshot)
	}
	if _, err := routeBegin(rule, "one:1", probeTime.Add(time.Second)); err != nil {
		t.Fatalf("routeBegin() after reachable recovery = %v", err)
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

func TestSelectRouteTargetsFullCandidateListRotatesEveryNonBestRoute(t *testing.T) {
	resetRouteHealthForTest()
	rule := routeHealthTestRule("best:1", "second:1", "third:1", "fourth:1")
	now := time.Date(2026, 8, 31, 14, 30, 0, 0, time.UTC)
	latencies := map[string]time.Duration{
		"best:1":   10 * time.Millisecond,
		"second:1": 20 * time.Millisecond,
		"third:1":  30 * time.Millisecond,
		"fourth:1": 40 * time.Millisecond,
	}
	initialAttempt := now.Add(-routeExplorationAfter)
	for _, target := range rule.Targets {
		observeRoute(t, rule, target.Address, latencies[target.Address], nil, initialAttempt)
	}

	for step, expectedExplorer := range []string{"second:1", "third:1", "fourth:1", "second:1"} {
		selectionTime := now.Add(time.Duration(step) * routeExplorationAfter)
		selected := selectRouteTargets(rule, len(rule.Targets), selectionTime)
		addresses := make([]string, 0, len(selected))
		for _, target := range selected {
			addresses = append(addresses, target.Address)
		}
		if len(selected) != len(rule.Targets) ||
			selected[0].Address != "best:1" || selected[1].Address != expectedExplorer {
			t.Fatalf("selection %d = %v, want best plus %s", step, addresses, expectedExplorer)
		}
		observeRoute(t, rule, expectedExplorer, latencies[expectedExplorer], nil, selectionTime)
	}
}

func TestRouteExplorationLeaseIsRuleWideTokenSafeAndExpires(t *testing.T) {
	rule := routeHealthTestRule("best:1", "stale:1")
	rule.Timeout = 1000
	registry := newRouteHealthRegistry()
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	staleAt := now.Add(-routeExplorationAfter - time.Second)
	attempt, err := registry.begin(rule, "stale:1", staleAt)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(attempt, 40*time.Millisecond, nil, staleAt)

	const callers = 32
	start := make(chan struct{})
	leases := make(chan routeExplorationLease, callers)
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			if lease, claimed := registry.claimExploration(rule, rule.Targets[1], now); claimed {
				leases <- lease
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(leases)
	var first routeExplorationLease
	claims := 0
	for lease := range leases {
		first = lease
		claims++
	}
	if claims != 1 {
		t.Fatalf("exploration claims = %d, want 1", claims)
	}

	expiredAt := now.Add(routeExplorationLeaseDuration(rule))
	second, claimed := registry.claimExploration(rule, rule.Targets[1], expiredAt)
	if !claimed || second.token == first.token {
		t.Fatalf("expired lease replacement = %+v claimed=%t, first=%+v", second, claimed, first)
	}
	registry.releaseExploration(first)
	registry.Lock()
	retained := registry.exploration[boostRuleKey(rule)]
	registry.Unlock()
	if retained.token != second.token {
		t.Fatalf("stale release removed replacement: retained=%+v second=%+v", retained, second)
	}
	registry.releaseExploration(second)
	registry.Lock()
	_, exists := registry.exploration[boostRuleKey(rule)]
	registry.Unlock()
	if exists {
		t.Fatal("current release retained exploration claim")
	}
}

func TestRouteRecoveryProbeRequiresExpiredCircuitCooldown(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := routeHealthTestRule("recovering:1")
	rule.Timeout = 1000
	tripAt := time.Date(2026, 9, 1, 8, 1, 0, 0, time.UTC)
	tripRouteInRegistry(t, registry, rule, "recovering:1", tripAt)

	if lease, claimed := registry.claimRecoveryProbe(
		rule,
		tripAt.Add(routeInitialCooldown-time.Nanosecond),
		nil,
	); claimed {
		t.Fatalf("claimed recovery before cooldown expiry: %+v", lease)
	}
	probeAt := tripAt.Add(routeInitialCooldown)
	if lease, claimed := registry.claimRecoveryProbe(
		rule,
		probeAt,
		map[string]struct{}{"recovering:1": {}},
	); claimed {
		t.Fatalf("claimed excluded recovery target: %+v", lease)
	}
	lease, claimed := registry.claimRecoveryProbe(rule, probeAt, nil)
	if !claimed {
		t.Fatal("did not claim recovery at cooldown expiry")
	}
	if lease.ruleKey != boostRuleKey(rule) || lease.address != "recovering:1" || lease.token == 0 {
		t.Fatalf("recovery lease = %+v", lease)
	}
	registry.releaseRecoveryProbe(lease)
}

func TestRouteRecoveryProbeIsRuleWideAndRateLimited(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := routeHealthTestRule("recovering:1")
	rule.Timeout = 1000
	tripAt := time.Date(2026, 9, 1, 8, 2, 0, 0, time.UTC)
	tripRouteInRegistry(t, registry, rule, "recovering:1", tripAt)
	probeAt := tripAt.Add(routeInitialCooldown)

	const callers = 32
	start := make(chan struct{})
	claims := make(chan routeRecoveryLease, callers)
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	for range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			if lease, claimed := registry.claimRecoveryProbe(rule, probeAt, nil); claimed {
				claims <- lease
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(claims)

	var first routeRecoveryLease
	claimCount := 0
	for lease := range claims {
		first = lease
		claimCount++
	}
	if claimCount != 1 {
		t.Fatalf("concurrent recovery claims = %d, want 1", claimCount)
	}
	registry.releaseRecoveryProbe(first)
	if lease, claimed := registry.claimRecoveryProbe(
		rule,
		probeAt.Add(routeRecoveryProbeInterval-time.Nanosecond),
		nil,
	); claimed {
		t.Fatalf("claimed recovery before rule interval elapsed: %+v", lease)
	}
	second, claimed := registry.claimRecoveryProbe(rule, probeAt.Add(routeRecoveryProbeInterval), nil)
	if !claimed {
		t.Fatal("did not claim recovery when rule interval elapsed")
	}
	if second.token == first.token {
		t.Fatalf("reused recovery token %d", second.token)
	}
	registry.releaseRecoveryProbe(second)
}

func TestRouteRecoveryProbeLeaseExpiryAndTokenSafeRelease(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := routeHealthTestRule("recovering:1")
	rule.Timeout = 1000
	tripAt := time.Date(2026, 9, 1, 8, 3, 0, 0, time.UTC)
	tripRouteInRegistry(t, registry, rule, "recovering:1", tripAt)
	probeAt := tripAt.Add(routeInitialCooldown)

	first, claimed := registry.claimRecoveryProbe(rule, probeAt, nil)
	if !claimed {
		t.Fatal("failed to claim initial recovery lease")
	}
	secondAt := probeAt.Add(routeExplorationLeaseDuration(rule))
	second, claimed := registry.claimRecoveryProbe(rule, secondAt, nil)
	if !claimed {
		t.Fatal("expired recovery lease was not replaced")
	}
	if second.token == first.token {
		t.Fatalf("replacement reused token %d", second.token)
	}

	registry.releaseRecoveryProbe(first)
	registry.Lock()
	retained, exists := registry.recovery[boostRuleKey(rule)]
	registry.Unlock()
	if !exists || retained.token != second.token || retained.address != second.address {
		t.Fatalf("stale release removed replacement: retained=%+v exists=%t second=%+v", retained, exists, second)
	}
	registry.releaseRecoveryProbe(second)
	registry.Lock()
	_, exists = registry.recovery[boostRuleKey(rule)]
	registry.Unlock()
	if exists {
		t.Fatal("current release retained recovery claim")
	}
}

func TestRouteRecoveryProbeChoosesOldestDueCircuit(t *testing.T) {
	t.Run("earliest open until", func(t *testing.T) {
		registry := newRouteHealthRegistry()
		rule := routeHealthTestRule("earliest:1", "later:1")
		rule.Timeout = 1000
		base := time.Date(2026, 9, 1, 8, 4, 0, 0, time.UTC)
		tripRouteInRegistry(t, registry, rule, "earliest:1", base)
		tripRouteInRegistry(t, registry, rule, "later:1", base.Add(time.Second))

		lease, claimed := registry.claimRecoveryProbe(
			rule,
			base.Add(time.Second).Add(routeInitialCooldown),
			nil,
		)
		if !claimed || lease.address != "earliest:1" {
			t.Fatalf("recovery lease = %+v claimed=%t, want earliest circuit", lease, claimed)
		}
	})

	t.Run("oldest last attempt breaks tie", func(t *testing.T) {
		registry := newRouteHealthRegistry()
		rule := routeHealthTestRule("newer-attempt:1", "older-attempt:1")
		rule.Timeout = 1000
		tripAt := time.Date(2026, 9, 1, 8, 5, 0, 0, time.UTC)
		tripRouteInRegistry(t, registry, rule, "newer-attempt:1", tripAt)
		tripRouteInRegistry(t, registry, rule, "older-attempt:1", tripAt)
		probeAt := tripAt.Add(routeInitialCooldown)

		probe, err := registry.begin(rule, "newer-attempt:1", probeAt)
		if err != nil {
			t.Fatalf("begin cancelled half-open attempt: %v", err)
		}
		routeObserve(probe, time.Millisecond, context.Canceled, probeAt)
		lease, claimed := registry.claimRecoveryProbe(rule, probeAt, nil)
		if !claimed || lease.address != "older-attempt:1" {
			t.Fatalf("recovery lease = %+v claimed=%t, want oldest last attempt", lease, claimed)
		}
	})
}

func TestRouteHealthClearRemovesRecoveryState(t *testing.T) {
	registry := newRouteHealthRegistry()
	tripAt := time.Date(2026, 9, 1, 8, 6, 0, 0, time.UTC)

	releasedRule := routeHealthTestRule("released:1")
	releasedRule.Name = "released-recovery"
	releasedRule.Listen = "127.0.0.1:10001"
	releasedRule.Timeout = 1000
	tripRouteInRegistry(t, registry, releasedRule, "released:1", tripAt)
	released, claimed := registry.claimRecoveryProbe(
		releasedRule,
		tripAt.Add(routeInitialCooldown),
		nil,
	)
	if !claimed {
		t.Fatal("failed to seed released recovery state")
	}
	registry.releaseRecoveryProbe(released)

	activeRule := routeHealthTestRule("active:1")
	activeRule.Name = "active-recovery"
	activeRule.Listen = "127.0.0.1:10002"
	activeRule.Timeout = 1000
	tripRouteInRegistry(t, registry, activeRule, "active:1", tripAt)
	if _, claimed := registry.claimRecoveryProbe(
		activeRule,
		tripAt.Add(routeInitialCooldown),
		nil,
	); !claimed {
		t.Fatal("failed to seed active recovery state")
	}

	registry.clear([]*config.Rule{releasedRule, activeRule})
	registry.Lock()
	defer registry.Unlock()
	for _, rule := range []*config.Rule{releasedRule, activeRule} {
		key := boostRuleKey(rule)
		if _, exists := registry.recovery[key]; exists {
			t.Fatalf("clear retained recovery claim for %s", rule.Name)
		}
		if _, exists := registry.recoveryNext[key]; exists {
			t.Fatalf("clear retained recovery interval for %s", rule.Name)
		}
	}
}

func TestSelectRouteTargetsDisablesPeriodicExplorerForProtocolCanary(t *testing.T) {
	rule := routeHealthTestRule("best:1", "second:1", "stale-canary:1")
	now := time.Date(2026, 9, 1, 8, 5, 0, 0, time.UTC)
	registry := newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "stale-canary:1" {
			return time.Second
		}
		return 0
	})
	for index, target := range rule.Targets {
		at := now
		if target.Address == "stale-canary:1" {
			at = now.Add(-routeExplorationAfter - time.Second)
		}
		attempt, err := registry.begin(rule, target.Address, at)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, time.Duration(index+1)*10*time.Millisecond, nil, at)
	}
	registry.protocolProbeClaim = func(_ *config.Rule, target *config.Target, _ time.Time) (uint64, bool) {
		if target.Address == "stale-canary:1" {
			return 1, true
		}
		return 0, false
	}

	selections := registry.selectTargetSelections(rule, len(rule.Targets), now, nil, true)
	if len(selections) == 0 || selections[0].protocolProbe.token == 0 {
		t.Fatalf("protocol canary not selected first: %+v", selections)
	}
	for _, selection := range selections {
		if selection.periodicExplorer {
			t.Fatalf("protocol canary selection also marked periodic explorer: %+v", selections)
		}
	}
}

func TestRouteHealthClearRemovesExplorationLease(t *testing.T) {
	rule := routeHealthTestRule("stale:1")
	registry := newRouteHealthRegistry()
	now := time.Date(2026, 9, 1, 8, 10, 0, 0, time.UTC)
	staleAt := now.Add(-routeExplorationAfter - time.Second)
	attempt, err := registry.begin(rule, "stale:1", staleAt)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(attempt, 10*time.Millisecond, nil, staleAt)
	if _, claimed := registry.claimExploration(rule, rule.Targets[0], now); !claimed {
		t.Fatal("failed to seed exploration claim")
	}
	registry.clear([]*config.Rule{rule})
	registry.Lock()
	_, exists := registry.exploration[boostRuleKey(rule)]
	registry.Unlock()
	if exists {
		t.Fatal("clear retained exploration claim")
	}
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

func TestSelectTargetsExcludingDefersProtocolPenaltyUntilHealthyAlternativesExhausted(t *testing.T) {
	rule := routeHealthTestRule("degraded-h3:443", "healthy-one:443", "healthy-two:443")
	now := time.Date(2026, 8, 26, 7, 0, 0, 0, time.UTC)
	var registry *routeHealthRegistry
	registry = newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		// The protocol source owns another lock domain. Prove selection invokes it
		// before routeHealthRegistry.Lock instead of nesting the locks.
		if !registry.TryLock() {
			t.Fatal("protocol penalty source was called while the route registry was locked")
		}
		registry.Unlock()
		if target.Address == "degraded-h3:443" {
			return 4 * time.Second
		}
		return 0
	})

	latencies := map[string]time.Duration{
		"degraded-h3:443": 5 * time.Millisecond,
		"healthy-one:443": 80 * time.Millisecond,
		"healthy-two:443": 120 * time.Millisecond,
	}
	for address, latency := range latencies {
		attempt, err := registry.begin(rule, address, now)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, latency, nil, now)
	}

	selected := registry.selectTargetsExcluding(rule, 2, now, nil)
	assertRouteAddresses(t, selected, "healthy-one:443", "healthy-two:443")

	// Once both healthy alternatives have been attempted, fail open to the
	// degraded route instead of pretending that no upstream remains.
	excluded := map[string]struct{}{
		"healthy-one:443": {},
		"healthy-two:443": {},
	}
	selected = registry.selectTargetsExcluding(rule, 2, now, excluded)
	assertRouteAddresses(t, selected, "degraded-h3:443")
	if snapshot := registry.snapshot(rule, "degraded-h3:443", now); snapshot.ConsecutiveFailures != 0 || snapshot.CircuitOpen {
		t.Fatalf("protocol penalty mutated target circuit state: %+v", snapshot)
	}
}

func TestSelectTargetsExcludingReservesOnePenalizedProtocolCanary(t *testing.T) {
	rule := routeHealthTestRule("degraded-h3:443", "healthy-one:443", "healthy-two:443")
	now := time.Date(2026, 8, 26, 7, 30, 0, 0, time.UTC)
	registry := newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "degraded-h3:443" {
			return 2 * time.Second
		}
		return 0
	})
	claimed := false
	released := false
	registry.protocolProbeClaim = func(_ *config.Rule, target *config.Target, _ time.Time) (uint64, bool) {
		if target.Address != "degraded-h3:443" || claimed {
			return 0, false
		}
		claimed = true
		return 1, true
	}
	registry.protocolProbeRelease = func(_ *config.Rule, target *config.Target, token uint64) {
		if target.Address != "degraded-h3:443" || token != 1 {
			t.Errorf("released protocol probe target=%q token=%d", target.Address, token)
		}
		released = true
	}

	selections := registry.selectTargetSelectionsExcluding(rule, 2, now, nil)
	assertRouteSelectionAddresses(t, selections, "degraded-h3:443", "healthy-one:443")
	registry.releaseProtocolProbe(rule, selections[0].target, selections[0].protocolProbe)
	if !released {
		t.Fatal("protocol canary ownership was not released")
	}
	selections = registry.selectTargetSelectionsExcluding(rule, 2, now, nil)
	assertRouteSelectionAddresses(t, selections, "healthy-one:443", "healthy-two:443")
}

func TestSelectTargetsExcludingAddsProtocolPenaltyToFailOpenScore(t *testing.T) {
	rule := routeHealthTestRule("lower-wire-latency:443", "lower-penalty:443")
	now := time.Date(2026, 8, 26, 7, 1, 0, 0, time.UTC)
	registry := newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "lower-wire-latency:443" {
			return 4 * time.Second
		}
		return time.Second
	})
	for address, latency := range map[string]time.Duration{
		"lower-wire-latency:443": 5 * time.Millisecond,
		"lower-penalty:443":      500 * time.Millisecond,
	} {
		attempt, err := registry.begin(rule, address, now)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, latency, nil, now)
	}

	selected := registry.selectTargetsExcluding(rule, 1, now, nil)
	assertRouteAddresses(t, selected, "lower-penalty:443")
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

func assertRouteSelectionAddresses(t *testing.T, selections []routeTargetSelection, want ...string) {
	t.Helper()
	if len(selections) != len(want) {
		t.Fatalf("selected %d targets, want %d", len(selections), len(want))
	}
	for index, selection := range selections {
		if selection.target.Address != want[index] {
			t.Fatalf("selection[%d] = %q, want %q", index, selection.target.Address, want[index])
		}
	}
}
