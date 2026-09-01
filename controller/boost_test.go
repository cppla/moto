package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
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

func hedgedBoostTestRule(name, listen string, addresses ...string) *config.Rule {
	rule := boostTestRule(name, listen, addresses...)
	rule.Hedge = &config.HedgeConfig{
		MinDelay: config.DefaultHedgeMinDelay,
		MaxDelay: config.DefaultHedgeMaxDelay,
	}
	return rule
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

func TestDegradedProtocolEvictsCachedWinnerAndFreshRaceUsesHealthyTarget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("protocol-penalty-cache", "127.0.0.1:18005", "degraded:443", "healthy:443")
	runtime.routes = newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "degraded:443" {
			return 2 * time.Second
		}
		return 0
	})
	key := boostRuleKey(rule)
	runtime.storeBoostWinner(key, "degraded:443")

	if entry, ok := runtime.loadUsableBoostWinnerToken(key, rule, time.Now()); ok {
		t.Fatalf("degraded cached winner remained usable: %+v", entry)
	}
	if _, ok := runtime.loadBoostWinnerToken(key); ok {
		t.Fatal("degraded cached winner was not evicted")
	}

	var dialed sync.Mutex
	var addresses []string
	peers := make(chan net.Conn, 1)
	winner, err := runtime.raceBoostTargetsPrepared(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			dialed.Lock()
			addresses = append(addresses, address)
			dialed.Unlock()
			connection, peer := net.Pipe()
			peers <- peer
			return connection, nil
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != "healthy:443" {
		t.Fatalf("fresh Boost winner = %q, want healthy:443", winner.addr)
	}
	dialed.Lock()
	defer dialed.Unlock()
	if len(addresses) != 1 || addresses[0] != "healthy:443" {
		t.Fatalf("fresh Boost dialed %v, want only healthy target", addresses)
	}
}

func TestProtocolPenaltyFailsOpenAfterUnpenalizedTargetIsActivelyUnhealthy(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"protocol-penalty-active-health",
		"127.0.0.1:18007",
		"unhealthy-one:443",
		"unhealthy-two:443",
		"degraded:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	check := config.HealthCheckConfig{FailureThreshold: 1, SuccessThreshold: 1}
	rule.HealthCheck = &check
	runtime.health.observe(activeHealthKey{rule: rule, address: "unhealthy-one:443"}, check, false)
	runtime.health.observe(activeHealthKey{rule: rule, address: "unhealthy-two:443"}, check, false)
	runtime.routes = newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "degraded:443" {
			return 2 * time.Second
		}
		return 0
	})

	var dialed []string
	var dialedMu sync.Mutex
	peers := make(chan net.Conn, 1)
	winner, err := runtime.raceBoostTargetsPrepared(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			dialedMu.Lock()
			dialed = append(dialed, address)
			dialedMu.Unlock()
			connection, peer := net.Pipe()
			peers <- peer
			return connection, nil
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != "degraded:443" {
		t.Fatalf("fail-open winner = %q, want degraded:443", winner.addr)
	}
	dialedMu.Lock()
	defer dialedMu.Unlock()
	if len(dialed) != 1 || dialed[0] != "degraded:443" {
		t.Fatalf("dialed targets = %v, want only degraded fail-open target", dialed)
	}
}

func TestCachedBoostActiveHealthExclusionDoesNotConsumeTargetAttempt(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"cached-active-health-attempt-budget",
		"127.0.0.1:18009",
		"cached-unhealthy:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5

	var dialedMu sync.Mutex
	var dialed []string
	peers := make(chan net.Conn, 1)
	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		"cached-unhealthy:443",
		func(_ context.Context, _ *config.Rule, address string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			dialedMu.Lock()
			dialed = append(dialed, address)
			dialedMu.Unlock()
			switch address {
			case "cached-unhealthy:443":
				return nil, routeAttempt{}, ErrActiveHealthUnhealthy
			case "fallback-fails:443":
				return nil, routeAttempt{}, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, routeAttempt{}, nil
			default:
				return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = outcome.winner.conn.Close()
	_ = (<-peers).Close()
	if outcome.winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", outcome.winner.addr)
	}
	dialedMu.Lock()
	defer dialedMu.Unlock()
	if len(dialed) != 3 {
		t.Fatalf("dialed targets = %v, want cached exclusion plus two real attempts", dialed)
	}
}

func TestFreshBoostPostAdmissionHealthExclusionReturnsAttemptBudget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"fresh-active-health-attempt-budget",
		"127.0.0.1:18010",
		"health-flips:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	check := config.HealthCheckConfig{FailureThreshold: 1, SuccessThreshold: 1}
	rule.HealthCheck = &check

	peers := make(chan net.Conn, 1)
	var unhealthyDialed atomic.Bool
	winner, err := runtime.raceBoostTargetsPreparedWithAdmission(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			switch address {
			case "health-flips:443":
				unhealthyDialed.Store(true)
				return nil, errors.New("health-flipped target reached the network dial")
			case "fallback-fails:443":
				return nil, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, nil
			}
			return nil, fmt.Errorf("unexpected target %s", address)
		},
		nil,
		func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
			if address == "health-flips:443" {
				runtime.health.observe(activeHealthKey{rule: rule, address: address}, check, false)
			}
			return func() {}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", winner.addr)
	}
	if unhealthyDialed.Load() {
		t.Fatal("health-flipped target reached the network dial")
	}
}

func TestCachedBoostCircuitExclusionDoesNotConsumeTargetAttempt(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"cached-circuit-attempt-budget",
		"127.0.0.1:18012",
		"cached-circuit:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	peers := make(chan net.Conn, 1)
	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		"cached-circuit:443",
		func(_ context.Context, _ *config.Rule, address string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			switch address {
			case "cached-circuit:443":
				return nil, routeAttempt{}, ErrCircuitOpen
			case "fallback-fails:443":
				return nil, routeAttempt{}, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, routeAttempt{}, nil
			default:
				return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = outcome.winner.conn.Close()
	_ = (<-peers).Close()
	if outcome.winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", outcome.winner.addr)
	}
}

func TestFreshBoostCircuitClaimReturnsAttemptBudget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"fresh-circuit-attempt-budget",
		"127.0.0.1:18013",
		"circuit-flips:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	peers := make(chan net.Conn, 1)
	winner, err := runtime.raceBoostTargetsPreparedWithAdmission(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			switch address {
			case "circuit-flips:443":
				return nil, errors.New("circuit-open target reached network dial")
			case "fallback-fails:443":
				return nil, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, nil
			default:
				return nil, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
		func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
			if address == "circuit-flips:443" {
				key := routeHealthKey{rule: boostRuleKey(rule), addr: address}
				runtime.routes.Lock()
				state := newRouteHealthState(rule)
				state.observed = true
				state.circuitOpen = true
				state.openUntil = time.Now().Add(time.Minute)
				runtime.routes.states[key] = state
				runtime.routes.Unlock()
			}
			return func() {}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", winner.addr)
	}
}

func TestCachedBoostTargetSaturationReturnsAttemptBudget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"cached-target-capacity-attempt-budget",
		"127.0.0.1:18015",
		"cached-saturated:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	peers := make(chan net.Conn, 1)
	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		"cached-saturated:443",
		func(_ context.Context, _ *config.Rule, address string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			switch address {
			case "cached-saturated:443":
				return nil, routeAttempt{}, &dialBulkheadError{
					target: address, saturated: true, scope: dialSaturationTarget,
				}
			case "fallback-fails:443":
				return nil, routeAttempt{}, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, routeAttempt{}, nil
			default:
				return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
		0,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = outcome.winner.conn.Close()
	_ = (<-peers).Close()
	if outcome.winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", outcome.winner.addr)
	}
}

func TestFreshBoostTargetSaturationReturnsAttemptBudget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"fresh-target-capacity-attempt-budget",
		"127.0.0.1:18016",
		"target-saturated:443",
		"fallback-fails:443",
		"fallback-works:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	peers := make(chan net.Conn, 1)
	var saturatedDialed atomic.Bool
	winner, err := runtime.raceBoostTargetsPreparedWithAdmission(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			switch address {
			case "target-saturated:443":
				saturatedDialed.Store(true)
				return nil, errors.New("saturated target reached network dial")
			case "fallback-fails:443":
				return nil, errors.New("fallback failed")
			case "fallback-works:443":
				connection, peer := net.Pipe()
				peers <- peer
				return connection, nil
			default:
				return nil, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
		func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
			if address == "target-saturated:443" {
				return nil, &dialBulkheadError{
					target: address, saturated: true, scope: dialSaturationTarget,
				}
			}
			return func() {}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != "fallback-works:443" {
		t.Fatalf("winner = %q, want fallback-works:443", winner.addr)
	}
	if saturatedDialed.Load() {
		t.Fatal("per-target saturated address reached network dial")
	}
}

func TestProtocolPenaltyEvictionCannotDeleteConcurrentBoostWinner(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("protocol-penalty-generation", "127.0.0.1:18006", "stale:443", "fresh:443")
	key := boostRuleKey(rule)
	stale := runtime.storeBoostWinner(key, "stale:443")
	var replaced atomic.Bool
	runtime.routes = newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == stale.addr && replaced.CompareAndSwap(false, true) {
			runtime.storeBoostWinner(key, "fresh:443")
			return time.Second
		}
		return 0
	})

	if _, ok := runtime.loadUsableBoostWinnerToken(key, rule, time.Now()); ok {
		t.Fatal("stale degraded winner unexpectedly remained usable")
	}
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != "fresh:443" || entry.generation == stale.generation {
		t.Fatalf("generation-safe eviction removed concurrent winner: entry=%+v ok=%t", entry, ok)
	}
}

func TestProtocolPenaltyCacheEvictionDoesNotConsumeRecoveryCanary(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("protocol-penalty-canary", "127.0.0.1:18008", "degraded:443", "healthy:443")
	key := boostRuleKey(rule)
	runtime.storeBoostWinner(key, "degraded:443")
	runtime.routes = newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if target.Address == "degraded:443" {
			return 2 * time.Second
		}
		return 0
	})
	claims := 0
	runtime.routes.protocolProbeClaim = func(_ *config.Rule, target *config.Target, _ time.Time) (uint64, bool) {
		claims++
		return uint64(claims), true
	}

	if _, ok := runtime.loadUsableBoostWinnerToken(key, rule, time.Now()); ok {
		t.Fatal("degraded cached target remained usable")
	}
	if claims != 0 {
		t.Fatalf("cache inspection consumed %d recovery canary claim(s)", claims)
	}
}

func TestBoostProtocolCanaryGetsExclusiveSetupAndReleasesLease(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	degraded := &config.Target{
		Address: "degraded-h3:443",
		ConnectProxy: &config.ConnectProxyConfig{
			ServerName: "degraded-h3",
			Protocols:  []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	healthy := &config.Target{Address: "healthy:443"}
	rule := &config.Rule{
		Name:     "protocol-canary-release",
		Listen:   "127.0.0.1:18011",
		Mode:     config.ModeBoost,
		Protocol: config.ProtocolSOCKS5,
		Timeout:  1000,
		Targets:  []*config.Target{degraded, healthy},
	}
	key := http3ConnectTransportKey{address: degraded.Address, serverName: degraded.ConnectProxy.ServerName}
	runtime.connectProxy.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)

	peers := make(chan net.Conn, 1)
	var healthyDialed atomic.Bool
	winner, err := runtime.raceBoostTargetsPrepared(
		context.Background(),
		rule,
		func(ctx context.Context, address string) (net.Conn, error) {
			switch address {
			case degraded.Address:
				connection, peer := net.Pipe()
				peers <- peer
				return connection, nil
			case healthy.Address:
				healthyDialed.Store(true)
				return nil, errors.New("healthy target raced protocol canary")
			default:
				return nil, fmt.Errorf("unexpected target %s", address)
			}
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != degraded.Address {
		t.Fatalf("winner = %q, want recovery canary %q", winner.addr, degraded.Address)
	}
	if healthyDialed.Load() {
		t.Fatal("healthy target raced an exclusive protocol recovery canary")
	}
	runtime.connectProxy.h3FallbackMu.Lock()
	state := *runtime.connectProxy.h3Fallback[key]
	runtime.connectProxy.h3FallbackMu.Unlock()
	if state.boostCanaryInFlight || state.boostCanaryToken != 0 || state.lastBoostCanary.IsZero() {
		t.Fatalf("completed losing canary retained ownership: %+v", state)
	}
}

func TestBoostProtocolCanaryFailureRefillsHealthyTarget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	degraded := &config.Target{
		Address: "degraded-h3:443",
		ConnectProxy: &config.ConnectProxyConfig{
			ServerName: "degraded-h3",
			Protocols:  []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	healthy := &config.Target{Address: "healthy:443"}
	rule := &config.Rule{
		Name:     "protocol-canary-fallback",
		Listen:   "127.0.0.1:18014",
		Mode:     config.ModeBoost,
		Protocol: config.ProtocolSOCKS5,
		Timeout:  1000,
		Targets:  []*config.Target{degraded, healthy},
	}
	key := http3ConnectTransportKey{address: degraded.Address, serverName: degraded.ConnectProxy.ServerName}
	runtime.connectProxy.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)

	var dialedMu sync.Mutex
	var dialed []string
	peers := make(chan net.Conn, 1)
	winner, err := runtime.raceBoostTargetsPrepared(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			dialedMu.Lock()
			dialed = append(dialed, address)
			dialedMu.Unlock()
			if address == degraded.Address {
				return nil, errors.New("canary failed")
			}
			connection, peer := net.Pipe()
			peers <- peer
			return connection, nil
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	_ = (<-peers).Close()
	if winner.addr != healthy.Address {
		t.Fatalf("winner = %q, want healthy fallback %q", winner.addr, healthy.Address)
	}
	dialedMu.Lock()
	defer dialedMu.Unlock()
	if len(dialed) != 2 || dialed[0] != degraded.Address || dialed[1] != healthy.Address {
		t.Fatalf("dial order = %v, want exclusive canary then healthy fallback", dialed)
	}
}

func TestCachedBoostHedgeDelayClampsTwiceEWMA(t *testing.T) {
	tests := []struct {
		name string
		ewma time.Duration
		want time.Duration
	}{
		{name: "no sample uses minimum", want: 25 * time.Millisecond},
		{name: "below minimum", ewma: 5 * time.Millisecond, want: 25 * time.Millisecond},
		{name: "inside range", ewma: 40 * time.Millisecond, want: 80 * time.Millisecond},
		{name: "above maximum", ewma: 200 * time.Millisecond, want: 250 * time.Millisecond},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newRoutingRuntime()
			defer runtime.stopBackground()
			rule := hedgedBoostTestRule(
				fmt.Sprintf("hedge-delay-%d", index),
				fmt.Sprintf("127.0.0.1:%d", 18000+index),
				"cached:443",
				"fallback:443",
			)
			if test.ewma > 0 {
				attempt, err := runtime.routes.begin(rule, "cached:443", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				routeObserve(attempt, test.ewma, nil, time.Now())
			}
			if got := runtime.cachedBoostHedgeDelay(rule, "cached:443"); got != test.want {
				t.Fatalf("cachedBoostHedgeDelay() = %s, want %s", got, test.want)
			}
		})
	}

	legacy := boostTestRule("legacy-delay", "127.0.0.1:18004", "cached:443", "fallback:443")
	legacyRuntime := newRoutingRuntime()
	defer legacyRuntime.stopBackground()
	if got := legacyRuntime.cachedBoostHedgeDelay(legacy, "cached:443"); got != 0 {
		t.Fatalf("omitted hedge delay = %s, want disabled", got)
	}
}

func TestCachedBoostHardFailureStartsFallbackWithoutHedgeDelay(t *testing.T) {
	resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hard-fallback", "127.0.0.1:18100", "cached:443", "fallback:443", "standby:443")
	heartbeat := make(chan time.Time)
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	standbyCanceled := make(chan struct{})

	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		"cached:443",
		func(ctx context.Context, _ *config.Rule, addr string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			switch addr {
			case "cached:443":
				return nil, routeAttempt{}, errors.New("cached route failed")
			case "fallback:443":
				return winnerConn, routeAttempt{}, nil
			case "standby:443":
				<-ctx.Done()
				close(standbyCanceled)
				return nil, routeAttempt{}, ctx.Err()
			default:
				return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
			}
		},
		nil,
		75*time.Millisecond,
		heartbeat,
	)
	if err != nil {
		t.Fatalf("raceCachedBoostTargetWithDial() error = %v", err)
	}
	defer outcome.winner.conn.Close()
	if outcome.winner.addr != "fallback:443" || !outcome.cachedFailed ||
		!outcome.fallbackStarted || outcome.hedged {
		t.Fatalf("outcome = %+v, want immediate fallback winner after cached failure", outcome)
	}
	select {
	case <-standbyCanceled:
	default:
		t.Fatal("first fallback winner did not cancel the other immediate fallback")
	}
	snapshot := processMetrics.snapshot()
	if snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeLaunched}] != 0 ||
		snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeWon}] != 0 {
		t.Fatal("hard-failure fallback was counted as a delayed hedge")
	}
}

func TestCachedBoostNeutralConnectFailurePreservesRuleWinner(t *testing.T) {
	t.Run("alternative succeeds for this destination", func(t *testing.T) {
		runtime := newRoutingRuntime()
		defer runtime.stopBackground()
		rule := boostTestRule("neutral-fallback", "127.0.0.1:18110", "cached:443", "fallback:443")
		rule.Protocol = config.ProtocolSOCKS5
		key := boostRuleKey(rule)
		cachedToken := runtime.storeBoostWinner(key, "cached:443")
		winnerConn, winnerPeer := net.Pipe()
		defer winnerPeer.Close()

		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(_ context.Context, _ *config.Rule, addr string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				if addr == "cached:443" {
					return nil, routeAttempt{}, &connectProxyStatusError{
						protocol: config.ConnectProxyH3, statusCode: 403,
					}
				}
				return winnerConn, routeAttempt{}, nil
			},
			nil,
			0,
			nil,
		)
		if err != nil {
			t.Fatalf("neutral fallback decision: %v", err)
		}
		defer outcome.winner.conn.Close()
		if outcome.cachedFailed || !outcome.cachedFailureNeutral || outcome.winner.addr != "fallback:443" {
			t.Fatalf("neutral fallback outcome = %+v", outcome)
		}
		cacheHit, relayToken := runtime.reconcileCachedBoostWinner(key, cachedToken, outcome, true)
		if cacheHit || relayToken.generation != 0 {
			t.Fatalf("neutral fallback cache result = hit:%t token:%+v", cacheHit, relayToken)
		}
		entry, ok := runtime.loadBoostWinnerToken(key)
		if !ok || entry.addr != cachedToken.addr || entry.generation != cachedToken.generation {
			t.Fatalf("destination fallback replaced rule winner: entry=%+v ok=%t", entry, ok)
		}
	})

	t.Run("all destinations return bad gateway", func(t *testing.T) {
		runtime := newRoutingRuntime()
		defer runtime.stopBackground()
		rule := boostTestRule("neutral-all-fail", "127.0.0.1:18111", "cached:443", "fallback:443", "standby:443")
		rule.Protocol = config.ProtocolSOCKS5
		key := boostRuleKey(rule)
		cachedToken := runtime.storeBoostWinner(key, "cached:443")

		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(_ context.Context, _ *config.Rule, _ string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				return nil, routeAttempt{}, &connectProxyStatusError{
					protocol: config.ConnectProxyH2, statusCode: 502,
				}
			},
			nil,
			0,
			nil,
		)
		if err == nil {
			t.Fatal("all-502 decision unexpectedly succeeded")
		}
		if outcome.cachedFailed || !outcome.cachedFailureNeutral {
			t.Fatalf("all-502 outcome = %+v", outcome)
		}
		runtime.reconcileCachedBoostWinner(key, cachedToken, outcome, false)
		entry, ok := runtime.loadBoostWinnerToken(key)
		if !ok || entry.addr != cachedToken.addr || entry.generation != cachedToken.generation {
			t.Fatalf("all-502 decision evicted rule winner: entry=%+v ok=%t", entry, ok)
		}
	})
}

func TestBoostSOCKS5BoundsDistinctTargetsToTwo(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"bounded-native-proxy",
		"127.0.0.1:18112",
		"one.example:443",
		"two.example:443",
		"three.example:443",
		"four.example:443",
	)
	rule.Protocol = config.ProtocolSOCKS5

	var callsMu sync.Mutex
	calls := make(map[string]int)
	connection, err := runtime.raceBoostTargets(context.Background(), rule, func(_ context.Context, addr string) (net.Conn, error) {
		callsMu.Lock()
		calls[addr]++
		callsMu.Unlock()
		return nil, &connectProxyStatusError{
			protocol:   config.ConnectProxyH2,
			target:     addr,
			statusCode: http.StatusServiceUnavailable,
		}
	})
	if connection.conn != nil {
		_ = connection.conn.Close()
		t.Fatal("all-503 Boost race returned a connection")
	}
	if err == nil {
		t.Fatal("all-503 Boost race unexpectedly succeeded")
	}

	callsMu.Lock()
	defer callsMu.Unlock()
	if len(calls) != connectProxyMaxTargetAttempts {
		t.Fatalf("distinct target calls = %v, want exactly %d targets", calls, connectProxyMaxTargetAttempts)
	}
	for addr, count := range calls {
		if count != 1 {
			t.Fatalf("target %q called %d times, want once", addr, count)
		}
	}
}

func TestFreshBoostSOCKS5UsesStaleExplorerInTopTwo(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"fresh-stale-explorer",
		"127.0.0.1:18117",
		"best.example:443",
		"second.example:443",
		"recent.example:443",
		"stale.example:443",
	)
	rule.Protocol = config.ProtocolSOCKS5

	now := time.Now()
	samples := []struct {
		address string
		latency time.Duration
		at      time.Time
	}{
		{address: "best.example:443", latency: 10 * time.Millisecond, at: now},
		{address: "second.example:443", latency: 20 * time.Millisecond, at: now},
		{address: "recent.example:443", latency: 30 * time.Millisecond, at: now},
		{
			address: "stale.example:443",
			latency: 40 * time.Millisecond,
			at:      now.Add(-routeExplorationAfter - time.Second),
		},
	}
	for _, sample := range samples {
		attempt, err := runtime.routes.begin(rule, sample.address, sample.at)
		if err != nil {
			t.Fatalf("begin route %q: %v", sample.address, err)
		}
		routeObserve(attempt, sample.latency, nil, sample.at)
	}

	var callsMu sync.Mutex
	calls := make(map[string]int)
	_, err := runtime.raceBoostTargetsPreparedWithAdmission(
		context.Background(),
		rule,
		func(_ context.Context, address string) (net.Conn, error) {
			callsMu.Lock()
			calls[address]++
			callsMu.Unlock()
			return nil, errors.New("fixture failure")
		},
		nil,
		func(context.Context, *config.Rule, string, bool) (boostDialRelease, error) {
			return func() {}, nil
		},
	)
	if err == nil {
		t.Fatal("all-failure Boost race unexpectedly succeeded")
	}

	callsMu.Lock()
	defer callsMu.Unlock()
	if len(calls) != connectProxyMaxTargetAttempts ||
		calls["best.example:443"] != 1 || calls["stale.example:443"] != 1 {
		t.Fatalf("dialed targets = %v, want best plus stale explorer", calls)
	}
}

func TestConcurrentFreshBoostUsesOnePeriodicExplorerWithoutWaiting(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"single-periodic-explorer",
		"127.0.0.1:18118",
		"best.example:443",
		"second.example:443",
		"stale.example:443",
	)
	rule.Protocol = config.ProtocolSOCKS5

	now := time.Now()
	for _, sample := range []struct {
		address string
		latency time.Duration
		at      time.Time
	}{
		{address: "best.example:443", latency: 10 * time.Millisecond, at: now},
		{address: "second.example:443", latency: 20 * time.Millisecond, at: now},
		{
			address: "stale.example:443",
			latency: 40 * time.Millisecond,
			at:      now.Add(-routeExplorationAfter - time.Second),
		},
	} {
		attempt, err := runtime.routes.begin(rule, sample.address, sample.at)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, sample.latency, nil, sample.at)
	}

	var staleAcquireOnce sync.Once
	staleAcquireStarted := make(chan struct{})
	releaseStaleAcquire := make(chan struct{})
	var staleAcquires atomic.Int32
	acquire := func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
		if address == "stale.example:443" {
			staleAcquires.Add(1)
			staleAcquireOnce.Do(func() { close(staleAcquireStarted) })
			<-releaseStaleAcquire
		}
		return func() {}, nil
	}
	var callsMu sync.Mutex
	calls := make(map[string]int)
	var firstBest atomic.Bool
	firstBestStarted := make(chan struct{})
	releaseFirstBest := make(chan struct{})
	dial := func(_ context.Context, address string) (net.Conn, error) {
		callsMu.Lock()
		calls[address]++
		callsMu.Unlock()
		if address == "best.example:443" && firstBest.CompareAndSwap(false, true) {
			close(firstBestStarted)
			<-releaseFirstBest
			return nil, errors.New("owner best failure")
		}
		if address != "stale.example:443" {
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		}
		return nil, errors.New("fixture failure")
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := runtime.raceBoostTargetsPreparedWithAdmission(
			context.Background(), rule, dial, nil, acquire,
		)
		firstDone <- err
	}()
	select {
	case <-staleAcquireStarted:
	case <-time.After(time.Second):
		t.Fatal("first periodic explorer did not reach admission")
	}
	select {
	case <-firstBestStarted:
	case <-time.After(time.Second):
		close(releaseFirstBest)
		close(releaseStaleAcquire)
		t.Fatal("first best route did not start")
	}

	const siblings = 12
	siblingDone := make(chan error, siblings)
	for range siblings {
		go func() {
			winner, err := runtime.raceBoostTargetsPreparedWithAdmission(
				context.Background(), rule, dial, nil, acquire,
			)
			if winner.conn != nil {
				_ = winner.conn.Close()
			}
			siblingDone <- err
		}()
	}
	progressed := true
	received := 0
	for received < siblings {
		select {
		case err := <-siblingDone:
			received++
			if err != nil {
				t.Errorf("ordinary sibling route failed: %v", err)
			}
		case <-time.After(time.Second):
			progressed = false
		}
		if !progressed {
			break
		}
	}
	close(releaseFirstBest)
	close(releaseStaleAcquire)
	for received < siblings {
		<-siblingDone
		received++
	}
	if err := <-firstDone; err == nil {
		t.Error("all-failure owner unexpectedly succeeded")
	}
	if !progressed {
		t.Fatal("sibling Boost request waited for another request's periodic explorer")
	}
	if got := staleAcquires.Load(); got != 1 {
		t.Fatalf("stale explorer admissions = %d, want 1", got)
	}
	callsMu.Lock()
	secondCalls := calls["second.example:443"]
	callsMu.Unlock()
	if secondCalls != siblings {
		t.Fatalf("ordinary second-route calls = %d, want %d sibling fallbacks", secondCalls, siblings)
	}
}

func TestFreshBoostReleasesPeriodicExplorerAfterAdmissionFailure(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule(
		"periodic-explorer-release",
		"127.0.0.1:18119",
		"best.example:443",
		"second.example:443",
		"stale.example:443",
	)
	rule.Protocol = config.ProtocolSOCKS5
	now := time.Now()
	for _, sample := range []struct {
		address string
		latency time.Duration
		at      time.Time
	}{
		{address: "best.example:443", latency: 10 * time.Millisecond, at: now},
		{address: "second.example:443", latency: 20 * time.Millisecond, at: now},
		{address: "stale.example:443", latency: 40 * time.Millisecond, at: now.Add(-routeExplorationAfter - time.Second)},
	} {
		attempt, err := runtime.routes.begin(rule, sample.address, sample.at)
		if err != nil {
			t.Fatal(err)
		}
		routeObserve(attempt, sample.latency, nil, sample.at)
	}

	_, err := runtime.raceBoostTargetsPreparedWithAdmission(
		context.Background(),
		rule,
		func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("fixture failure")
		},
		nil,
		func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
			if address == "stale.example:443" {
				return nil, &dialBulkheadError{
					target: address, saturated: true, scope: dialSaturationTarget,
				}
			}
			return func() {}, nil
		},
	)
	if err == nil {
		t.Fatal("all-failure Boost race unexpectedly succeeded")
	}
	lease, claimed := runtime.routes.claimExploration(rule, rule.Targets[2], time.Now())
	if !claimed {
		t.Fatal("admission failure leaked periodic exploration lease")
	}
	runtime.routes.releaseExploration(lease)
}

func TestCachedBoostSlowPrimaryLaunchesHedgeOnSignalAndCancelsLoser(t *testing.T) {
	resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("slow-hedge", "127.0.0.1:18101", "cached:443", "fallback:443")
	hedgeReady := make(chan time.Time, 1)
	primaryStarted := make(chan struct{})
	primaryCanceled := make(chan struct{})
	fallbackStarted := make(chan struct{})
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()

	type result struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(ctx context.Context, _ *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				switch addr {
				case "cached:443":
					options.onStart()
					close(primaryStarted)
					<-ctx.Done()
					close(primaryCanceled)
					return nil, routeAttempt{}, ctx.Err()
				case "fallback:443":
					options.onStart()
					close(fallbackStarted)
					return winnerConn, routeAttempt{}, nil
				default:
					return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
				}
			},
			nil,
			80*time.Millisecond,
			hedgeReady,
		)
		done <- result{outcome: outcome, err: err}
	}()

	<-primaryStarted
	select {
	case <-fallbackStarted:
		t.Fatal("fallback started before the hedge signal")
	default:
	}
	hedgeReady <- time.Now()
	got := <-done
	if got.err != nil {
		t.Fatalf("raceCachedBoostTargetWithDial() error = %v", got.err)
	}
	defer got.outcome.winner.conn.Close()
	if got.outcome.winner.addr != "fallback:443" || !got.outcome.hedged || got.outcome.cachedFailed {
		t.Fatalf("outcome = %+v, want delayed fallback winner and neutral canceled primary", got.outcome)
	}
	select {
	case <-primaryCanceled:
	default:
		t.Fatal("hedge winner did not cancel the slow primary")
	}

	snapshot := processMetrics.snapshot()
	for _, event := range []string{boostHedgeScheduled, boostHedgeLaunched, boostHedgeWon} {
		if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: event}]; got != 1 {
			t.Fatalf("hedge event %s = %d, want 1", event, got)
		}
	}
	if got := snapshot.boostHedgeDelayNanos[rule.Name]; got != uint64(80*time.Millisecond) {
		t.Fatalf("recorded hedge delay = %s, want 80ms", time.Duration(got))
	}
}

func TestCachedBoostHedgeCapacitySkipKeepsPrimaryAlive(t *testing.T) {
	resetProcessMetricsForTest()
	bulkhead := newDialBulkhead(1, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hedge-capacity", "127.0.0.1:18102", "cached:443", "fallback:443")
	hedgeReady := make(chan time.Time, 1)
	primaryStarted := make(chan struct{})
	releasePrimary := make(chan struct{})
	fallbackSkipped := make(chan struct{})
	primaryConn, primaryPeer := net.Pipe()
	defer primaryPeer.Close()

	type result struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(ctx context.Context, dialRule *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				var permit *dialPermit
				var acquireErr error
				if options.tryOnly {
					permit, acquireErr = runtime.tryAcquireTrafficDial(ctx, dialRule, addr)
				} else {
					permit, acquireErr = runtime.acquireTrafficDial(ctx, dialRule, addr)
				}
				if acquireErr != nil {
					if addr == "fallback:443" {
						close(fallbackSkipped)
					}
					return nil, routeAttempt{}, acquireErr
				}
				defer permit.release()
				if options.onStart != nil {
					options.onStart()
				}
				if addr != "cached:443" {
					return nil, routeAttempt{}, fmt.Errorf("unexpected admitted target %s", addr)
				}
				close(primaryStarted)
				<-releasePrimary
				return primaryConn, routeAttempt{}, nil
			},
			nil,
			50*time.Millisecond,
			hedgeReady,
		)
		done <- result{outcome: outcome, err: err}
	}()

	<-primaryStarted
	hedgeReady <- time.Now()
	<-fallbackSkipped
	select {
	case early := <-done:
		t.Fatalf("capacity-limited optional hedge canceled primary: %+v", early)
	default:
	}
	close(releasePrimary)
	got := <-done
	if got.err != nil {
		t.Fatalf("raceCachedBoostTargetWithDial() error = %v", got.err)
	}
	defer got.outcome.winner.conn.Close()
	if got.outcome.winner.addr != "cached:443" {
		t.Fatalf("winner = %s, want primary", got.outcome.winner.addr)
	}
	if snapshot := bulkhead.snapshot(); snapshot.Active != 0 || snapshot.Waiting != 0 {
		t.Fatalf("bulkhead leaked after hedge: %+v", snapshot)
	}
	metrics := processMetrics.snapshot()
	if got := metrics.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeSkippedCapacity}]; got != 1 {
		t.Fatalf("skipped-capacity events = %d, want 1", got)
	}
	if got := metrics.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeLaunched}]; got != 0 {
		t.Fatalf("capacity-skipped hedge launched events = %d, want 0", got)
	}
}

func TestCachedBoostRetriesSkippedHedgeAsRequiredFallback(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hedge-capacity-retry", "127.0.0.1:18107", "cached:443", "fallback:443")
	hedgeReady := make(chan time.Time, 1)
	primaryStarted := make(chan struct{})
	failPrimary := make(chan struct{})
	optionalSkipped := make(chan struct{})
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	var fallbackCalls atomic.Int32

	type result struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(ctx context.Context, _ *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				switch addr {
				case "cached:443":
					options.onStart()
					close(primaryStarted)
					select {
					case <-failPrimary:
						return nil, routeAttempt{}, errors.New("primary failed after skipped hedge")
					case <-ctx.Done():
						return nil, routeAttempt{}, ctx.Err()
					}
				case "fallback:443":
					call := fallbackCalls.Add(1)
					if call == 1 {
						if !options.tryOnly {
							return nil, routeAttempt{}, errors.New("optional hedge did not use try-only admission")
						}
						close(optionalSkipped)
						return nil, routeAttempt{}, &dialBulkheadError{target: addr, saturated: true}
					}
					if options.tryOnly {
						return nil, routeAttempt{}, errors.New("required fallback still used try-only admission")
					}
					return winnerConn, routeAttempt{}, nil
				default:
					return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
				}
			},
			nil,
			50*time.Millisecond,
			hedgeReady,
		)
		done <- result{outcome: outcome, err: err}
	}()

	<-primaryStarted
	hedgeReady <- time.Now()
	<-optionalSkipped
	close(failPrimary)
	got := <-done
	if got.err != nil {
		t.Fatalf("race error = %v", got.err)
	}
	defer got.outcome.winner.conn.Close()
	if got.outcome.winner.addr != "fallback:443" || !got.outcome.cachedFailed ||
		!got.outcome.fallbackStarted || got.outcome.hedged {
		t.Fatalf("capacity retry outcome = %+v", got.outcome)
	}
	if calls := fallbackCalls.Load(); calls != 2 {
		t.Fatalf("fallback calls = %d, want optional attempt plus required retry", calls)
	}
	snapshot := processMetrics.snapshot()
	if skipped := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeSkippedCapacity}]; skipped != 1 {
		t.Fatalf("skipped-capacity events = %d, want 1", skipped)
	}
	for _, event := range []string{boostHedgeLaunched, boostHedgeWon} {
		if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: event}]; got != 0 {
			t.Fatalf("capacity-skipped event %s = %d, want 0", event, got)
		}
	}
}

func TestCachedBoostRetriesLateCapacityResultAfterPrimaryFailure(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule(
		"hedge-capacity-reverse",
		"127.0.0.1:18108",
		"cached:443",
		"fallback:443",
		"standby:443",
	)
	hedgeReady := make(chan time.Time, 1)
	primaryStarted := make(chan struct{})
	failPrimary := make(chan struct{})
	optionalAttempted := make(chan struct{})
	releaseOptionalResult := make(chan struct{})
	requiredStandbyStarted := make(chan struct{})
	standbyCanceled := make(chan struct{})
	winnerConn, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	var fallbackCalls atomic.Int32

	type result struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(ctx context.Context, _ *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				switch addr {
				case "cached:443":
					options.onStart()
					close(primaryStarted)
					select {
					case <-failPrimary:
						return nil, routeAttempt{}, errors.New("primary failed before optional result")
					case <-ctx.Done():
						return nil, routeAttempt{}, ctx.Err()
					}
				case "fallback:443":
					call := fallbackCalls.Add(1)
					if call == 1 {
						if !options.tryOnly {
							return nil, routeAttempt{}, errors.New("first fallback was not optional")
						}
						close(optionalAttempted)
						select {
						case <-releaseOptionalResult:
							return nil, routeAttempt{}, &dialBulkheadError{target: addr, saturated: true}
						case <-ctx.Done():
							return nil, routeAttempt{}, ctx.Err()
						}
					}
					if options.tryOnly {
						return nil, routeAttempt{}, errors.New("retried fallback was still optional")
					}
					return winnerConn, routeAttempt{}, nil
				case "standby:443":
					if options.tryOnly {
						return nil, routeAttempt{}, errors.New("post-primary standby was still optional")
					}
					close(requiredStandbyStarted)
					<-ctx.Done()
					close(standbyCanceled)
					return nil, routeAttempt{}, ctx.Err()
				default:
					return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
				}
			},
			nil,
			50*time.Millisecond,
			hedgeReady,
		)
		done <- result{outcome: outcome, err: err}
	}()

	<-primaryStarted
	hedgeReady <- time.Now()
	<-optionalAttempted
	close(failPrimary)
	select {
	case <-requiredStandbyStarted:
	case <-time.After(time.Second):
		t.Fatal("primary failure did not switch new fallback to required admission")
	}
	close(releaseOptionalResult)
	got := <-done
	if got.err != nil {
		t.Fatalf("race error = %v", got.err)
	}
	defer got.outcome.winner.conn.Close()
	if got.outcome.winner.addr != "fallback:443" || !got.outcome.cachedFailed ||
		!got.outcome.fallbackStarted || got.outcome.hedged {
		t.Fatalf("reverse capacity retry outcome = %+v", got.outcome)
	}
	if calls := fallbackCalls.Load(); calls != 2 {
		t.Fatalf("fallback calls = %d, want optional attempt plus required retry", calls)
	}
	select {
	case <-standbyCanceled:
	default:
		t.Fatal("required retry winner did not cancel the other fallback")
	}
	snapshot := processMetrics.snapshot()
	if skipped := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeSkippedCapacity}]; skipped != 1 {
		t.Fatalf("skipped-capacity events = %d, want 1", skipped)
	}
	for _, event := range []string{boostHedgeLaunched, boostHedgeWon} {
		if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: event}]; got != 0 {
			t.Fatalf("reverse capacity event %s = %d, want 0", event, got)
		}
	}
}

func TestCachedBoostRejectedBeforeDialDoesNotScheduleHedge(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hedge-prestart-reject", "127.0.0.1:18104", "cached:443", "fallback:443")

	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(),
		rule,
		"cached:443",
		func(context.Context, *config.Rule, string, boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			return nil, routeAttempt{}, &dialBulkheadError{target: "cached:443", saturated: true}
		},
		nil,
		50*time.Millisecond,
		nil,
	)
	if !errors.Is(err, errDialBulkheadSaturated) {
		t.Fatalf("race error = %v, want bulkhead saturation", err)
	}
	if outcome.fallbackStarted || outcome.hedged || outcome.cachedFailed {
		t.Fatalf("pre-dial rejection changed Hedge outcome: %+v", outcome)
	}
	snapshot := processMetrics.snapshot()
	for _, event := range []string{boostHedgeScheduled, boostHedgeLaunched, boostHedgeAvoided} {
		if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: event}]; got != 0 {
			t.Fatalf("pre-dial rejection event %s = %d, want 0", event, got)
		}
	}
	if got := snapshot.boostHedgeDelayCount[rule.Name]; got != 0 {
		t.Fatalf("pre-dial rejection recorded %d Hedge delay sample(s)", got)
	}
}

func TestCachedBoostAlternativeRejectedBeforeDialIsNotLaunched(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hedge-alt-prestart", "127.0.0.1:18105", "cached:443", "fallback:443")
	hedgeReady := make(chan time.Time, 1)
	primaryStarted := make(chan struct{})
	releasePrimary := make(chan struct{})
	fallbackReturned := make(chan struct{})
	primaryConn, primaryPeer := net.Pipe()
	defer primaryPeer.Close()

	type result struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			"cached:443",
			func(ctx context.Context, _ *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				switch addr {
				case "cached:443":
					options.onStart()
					close(primaryStarted)
					select {
					case <-releasePrimary:
						return primaryConn, routeAttempt{}, nil
					case <-ctx.Done():
						return nil, routeAttempt{}, ctx.Err()
					}
				case "fallback:443":
					close(fallbackReturned)
					return nil, routeAttempt{}, ErrCircuitOpen
				default:
					return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
				}
			},
			nil,
			50*time.Millisecond,
			hedgeReady,
		)
		done <- result{outcome: outcome, err: err}
	}()

	<-primaryStarted
	hedgeReady <- time.Now()
	<-fallbackReturned
	close(releasePrimary)
	got := <-done
	if got.err != nil {
		t.Fatalf("race error = %v", got.err)
	}
	defer got.outcome.winner.conn.Close()
	if got.outcome.hedged || !got.outcome.fallbackStarted {
		t.Fatalf("pre-dial fallback outcome = %+v, want selected but not launched", got.outcome)
	}
	snapshot := processMetrics.snapshot()
	if launched := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeLaunched}]; launched != 0 {
		t.Fatalf("pre-dial fallback launched events = %d, want 0", launched)
	}
}

func TestCachedBoostSkipsHedgeWithoutDeadlineBudget(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule("hedge-deadline", "127.0.0.1:18106", "cached:443", "fallback:443")
	primaryConn, primaryPeer := net.Pipe()
	defer primaryPeer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	outcome, err := runtime.raceCachedBoostTargetWithDial(
		ctx,
		rule,
		"cached:443",
		func(_ context.Context, _ *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			if addr != "cached:443" {
				return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", addr)
			}
			options.onStart()
			return primaryConn, routeAttempt{}, nil
		},
		nil,
		50*time.Millisecond,
		nil,
	)
	if err != nil {
		t.Fatalf("race error = %v", err)
	}
	defer outcome.winner.conn.Close()
	snapshot := processMetrics.snapshot()
	if skipped := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeSkippedDeadline}]; skipped != 1 {
		t.Fatalf("skipped-deadline events = %d, want 1", skipped)
	}
	for _, event := range []string{boostHedgeScheduled, boostHedgeLaunched, boostHedgeAvoided} {
		if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: event}]; got != 0 {
			t.Fatalf("deadline-skipped event %s = %d, want 0", event, got)
		}
	}
	if got := snapshot.boostHedgeDelayCount[rule.Name]; got != 0 {
		t.Fatalf("deadline-skipped path recorded %d delay sample(s)", got)
	}
}

func TestCachedBoostHedgeDelayStartsAfterPrimaryAdmission(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()

	primaryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer primaryListener.Close()
	fallbackListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fallbackListener.Close()

	acceptOne := func(listener net.Listener) <-chan net.Conn {
		accepted := make(chan net.Conn, 1)
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr == nil {
				accepted <- connection
			}
		}()
		return accepted
	}
	primaryAccepted := acceptOne(primaryListener)
	fallbackAccepted := acceptOne(fallbackListener)

	bulkhead := newDialBulkhead(1, 1, time.Second)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := hedgedBoostTestRule(
		"hedge-admission-anchor",
		"127.0.0.1:18103",
		primaryListener.Addr().String(),
		fallbackListener.Addr().String(),
	)
	rule.Hedge.MinDelay = 25
	rule.Hedge.MaxDelay = 25

	holder, _, err := bulkhead.acquire(context.Background(), "capacity-holder:443")
	if err != nil {
		t.Fatal(err)
	}
	holderReleased := false
	defer func() {
		if !holderReleased {
			holder.release()
		}
	}()

	type cachedResult struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan cachedResult, 1)
	go func() {
		outcome, raceErr := runtime.raceCachedBoostTarget(context.Background(), rule, primaryListener.Addr().String(), nil)
		done <- cachedResult{outcome: outcome, err: raceErr}
	}()

	deadline := time.Now().Add(time.Second)
	for bulkhead.snapshot().Waiting != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bulkhead.snapshot().Waiting; got != 1 {
		t.Fatalf("primary bulkhead waiters = %d, want 1", got)
	}
	time.Sleep(3 * time.Duration(rule.Hedge.MinDelay) * time.Millisecond)
	select {
	case connection := <-fallbackAccepted:
		_ = connection.Close()
		t.Fatal("fallback dialed while the primary was still waiting for admission")
	default:
	}

	holder.release()
	holderReleased = true

	var result cachedResult
	select {
	case result = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cached Boost race did not finish after admission became available")
	}
	if result.err != nil {
		t.Fatalf("raceCachedBoostTarget() error = %v", result.err)
	}
	if result.outcome.winner.addr != primaryListener.Addr().String() {
		t.Fatalf("winner = %q, want admitted primary", result.outcome.winner.addr)
	}
	defer result.outcome.winner.conn.Close()

	select {
	case connection := <-primaryAccepted:
		defer connection.Close()
	case <-time.After(time.Second):
		t.Fatal("primary listener did not accept the admitted dial")
	}
	select {
	case connection := <-fallbackAccepted:
		_ = connection.Close()
		t.Fatal("fallback dialed before the admitted primary could win")
	case <-time.After(3 * time.Duration(rule.Hedge.MinDelay) * time.Millisecond):
	}

	snapshot := processMetrics.snapshot()
	if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeAvoided}]; got != 1 {
		t.Fatalf("avoided hedge events = %d, want 1", got)
	}
	if got := snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: rule.Name, outcome: boostHedgeLaunched}]; got != 0 {
		t.Fatalf("launched hedge events = %d, want 0", got)
	}
}

func TestRaceBoostTargetsClosesEveryLoser(t *testing.T) {
	resetRouteHealthForTest()
	rule := boostTestRule("race", "127.0.0.1:1001", "one:1", "two:2", "three:3")
	connections := make(map[string]*boostTrackingConn, len(rule.Targets))
	dialed := make(map[string]bool, 2)
	var dialedMu sync.Mutex
	initialPairStarted := make(chan struct{})
	var initialPairOnce sync.Once
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

	winner, err := raceBoostTargets(context.Background(), rule, func(ctx context.Context, addr string) (net.Conn, error) {
		dialedMu.Lock()
		dialed[addr] = true
		if len(dialed) == 2 {
			initialPairOnce.Do(func() { close(initialPairStarted) })
		}
		dialedMu.Unlock()
		select {
		case <-initialPairStarted:
		case <-ctx.Done():
			// The pair barrier and cancellation can become ready together after
			// the first success wins. Once both test dials have started, prefer
			// returning their connections so the race owns and closes its loser.
			select {
			case <-initialPairStarted:
			default:
				return nil, ctx.Err()
			}
		}
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

func TestFinishBoostRelayKeepsWinnerForClientDisconnect(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("relay-client-close", "127.0.0.1:18199", "one:1", "two:2")
	key := boostRuleKey(rule)
	token := runtime.storeBoostWinner(key, "one:1")

	clientReset := &net.OpError{Op: "writeto", Net: "tcp", Err: &net.OpError{
		Op: "read", Net: "tcp", Err: syscall.ECONNRESET,
	}}
	runtime.finishBoostRelay(token, routeAttempt{}, relayResult{
		ClientToTarget: relayDirectionResult{
			Err: clientReset, Origin: relayErrorOriginPrimary,
		},
		TargetToClient: relayDirectionResult{
			Err: net.ErrClosed, Origin: relayErrorOriginSecondary,
		},
		StopCause: relayStopCause{
			Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
		},
	})

	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != token.addr || entry.generation != token.generation {
		t.Fatalf("client disconnect removed cached winner: entry=%+v ok=%v", entry, ok)
	}
}

func TestFinishBoostRelayDropsOnlyActionableCurrentWinner(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := boostTestRule("relay-cache", "127.0.0.1:18200", "one:1", "two:2")
	key := boostRuleKey(rule)
	token := runtime.storeBoostWinner(key, "one:1")

	runtime.finishBoostRelay(token, routeAttempt{}, relayResult{
		TargetToClient: relayDirectionResult{Err: errors.New("ambiguous relay error")},
	})
	if _, ok := runtime.loadBoostWinnerToken(key); ok {
		t.Fatal("errored relay retained its cached winner")
	}

	stale := runtime.storeBoostWinner(key, "one:1")
	current := runtime.storeBoostWinner(key, "two:2")
	runtime.finishBoostRelay(stale, routeAttempt{}, relayResult{
		ClientToTarget: relayDirectionResult{Err: errors.New("old stream failed")},
	})
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != current.addr || entry.generation != current.generation {
		t.Fatalf("old stream deleted newer winner: entry=%+v ok=%v", entry, ok)
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
