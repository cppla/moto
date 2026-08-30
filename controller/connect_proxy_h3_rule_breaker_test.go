package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestHTTP3RuleBreakerDifferentIPsRequireDataPlaneProbation(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	first := http3ConnectTransportKey{address: "first.example:443"}
	second := http3ConnectTransportKey{address: "second.example:443"}
	breaker.register("mixed", first)
	breaker.register("mixed", second)

	breaker.noteDegradation(http3RuleDegradationEvent{
		key: first, remoteIP: "192.0.2.10", generationID: 1, at: now,
	})
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: second, remoteIP: "192.0.2.20", generationID: 2, at: now.Add(30 * time.Second),
	})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", first, true)
	now = now.Add(5*time.Minute + 30*time.Second)
	token, probation, allowed := breaker.begin("mixed", second)
	if token == 0 || !probation || !allowed {
		t.Fatalf("probation admission = token:%d probation:%t allowed:%t", token, probation, allowed)
	}
	if _, _, siblingAllowed := breaker.begin("mixed", first); siblingAllowed {
		t.Fatal("concurrent H3 admitted while rule probation is active")
	}
	binding := http3RuleProbationBinding{
		generationID: 3,
		remoteIP:     "192.0.2.20",
		stats:        quic.ConnectionStats{PacketsSent: 100},
		payloadBytes: 1000,
	}
	if !breaker.establish("mixed", token, second, binding) {
		t.Fatal("probation binding was rejected")
	}
	established := now
	for index, elapsed := range []time.Duration{26 * time.Second, 28 * time.Second, 30 * time.Second} {
		breaker.noteSample(http3RuleSampleEvent{
			key:          second,
			remoteIP:     binding.remoteIP,
			generationID: binding.generationID,
			at:           established.Add(elapsed),
			stats:        quic.ConnectionStats{PacketsSent: 400},
			payloadBytes: binding.payloadBytes + http3RuleProbationMinPayload,
			decision: http3DegradationDecision{Signals: http3DegradationSignals{
				Sampled: true,
			}},
		})
		state := breaker.rules["mixed"]
		if index < 2 && state.phase != http3RuleBreakerProbation {
			t.Fatalf("probation recovered before 30s at sample %d", index)
		}
	}
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerClosed || state.failures != 0 {
		t.Fatalf("rule state after proven recovery = %+v", state)
	}
	if state.events["recovered"] != 1 {
		t.Fatalf("recovered events = %d, want 1", state.events["recovered"])
	}
}

func TestHTTP3RuleBreakerSameRemoteIPAcrossTargetsCountsIndependentGenerations(t *testing.T) {
	now := time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	first := http3ConnectTransportKey{address: "first.example:443"}
	second := http3ConnectTransportKey{address: "second.example:443"}
	breaker.register("mixed", first)
	breaker.register("mixed", second)
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: first, remoteIP: "192.0.2.30", generationID: 10, at: now,
	})
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: second, remoteIP: "192.0.2.30", generationID: 11, at: now.Add(10 * time.Second),
	})
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerEvaluating {
		t.Fatalf("same resolved endpoint generations did not start H2 validation: %+v", state)
	}
}

func TestHTTP3RuleBreakerIgnoresStaleOrDuplicateDegradation(t *testing.T) {
	now := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.40", generationID: 20, at: now,
	})
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.40", generationID: 20, at: now.Add(10 * time.Second),
	})
	breaker.noteDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.40", generationID: 21, at: now.Add(61 * time.Second),
	})
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerClosed {
		t.Fatalf("stale or duplicate event opened breaker: %+v", state)
	}
}

func TestHTTP3RuleBreakerProbationBackoffIsBounded(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.50", generationID: 30, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.50", generationID: 31, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", key, true)

	wants := []time.Duration{10 * time.Minute, 20 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for index, want := range wants {
		state := breaker.rules["mixed"]
		now = state.retryAt
		token, probation, allowed := breaker.begin("mixed", key)
		if token == 0 || !probation || !allowed {
			t.Fatalf("probation %d not admitted", index)
		}
		breaker.failProbation("mixed", token, "test")
		state = breaker.rules["mixed"]
		if got := state.retryAt.Sub(now); got != want {
			t.Fatalf("backoff %d = %s, want %s", index, got, want)
		}
	}
}

func TestHTTP3RuleBreakerInsufficientProbationEvidenceReturnsToCooldown(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 30, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.55", generationID: 35, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.55", generationID: 36, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", key, true)
	now = breaker.rules["mixed"].retryAt
	token, _, allowed := breaker.begin("mixed", key)
	if token == 0 || !allowed {
		t.Fatal("probation was not admitted")
	}
	if !breaker.establish("mixed", token, key, http3RuleProbationBinding{generationID: 37}) {
		t.Fatal("probation was not established")
	}
	now = now.Add(http3RuleProbationMaxDuration)
	breaker.noteSample(http3RuleSampleEvent{
		key:          key,
		generationID: 37,
		at:           now,
		decision: http3DegradationDecision{Signals: http3DegradationSignals{
			Sampled: true,
		}},
	})
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerCooldown || state.retryAt.Sub(now) != 10*time.Minute {
		t.Fatalf("insufficient probation evidence state = %+v", state)
	}
}

func TestHTTP3RuleBreakerDoesNotApplyToH3OnlyOrH2First(t *testing.T) {
	manager := newConnectProxyManager()
	defer manager.close()
	for _, target := range []*config.Target{
		{Address: "h3-only.example:443", ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}},
		{Address: "h2-first.example:443", ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH2, config.ConnectProxyH3}}},
	} {
		manager.registerHTTP3RuleTarget("rule", target)
		if _, probation, allowed := manager.beginHTTP3RuleAttempt(context.Background(), "rule", target); probation || !allowed {
			t.Fatalf("protocols %v unexpectedly entered rule breaker", target.ConnectProxy.Protocols)
		}
	}
	if len(manager.h3RuleBreaker.rules) != 0 {
		t.Fatalf("non-mixed targets registered rule breaker state: %+v", manager.h3RuleBreaker.rules)
	}
}

func TestHTTP3RuleCooldownSuppressesH3BoostPenaltyAndCanary(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 45, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	rule := &config.Rule{Name: "mixed", Mode: config.ModeBoost}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	manager.registerHTTP3RuleTarget(rule.Name, target)
	manager.h3FallbackMu.Lock()
	manager.h3Fallback[key] = &http3FallbackState{
		degradationActive:  true,
		degradationStrikes: 1,
	}
	manager.h3FallbackMu.Unlock()
	if penalty := manager.http3RoutePenalty(rule, target, now); penalty <= 0 {
		t.Fatal("pre-breaker H3 degradation did not publish Boost penalty")
	}
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.58", generationID: 38, at: now})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.58", generationID: 39, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, manager.h3RuleBreaker, rule.Name, key, true)
	if penalty := manager.http3RoutePenalty(rule, target, now); penalty != 0 {
		t.Fatalf("rule H2 bypass retained H3 Boost penalty %s", penalty)
	}
	if token, claimed := manager.claimHTTP3BoostProbe(rule, target, now); token != 0 || claimed {
		t.Fatalf("rule H2 bypass admitted target H3 canary token=%d claimed=%t", token, claimed)
	}
}

func TestHTTP3RuleProbationRouteLeaseIsExclusive(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 50, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	rule := &config.Rule{Name: "mixed", Mode: config.ModeBoost}
	first := &config.Target{Address: "first.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	second := &config.Target{Address: "second.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule.Targets = []*config.Target{first, second}
	firstKey := http3ConnectTransportKey{address: first.Address}
	secondKey := http3ConnectTransportKey{address: second.Address}
	manager.registerHTTP3RuleTarget(rule.Name, first)
	manager.registerHTTP3RuleTarget(rule.Name, second)
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: firstKey, remoteIP: "192.0.2.90", generationID: 70, at: now})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: secondKey, remoteIP: "192.0.2.91", generationID: 71, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, manager.h3RuleBreaker, rule.Name, firstKey, true)
	now = manager.h3RuleBreaker.rules[rule.Name].retryAt
	if penalty := manager.http3RoutePenalty(rule, first, now); penalty <= 0 {
		t.Fatal("due rule probation did not invalidate cached Boost route")
	}
	routes := newRouteHealthRegistry(manager.http3RoutePenalty)
	routes.protocolProbeClaim = manager.claimHTTP3BoostProbe
	routes.protocolProbeRelease = manager.releaseHTTP3BoostProbe
	selections := routes.selectTargetSelections(rule, 2, now, nil, true)
	if len(selections) == 0 || selections[0].protocolProbe.token&http3RuleRouteProbeTokenMask == 0 {
		t.Fatalf("all-penalized route selection did not reserve exclusive rule probe: %+v", selections)
	}
	leaseToken := selections[0].protocolProbe.token
	leasedTarget := selections[0].target
	if token, secondClaimed := manager.claimHTTP3BoostProbe(rule, second, now); secondClaimed || token != 0 {
		t.Fatalf("concurrent rule recovery lease = token:%d claimed:%t", token, secondClaimed)
	}
	withoutLease := second
	if leasedTarget == second {
		withoutLease = first
	}
	if _, probation, allowed := manager.beginHTTP3RuleAttempt(context.Background(), rule.Name, withoutLease); probation || allowed {
		t.Fatal("request without the route lease entered H3 probation")
	}
	probeCtx := withRouteProtocolProbeLease(context.Background(), routeProtocolProbeLease{token: leaseToken})
	probeToken, probation, allowed := manager.beginHTTP3RuleAttempt(probeCtx, rule.Name, leasedTarget)
	if probeToken == 0 || !probation || !allowed {
		t.Fatalf("leased H3 probation = token:%d probation:%t allowed:%t", probeToken, probation, allowed)
	}
	manager.releaseHTTP3BoostProbe(rule, leasedTarget, leaseToken)
}

func TestHTTP3RuleUnusedRouteProbeLeaseDefersRetry(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 52, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.94", generationID: 74, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.94", generationID: 75, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", key, true)
	now = breaker.rules["mixed"].retryAt

	lease, claimed := breaker.claimRecoveryRouteProbe("mixed", key, now)
	if !claimed || lease&http3RuleRouteProbeTokenMask == 0 {
		t.Fatalf("route probation lease = token:%d claimed:%t", lease, claimed)
	}
	if !breaker.releaseRecoveryRouteProbe("mixed", lease) {
		t.Fatal("unused route probation lease was not released")
	}
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerCooldown || state.routeProbeToken != 0 ||
		state.retryAt.Sub(now) != http3RuleProbationAbortDelay || state.failures != 1 {
		t.Fatalf("unused route lease retry state = %+v", state)
	}
	if breaker.recoveryProbeDue("mixed", now) {
		t.Fatal("unused route lease immediately reopened recovery probing")
	}
}

func TestBoostPassesExclusiveRuleProbationLeaseToOnlyCanary(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	first := &config.Target{Address: "first.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	second := &config.Target{Address: "second.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{
		Name: "mixed", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{first, second},
	}
	firstKey := http3ConnectTransportKey{address: first.Address}
	secondKey := http3ConnectTransportKey{address: second.Address}
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, first)
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, second)
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: firstKey, remoteIP: "192.0.2.92", generationID: 72, at: now})
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: secondKey, remoteIP: "192.0.2.93", generationID: 73, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, runtime.connectProxy.h3RuleBreaker, rule.Name, firstKey, true)
	runtime.connectProxy.h3RuleBreaker.mu.Lock()
	runtime.connectProxy.h3RuleBreaker.rules[rule.Name].retryAt = now.Add(-time.Second)
	runtime.connectProxy.h3RuleBreaker.mu.Unlock()

	dialCount := 0
	peerConnections := make(chan net.Conn, 1)
	winner, err := runtime.raceBoostTargetsPrepared(context.Background(), rule,
		func(ctx context.Context, _ string) (net.Conn, error) {
			dialCount++
			if token := routeProtocolProbeTokenFromContext(ctx); token&http3RuleRouteProbeTokenMask == 0 {
				return nil, errors.New("missing rule probation route lease")
			}
			connection, peer := net.Pipe()
			peerConnections <- peer
			return connection, nil
		}, nil)
	if err != nil {
		t.Fatalf("exclusive Boost canary: %v", err)
	}
	_ = winner.conn.Close()
	_ = (<-peerConnections).Close()
	if dialCount != 1 {
		t.Fatalf("Boost raced %d routes against exclusive rule canary", dialCount)
	}
}

func TestCachedBoostPassesExclusiveRuleProbationLeaseAndSuppressesHedge(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	cached := &config.Target{Address: "cached.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	fallback := &config.Target{Address: "fallback.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{
		Name: "cached-mixed", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Hedge:   &config.HedgeConfig{MinDelay: 25, MaxDelay: 250},
		Targets: []*config.Target{cached, fallback},
	}
	key := http3ConnectTransportKey{address: cached.Address}
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, cached)
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, fallback)
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.101", generationID: 81, at: now,
	})
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.101", generationID: 82, at: now.Add(time.Second),
	})
	validateHTTP3RuleFallbackForTest(t, runtime.connectProxy.h3RuleBreaker, rule.Name, key, true)
	runtime.connectProxy.h3RuleBreaker.mu.Lock()
	runtime.connectProxy.h3RuleBreaker.rules[rule.Name].retryAt = now.Add(-time.Second)
	runtime.connectProxy.h3RuleBreaker.mu.Unlock()

	hedgeReady := make(chan time.Time)
	primaryStarted := make(chan struct{})
	releasePrimary := make(chan struct{})
	fallbackStarted := make(chan struct{}, 1)
	primaryConnection, primaryPeer := net.Pipe()
	defer primaryPeer.Close()
	type raceResult struct {
		outcome cachedBoostOutcome
		err     error
	}
	done := make(chan raceResult, 1)
	go func() {
		outcome, err := runtime.raceCachedBoostTargetWithDial(
			context.Background(),
			rule,
			cached.Address,
			func(ctx context.Context, _ *config.Rule, address string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
				switch address {
				case cached.Address:
					if token := routeProtocolProbeTokenFromContext(ctx); token&http3RuleRouteProbeTokenMask == 0 {
						return nil, routeAttempt{}, errors.New("cached H3 canary missing rule probation lease")
					}
					options.onStart()
					close(primaryStarted)
					<-releasePrimary
					return primaryConnection, routeAttempt{}, nil
				case fallback.Address:
					fallbackStarted <- struct{}{}
					return nil, routeAttempt{}, errors.New("hedge raced exclusive cached H3 canary")
				default:
					return nil, routeAttempt{}, fmt.Errorf("unexpected target %s", address)
				}
			},
			nil,
			25*time.Millisecond,
			hedgeReady,
		)
		done <- raceResult{outcome: outcome, err: err}
	}()

	<-primaryStarted
	// The unbuffered send returns only after the cached-race loop has consumed
	// the hedge signal. An exclusive protocol probe must ignore it.
	hedgeReady <- now
	select {
	case <-fallbackStarted:
		t.Fatal("cached protocol probation was raced by a hedge")
	default:
	}
	close(releasePrimary)
	result := <-done
	if result.err != nil {
		t.Fatalf("cached exclusive H3 canary: %v", result.err)
	}
	defer result.outcome.winner.conn.Close()
	if result.outcome.winner.addr != cached.Address || result.outcome.hedged || result.outcome.fallbackStarted {
		t.Fatalf("cached probation outcome = %+v", result.outcome)
	}
	runtime.connectProxy.h3RuleBreaker.mu.Lock()
	state := *runtime.connectProxy.h3RuleBreaker.rules[rule.Name]
	runtime.connectProxy.h3RuleBreaker.mu.Unlock()
	if state.routeProbeToken != 0 {
		t.Fatalf("cached protocol-probe lease was not released: %+v", state)
	}
}

func TestHTTP3RuleProbationAbortDoesNotIncreaseBackoff(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 55, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.95", generationID: 75, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.95", generationID: 76, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", key, true)
	now = breaker.rules["mixed"].retryAt
	token, probation, allowed := breaker.begin("mixed", key)
	if token == 0 || !probation || !allowed {
		t.Fatal("probation was not admitted")
	}
	breaker.abortProbation("mixed", token, "capacity")
	state := breaker.rules["mixed"]
	if state.failures != 1 || state.retryAt.Sub(now) != http3RuleProbationAbortDelay {
		t.Fatalf("aborted probation changed failure backoff: %+v", state)
	}
}

func TestConnectProxyRuleCooldownAdmitsOnlyOneHTTP3Probation(t *testing.T) {
	now := time.Date(2026, 8, 28, 16, 0, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	manager.registerHTTP3RuleTarget("mixed", target)
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.60", generationID: 40, at: now,
	})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.60", generationID: 41, at: now.Add(time.Second),
	})

	var callsMu sync.Mutex
	h3Calls := 0
	h2Calls := 0
	manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
		callsMu.Lock()
		h3Calls++
		callsMu.Unlock()
		return &http3RuleBreakerTestConn{binding: http3RuleProbationBinding{
			generationID: 42,
			remoteIP:     "192.0.2.60",
		}}, nil
	}
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		callsMu.Lock()
		h2Calls++
		callsMu.Unlock()
		return &http3RuleBreakerTestConn{}, nil
	}

	connection, err := manager.dialForRule(context.Background(), "mixed", target, "example.org:443")
	if err != nil {
		t.Fatalf("H2 during rule cooldown: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 0 || h2Calls != 1 {
		t.Fatalf("cooldown calls = h3:%d h2:%d, want 0/1", h3Calls, h2Calls)
	}

	now = manager.h3RuleBreaker.rules["mixed"].retryAt
	probe, err := manager.dialForRule(context.Background(), "mixed", target, "probation.example:443")
	if err != nil {
		t.Fatalf("H3 probation: %v", err)
	}
	sibling, err := manager.dialForRule(context.Background(), "mixed", target, "sibling.example:443")
	if err != nil {
		t.Fatalf("H2 sibling during probation: %v", err)
	}
	_ = sibling.Close()
	if h3Calls != 1 || h2Calls != 2 {
		t.Fatalf("probation calls = h3:%d h2:%d, want 1/2", h3Calls, h2Calls)
	}
	_ = probe.Close()
	state := manager.h3RuleBreaker.rules["mixed"]
	if state.phase != http3RuleBreakerCooldown || state.retryAt.Sub(now) != 10*time.Minute {
		t.Fatalf("closed unproven probation did not re-enter 10m cooldown: %+v", state)
	}
}

func TestHTTP3RuleCooldownStillSettlesTargetPendingFallback(t *testing.T) {
	now := time.Date(2026, 8, 28, 16, 30, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	manager.registerHTTP3RuleTarget("mixed", target)
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.65", generationID: 45, at: now})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.65", generationID: 46, at: now.Add(time.Second)})
	manager.h3FallbackMu.Lock()
	manager.h3Fallback[key] = &http3FallbackState{
		epoch:        manager.nextHTTP3EpochLocked(),
		pending:      true,
		pendingCause: http3FallbackCauseDegradation,
	}
	manager.h3FallbackMu.Unlock()
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return &http3RuleBreakerTestConn{}, nil
	}

	connection, err := manager.dialForRule(context.Background(), "mixed", target, "example.org:443")
	if err != nil {
		t.Fatalf("H2 fallback: %v", err)
	}
	_ = connection.Close()
	manager.h3FallbackMu.Lock()
	state := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if state.pending || state.failures != 1 || state.cooldownCause != http3FallbackCauseDegradation {
		t.Fatalf("target fallback was not settled by rule-level H2 bypass: %+v", state)
	}
}

func TestConnectProxyFailedH2ValidationFailsOpenToH3(t *testing.T) {
	now := time.Date(2026, 8, 28, 16, 40, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	target := &config.Target{Address: "proxy.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	key := http3ConnectTransportKey{address: target.Address}
	manager.registerHTTP3RuleTarget("mixed", target)
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.66", generationID: 47, at: now})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.66", generationID: 48, at: now.Add(time.Second)})
	h3Calls := 0
	manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h3Calls++
		return &http3RuleBreakerTestConn{}, nil
	}
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return nil, errors.New("H2 transport unavailable")
	}
	if _, err := manager.dialForRule(context.Background(), "mixed", target, "validation.example:443"); err == nil {
		t.Fatal("failed H2 validation unexpectedly established a tunnel")
	}
	if state := manager.h3RuleBreaker.rules["mixed"]; state.phase != http3RuleBreakerEvaluating {
		t.Fatalf("failed H2 validation did not preserve serial fallback grace: %+v", state)
	}
	now = now.Add(http3RuleValidationGrace)
	connection, err := manager.dialForRule(context.Background(), "mixed", target, "h3.example:443")
	if err != nil {
		t.Fatalf("H3 after failed H2 validation: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 {
		t.Fatalf("H3 calls after fail-open = %d, want 1", h3Calls)
	}
}

func TestConnectProxyNonNetworkProbationAbortDoesNotEscalate(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{name: "capacity", err: errConnectProxyProtocolCapacity},
		{name: "canceled", err: context.Canceled},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			now := time.Date(2026, 8, 28, 16, 50, 0, 0, time.UTC)
			manager := newConnectProxyManager()
			defer manager.close()
			manager.now = func() time.Time { return now }
			target := &config.Target{Address: "proxy.example:443", ConnectProxy: &config.ConnectProxyConfig{
				Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
			}}
			key := http3ConnectTransportKey{address: target.Address}
			manager.registerHTTP3RuleTarget("mixed", target)
			manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.67", generationID: 49, at: now})
			manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.67", generationID: 50, at: now.Add(time.Second)})
			validateHTTP3RuleFallbackForTest(t, manager.h3RuleBreaker, "mixed", key, true)
			now = manager.h3RuleBreaker.rules["mixed"].retryAt
			manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
				return nil, testCase.err
			}
			manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
				return &http3RuleBreakerTestConn{}, nil
			}
			connection, err := manager.dialForRule(context.Background(), "mixed", target, "example.org:443")
			if err != nil {
				t.Fatalf("H2 after aborted probation: %v", err)
			}
			_ = connection.Close()
			state := manager.h3RuleBreaker.rules["mixed"]
			if state.failures != 1 || state.retryAt.Sub(now) != http3RuleProbationAbortDelay {
				t.Fatalf("non-network probation outcome escalated backoff: %+v", state)
			}
		})
	}
}

func TestHTTP3RuleBreakerMetrics(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	now := time.Date(2026, 8, 28, 17, 0, 0, 0, time.UTC)
	runtime.connectProxy.now = func() time.Time { return now }
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	runtime.connectProxy.registerHTTP3RuleTarget("mixed", target)
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.70", generationID: 50, at: now,
	})
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.70", generationID: 51, at: now.Add(time.Second),
	})
	token, _, allowed := runtime.connectProxy.h3RuleBreaker.begin("mixed", key)
	if token == 0 || allowed {
		t.Fatalf("H2 validation admission = token:%d allowed:%t", token, allowed)
	}
	runtime.connectProxy.observeHTTP3RuleValidation("mixed", token, nil, true)
	var output strings.Builder
	runtime.renderOperationalGauges(&output)
	body := output.String()
	for _, want := range []string{
		`moto_connect_proxy_h3_rule_cooldown_active{rule="mixed"} 1`,
		`moto_connect_proxy_h3_rule_cooldown_remaining_seconds{rule="mixed"} 300`,
		`moto_connect_proxy_h3_rule_probation_active{rule="mixed"} 0`,
		`moto_connect_proxy_h3_rule_breaker_events{rule="mixed",outcome="opened"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\n%s", want, body)
		}
	}
	now = runtime.connectProxy.h3RuleBreaker.rules["mixed"].retryAt
	output.Reset()
	runtime.renderOperationalGauges(&output)
	body = output.String()
	for _, want := range []string{
		`moto_connect_proxy_h3_rule_cooldown_active{rule="mixed"} 0`,
		`moto_connect_proxy_h3_rule_probe_due{rule="mixed"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("due-probe metrics output missing %q\n%s", want, body)
		}
	}
}

func TestHTTP3RuleBreakerFailedH2ValidationKeepsH3FailOpen(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 30, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.80", generationID: 60, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.80", generationID: 61, at: now.Add(time.Second)})
	validateHTTP3RuleFallbackForTest(t, breaker, "mixed", key, false)
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerEvaluating || state.failures != 0 {
		t.Fatalf("failed H2 validation did not preserve serial fallback grace: %+v", state)
	}
	now = now.Add(http3RuleValidationGrace)
	if _, probation, allowed := breaker.begin("mixed", key); probation || !allowed {
		t.Fatal("H3 did not fail open after H2 validation failure")
	}
}

func TestHTTP3RuleBreakerAnyConcurrentH2ValidationCanCommit(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 40, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.81", generationID: 62, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.81", generationID: 63, at: now.Add(time.Second)})
	first, _, firstAllowed := breaker.begin("mixed", key)
	second, _, secondAllowed := breaker.begin("mixed", key)
	if first == 0 || first != second || firstAllowed || secondAllowed {
		t.Fatalf("validation participants = first:%d/%t second:%d/%t", first, firstAllowed, second, secondAllowed)
	}
	breaker.observeValidation("mixed", first, errors.New("first H2 failed"), false)
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerEvaluating {
		t.Fatalf("first failed participant prematurely ended validation: %+v", state)
	}
	// The H2 response remains valid evidence even if a sibling Boost route wins
	// and cancels this participant immediately after the response arrives.
	breaker.observeValidation("mixed", second, context.Canceled, true)
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerCooldown || state.failures != 1 {
		t.Fatalf("reachable sibling did not commit cooldown: %+v", state)
	}
}

func TestHTTP3RuleBreakerSerialH2FallbackCanCommit(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 45, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	firstKey := http3ConnectTransportKey{address: "first.example:443"}
	secondKey := http3ConnectTransportKey{address: "second.example:443"}
	breaker.register("mixed", firstKey)
	breaker.register("mixed", secondKey)
	breaker.noteDegradation(http3RuleDegradationEvent{key: firstKey, remoteIP: "192.0.2.82", generationID: 64, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: secondKey, remoteIP: "192.0.2.83", generationID: 65, at: now.Add(time.Second)})

	first, _, firstAllowed := breaker.begin("mixed", firstKey)
	if first == 0 || firstAllowed {
		t.Fatalf("first serial validation = token:%d allowed:%t", first, firstAllowed)
	}
	breaker.observeValidation("mixed", first, errors.New("first H2 failed"), false)
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerEvaluating || state.evaluationInFlight != 0 {
		t.Fatalf("first serial failure prematurely ended validation: %+v", state)
	}

	second, _, secondAllowed := breaker.begin("mixed", secondKey)
	if second != first || secondAllowed {
		t.Fatalf("second serial validation = token:%d allowed:%t, want token %d and H2", second, secondAllowed, first)
	}
	breaker.observeValidation("mixed", second, nil, true)
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerCooldown || state.failures != 1 {
		t.Fatalf("serial fallback H2 did not commit cooldown: %+v", state)
	}
}

func TestHTTP3RuleBreakerSerialValidationGraceExpiresFailOpen(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 50, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.84", generationID: 66, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.84", generationID: 67, at: now.Add(time.Second)})

	token, _, allowed := breaker.begin("mixed", key)
	if token == 0 || allowed {
		t.Fatalf("validation admission = token:%d allowed:%t", token, allowed)
	}
	breaker.observeValidation("mixed", token, errors.New("H2 unavailable"), false)
	now = now.Add(http3RuleValidationGrace)
	if nextToken, probation, h3Allowed := breaker.begin("mixed", key); nextToken != 0 || probation || !h3Allowed {
		t.Fatalf("expired validation did not fail open: token:%d probation:%t allowed:%t", nextToken, probation, h3Allowed)
	}
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerClosed || state.events["validation_failed"] != 1 {
		t.Fatalf("expired validation state = %+v", state)
	}
}

func TestHTTP3RuleBreakerValidationDeadlineStopsNewParticipants(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 52, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.87", generationID: 70, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.87", generationID: 71, at: now.Add(time.Second)})

	first, _, firstAllowed := breaker.begin("mixed", key)
	second, _, secondAllowed := breaker.begin("mixed", key)
	if first == 0 || second != first || firstAllowed || secondAllowed {
		t.Fatalf("active validation participants = first:%d/%t second:%d/%t", first, firstAllowed, second, secondAllowed)
	}
	now = now.Add(http3RuleValidationGrace)
	if token, probation, allowed := breaker.begin("mixed", key); token != 0 || probation || !allowed {
		t.Fatalf("deadline admitted another H2 participant: token:%d probation:%t allowed:%t", token, probation, allowed)
	}
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerClosed || state.evaluationInFlight != 0 || state.events["validation_failed"] != 1 {
		t.Fatalf("deadline fail-open state = %+v", state)
	}
	breaker.observeValidation("mixed", first, nil, true)
	if state.phase != http3RuleBreakerClosed {
		t.Fatalf("stale validation token changed fail-open state: %+v", state)
	}
}

func TestHTTP3RuleBreakerLateH2ValidationResponseIsStale(t *testing.T) {
	now := time.Date(2026, 8, 28, 17, 54, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.89", generationID: 72, at: now})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, remoteIP: "192.0.2.89", generationID: 73, at: now.Add(time.Second)})

	token, _, allowed := breaker.begin("mixed", key)
	if token == 0 || allowed {
		t.Fatalf("validation admission = token:%d allowed:%t", token, allowed)
	}
	now = now.Add(http3RuleValidationGrace)
	if breaker.observeValidation("mixed", token, nil, true) {
		t.Fatal("late H2 response committed rule cooldown")
	}
	state := breaker.rules["mixed"]
	if state.phase != http3RuleBreakerClosed || state.evaluationInFlight != 0 ||
		state.events["validation_failed"] != 1 || state.events["opened"] != 0 {
		t.Fatalf("late H2 response changed fail-open state: %+v", state)
	}

	// Replaying the expired participant must remain a harmless stale-token no-op.
	if breaker.observeValidation("mixed", token, nil, true) {
		t.Fatal("replayed stale H2 response committed rule cooldown")
	}
	if state.phase != http3RuleBreakerClosed || state.events["validation_failed"] != 1 || state.events["opened"] != 0 {
		t.Fatalf("replayed stale response changed breaker state: %+v", state)
	}
}

func TestCachedBoostSerialH2FallbackCommitsRuleCooldown(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	first := &config.Target{Address: "first.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	second := &config.Target{Address: "second.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{
		Name: "serial-mixed", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{first, second},
	}
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, first)
	runtime.connectProxy.registerHTTP3RuleTarget(rule.Name, second)
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: http3ConnectTransportKey{address: first.Address}, remoteIP: "192.0.2.85", generationID: 68, at: now,
	})
	runtime.connectProxy.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: http3ConnectTransportKey{address: second.Address}, remoteIP: "192.0.2.86", generationID: 69, at: now.Add(time.Second),
	})

	var callsMu sync.Mutex
	h3Calls := 0
	h2Calls := make(map[string]int)
	runtime.connectProxy.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
		callsMu.Lock()
		h3Calls++
		callsMu.Unlock()
		return nil, errors.New("H3 must remain bypassed during serial validation")
	}
	peers := make(chan net.Conn, 1)
	runtime.connectProxy.dialers[config.ConnectProxyH2] = func(_ context.Context, target *config.Target, _ string) (net.Conn, error) {
		callsMu.Lock()
		h2Calls[target.Address]++
		callsMu.Unlock()
		if target.Address == first.Address {
			return nil, errors.New("cached H2 unavailable")
		}
		connection, peer := net.Pipe()
		peers <- peer
		return connection, nil
	}

	outcome, err := runtime.raceCachedBoostTargetWithDial(
		context.Background(), rule, first.Address,
		func(ctx context.Context, _ *config.Rule, address string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			target := targetByAddress(rule, address)
			connection, dialErr := runtime.connectProxy.dialForRule(ctx, rule.Name, target, "destination.example:443")
			return connection, routeAttempt{}, dialErr
		},
		nil, 0, nil,
	)
	if err != nil {
		t.Fatalf("cached serial H2 fallback: %v", err)
	}
	defer outcome.winner.conn.Close()
	defer (<-peers).Close()
	if outcome.winner.addr != second.Address {
		t.Fatalf("serial fallback winner = %s, want %s", outcome.winner.addr, second.Address)
	}
	callsMu.Lock()
	gotH3 := h3Calls
	gotFirstH2 := h2Calls[first.Address]
	gotSecondH2 := h2Calls[second.Address]
	callsMu.Unlock()
	if gotH3 != 0 || gotFirstH2 != 1 || gotSecondH2 != 1 {
		t.Fatalf("serial fallback calls = h3:%d firstH2:%d secondH2:%d", gotH3, gotFirstH2, gotSecondH2)
	}
	if state := runtime.connectProxy.h3RuleBreaker.rules[rule.Name]; state.phase != http3RuleBreakerCooldown {
		t.Fatalf("serial fallback did not commit rule cooldown: %+v", state)
	}
}

func TestHTTP3RuleRecoveryDueEvictsH2OnlyCacheForMixedCanary(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	h2Only := &config.Target{Address: "h2-only.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH2},
	}}
	mixed := &config.Target{Address: "mixed.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{Name: "heterogeneous-due", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{h2Only, mixed}}
	now = openHTTP3RuleCooldownForTest(t, runtime.connectProxy, rule.Name, mixed)

	key := boostRuleKey(rule)
	runtime.storeBoostWinner(key, h2Only.Address)
	if entry, ok := runtime.loadUsableBoostWinnerToken(key, rule, now); ok {
		t.Fatalf("H2-only cache remained usable while H3 probation was due: %+v", entry)
	}
	selections := runtime.routes.selectTargetSelections(rule, len(rule.Targets), now, nil, true)
	if len(selections) == 0 || selections[0].target != mixed ||
		selections[0].protocolProbe.token&http3RuleRouteProbeTokenMask == 0 {
		t.Fatalf("due recovery did not select one mixed canary: %+v", selections)
	}
	runtime.routes.releaseProtocolProbe(rule, mixed, selections[0].protocolProbe)
}

func TestHTTP3RuleCooldownEvictsH3OnlyCacheWhenH2CapableTargetExists(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	h3Only := &config.Target{Address: "h3-only.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3},
	}}
	mixed := &config.Target{Address: "mixed.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{Name: "heterogeneous-cooldown", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{h3Only, mixed}}
	_ = openHTTP3RuleCooldownForTest(t, runtime.connectProxy, rule.Name, mixed)

	key := boostRuleKey(rule)
	runtime.storeBoostWinner(key, h3Only.Address)
	if entry, ok := runtime.loadUsableBoostWinnerToken(key, rule, now); ok {
		t.Fatalf("H3-only cache bypassed active rule cooldown: %+v", entry)
	}
	selections := runtime.routes.selectTargetSelections(rule, len(rule.Targets), now, nil, true)
	if len(selections) == 0 || selections[0].target != mixed {
		t.Fatalf("cooldown did not prefer H2-capable target: %+v", selections)
	}
	for _, selection := range selections {
		if selection.target == h3Only {
			t.Fatalf("H3-only target remained eligible beside an H2-capable target: %+v", selections)
		}
	}
}

func TestHTTP3RuleCooldownKeepsH3OnlyFailOpenWithoutSafeCandidate(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	registeredMixed := &config.Target{Address: "registered-mixed.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	h3Only := &config.Target{Address: "only-route.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3},
	}}
	rule := &config.Rule{Name: "heterogeneous-fail-open", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{h3Only}}
	_ = openHTTP3RuleCooldownForTest(t, runtime.connectProxy, rule.Name, registeredMixed)

	selections := runtime.routes.selectTargetSelections(rule, 1, now, nil, true)
	if len(selections) != 1 || selections[0].target != h3Only {
		t.Fatalf("H3-only last resort did not fail open: %+v", selections)
	}
}

func TestHTTP3RuleProbeLeaseLetsCachedH2ServeSiblings(t *testing.T) {
	now := time.Now()
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.connectProxy.now = func() time.Time { return now }
	h2Only := &config.Target{Address: "h2-only.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH2},
	}}
	mixed := &config.Target{Address: "mixed.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	rule := &config.Rule{Name: "heterogeneous-leased", Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5,
		Targets: []*config.Target{h2Only, mixed}}
	now = openHTTP3RuleCooldownForTest(t, runtime.connectProxy, rule.Name, mixed)
	leaseToken, claimed := runtime.connectProxy.claimHTTP3BoostProbe(rule, mixed, now)
	if !claimed || leaseToken&http3RuleRouteProbeTokenMask == 0 {
		t.Fatalf("exclusive mixed probation lease = token:%d claimed:%t", leaseToken, claimed)
	}
	defer runtime.connectProxy.releaseHTTP3BoostProbe(rule, mixed, leaseToken)

	key := boostRuleKey(rule)
	runtime.storeBoostWinner(key, h2Only.Address)
	if entry, ok := runtime.loadUsableBoostWinnerToken(key, rule, now); !ok || entry.addr != h2Only.Address {
		t.Fatalf("cached H2 sibling was displaced while canary lease was held: entry=%+v ok=%t", entry, ok)
	}
	if duplicate, duplicateClaimed := runtime.connectProxy.claimHTTP3BoostProbe(rule, mixed, now); duplicateClaimed || duplicate != 0 {
		t.Fatalf("second probation lease = token:%d claimed:%t", duplicate, duplicateClaimed)
	}
}

func TestRouteSelectionRefreshesProtocolPenaltyAfterLostProbeRace(t *testing.T) {
	now := time.Now()
	safe := &config.Target{Address: "safe-h2.example:443"}
	h3Only := &config.Target{Address: "h3-only.example:443"}
	rule := &config.Rule{Name: "probe-snapshot-race", Mode: config.ModeBoost,
		Targets: []*config.Target{safe, h3Only}}
	leaseClaimedElsewhere := false
	registry := newRouteHealthRegistry(func(_ *config.Rule, target *config.Target, _ time.Time) time.Duration {
		if !leaseClaimedElsewhere {
			return http3DegradationPenaltyBase
		}
		if target == safe {
			return 0
		}
		return http3DegradationPenaltyBase
	})
	registry.protocolProbeClaim = func(*config.Rule, *config.Target, time.Time) (uint64, bool) {
		// Simulate another request winning the rule-level lease after this
		// selector captured its first all-penalized snapshot.
		leaseClaimedElsewhere = true
		return 0, false
	}

	selections := registry.selectTargetSelections(rule, 2, now, nil, true)
	if len(selections) != 1 || selections[0].target != safe {
		t.Fatalf("stale penalty snapshot admitted H3-only sibling: %+v", selections)
	}
}

func openHTTP3RuleCooldownForTest(
	t *testing.T,
	manager *connectProxyManager,
	rule string,
	mixed *config.Target,
) time.Time {
	t.Helper()
	now := manager.timeNow()
	key := http3ConnectTransportKey{address: mixed.Address, serverName: mixed.ConnectProxy.ServerName}
	manager.registerHTTP3RuleTarget(rule, mixed)
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.88", generationID: 72, at: now,
	})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.88", generationID: 73, at: now.Add(time.Second),
	})
	validateHTTP3RuleFallbackForTest(t, manager.h3RuleBreaker, rule, key, true)
	manager.h3RuleBreaker.mu.Lock()
	retryAt := manager.h3RuleBreaker.rules[rule].retryAt
	manager.h3RuleBreaker.mu.Unlock()
	return retryAt
}

func validateHTTP3RuleFallbackForTest(
	t *testing.T,
	breaker *http3RuleBreaker,
	rule string,
	key http3ConnectTransportKey,
	reachable bool,
) {
	t.Helper()
	token, probation, allowed := breaker.begin(rule, key)
	if token == 0 || probation || allowed {
		t.Fatalf("H2 validation admission = token:%d probation:%t allowed:%t", token, probation, allowed)
	}
	breaker.observeValidation(rule, token, nil, reachable)
}

type http3RuleBreakerTestConn struct {
	binding   http3RuleProbationBinding
	closeOnce sync.Once
}

func (conn *http3RuleBreakerTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (conn *http3RuleBreakerTestConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (conn *http3RuleBreakerTestConn) Close() error {
	conn.closeOnce.Do(func() {})
	return nil
}
func (conn *http3RuleBreakerTestConn) LocalAddr() net.Addr {
	return tunnelAddr{network: "test", value: "local"}
}
func (conn *http3RuleBreakerTestConn) RemoteAddr() net.Addr {
	return tunnelAddr{network: "test", value: "remote"}
}
func (conn *http3RuleBreakerTestConn) SetDeadline(time.Time) error      { return nil }
func (conn *http3RuleBreakerTestConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *http3RuleBreakerTestConn) SetWriteDeadline(time.Time) error { return nil }
func (conn *http3RuleBreakerTestConn) http3RuleProbationBinding() (http3RuleProbationBinding, bool) {
	return conn.binding, conn.binding.generationID != 0
}
