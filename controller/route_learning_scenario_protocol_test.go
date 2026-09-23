package controller

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The protocol dialers below supply controlled outcomes, while production
// manager hooks, fallback state, selection, and cache reconciliation all run.
// These scenarios advance event time, not wall time, and never contact a proxy.
func TestRouteLearningScenarioConfirmationHTTPStatusAndProtocolFallback(t *testing.T) {
	for _, status := range []int{403, 503} {
		for _, transportFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("status_%d_transport_failure_%t", status, transportFailure), func(t *testing.T) {
				runtime, rule, start := learningScalingRuntime(t, 8, config.ConnectProxyH3, config.ConnectProxyH2)
				key := boostRuleKey(rule)
				cached, _ := runtime.loadBoostWinnerToken(key)
				firstAt := start.Add(routeLearningExploreInterval)
				first := runtime.chooseLearningRoute(rule, firstAt)
				learningScalingCompleteProbe(t, runtime, rule, first, firstAt, 10*time.Millisecond, nil)
				now := firstAt.Add(routeLearningExploreInterval)
				confirmation := runtime.chooseLearningRoute(rule, now)
				if confirmation.address != first.address || confirmation.reason != "explore" {
					t.Fatalf("promising alternative did not receive confirmation: %+v", confirmation)
				}
				target := targetByAddress(rule, confirmation.address)
				h3Key := routeLearningKey{key, target.Address, config.ConnectProxyH3}
				h2Key := routeLearningKey{key, target.Address, config.ConnectProxyH2}
				h3Before := learningObserverState(runtime.learning, h3Key)
				h2Before := learningObserverState(runtime.learning, h2Key)
				var clock atomic.Int64
				clock.Store(now.Add(time.Second).UnixNano())
				runtime.connectProxy.now = func() time.Time { return time.Unix(0, clock.Load()) }
				var h3Calls, h2Calls atomic.Int32
				runtime.connectProxy.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
					h3Calls.Add(1)
					if transportFailure {
						return nil, errors.New("independent QUIC transport failure")
					}
					return nil, &connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: status}
				}
				runtime.connectProxy.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
					h2Calls.Add(1)
					return nil, &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: status}
				}
				ctx := withRouteLearningScope(context.Background(), runtime.learning, rule)
				ctx = context.WithValue(ctx, routeLearningExplorerContextKey{}, true)
				outcome, err := runtime.raceCachedBoostTargetWithDial(ctx, rule, target.Address,
					func(ctx context.Context, _ *config.Rule, address string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
						if options.onStart != nil {
							options.onStart()
						}
						if address == target.Address {
							connection, failure := runtime.connectProxy.dialForRule(ctx, rule.Name, target, "destination.example:443")
							return connection, routeAttempt{}, failure
						}
						return &http3RuleBreakerTestConn{}, routeAttempt{}, nil
					}, nil, learningExplorationHedgeDelay(rule), make(chan time.Time))
				if err != nil || outcome.winner.addr == target.Address || !outcome.cachedFailureNeutral {
					t.Fatalf("destination rejection lost target fallback semantics: outcome=%+v error=%v", outcome, err)
				}
				_ = outcome.winner.conn.Close()
				runtime.reconcileLearningBoostWinner(key, boostWinnerToken{key: key, addr: cached.addr, generation: cached.generation}, confirmation, outcome, true)
				runtime.releaseLearningChoice(rule, confirmation)
				if h3Calls.Load() != 1 || h2Calls.Load() != map[bool]int32{false: 0, true: 1}[transportFailure] {
					t.Fatalf("protocol attempts h3=%d h2=%d", h3Calls.Load(), h2Calls.Load())
				}
				if after := learningObserverState(runtime.learning, h2Key); after != h2Before {
					t.Fatalf("HTTP status fabricated H2 learning evidence: before=%+v after=%+v", h2Before, after)
				}
				h3After := learningObserverState(runtime.learning, h3Key)
				if !transportFailure && h3After != h3Before {
					t.Fatal("H3 HTTP status contaminated transport learning")
				}
				if transportFailure && !h3After.lastFailure.After(h3Before.lastFailure) {
					t.Fatal("real H3 transport failure was hidden by neutral H2 response")
				}
				wantProtocol := config.ConnectProxyH3
				if transportFailure {
					wantProtocol = config.ConnectProxyH2
				}
				if got := runtime.learningProtocol(rule, target, now.Add(2*time.Second)); got != wantProtocol {
					t.Fatalf("post-response protocol = %s, want %s", got, wantProtocol)
				}
				if entry, ok := runtime.loadBoostWinnerToken(key); !ok || entry != cached {
					t.Fatalf("confirmation rejection changed global winner: %+v, %t", entry, ok)
				}
				if next := runtime.chooseLearningRoute(rule, now.Add(routeLearningExploreInterval)); next.reason != "explore" || next.address != rule.Targets[2].Address {
					t.Fatalf("non-successful confirmation monopolized the next exploration: %+v", next)
				}
			})
		}
	}
}

func TestRouteLearningScenarioRuleCooldownProbationAndLearnedProtocol(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH3, config.ConnectProxyH2)
	start := time.Unix(1700000000, 0)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	manager := runtime.connectProxy
	manager.now = func() time.Time { return time.Unix(0, clock.Load()) }
	for _, target := range rule.Targets {
		manager.registerHTTP3RuleTarget(rule.Name, target)
	}
	learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, config.ConnectProxyH3,
		[]time.Duration{10 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond})
	learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, config.ConnectProxyH2,
		[]time.Duration{300 * time.Millisecond, 20 * time.Millisecond, 400 * time.Millisecond, 500 * time.Millisecond})
	runtime.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
	if choice := runtime.chooseLearningRoute(rule, start); choice.address != rule.Targets[0].Address || choice.protocol != config.ConnectProxyH3 {
		t.Fatalf("initial H3 preference = %+v", choice)
	}
	for index := range 2 {
		at := start.Add(time.Duration(index) * time.Second)
		clock.Store(at.UnixNano())
		manager.h3.onConnectionDegraded(http3RuleDegradationEvent{
			key: http3ConnectTransportKey{address: rule.Targets[index].Address}, remoteIP: fmt.Sprintf("192.0.2.%d", index+1),
			generationID: uint64(index + 1), at: at, reason: http3DegradationReasonSustainedSignals,
		})
	}
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return &http3RuleBreakerTestConn{}, nil
	}
	manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return nil, errors.New("H3 must be skipped during fallback validation")
	}
	ctx := withRouteLearningScope(context.Background(), runtime.learning, rule)
	connection, err := manager.dialForRule(ctx, rule.Name, rule.Targets[1], "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	breaker := manager.h3RuleBreaker
	breaker.mu.Lock()
	phase, retryAt := breaker.rules[rule.Name].phase, breaker.rules[rule.Name].retryAt
	breaker.mu.Unlock()
	if phase != http3RuleBreakerCooldown || retryAt.IsZero() {
		t.Fatalf("real H2 validation did not activate cooldown: phase=%v retry=%v", phase, retryAt)
	}
	// Protocol cooldown takes effect immediately, but a healthy H2 incumbent
	// still receives the ordinary preference hold before changing endpoints.
	if got := runtime.learningProtocol(rule, rule.Targets[0], start.Add(2*time.Second)); got != config.ConnectProxyH2 {
		t.Fatalf("cooldown left the cached endpoint on %s", got)
	}
	if choice := runtime.chooseLearningRoute(rule, start.Add(routeLearningPreferenceHold+time.Second)); choice.address != rule.Targets[1].Address || choice.protocol != config.ConnectProxyH2 {
		t.Fatalf("cooldown retained H3's learned winner instead of best H2: %+v", choice)
	}
	// Ordinary H2 traffic continues during cooldown; H3 evidence is not
	// refreshed merely because the same endpoint successfully speaks H2.
	h3Before := learningObserverState(runtime.learning, routeLearningKey{boostRuleKey(rule), rule.Targets[1].Address, config.ConnectProxyH3})
	learningPolicyFeed(runtime, rule, retryAt.Add(-3*time.Second), 3, config.ConnectProxyH2,
		[]time.Duration{300 * time.Millisecond, 20 * time.Millisecond, 400 * time.Millisecond, 500 * time.Millisecond})
	clock.Store(retryAt.UnixNano())
	if choice := runtime.chooseLearningRoute(rule, retryAt); choice != (routeLearningChoice{}) {
		t.Fatalf("cached learning preference preempted due rule recovery: %+v", choice)
	}
	selections := runtime.routes.selectTargetSelections(rule, len(rule.Targets), retryAt, nil, true)
	if len(selections) == 0 || selections[0].protocolProbe.token == 0 {
		t.Fatalf("recovery selection did not reserve an exclusive canary: %+v", selections)
	}
	for _, sibling := range selections[1:] {
		if sibling.protocolProbe.token != 0 {
			t.Fatalf("selector allocated multiple probation owners: %+v", selections)
		}
	}
	selected := selections[0]
	t.Cleanup(func() { runtime.routes.releaseProtocolProbe(rule, selected.target, selected.protocolProbe) })
	binding := http3RuleProbationBinding{generationID: 3, remoteIP: "192.0.2.3", stats: quic.ConnectionStats{PacketsSent: 100}, payloadBytes: 1000}
	manager.dialers[config.ConnectProxyH3] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		if !http3RuleProbationFromContext(ctx) {
			return nil, errors.New("recovery bypassed rule probation")
		}
		return &http3RuleBreakerTestConn{binding: binding}, nil
	}
	probe, err := manager.dialForRule(withRouteProtocolProbeLease(ctx, selected.protocolProbe), rule.Name, selected.target, "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if got := runtime.learningProtocol(rule, rule.Targets[1], retryAt); got != config.ConnectProxyH2 {
		t.Fatalf("a successful probe CONNECT prematurely reopened ordinary %s", got)
	}
	for _, target := range rule.Targets {
		if _, _, allowed := manager.beginHTTP3RuleAttempt(context.Background(), rule.Name, target); allowed {
			t.Fatalf("ordinary sibling bypassed the active probation: %s", target.Address)
		}
	}
	for _, elapsed := range []time.Duration{26 * time.Second, 28 * time.Second, 30 * time.Second} {
		at := retryAt.Add(elapsed)
		clock.Store(at.UnixNano())
		manager.h3.onConnectionSample(http3RuleSampleEvent{
			key: http3ConnectTransportKey{address: selected.target.Address}, generationID: binding.generationID, remoteIP: binding.remoteIP,
			at: at, stats: quic.ConnectionStats{PacketsSent: binding.stats.PacketsSent + http3RuleProbationMinPackets},
			payloadBytes: binding.payloadBytes + http3RuleProbationMinPayload,
			decision:     http3DegradationDecision{Signals: http3DegradationSignals{Sampled: true}},
		})
		want := config.ConnectProxyH2
		if elapsed == 30*time.Second {
			want = config.ConnectProxyH3
		}
		if got := runtime.learningProtocol(rule, rule.Targets[1], at); got != want {
			t.Fatalf("at probation %s ordinary protocol = %s, want %s", elapsed, got, want)
		}
	}
	if selected.target.Address != rule.Targets[1].Address {
		if after := learningObserverState(runtime.learning, routeLearningKey{boostRuleKey(rule), rule.Targets[1].Address, config.ConnectProxyH3}); after != h3Before {
			t.Fatal("another endpoint's probation manufactured H3 observations for the H2 winner")
		}
	}
	for _, target := range rule.Targets {
		if state := runtime.routes.snapshot(rule, target.Address, retryAt.Add(30*time.Second)); state.CircuitOpen || state.ConsecutiveFailures != 0 {
			t.Fatalf("protocol-only degradation contaminated target-wide circuit: %+v", state)
		}
	}
}

func TestRouteLearningScenarioConfirmationCannotCancelCircuitRecovery(t *testing.T) {
	for _, status := range []int{403, 503} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
			now := time.Now()
			start := now.Add(-2 * routeLearningExploreInterval)
			key := boostRuleKey(rule)
			learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, config.ConnectProxyH2, []time.Duration{500 * time.Millisecond})
			original := runtime.storeBoostWinner(key, rule.Targets[0].Address)
			runtime.chooseLearningRoute(rule, start)
			firstAt := start.Add(routeLearningExploreInterval)
			first := runtime.chooseLearningRoute(rule, firstAt)
			if first.address != rule.Targets[1].Address || first.reason != "explore" {
				t.Fatalf("first alternative = %+v", first)
			}
			learningScalingCompleteProbe(t, runtime, rule, first, firstAt, 10*time.Millisecond, nil)
			recovering := rule.Targets[2]
			recoveringKey := routeLearningKey{key, recovering.Address, config.ConnectProxyH2}
			for offset := range 3 {
				runtime.learning.observeSetup(recoveringKey, 700*time.Millisecond, nil, start.Add(time.Duration(offset)*time.Second))
			}
			before := learningObserverState(runtime.learning, recoveringKey)
			tripRouteInRegistry(t, runtime.routes, rule, recovering.Address, now.Add(-routeInitialCooldown-time.Second))
			recovery := runtime.claimBoostRecoveryProbe(rule, now)
			t.Cleanup(func() { runtime.releaseBoostRecoveryProbe(rule, recovery) })
			if recovery.token == 0 || recovery.address != recovering.Address {
				t.Fatalf("due target did not acquire recovery ownership: %+v", recovery)
			}
			started, finish := make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			runtime.connectProxy.dialers[config.ConnectProxyH2] = func(ctx context.Context, target *config.Target, _ string) (net.Conn, error) {
				if target.Address == first.address && routeLearningExplorer(ctx) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if target.Address != recovering.Address {
					return &http3RuleBreakerTestConn{}, nil
				}
				close(started)
				select {
				case <-finish:
					return nil, &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: status}
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			type result struct {
				winner dialResult
				err    error
			}
			completed := make(chan result, 1)
			scope := withRouteLearningScope(ctx, runtime.learning, rule)
			go func() {
				winner, err := runtime.raceBoostTargetsPreparedWithRecovery(scope, rule,
					func(ctx context.Context, address string) (net.Conn, error) {
						return runtime.connectProxy.dialForRule(ctx, rule.Name, targetByAddress(rule, address), "destination.example:443")
					}, nil, recovery)
				completed <- result{winner: winner, err: err}
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("reserved recovery never started")
			}
			if duplicate := runtime.claimBoostRecoveryProbe(rule, now); duplicate.token != 0 {
				runtime.releaseBoostRecoveryProbe(rule, duplicate)
				t.Fatalf("sibling acquired duplicate recovery: %+v", duplicate)
			}
			confirmation := runtime.chooseLearningRoute(rule, now)
			if confirmation.reason != "explore" || confirmation.address != first.address {
				t.Fatalf("healthy sibling could not continue its independent confirmation: %+v", confirmation)
			}
			confirmationBefore := learningObserverState(runtime.learning, routeLearningKey{key, first.address, config.ConnectProxyH2})
			explorer := context.WithValue(scope, routeLearningExplorerContextKey{}, true)
			hedgeReady := make(chan time.Time, 1)
			var confirmationStarts, hedgeStarts atomic.Int32
			outcome, err := runtime.raceCachedBoostTargetWithDial(explorer, rule, confirmation.address,
				func(ctx context.Context, _ *config.Rule, address string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
					if !routeLearningExplorer(ctx) || options.onStart == nil {
						return nil, routeAttempt{}, errors.New("learning explorer lost its context/start notification")
					}
					options.onStart()
					if address == confirmation.address {
						confirmationStarts.Add(1)
						hedgeReady <- now // Simulated timer, after the real primary-start callback.
					} else {
						if !options.tryOnly {
							return nil, routeAttempt{}, errors.New("optional learning hedge did not use immediate-only admission")
						}
						hedgeStarts.Add(1)
					}
					connection, err := runtime.connectProxy.dialForRule(ctx, rule.Name, targetByAddress(rule, address), "destination.example:443")
					return connection, routeAttempt{}, err
				}, nil, learningExplorationHedgeDelay(rule), hedgeReady)
			if err != nil || outcome.winner.addr == confirmation.address || outcome.winner.addr == recovering.Address || !outcome.hedged {
				t.Fatalf("independent confirmation hedge failed: outcome=%+v error=%v", outcome, err)
			}
			if confirmationStarts.Load() != 1 || hedgeStarts.Load() != 1 {
				t.Fatalf("explorer attempts primary=%d hedge=%d, want one each", confirmationStarts.Load(), hedgeStarts.Load())
			}
			_ = outcome.winner.conn.Close()
			runtime.reconcileLearningBoostWinner(key, original, confirmation, outcome, true)
			runtime.releaseLearningChoice(rule, confirmation)
			if after := learningObserverState(runtime.learning, routeLearningKey{key, first.address, config.ConnectProxyH2}); after != confirmationBefore {
				t.Fatalf("hedge cancellation became a learned transport failure: before=%+v after=%+v", confirmationBefore, after)
			}
			select {
			case got := <-completed:
				if got.winner.conn != nil {
					_ = got.winner.conn.Close()
				}
				t.Fatalf("confirmation completion canceled/raced the recovery owner: %+v", got)
			default:
			}
			if snapshot := runtime.routes.snapshot(rule, recovering.Address, now); !snapshot.HalfOpen || !snapshot.CircuitOpen {
				t.Fatalf("sibling completion altered half-open ownership: %+v", snapshot)
			}
			close(finish)
			select {
			case got := <-completed:
				if got.err != nil || got.winner.addr == recovering.Address {
					t.Fatalf("neutral recovery status did not permit destination fallback: %+v", got)
				}
				_ = got.winner.conn.Close()
			case <-ctx.Done():
				t.Fatal("recovery failed to finish after release")
			}
			if snapshot := runtime.routes.snapshot(rule, recovering.Address, time.Now()); snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.LastRecovery.IsZero() {
				t.Fatalf("reachable HTTP rejection did not restore the target circuit: %+v", snapshot)
			}
			if after := learningObserverState(runtime.learning, recoveringKey); after != before {
				t.Fatalf("neutral circuit recovery fabricated successful learning: before=%+v after=%+v", before, after)
			}
			if cached, ok := runtime.loadBoostWinnerToken(key); !ok || cached.addr != original.addr || cached.generation != original.generation {
				t.Fatalf("independent learning confirmation rewrote ordinary cache: %+v %t", cached, ok)
			}
		})
	}
}

func TestRouteLearningScenarioIngressRecoveryPrecedesLearning(t *testing.T) {
	var callsA, callsB, callsC atomic.Int32
	a, installA := newLearningIntegrationUpstream(t, config.ConnectProxyH2,
		learningIntegrationHandler(t, config.ConnectProxyH2, "A\n", "", 0, &callsA))
	b, installB := newLearningIntegrationUpstream(t, config.ConnectProxyH2,
		learningIntegrationHandler(t, config.ConnectProxyH2, "B\n", "", 0, &callsB))
	recoveryStarted, recoveryFinish, recoveryCanceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	handlerC := learningIntegrationHandler(t, config.ConnectProxyH2, "C\n", "", 0, &callsC)
	c, installC := newLearningIntegrationUpstream(t, config.ConnectProxyH2, func(writer http.ResponseWriter, request *http.Request) {
		close(recoveryStarted)
		select {
		case <-recoveryFinish:
			handlerC(writer, request)
		case <-request.Context().Done():
			close(recoveryCanceled)
		}
	})
	server, clock := learningIntegrationServer(t, httpConnectIntegrationRule(config.ModeBoost, a, b, c), installA, installB, installC)
	generation := server.current.Load()
	runtime, rule := generation.runtime, generation.rules[0]
	now := time.Now()
	clock.Store(now.UnixNano())
	start := now.Add(-2 * routeLearningExploreInterval)
	key := boostRuleKey(rule)
	learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, config.ConnectProxyH2, []time.Duration{500 * time.Millisecond})
	runtime.storeBoostWinner(key, a.Address)
	runtime.chooseLearningRoute(rule, start)
	firstAt := start.Add(routeLearningExploreInterval)
	first := runtime.chooseLearningRoute(rule, firstAt)
	if first.address != b.Address || first.reason != "explore" {
		t.Fatalf("initial alternative = %+v", first)
	}
	learningScalingCompleteProbe(t, runtime, rule, first, firstAt, 10*time.Millisecond, nil)
	tripRouteInRegistry(t, runtime.routes, rule, c.Address, now.Add(-routeInitialCooldown-time.Second))
	owner := dialHTTPConnectIntegrationClient(t, server)
	writeHTTPConnectIntegrationRequest(t, owner, "destination.example:443")
	select {
	case <-recoveryStarted:
	case <-time.After(3 * time.Second):
		t.Fatalf("ingress did not prioritize target recovery: cached calls=%d learning calls=%d", callsA.Load(), callsB.Load())
	}
	runtime.learningPolicy.mu.Lock()
	explorations := runtime.learningPolicy.rules[key].decisions["explore"]
	lease := runtime.learningPolicy.rules[key].exploreToken
	runtime.learningPolicy.mu.Unlock()
	if explorations != 1 || lease != 0 || callsA.Load() != 0 || callsB.Load() != 0 {
		t.Fatalf("ingress spent learning ownership ahead of recovery: explorations=%d lease=%d A=%d B=%d", explorations, lease, callsA.Load(), callsB.Load())
	}
	if label := learningIntegrationRequest(t, server, clock, "destination.example:443", http.StatusOK); label != "B\n" {
		t.Fatalf("ordinary sibling was blocked by recovery or lost confirmation: %q", label)
	}
	select {
	case <-recoveryCanceled:
		t.Fatal("learning sibling canceled the independent ingress recovery owner")
	default:
	}
	if snapshot := runtime.routes.snapshot(rule, c.Address, time.Now()); !snapshot.CircuitOpen || !snapshot.HalfOpen {
		t.Fatalf("sibling changed recovery ownership before its response: %+v", snapshot)
	}
	close(recoveryFinish)
	reader := bufio.NewReader(owner)
	if response := readHTTPConnectIntegrationResponse(t, reader); response.StatusCode != http.StatusOK {
		t.Fatalf("recovery tunnel returned %s", response.Status)
	}
	const payload = "recovery-owner-payload\n"
	if _, err := io.WriteString(owner, payload); err != nil {
		t.Fatal(err)
	}
	if err := owner.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "C\n"+payload {
		t.Fatalf("recovery stream did not carry its own payload: %q, %v", strings.TrimSpace(string(body)), err)
	}
	if snapshot := runtime.routes.snapshot(rule, c.Address, time.Now()); snapshot.CircuitOpen || snapshot.HalfOpen || snapshot.LastRecovery.IsZero() {
		t.Fatalf("successful ingress recovery did not close circuit: %+v", snapshot)
	}
	if callsA.Load() != 0 || callsB.Load() != 1 || callsC.Load() != 1 {
		t.Fatalf("ingress duplicated/raced recovery: A=%d B=%d C=%d", callsA.Load(), callsB.Load(), callsC.Load())
	}
}
