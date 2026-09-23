package controller

import (
	"context"
	"fmt"
	"moto/config"
	"net"
	"sync"
	"testing"
	"time"
)

func learningPolicyRuntime(t *testing.T, protocols ...string) (*routingRuntime, *config.Rule) {
	t.Helper()
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	rule := &config.Rule{Name: t.Name(), Listen: "127.0.0.1:19006", Protocol: config.ProtocolHTTP, Mode: config.ModeBoost, Timeout: 2000}
	for _, name := range []string{"2", "21", "31", "41"} {
		rule.Targets = append(rule.Targets, &config.Target{Address: "route-" + name + ".example:443",
			ConnectProxy: &config.ConnectProxyConfig{Protocols: append([]string(nil), protocols...)}})
	}
	return runtime, rule
}

func learningPolicyFeed(runtime *routingRuntime, rule *config.Rule, start time.Time, windows int, protocol string, latencies []time.Duration) time.Time {
	for offset := 0; offset < windows; offset++ {
		at := start.Add(time.Duration(offset) * routeLearningWindow)
		for index, latency := range latencies {
			runtime.learning.observeSetup(routeLearningKey{boostRuleKey(rule), rule.Targets[index].Address, protocol}, latency, nil, at)
		}
	}
	return start.Add(time.Duration(windows-1) * routeLearningWindow)
}

func learningPolicyOrdinaryChoice(runtime *routingRuntime, rule *config.Rule, now time.Time) routeLearningChoice {
	choice := runtime.chooseLearningRoute(rule, now)
	if choice.reason == "explore" {
		// The independent exploration owner does not replace the ordinary route
		// seen by a concurrent request at exactly the same simulated instant.
		runtime.releaseLearningChoice(rule, choice)
		return runtime.chooseLearningRoute(rule, now)
	}
	return choice
}

func TestRouteLearningPolicyFourRouteQualityReversal(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	start := time.Unix(1700000000, 0)
	for phase, expected := range rule.Targets {
		latencies := []time.Duration{700 * time.Millisecond, 700 * time.Millisecond, 700 * time.Millisecond, 700 * time.Millisecond}
		latencies[phase] = 25 * time.Millisecond
		at := learningPolicyFeed(runtime, rule, start.Add(time.Duration(phase*20)*time.Second), 20, config.ConnectProxyH2, latencies)
		choice := learningPolicyOrdinaryChoice(runtime, rule, at)
		if choice.address != expected.Address || choice.reason != "quality" || choice.protocol != config.ConnectProxyH2 {
			t.Fatalf("quality reversal phase %d = %+v, want %s/h2", phase, choice, expected.Address)
		}
	}
}

func TestRouteLearningPolicyCacheHitExploresTailAndReleaseDoesNotRefillInterval(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	start := time.Unix(1700000000, 0)
	learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, config.ConnectProxyH2, []time.Duration{50 * time.Millisecond})
	key := boostRuleKey(rule)
	cached := runtime.storeBoostWinner(key, rule.Targets[0].Address)
	runtime.chooseLearningRoute(rule, start)
	for index := 1; index < len(rule.Targets); index++ {
		now := start.Add(time.Duration(index) * routeLearningExploreInterval)
		choice := runtime.chooseLearningRoute(rule, now)
		if choice.reason != "explore" || choice.token == 0 || choice.address != rule.Targets[index].Address {
			t.Fatalf("exploration %d = %+v, want tail target %s", index, choice, rule.Targets[index].Address)
		}
		runtime.releaseLearningChoice(rule, choice)
		if repeated := runtime.chooseLearningRoute(rule, now); repeated.reason == "explore" || repeated.token != 0 {
			t.Fatalf("release refilled the same interval: %+v", repeated)
		}
		entry, ok := runtime.loadBoostWinnerToken(key)
		if !ok || entry.addr != cached.addr || entry.generation != cached.generation {
			t.Fatalf("exploration touched existing winner: %+v, %t", entry, ok)
		}
	}
}

func TestRouteLearningPolicyConcurrentExplorationHasOneLease(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	start := time.Unix(1700000000, 0)
	runtime.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
	runtime.chooseLearningRoute(rule, start)
	now := start.Add(routeLearningExploreInterval)
	choices := make(chan routeLearningChoice, 64)
	var workers sync.WaitGroup
	for index := 0; index < cap(choices); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			choices <- runtime.chooseLearningRoute(rule, now)
		}()
	}
	workers.Wait()
	close(choices)
	var owner routeLearningChoice
	count := 0
	for choice := range choices {
		if choice.reason == "explore" {
			owner = choice
			count++
		}
	}
	if count != 1 || owner.token == 0 {
		t.Fatalf("concurrent owners = %d, owner=%+v", count, owner)
	}
	wrong := owner
	wrong.token++
	runtime.releaseLearningChoice(rule, wrong)
	runtime.learningPolicy.mu.Lock()
	retained := runtime.learningPolicy.rules[boostRuleKey(rule)].exploreToken
	runtime.learningPolicy.mu.Unlock()
	if retained != owner.token {
		t.Fatal("stale release revoked another request's exploration lease")
	}
	runtime.releaseLearningChoice(rule, owner)
	if choice := runtime.chooseLearningRoute(rule, now.Add(time.Second)); choice.reason == "explore" {
		t.Fatalf("completed lease bypassed 30-second budget: %+v", choice)
	}
}

func TestRouteLearningPolicySmallAdvantageAndHoldPreventFlapping(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	rule.Targets = rule.Targets[:2]
	start := time.Unix(1700000000, 0)
	at := learningPolicyFeed(runtime, rule, start, 3, config.ConnectProxyH2, []time.Duration{100 * time.Millisecond, 110 * time.Millisecond})
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[0].Address {
		t.Fatalf("initial choice = %+v", choice)
	}
	at = learningPolicyFeed(runtime, rule, start.Add(3*time.Second), 6, config.ConnectProxyH2, []time.Duration{100 * time.Millisecond, 20 * time.Millisecond})
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[0].Address {
		t.Fatalf("large but unconfirmed-in-time advantage ignored hold: %+v", choice)
	}
	// In a fresh runtime, a small advantage must not switch even after hold.
	other, otherRule := learningPolicyRuntime(t, config.ConnectProxyH2)
	otherRule.Targets = otherRule.Targets[:2]
	at = learningPolicyFeed(other, otherRule, start, 3, config.ConnectProxyH2, []time.Duration{100 * time.Millisecond, 110 * time.Millisecond})
	other.chooseLearningRoute(otherRule, at)
	at = learningPolicyFeed(other, otherRule, start.Add(3*time.Second), 22, config.ConnectProxyH2, []time.Duration{100 * time.Millisecond, 90 * time.Millisecond})
	if choice := other.chooseLearningRoute(otherRule, at); choice.address != otherRule.Targets[0].Address {
		t.Fatalf("10ms advantage caused route flapping: %+v", choice)
	}
}

func TestRouteLearningPolicyConfirmedDegradationBypassesHold(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	rule.Targets = rule.Targets[:2]
	start := time.Unix(1700000000, 0)
	at := learningPolicyFeed(runtime, rule, start, 3, config.ConnectProxyH2, []time.Duration{50 * time.Millisecond, 80 * time.Millisecond})
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[0].Address {
		t.Fatalf("initial choice = %+v", choice)
	}
	at = at.Add(time.Second)
	runtime.learning.observeDegradation(rule.Targets[0].Address, config.ConnectProxyH2, at)
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[1].Address {
		t.Fatalf("confirmed physical degradation retained bad route during hold: %+v", choice)
	}
}

func TestRouteLearningPolicyAgedConfidenceDoesNotHideFreshPhysicalDegradation(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	rule.Targets = rule.Targets[:2]
	start := time.Unix(1700000000, 0)
	at := learningPolicyFeed(runtime, rule, start, 3, config.ConnectProxyH2, []time.Duration{50 * time.Millisecond, 80 * time.Millisecond})
	runtime.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
	runtime.chooseLearningRoute(rule, at)
	// A reused physical connection can carry traffic without new setup samples.
	// Its confidence may age while an alternative receives fresh observations.
	at = start.Add(routeLearningHalfLife + 10*time.Second)
	for offset := 0; offset < 4; offset++ {
		runtime.learning.observeSetup(routeLearningKey{boostRuleKey(rule), rule.Targets[1].Address, config.ConnectProxyH2},
			80*time.Millisecond, nil, at.Add(time.Duration(offset)*time.Second))
	}
	at = at.Add(3 * time.Second)
	runtime.learning.observeDegradation(rule.Targets[0].Address, config.ConnectProxyH2, at)
	if choice := learningPolicyOrdinaryChoice(runtime, rule, at); choice.address != rule.Targets[1].Address || choice.reason != "quality" {
		t.Fatalf("fresh physical failure hidden by aged confidence: %+v", choice)
	}
}

func TestRouteLearningPolicyH3DegradationDoesNotContaminateH2CooldownChoice(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH3, config.ConnectProxyH2)
	rule.Targets = rule.Targets[:2]
	start := time.Unix(1700000000, 0)
	learningPolicyFeed(runtime, rule, start, 4, config.ConnectProxyH3, []time.Duration{30 * time.Millisecond, 200 * time.Millisecond})
	at := learningPolicyFeed(runtime, rule, start, 4, config.ConnectProxyH2, []time.Duration{40 * time.Millisecond, 250 * time.Millisecond})
	target := rule.Targets[0]
	h2Key := routeLearningKey{boostRuleKey(rule), target.Address, config.ConnectProxyH2}
	before := runtime.learning.estimate(h2Key, at)
	runtime.learning.observeDegradation(target.Address, config.ConnectProxyH3, at)
	if after := runtime.learning.estimate(h2Key, at); after != before {
		t.Fatalf("H3 event damaged H2: before=%+v after=%+v", before, after)
	}
	transportKey := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	runtime.connectProxy.h3FallbackMu.Lock()
	runtime.connectProxy.h3Fallback[transportKey] = &http3FallbackState{failures: 1, retryAt: at.Add(time.Minute), degradationActive: true}
	runtime.connectProxy.h3FallbackMu.Unlock()
	if protocol := runtime.learningProtocol(rule, target, at); protocol != config.ConnectProxyH2 {
		t.Fatalf("cooldown protocol = %s, want h2", protocol)
	}
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != target.Address || choice.protocol != config.ConnectProxyH2 {
		t.Fatalf("healthy fallback excluded or H3 penalty leaked: %+v", choice)
	}
}

func TestRouteLearningPolicyRuleCooldownUsesH2AndRecoveryKeepsOwnership(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH3, config.ConnectProxyH2)
	rule.Targets = rule.Targets[:2]
	start := time.Unix(1700000000, 0)
	learningPolicyFeed(runtime, rule, start, 4, config.ConnectProxyH3, []time.Duration{30 * time.Millisecond, 200 * time.Millisecond})
	at := learningPolicyFeed(runtime, rule, start, 4, config.ConnectProxyH2, []time.Duration{250 * time.Millisecond, 40 * time.Millisecond})
	breaker := runtime.connectProxy.h3RuleBreaker
	breaker.mu.Lock()
	breaker.rules[rule.Name] = &http3RuleBreakerState{phase: http3RuleBreakerCooldown, retryAt: at.Add(time.Minute)}
	breaker.mu.Unlock()
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[1].Address || choice.protocol != config.ConnectProxyH2 {
		t.Fatalf("rule cooldown did not rank actual H2 path: %+v", choice)
	}
	if choice := runtime.chooseLearningRoute(rule, at.Add(time.Minute)); choice != (routeLearningChoice{}) {
		t.Fatalf("learning preempted due H3 recovery ownership: %+v", choice)
	}
}

func TestRouteLearningPolicyNeutralHTTPResponsesPreserveWinnerAndEvidence(t *testing.T) {
	for _, status := range []int{403, 503} {
		for _, fallbackSuccess := range []bool{false, true} {
			t.Run(fmt.Sprintf("status_%d_fallback_%t", status, fallbackSuccess), func(t *testing.T) {
				runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
				rule.Targets = rule.Targets[:2]
				key := boostRuleKey(rule)
				cached := runtime.storeBoostWinner(key, rule.Targets[0].Address)
				at := learningPolicyFeed(runtime, rule, time.Unix(1700000000, 0), 3, config.ConnectProxyH2, []time.Duration{50 * time.Millisecond, 100 * time.Millisecond})
				choice := runtime.chooseLearningRoute(rule, at)
				learningKey := routeLearningKey{key, cached.addr, config.ConnectProxyH2}
				before := runtime.learning.estimate(learningKey, at)
				ctx := withRouteLearningScope(context.Background(), runtime.learning, rule)
				winner, peer := net.Pipe()
				t.Cleanup(func() { winner.Close(); peer.Close() })
				outcome, err := runtime.raceCachedBoostTargetWithDial(ctx, rule, cached.addr,
					func(ctx context.Context, _ *config.Rule, address string, _ boostRouteDialOptions) (net.Conn, routeAttempt, error) {
						if fallbackSuccess && address != cached.addr {
							return winner, routeAttempt{}, nil
						}
						failure := &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: status}
						observeRouteLearningSetup(ctx, &config.Target{Address: address, ConnectProxy: &config.ConnectProxyConfig{}}, config.ConnectProxyH2, time.Second, failure, at.Add(time.Second))
						return nil, routeAttempt{}, failure
					}, nil, 0, nil)
				if (err == nil) != fallbackSuccess {
					t.Fatalf("unexpected outcome=%+v error=%v", outcome, err)
				}
				runtime.reconcileLearningBoostWinner(key, cached, choice, outcome, err == nil)
				entry, ok := runtime.loadBoostWinnerToken(key)
				if !ok || entry.addr != cached.addr || entry.generation != cached.generation {
					t.Fatalf("HTTP %d changed global cache: %+v %t", status, entry, ok)
				}
				if after := runtime.learning.estimate(learningKey, at); after != before {
					t.Fatalf("HTTP %d changed learning evidence: before=%+v after=%+v", status, before, after)
				}
			})
		}
	}
}

func TestRouteLearningPolicyExplorationCannotReplaceOrDeleteGlobalWinner(t *testing.T) {
	for _, succeeded := range []bool{false, true} {
		t.Run(fmt.Sprint(succeeded), func(t *testing.T) {
			runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
			key := boostRuleKey(rule)
			cached := runtime.storeBoostWinner(key, rule.Targets[0].Address)
			choice := routeLearningChoice{address: rule.Targets[3].Address, protocol: config.ConnectProxyH2, reason: "explore", token: 1}
			outcome := cachedBoostOutcome{winner: dialResult{addr: choice.address}, cachedFailed: !succeeded}
			hit, token := runtime.reconcileLearningBoostWinner(key, cached, choice, outcome, succeeded)
			if hit || token.generation != 0 {
				t.Fatalf("exploration returned global relay ownership: hit=%t token=%+v", hit, token)
			}
			entry, ok := runtime.loadBoostWinnerToken(key)
			if !ok || entry.addr != cached.addr || entry.generation != cached.generation {
				t.Fatalf("exploration changed global winner: %+v %t", entry, ok)
			}
		})
	}
}

func TestRouteLearningPolicyReloadInheritsEvidenceNotExplorationLease(t *testing.T) {
	previous, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	next := newRoutingRuntime()
	t.Cleanup(next.stopBackground)
	start := time.Unix(1700000000, 0)
	at := learningPolicyFeed(previous, rule, start, 4, config.ConnectProxyH2,
		[]time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 150 * time.Millisecond, 200 * time.Millisecond})
	previous.chooseLearningRoute(rule, at)
	at = at.Add(routeLearningExploreInterval)
	owner := previous.chooseLearningRoute(rule, at)
	if owner.reason != "explore" || owner.token == 0 {
		t.Fatalf("missing original exploration lease: %+v", owner)
	}
	clone := *rule
	clone.Targets = append([]*config.Target(nil), rule.Targets...)
	next.inheritUnchangedState(previous, []*config.Rule{rule}, []*config.Rule{&clone})
	key := routeLearningKey{boostRuleKey(rule), rule.Targets[0].Address, config.ConnectProxyH2}
	if next.learning.estimate(key, at) != previous.learning.estimate(key, at) {
		t.Fatal("unchanged reload discarded learned evidence")
	}
	if next.learning == previous.learning || next.learningPolicy == previous.learningPolicy {
		t.Fatal("reload shares mutable learning ownership")
	}
	choice := next.chooseLearningRoute(&clone, at)
	if choice.token != 0 || choice.reason == "explore" {
		t.Fatalf("reload inherited in-flight exploration: %+v", choice)
	}
	previous.releaseLearningChoice(rule, owner)
	if later := next.chooseLearningRoute(&clone, at.Add(routeLearningExploreInterval)); later.reason != "explore" || later.token == 0 {
		t.Fatalf("old lease release suppressed new runtime exploration: %+v", later)
	}
}

func TestRouteLearningPolicyPureTCPUnaffected(t *testing.T) {
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH2)
	rule.Protocol = config.ProtocolTCP
	for _, target := range rule.Targets {
		target.ConnectProxy = nil
	}
	start := time.Unix(1700000000, 0)
	learningPolicyFeed(runtime, rule, start, 5, config.ConnectProxyH2,
		[]time.Duration{500 * time.Millisecond, 400 * time.Millisecond, 300 * time.Millisecond, 10 * time.Millisecond})
	key := boostRuleKey(rule)
	cached := runtime.storeBoostWinner(key, rule.Targets[0].Address)
	for _, offset := range []time.Duration{5 * time.Second, time.Minute, time.Hour} {
		if choice := runtime.chooseLearningRoute(rule, start.Add(offset)); choice != (routeLearningChoice{}) {
			t.Fatalf("TCP rule entered learning: %+v", choice)
		}
	}
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != cached.addr || entry.generation != cached.generation || len(runtime.learningPolicy.rules) != 0 {
		t.Fatal("TCP cache/policy mutated")
	}
}
