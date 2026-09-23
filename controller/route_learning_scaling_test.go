package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"sync"
	"testing"
	"time"
)

func learningScalingRuntime(t *testing.T, count int, protocols ...string) (*routingRuntime, *config.Rule, time.Time) {
	t.Helper()
	runtime, rule := learningPolicyRuntime(t, protocols...)
	rule.Targets = nil
	for index := 0; index < count; index++ {
		rule.Targets = append(rule.Targets, &config.Target{
			Address:      fmt.Sprintf("scaling-%03d.example:443", index),
			ConnectProxy: &config.ConnectProxyConfig{Protocols: append([]string(nil), protocols...)},
		})
	}
	start := time.Unix(1700000000, 0)
	learningPolicyFeed(runtime, rule, start.Add(-3*time.Second), 3, protocols[0], []time.Duration{500 * time.Millisecond})
	runtime.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
	if choice := runtime.chooseLearningRoute(rule, start); choice.address != rule.Targets[0].Address || choice.reason != "quality" {
		t.Fatalf("initial primary = %+v", choice)
	}
	return runtime, rule, start
}

func learningScalingCompleteProbe(t *testing.T, runtime *routingRuntime, rule *config.Rule, choice routeLearningChoice, now time.Time, latency time.Duration, err error) {
	t.Helper()
	ordinary := runtime.chooseLearningRoute(rule, now.Add(time.Second))
	if ordinary.reason == "explore" || ordinary.token != 0 {
		t.Fatalf("another request acquired the live explorer's lease: %+v", ordinary)
	}
	// A cold learning result still uses the existing cached path. This keeps
	// the simulation faithful when widely spaced requests age confidence.
	address := ordinary.address
	if address == "" {
		cached, ok := runtime.loadBoostWinnerToken(boostRuleKey(rule))
		if !ok {
			t.Fatal("ordinary request has neither a learned nor a cached route")
		}
		address = cached.addr
	}
	runtime.learning.observeSetup(routeLearningKey{boostRuleKey(rule), address, choice.protocol}, 500*time.Millisecond, nil, now.Add(time.Second))
	runtime.learning.observeSetup(routeLearningKey{boostRuleKey(rule), choice.address, choice.protocol}, latency, err, now.Add(2*time.Second))
	runtime.releaseLearningChoice(rule, choice)
}

func TestRouteLearningScalingFastTailBecomesOrdinaryWinner(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		for _, count := range []int{8, 16, 21, 128} {
			t.Run(fmt.Sprintf("%s_%d", protocol, count), func(t *testing.T) {
				runtime, rule, start := learningScalingRuntime(t, count, protocol)
				key := boostRuleKey(rule)
				fast := rule.Targets[len(rule.Targets)-1].Address
				fastProbes := 0
				latency := func(address string) time.Duration {
					if address == fast {
						return 10 * time.Millisecond
					}
					if address == rule.Targets[0].Address {
						return 500 * time.Millisecond
					}
					return 700 * time.Millisecond
				}
				// Only actual policy choices produce evidence. Ordinary traffic
				// maintains the incumbent while each explorer holds its lease for
				// two seconds; no backup receives synthetic warm-up observations.
				for step := 1; step <= 3*count; step++ {
					now := start.Add(time.Duration(step) * routeLearningExploreInterval)
					probe := runtime.chooseLearningRoute(rule, now)
					if probe.reason != "explore" || probe.token == 0 {
						t.Fatalf("step %d: expected exploration, got %+v", step, probe)
					}
					ordinary := runtime.chooseLearningRoute(rule, now.Add(time.Second))
					if ordinary.reason != "quality" || ordinary.token != 0 {
						t.Fatalf("step %d: lease sibling lost ordinary path: %+v", step, ordinary)
					}
					runtime.learning.observeSetup(routeLearningKey{key, ordinary.address, protocol}, latency(ordinary.address), nil, now.Add(time.Second))
					runtime.learning.observeSetup(routeLearningKey{key, probe.address, protocol}, latency(probe.address), nil, now.Add(2*time.Second))
					if probe.address == fast {
						fastProbes++
					}
					runtime.releaseLearningChoice(rule, probe)
					ordinary = runtime.chooseLearningRoute(rule, now.Add(3*time.Second))
					if ordinary.reason == "quality" && ordinary.address == fast {
						if fastProbes != 3 {
							t.Fatalf("fast tail needed %d probes, want three independent observations", fastProbes)
						}
						return
					}
					if ordinary.reason != "quality" || ordinary.token != 0 {
						t.Fatalf("step %d: probe release refilled the 30-second budget: %+v", step, ordinary)
					}
					runtime.learning.observeSetup(routeLearningKey{key, ordinary.address, protocol}, latency(ordinary.address), nil, now.Add(3*time.Second))
				}
				estimate := runtime.learning.estimate(routeLearningKey{key, fast, protocol}, start.Add(time.Duration(3*count)*routeLearningExploreInterval))
				t.Fatalf("%d-target fast tail never became an ordinary winner after %d probes: %+v", count, fastProbes, estimate)
			})
		}
	}
}

func TestRouteLearningScalingConfirmationIsBoundedAndReturnsToFairRotation(t *testing.T) {
	runtime, rule, start := learningScalingRuntime(t, 8, config.ConnectProxyH2)
	for index, want := range []int{1, 1, 1, 2, 3} {
		// After ninety seconds even the third successful sample has decayed
		// below Known. Ending confirmation must therefore come from its bound,
		// not from the candidate coincidentally qualifying for ordinary use.
		now := start.Add(time.Duration(index+1) * 90 * time.Second)
		choice := runtime.chooseLearningRoute(rule, now)
		if choice.reason != "explore" || choice.address != rule.Targets[want].Address {
			t.Fatalf("exploration %d = %+v, want target %d", index+1, choice, want)
		}
		latency := 700 * time.Millisecond
		if want == 1 {
			latency = 10 * time.Millisecond
		}
		learningScalingCompleteProbe(t, runtime, rule, choice, now, latency, nil)
	}
}

func TestRouteLearningScalingConfirmationStopsWithoutFreshHealthyAdvantage(t *testing.T) {
	for _, outcome := range []string{"failure", "neutral", "stale_success", "lost_advantage", "degraded", "unhealthy", "circuit_open", "protocol_change"} {
		t.Run(outcome, func(t *testing.T) {
			runtime, rule, start := learningScalingRuntime(t, 8, config.ConnectProxyH3, config.ConnectProxyH2)
			key := boostRuleKey(rule)
			backup := rule.Targets[1]
			if outcome == "protocol_change" {
				// A prior H2 observation makes the untouched H3 alternatives older
				// in fair rotation, so retaining H3 confirmation is distinguishable.
				runtime.learning.observeSetup(routeLearningKey{key, backup.Address, config.ConnectProxyH2}, 700*time.Millisecond, nil, start)
			}
			firstAt := start.Add(routeLearningExploreInterval)
			first := runtime.chooseLearningRoute(rule, firstAt)
			if first.reason != "explore" || first.address != backup.Address {
				t.Fatalf("initial backup probe = %+v", first)
			}
			learningScalingCompleteProbe(t, runtime, rule, first, firstAt, 10*time.Millisecond, nil)
			secondAt := firstAt.Add(routeLearningExploreInterval)
			second := runtime.chooseLearningRoute(rule, secondAt)
			if second.reason != "explore" || second.address != backup.Address || second.protocol != config.ConnectProxyH3 {
				t.Fatalf("promising backup did not receive confirmation: %+v", second)
			}
			latency, failure := 10*time.Millisecond, error(nil)
			switch outcome {
			case "failure":
				failure = errors.New("independent setup failed")
			case "neutral", "stale_success":
				failure = context.Canceled
			case "lost_advantage":
				latency = 5 * time.Second
			}
			learningScalingCompleteProbe(t, runtime, rule, second, secondAt, latency, failure)
			switch outcome {
			case "stale_success":
				runtime.learning.observeSetup(routeLearningKey{key, backup.Address, config.ConnectProxyH3}, 10*time.Millisecond, nil, firstAt.Add(time.Second))
			case "degraded":
				runtime.learning.observeDegradation(backup.Address, config.ConnectProxyH3, secondAt.Add(3*time.Second))
			case "unhealthy":
				runtime.health.observe(activeHealthKey{rule: rule, address: backup.Address}, config.HealthCheckConfig{FailureThreshold: 1}, false)
			case "circuit_open":
				tripRouteInRegistry(t, runtime.routes, rule, backup.Address, secondAt.Add(3*time.Second))
			case "protocol_change":
				endpoint := http3ConnectTransportKey{address: backup.Address, serverName: backup.ConnectProxy.ServerName}
				runtime.connectProxy.h3FallbackMu.Lock()
				runtime.connectProxy.h3Fallback[endpoint] = &http3FallbackState{failures: 1, retryAt: secondAt.Add(time.Minute)}
				runtime.connectProxy.h3FallbackMu.Unlock()
			}
			third := runtime.chooseLearningRoute(rule, secondAt.Add(routeLearningExploreInterval))
			if third.reason != "explore" || third.address != rule.Targets[2].Address {
				t.Fatalf("%s retained confirmation ahead of untouched backup: %+v", outcome, third)
			}
		})
	}
}

func TestRouteLearningScalingConfirmationKeepsOneLeaseAndThirtySecondBudget(t *testing.T) {
	runtime, rule, start := learningScalingRuntime(t, 8, config.ConnectProxyH2)
	firstAt := start.Add(routeLearningExploreInterval)
	first := runtime.chooseLearningRoute(rule, firstAt)
	learningScalingCompleteProbe(t, runtime, rule, first, firstAt, 10*time.Millisecond, nil)
	now := firstAt.Add(routeLearningExploreInterval)
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
	owners := 0
	for choice := range choices {
		if choice.reason == "explore" {
			owner = choice
			owners++
		}
	}
	if owners != 1 || owner.token == 0 || owner.address != first.address {
		t.Fatalf("confirmation owners = %d, choice = %+v", owners, owner)
	}
	wrong := owner
	wrong.token++
	runtime.releaseLearningChoice(rule, wrong)
	if sibling := runtime.chooseLearningRoute(rule, now.Add(time.Second)); sibling.reason == "explore" || sibling.token != 0 {
		t.Fatalf("wrong token released the confirmation lease: %+v", sibling)
	}
	learningScalingCompleteProbe(t, runtime, rule, owner, now, 10*time.Millisecond, nil)
	if early := runtime.chooseLearningRoute(rule, now.Add(routeLearningExploreInterval-time.Nanosecond)); early.reason == "explore" || early.token != 0 {
		t.Fatalf("confirmation refilled the thirty-second budget: %+v", early)
	}
	last := runtime.chooseLearningRoute(rule, now.Add(routeLearningExploreInterval))
	if last.reason != "explore" || last.address != first.address || last.token == 0 {
		t.Fatalf("last bounded confirmation = %+v", last)
	}
}
