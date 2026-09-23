package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func learningRecoveryFixture(t *testing.T) (*routingRuntime, *config.Rule, time.Time, http3ConnectTransportKey) {
	t.Helper()
	runtime, rule := learningPolicyRuntime(t, config.ConnectProxyH3)
	rule.Targets = rule.Targets[:2]
	at := time.Now()
	learningPolicyFeed(runtime, rule, at.Add(-3*time.Second), 3, config.ConnectProxyH3,
		[]time.Duration{20 * time.Millisecond, 200 * time.Millisecond})
	runtime.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[0].Address || choice.reason != "quality" {
		t.Fatalf("fixture did not prefer healthy A: %+v", choice)
	}
	key := http3ConnectTransportKey{address: rule.Targets[1].Address, serverName: rule.Targets[1].ConnectProxy.ServerName}
	// This is the endpoint state that requests an existing warming slot's
	// canary. Neither target circuit is open and no rule cooldown is due.
	runtime.connectProxy.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	return runtime, rule, at, key
}

func TestRouteLearningExpiredCacheCannotStarveEndpointH3Canary(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "expired"
		if missing {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			runtime, rule, at, endpoint := learningRecoveryFixture(t)
			key := boostRuleKey(rule)
			if missing {
				runtime.deleteBoostWinner(key)
			} else {
				runtime.boost.cache.Lock()
				entry := runtime.boost.cache.entries[key]
				entry.expires = time.Now().Add(-time.Second)
				runtime.boost.cache.entries[key] = entry
				runtime.boost.cache.Unlock()
			}
			if recovery := runtime.claimBoostRecoveryProbe(rule, at); recovery.token != 0 {
				t.Fatalf("fixture unexpectedly needs target-circuit recovery: %+v", recovery)
			}
			if choice := runtime.chooseLearningRoute(rule, at); choice != (routeLearningChoice{}) {
				t.Fatalf("learning synthesized a cache entry ahead of endpoint recovery: %+v", choice)
			}
			if _, usable := runtime.loadUsableBoostWinnerToken(key, rule, at); usable {
				t.Fatal("expired winner prevented the ordinary fresh-selection path")
			}
			runtime.connectProxy.h3FallbackMu.Lock()
			claimedEarly := runtime.connectProxy.h3Fallback[endpoint].boostCanaryInFlight
			runtime.connectProxy.h3FallbackMu.Unlock()
			if claimedEarly {
				t.Fatal("read-only learning decision consumed protocol canary ownership")
			}
			var ordinaryDialed atomic.Bool
			winner, peer := net.Pipe()
			t.Cleanup(func() { winner.Close(); peer.Close() })
			result, err := runtime.raceBoostTargetsPrepared(context.Background(), rule,
				func(ctx context.Context, address string) (net.Conn, error) {
					if address != rule.Targets[1].Address {
						ordinaryDialed.Store(true)
						return nil, errors.New("healthy target raced endpoint recovery")
					}
					if routeProtocolProbeTokenFromContext(ctx) == 0 {
						return nil, errors.New("endpoint canary has no protocol lease")
					}
					return winner, nil
				}, nil)
			if err != nil || result.addr != rule.Targets[1].Address || ordinaryDialed.Load() {
				t.Fatalf("endpoint recovery was not exclusive: result=%+v err=%v ordinary=%t", result, err, ordinaryDialed.Load())
			}
			runtime.connectProxy.h3FallbackMu.Lock()
			state := *runtime.connectProxy.h3Fallback[endpoint]
			runtime.connectProxy.h3FallbackMu.Unlock()
			if state.boostCanaryInFlight || state.boostCanaryToken != 0 || state.lastBoostCanary.IsZero() {
				t.Fatalf("canary lease did not complete normally: %+v", state)
			}
		})
	}
}

func TestRouteLearningLiveCacheDoesNotInventEndpointRecovery(t *testing.T) {
	runtime, rule, at, endpoint := learningRecoveryFixture(t)
	if choice := runtime.chooseLearningRoute(rule, at); choice.address != rule.Targets[0].Address || choice.reason != "quality" {
		t.Fatalf("ordinary live cached quality preference was interrupted: %+v", choice)
	}
	runtime.connectProxy.h3FallbackMu.Lock()
	state := *runtime.connectProxy.h3Fallback[endpoint]
	runtime.connectProxy.h3FallbackMu.Unlock()
	if state.boostCanaryInFlight || state.boostCanaryToken != 0 || !state.lastBoostCanary.IsZero() {
		t.Fatalf("learning invented or acquired a protocol probe: %+v", state)
	}
}

func TestRouteLearningFreshSelectionCannotStealOwnedEndpointCanary(t *testing.T) {
	runtime, rule, at, endpoint := learningRecoveryFixture(t)
	runtime.deleteBoostWinner(boostRuleKey(rule))
	owner, ok := runtime.connectProxy.claimHTTP3BoostProbe(rule, rule.Targets[1], at)
	if !ok || owner == 0 {
		t.Fatal("could not establish existing canary owner")
	}
	t.Cleanup(func() { runtime.connectProxy.releaseHTTP3BoostProbe(rule, rule.Targets[1], owner) })
	if choice := runtime.chooseLearningRoute(rule, at); choice != (routeLearningChoice{}) {
		t.Fatalf("missing cache bypassed fresh selection: %+v", choice)
	}
	selections := runtime.routes.selectTargetSelections(rule, len(rule.Targets), at, nil, true)
	if len(selections) != 1 || selections[0].target.Address != rule.Targets[0].Address || selections[0].protocolProbe.token != 0 {
		t.Fatalf("fresh selection stole or raced owned canary: %+v", selections)
	}
	runtime.connectProxy.h3FallbackMu.Lock()
	state := *runtime.connectProxy.h3Fallback[endpoint]
	runtime.connectProxy.h3FallbackMu.Unlock()
	if !state.boostCanaryInFlight || state.boostCanaryToken != owner {
		t.Fatalf("existing canary ownership changed: %+v", state)
	}
}
