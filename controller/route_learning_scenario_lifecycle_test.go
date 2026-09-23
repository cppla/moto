package controller

import (
	"context"
	"encoding/json"
	"errors"
	"moto/config"
	"sync"
	"testing"
	"time"
)

func learningScenarioCloneRule(t *testing.T, rule *config.Rule) *config.Rule {
	t.Helper()
	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var clone config.Rule
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return &clone
}

func learningScenarioObserve(runtime *routingRuntime, rule *config.Rule, index int, protocol string, latency time.Duration, err error, at time.Time) {
	ctx := withRouteLearningScope(context.Background(), runtime.learning, rule)
	observeRouteLearningSetup(ctx, rule.Targets[index], protocol, latency, err, at)
}

func learningScenarioStates(learner *routeLearner) map[routeLearningKey]routeLearningState {
	learner.mu.Lock()
	defer learner.mu.Unlock()
	states := make(map[routeLearningKey]routeLearningState, len(learner.states))
	for key, state := range learner.states {
		states[key] = *state
	}
	return states
}

func learningScenarioAssertStates(t *testing.T, learner *routeLearner, want map[routeLearningKey]routeLearningState) {
	t.Helper()
	got := learningScenarioStates(learner)
	if len(got) != len(want) {
		t.Fatalf("late generation event changed state count: got %d, want %d", len(got), len(want))
	}
	for key, expected := range want {
		if actual, ok := got[key]; !ok || actual != expected {
			t.Fatalf("late generation event changed %s/%s: got %+v, want %+v", key.target, key.protocol, actual, expected)
		}
	}
}

// An unchanged reload may copy observations, but cannot copy a pending
// confirmation schedule or share the ownership used to release a live probe.
// In particular, numeric tokens can coincide across runtime generations.
func TestRouteLearningScenarioReloadWithConfirmationAndLateOldEvents(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			previous, rule := learningPolicyRuntime(t, protocol)
			// All policy steps use virtual time. Anchor the clock within the
			// evidence TTL because the production H2 PING callback uses Now.
			start := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
			for window := range 3 {
				learningScenarioObserve(previous, rule, 0, protocol, 500*time.Millisecond, nil,
					start.Add(time.Duration(window-3)*time.Second))
			}
			previous.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
			if choice := previous.chooseLearningRoute(rule, start); choice.reason != "quality" || choice.address != rule.Targets[0].Address {
				t.Fatalf("initial primary = %+v", choice)
			}
			firstAt := start.Add(routeLearningExploreInterval)
			first := previous.chooseLearningRoute(rule, firstAt)
			if first.reason != "explore" || first.address != rule.Targets[1].Address {
				t.Fatalf("first backup exploration = %+v", first)
			}
			learningScenarioObserve(previous, rule, 0, protocol, 500*time.Millisecond, nil, firstAt.Add(time.Second))
			learningScenarioObserve(previous, rule, 1, protocol, 10*time.Millisecond, nil, firstAt.Add(2*time.Second))
			previous.releaseLearningChoice(rule, first)
			reloadAt := firstAt.Add(routeLearningExploreInterval)
			oldOwner := previous.chooseLearningRoute(rule, reloadAt)
			if oldOwner.reason != "explore" || oldOwner.address != first.address || oldOwner.token == 0 {
				t.Fatalf("promising backup did not enter confirmation: %+v", oldOwner)
			}
			oldScope := withRouteLearningScope(context.Background(), previous.learning, rule)
			oldPing := previous.connectProxy.h2.newTransport(http2ConnectTransportKey{
				address: rule.Targets[0].Address, tlsProfile: http2TLSProfileForUserAgent(""),
			}).CountError

			next := newRoutingRuntime()
			t.Cleanup(next.stopBackground)
			clone := learningScenarioCloneRule(t, rule)
			next.inheritUnchangedState(previous, []*config.Rule{rule}, []*config.Rule{clone})
			learningScenarioAssertStates(t, next.learning, learningScenarioStates(previous.learning))
			if choice := next.chooseLearningRoute(clone, reloadAt); choice.reason != "quality" || choice.address != rule.Targets[0].Address || choice.token != 0 {
				t.Fatalf("reload copied pending confirmation instead of ordinary preference: %+v", choice)
			}
			next.learningPolicy.mu.Lock()
			confirmation := next.learningPolicy.rules[boostRuleKey(clone)].confirmation
			next.learningPolicy.mu.Unlock()
			if confirmation != (routeLearningConfirmation{}) {
				t.Fatalf("reload inherited the old confirmation schedule: %+v", confirmation)
			}

			// B has one copied sample, while C has none. Without copied pending
			// ownership, the new generation fairly starts with C, then confirms C.
			newFirstAt := reloadAt.Add(routeLearningExploreInterval)
			newFirst := next.chooseLearningRoute(clone, newFirstAt)
			if newFirst.reason != "explore" || newFirst.address != clone.Targets[2].Address {
				t.Fatalf("new generation inherited B confirmation priority: %+v", newFirst)
			}
			learningScenarioObserve(next, clone, 0, protocol, 500*time.Millisecond, nil, newFirstAt.Add(time.Second))
			learningScenarioObserve(next, clone, 2, protocol, 10*time.Millisecond, nil, newFirstAt.Add(2*time.Second))
			next.releaseLearningChoice(clone, newFirst)
			newOwnerAt := newFirstAt.Add(routeLearningExploreInterval)
			newOwner := next.chooseLearningRoute(clone, newOwnerAt)
			if newOwner.reason != "explore" || newOwner.address != newFirst.address || newOwner.token != oldOwner.token {
				t.Fatalf("fixture needs coincident generation-local tokens: old=%+v new=%+v", oldOwner, newOwner)
			}
			before := learningScenarioStates(next.learning)

			// These callbacks still own the old runtime captured before reload.
			// Release and setup completion can arrive concurrently while the new
			// generation has a numerically identical live confirmation lease.
			ready := make(chan struct{})
			var workers sync.WaitGroup
			for range 16 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-ready
					observeRouteLearningSetup(oldScope, rule.Targets[1], protocol, time.Second,
						errors.New("late old generation setup failure"), newOwnerAt.Add(time.Second))
					previous.releaseLearningChoice(rule, oldOwner)
				}()
			}
			close(ready)
			workers.Wait()
			if protocol == config.ConnectProxyH2 {
				oldPing("conn_close_lost_ping")
			} else {
				previous.connectProxy.h3.onConnectionDegraded(http3RuleDegradationEvent{
					key: http3ConnectTransportKey{address: rule.Targets[0].Address},
					at:  newOwnerAt.Add(2 * time.Second), generationID: 17,
					reason: http3DegradationReasonSustainedSignals,
				})
			}
			oldKey := routeLearningKey{boostRuleKey(rule), rule.Targets[0].Address, protocol}
			if learningObserverState(previous.learning, oldKey).degradedAt.IsZero() {
				t.Fatal("fixture did not exercise the old generation's physical callback")
			}
			learningScenarioAssertStates(t, next.learning, before)
			next.learningPolicy.mu.Lock()
			retained := next.learningPolicy.rules[boostRuleKey(clone)].exploreToken
			next.learningPolicy.mu.Unlock()
			if retained != newOwner.token {
				t.Fatalf("old lease release stole new generation ownership: got %d, want %d", retained, newOwner.token)
			}
			previous.stopBackground()
			previous.releaseLearningChoice(rule, oldOwner)
			learningScenarioAssertStates(t, next.learning, before)
			if sibling := next.chooseLearningRoute(clone, newOwnerAt.Add(2*time.Second)); sibling.reason != "quality" || sibling.address != clone.Targets[0].Address || sibling.token != 0 {
				t.Fatalf("old generation lifecycle disturbed new ordinary traffic: %+v", sibling)
			}
			next.releaseLearningChoice(clone, newOwner)
			if early := next.chooseLearningRoute(clone, newOwnerAt.Add(3*time.Second)); early.reason == "explore" || early.token != 0 {
				t.Fatalf("new owner release refilled its exploration interval: %+v", early)
			}
		})
	}
}

// A reload can contain both retained and changed rules whose learning key is
// unchanged. Full config equality, rather than endpoint/name equality alone,
// must decide which evidence and cached winners survive.
func TestRouteLearningScenarioMixedReloadRejectsChangedRuleEvidence(t *testing.T) {
	for _, change := range []string{"server_name", "credentials", "protocol_order"} {
		t.Run(change, func(t *testing.T) {
			previous, stable := learningPolicyRuntime(t, config.ConnectProxyH3, config.ConnectProxyH2)
			stable.Name += "/stable"
			changed := learningScenarioCloneRule(t, stable)
			changed.Name += "/changed"
			changed.Listen = "127.0.0.1:19007"
			start := time.Unix(1700000000, 0)
			for _, rule := range []*config.Rule{stable, changed} {
				for window := range 3 {
					for _, protocol := range []string{config.ConnectProxyH3, config.ConnectProxyH2} {
						learningScenarioObserve(previous, rule, 0, protocol, 50*time.Millisecond, nil, start.Add(time.Duration(window)*time.Second))
						learningScenarioObserve(previous, rule, 1, protocol, 150*time.Millisecond, nil, start.Add(time.Duration(window)*time.Second))
					}
				}
				previous.storeBoostWinner(boostRuleKey(rule), rule.Targets[0].Address)
				if choice := previous.chooseLearningRoute(rule, start.Add(2*time.Second)); choice.reason != "quality" || choice.address != rule.Targets[0].Address {
					t.Fatalf("old rule did not learn primary A: %+v", choice)
				}
			}
			stableClone, changedClone := learningScenarioCloneRule(t, stable), learningScenarioCloneRule(t, changed)
			for _, target := range changedClone.Targets {
				switch change {
				case "server_name":
					target.ConnectProxy.ServerName = "replacement.example"
				case "credentials":
					target.ConnectProxy.BasicAuth = &config.BasicAuthConfig{Username: "example-user", Password: "example-password"}
				case "protocol_order":
					target.ConnectProxy.Protocols = []string{config.ConnectProxyH2, config.ConnectProxyH3}
				}
			}
			if boostRuleKey(changedClone) != boostRuleKey(changed) {
				t.Fatal("fixture must retain the key while changing serialized configuration")
			}
			next := newRoutingRuntime()
			t.Cleanup(next.stopBackground)
			next.inheritUnchangedState(previous, []*config.Rule{stable, changed}, []*config.Rule{stableClone, changedClone})
			want := make(map[routeLearningKey]routeLearningState)
			for key, state := range learningScenarioStates(previous.learning) {
				if key.rule == boostRuleKey(stable) {
					want[key] = state
				}
			}
			learningScenarioAssertStates(t, next.learning, want)
			if _, ok := next.loadBoostWinnerToken(boostRuleKey(changedClone)); ok {
				t.Fatal("changed rule inherited a stale cached winner")
			}
			if winner, ok := next.loadBoostWinnerToken(boostRuleKey(stableClone)); !ok || winner.addr != stable.Targets[0].Address {
				t.Fatalf("unrelated unchanged rule lost its winner: %+v, %t", winner, ok)
			}
			if choice := next.chooseLearningRoute(changedClone, start.Add(3*time.Second)); choice != (routeLearningChoice{}) {
				t.Fatalf("changed rule made an evidence-based decision before relearning: %+v", choice)
			}

			// Both rules shared the old physical endpoint. Its late H3 failure
			// may affect both old rules, but not the retained copy or the new rule.
			learningScenarioObserve(previous, changed, 0, config.ConnectProxyH2, time.Second,
				errors.New("old transport completed after config reload"), start.Add(4*time.Second))
			previous.connectProxy.h3.onConnectionDegraded(http3RuleDegradationEvent{
				key: http3ConnectTransportKey{address: changed.Targets[0].Address},
				at:  start.Add(5 * time.Second), generationID: 29,
				reason: http3DegradationReasonSustainedSignals,
			})
			previous.stopBackground()
			learningScenarioAssertStates(t, next.learning, want)

			// The changed rule must accumulate its own independent windows and
			// may learn the opposite preference without modifying the stable rule.
			protocol := changedClone.Targets[0].ConnectProxy.Protocols[0]
			for window := range 3 {
				at := start.Add(time.Duration(10+window) * time.Second)
				learningScenarioObserve(next, changedClone, 0, protocol, 600*time.Millisecond, nil, at)
				learningScenarioObserve(next, changedClone, 1, protocol, 20*time.Millisecond, nil, at)
				choice := next.chooseLearningRoute(changedClone, at)
				if window < 2 && choice != (routeLearningChoice{}) {
					t.Fatalf("changed rule reused stale confidence after only %d fresh windows: %+v", window+1, choice)
				}
				if window == 2 && (choice.reason != "quality" || choice.address != changedClone.Targets[1].Address || choice.protocol != protocol) {
					t.Fatalf("changed rule did not learn its new primary independently: %+v", choice)
				}
			}
			for key, expected := range want {
				if got := learningObserverState(next.learning, key); got != expected {
					t.Fatalf("changed rule relearning mutated unchanged rule: got %+v, want %+v", got, expected)
				}
			}
			if choice := next.chooseLearningRoute(stableClone, start.Add(12*time.Second)); choice.reason != "quality" || choice.address != stableClone.Targets[0].Address {
				t.Fatalf("unchanged rule lost its opposite learned preference: %+v", choice)
			}
		})
	}
}
