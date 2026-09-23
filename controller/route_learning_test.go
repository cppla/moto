package controller

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func learningTestKey(target, protocol string) routeLearningKey {
	return routeLearningKey{rule: "learning-rule", target: target, protocol: protocol}
}

func TestRouteLearningQualityReversesWithoutTimeOfDay(t *testing.T) {
	learner := newRouteLearner()
	a, b := learningTestKey("a.example:443", "h2"), learningTestKey("b.example:443", "h2")
	start := time.Unix(1000, 0)
	for i := 0; i < 8; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		learner.observeSetup(a, 50*time.Millisecond, nil, at)
		learner.observeSetup(b, 400*time.Millisecond, nil, at)
	}
	first := start.Add(7 * time.Second)
	if !learner.estimate(a, first).Known || learner.estimate(a, first).Cost >= learner.estimate(b, first).Cost {
		t.Fatal("initial observations did not prefer A")
	}
	for i := 8; i < 20; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		learner.observeSetup(a, 600*time.Millisecond, nil, at)
		learner.observeSetup(b, 60*time.Millisecond, nil, at)
	}
	last := start.Add(19 * time.Second)
	if learner.estimate(b, last).Cost >= learner.estimate(a, last).Cost {
		t.Fatal("fresh quality reversal did not prefer B")
	}
}

func TestRouteLearningConfidenceUsesIndependentWindows(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h3")
	start := time.Unix(1000, 0)
	for i := 0; i < 1000; i++ {
		learner.observeSetup(key, 100*time.Millisecond, nil, start)
	}
	got := learner.estimate(key, start)
	if got.Known || got.Samples != 1 || got.Latency != 100*time.Millisecond {
		t.Fatalf("burst became independent evidence: %+v", got)
	}
	for i := 1; i <= 2; i++ {
		learner.observeSetup(key, 100*time.Millisecond, nil, start.Add(time.Duration(i)*time.Second))
		if i == 1 {
			for j := 0; j < 1000; j++ {
				learner.observeSetup(key, 100*time.Millisecond, nil, start.Add(time.Second))
			}
			if got := learner.estimate(key, start.Add(time.Second)); got.Known {
				t.Fatalf("two burst windows became known: %+v", got)
			}
		}
	}
	got = learner.estimate(key, start.Add(2*time.Second))
	if !got.Known || got.Samples > 3 {
		t.Fatalf("three independent windows: %+v", got)
	}
}

func TestRouteLearningDecayAndExpiry(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	start := time.Unix(1000, 0)
	for i := 0; i < 4; i++ {
		learner.observeSetup(key, 100*time.Millisecond, nil, start.Add(time.Duration(i)*time.Second))
	}
	last := start.Add(3 * time.Second)
	initial := learner.estimate(key, last)
	decayed := learner.estimate(key, last.Add(routeLearningHalfLife))
	if !initial.Known || math.Abs(decayed.Samples-initial.Samples/2) > 1e-9 {
		t.Fatalf("confidence did not decay: initial=%+v later=%+v", initial, decayed)
	}
	if older := learner.estimate(key, last.Add(2*routeLearningHalfLife)); older.Known {
		t.Fatalf("old confidence still qualified: %+v", older)
	}
	if expired := learner.estimate(key, last.Add(routeLearningTTL)); expired != (routeLearningEstimate{}) {
		t.Fatalf("stale observation survived TTL: %+v", expired)
	}
	if len(learner.states) != 0 {
		t.Fatal("expired entry retained")
	}
}

func TestRouteLearningNeutralOutcomes(t *testing.T) {
	neutral := []error{
		&connectProxyStatusError{statusCode: 403}, &connectProxyStatusError{statusCode: 503},
		&connectProxyStatusError{statusCode: 407}, &connectProxyStatusError{statusCode: 429},
		&connectProxyStatusError{statusCode: 405}, context.Canceled,
		errConnectProxyProtocolCapacity, errors.Join(errConnectProxyProtocolCapacity, context.DeadlineExceeded),
		&dialBulkheadError{cause: context.DeadlineExceeded}, errDialBulkheadSaturated,
		ErrCircuitOpen, ErrActiveHealthUnhealthy, errRouteReachable,
		errConnectProxyProtocolCoolingDown, errConnectProxyProtocolUnavailable,
	}
	for _, err := range neutral {
		t.Run(err.Error(), func(t *testing.T) {
			learner := newRouteLearner()
			key := learningTestKey("proxy.example:443", "h3")
			at := time.Unix(1000, 0)
			learner.observeSetup(key, time.Second, fmt.Errorf("wrapped: %w", err), at)
			if got := learner.estimate(key, at); got != (routeLearningEstimate{}) {
				t.Fatalf("neutral error became sample: %+v", got)
			}
		})
	}
}

func TestRouteLearningFailureIsImmediateBoundedAndRecovers(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	at := time.Unix(1000, 0)
	for i := 0; i < 50; i++ {
		learner.observeSetup(key, time.Minute, context.DeadlineExceeded, at)
	}
	failed := learner.estimate(key, at)
	if failed.FailureRatio != 0.25 || failed.Samples != 1 || failed.Cost <= routeLearningUnknownLatency {
		t.Fatalf("failure must apply immediately but be window bounded: %+v", failed)
	}
	for i := 1; i <= 20; i++ {
		learner.observeSetup(key, 50*time.Millisecond, nil, at.Add(time.Duration(i)*time.Second))
	}
	healthy := learner.estimate(key, at.Add(20*time.Second))
	if !healthy.Known || healthy.FailureRatio >= 0.01 || healthy.Cost >= failed.Cost {
		t.Fatalf("fresh recovery not learned: %+v", healthy)
	}
}

func TestRouteLearningSharedFailureClaimIsIndependent(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h3")
	group := newRouteFailureGroup()
	err := &http3SetupError{cause: context.DeadlineExceeded, group: group}
	at := time.Unix(1000, 0)
	for i := 0; i < 50; i++ {
		learner.observeSetup(key, time.Second, err, at.Add(time.Duration(i)*time.Second))
	}
	if got := learner.estimate(key, at); got.Samples != 1 {
		t.Fatalf("shared physical failure counted repeatedly: %+v", got)
	}
	actualRegistry := newRouteHealthRegistry()
	if !group.claim(actualRegistry, routeHealthKey{rule: key.rule, addr: key.target}) {
		t.Fatal("learning consumed the actual circuit's failure claim")
	}
	second := learningTestKey(key.target, "h2")
	learner.observeSetup(second, time.Second, err, at)
	if got := learner.estimate(second, at); got.Samples != 1 {
		t.Fatalf("protocol claims were not isolated: %+v", got)
	}
}

func TestRouteLearningDegradationIsProtocolScopedAndExpires(t *testing.T) {
	learner := newRouteLearner()
	h2, h3 := learningTestKey("proxy.example:443", "h2"), learningTestKey("proxy.example:443", "h3")
	at := time.Unix(1000, 0)
	learner.observeSetup(h2, 100*time.Millisecond, nil, at)
	learner.observeSetup(h3, 100*time.Millisecond, nil, at)
	before := learner.estimate(h3, at)
	for i := 0; i < 20; i++ {
		learner.observeDegradation(h3.target, "h3", at)
	}
	after := learner.estimate(h3, at)
	if after.Cost-before.Cost != routeLearningDegradationPenalty || after.Samples != before.Samples {
		t.Fatalf("degradation amplified confidence or penalty: before=%+v after=%+v", before, after)
	}
	if got := learner.estimate(h2, at); got.Cost != before.Cost {
		t.Fatalf("H3 degradation contaminated H2: %+v", got)
	}
	if got := learner.estimate(h3, at.Add(routeLearningDegradationMemory)); got.Cost != before.Cost {
		t.Fatalf("old degradation penalty did not expire: %+v", got)
	}
}

func TestRouteLearningStateBoundedAndLatencyClamped(t *testing.T) {
	learner := newRouteLearner()
	at := time.Unix(1000, 0)
	for i := 0; i < routeLearningMaxEntries+10; i++ {
		key := learningTestKey(fmt.Sprintf("proxy-%d.example:443", i), "h2")
		learner.observeSetup(key, time.Hour, nil, at.Add(time.Duration(i)*time.Millisecond))
	}
	if len(learner.states) != routeLearningMaxEntries {
		t.Fatalf("entry bound: %d", len(learner.states))
	}
	key := learningTestKey(fmt.Sprintf("proxy-%d.example:443", routeLearningMaxEntries+9), "h2")
	if got := learner.estimate(key, at.Add(2*time.Second)); got.Latency != routeLearningMaxLatency {
		t.Fatalf("unbounded latency: %+v", got)
	}
	learner.clearRule(key.rule)
	if len(learner.states) != 0 {
		t.Fatal("clearRule retained states")
	}
}

func TestRouteLearningInheritanceCopiesOnlyUnchangedRules(t *testing.T) {
	previous, next := newRouteLearner(), newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	other := key
	other.rule = "changed-rule"
	at := time.Unix(1000, 0)
	previous.observeSetup(key, 100*time.Millisecond, nil, at)
	previous.observeSetup(other, 200*time.Millisecond, nil, at)
	next.inherit(previous, map[string]struct{}{key.rule: {}})
	if next.estimate(key, at) != previous.estimate(key, at) || next.estimate(other, at).Samples != 0 {
		t.Fatal("inheritance did not preserve only unchanged rules")
	}
	previous.observeDegradation(key.target, key.protocol, at)
	if next.estimate(key, at).Cost == previous.estimate(key, at).Cost {
		t.Fatal("inherited state aliases prior runtime")
	}
	if next.failureIdentity == previous.failureIdentity {
		t.Fatal("failure claim ownership inherited")
	}
}

func TestRouteLearningConcurrentObservers(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h3")
	at := time.Unix(1000, 0)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				learner.observeSetup(key, 100*time.Millisecond, nil, at)
				learner.observeDegradation(key.target, key.protocol, at)
				learner.estimate(key, at)
			}
		}()
	}
	workers.Wait()
	if got := learner.estimate(key, at); got.Samples != 1 {
		t.Fatalf("concurrent burst increased confidence: %+v", got)
	}
}

func TestRouteLearningLateAndNeutralEventsDoNotRefreshEvidence(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	at := time.Unix(1000, 0)
	learner.observeSetup(key, 100*time.Millisecond, nil, at)
	before := learner.estimate(key, at)
	learner.observeSetup(key, time.Second, context.DeadlineExceeded, at.Add(-time.Second))
	learner.observeSetup(key, time.Second, &connectProxyStatusError{statusCode: 503}, at.Add(time.Minute))
	learner.observeDegradation(key.target, key.protocol, at.Add(-time.Second))
	if after := learner.estimate(key, at); before != after {
		t.Fatalf("late/neutral events changed evidence: before=%+v after=%+v", before, after)
	}
}

func TestRouteLearningSampleConfidenceIsBounded(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	at := time.Unix(1000, 0)
	for i := 0; i < 1000; i++ {
		learner.observeSetup(key, time.Millisecond, nil, at.Add(time.Duration(i)*time.Second))
	}
	if got := learner.estimate(key, at.Add(999*time.Second)); got.Samples > routeLearningMaxSamples || !got.Known {
		t.Fatalf("unbounded or absent confidence: %+v", got)
	}
}

func TestRouteLearningSparseExplorationCanBecomeKnown(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("backup.example:443", "h2")
	at := time.Unix(1000, 0)
	for i := 0; i < 20; i++ {
		now := at.Add(time.Duration(i) * 90 * time.Second)
		learner.observeSetup(key, 100*time.Millisecond, nil, now)
		got := learner.estimate(key, now)
		if i < 2 && got.Known {
			t.Fatalf("backup qualified after only %d windows: %+v", i+1, got)
		}
		if i >= 2 && !got.Known {
			t.Fatalf("sparse backup could not qualify after %d windows: %+v", i+1, got)
		}
	}
}

func TestRouteLearningInheritanceContinuesTheCurrentWindow(t *testing.T) {
	previous, next := newRouteLearner(), newRouteLearner()
	key := learningTestKey("proxy.example:443", "h2")
	at := time.Unix(1000, 0)
	previous.observeSetup(key, 100*time.Millisecond, nil, at)
	previous.observeSetup(key, 100*time.Millisecond, nil, at.Add(time.Second))
	next.inherit(previous, map[string]struct{}{key.rule: {}})
	continued := at.Add(time.Second + 100*time.Millisecond)
	for i := 0; i < 100; i++ {
		next.observeSetup(key, 200*time.Millisecond, nil, continued)
	}
	got := next.estimate(key, continued)
	if got.Known || got.Samples > 2 || next.states[key].windows != 2 {
		t.Fatalf("same-second reload added a confidence window: %+v", got)
	}
	if previous.states[key].windowSuccesses != 1 || previous.estimate(key, continued).Latency != 100*time.Millisecond {
		t.Fatal("continued new-generation observations changed prior runtime")
	}
	next.observeSetup(key, 200*time.Millisecond, nil, at.Add(2*time.Second))
	if got := next.estimate(key, at.Add(2*time.Second)); !got.Known || next.states[key].windows != 3 {
		t.Fatalf("next distinct window did not qualify: %+v", got)
	}
}

func TestRouteLearningDegradationRefreshDoesNotRefreshConfidence(t *testing.T) {
	learner := newRouteLearner()
	key := learningTestKey("proxy.example:443", "h3")
	at := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		learner.observeSetup(key, 100*time.Millisecond, nil, at.Add(time.Duration(i)*time.Second))
	}
	last := at.Add(2 * time.Second)
	before := learner.estimate(key, last)
	degraded := last.Add(2 * routeLearningHalfLife)
	learner.observeDegradation(key.target, key.protocol, degraded)
	after := learner.estimate(key, degraded)
	if after.LastObservation != degraded || after.Known || math.Abs(after.Samples-before.Samples/4) > 1e-9 {
		t.Fatalf("physical degradation refreshed learning confidence: before=%+v after=%+v", before, after)
	}
	if learner.states[key].windows != 3 {
		t.Fatal("physical degradation created a setup window")
	}
}
