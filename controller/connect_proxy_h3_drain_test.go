package controller

import (
	"context"
	"moto/config"
	"testing"
	"time"
)

func TestHTTP3SeverePromotionArmsBoundedForcedDrain(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	started := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	attachHTTP3TestConnection(t, manager, key, source, started)
	manager.mu.Lock()
	source.health = http3TransportDegraded
	source.rotationReason = http3DegradationReasonSevereLossAndWrite
	candidate, err := manager.ensureHTTP3RotationCandidateLocked(key, source, started.Add(time.Minute))
	manager.mu.Unlock()
	if err != nil || candidate == nil {
		t.Fatalf("create candidate: candidate=%p err=%v", candidate, err)
	}

	_, selected, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire candidate: %v", err)
	}
	if selected != candidate {
		t.Fatal("warming candidate was not selected")
	}
	manager.promoteHTTP3Candidate(key, candidate)

	manager.mu.Lock()
	armed := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "forced_drain_armed",
	}]
	sourceState := source.lifecycle
	sourceRetained := manager.containsSlotLocked(key, source)
	manager.mu.Unlock()
	if armed != 1 || sourceState != http3TransportDraining || !sourceRetained {
		t.Fatalf("forced drain after promotion = armed:%d state:%s retained:%t", armed, sourceState, sourceRetained)
	}

	releaseCandidate()
	releaseSource()
}

func TestHTTP3ForcedDrainResetsStallWindowOnPayloadProgress(t *testing.T) {
	manager, key, slot, monitor, release := prepareHTTP3ForcedDrainTest(
		t, http3DegradationReasonSevereLossAndWrite, true,
	)
	defer release()
	started := monitor.startedAt

	if result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(29*time.Second)); result.closed {
		t.Fatal("severe connection closed before the stall bound")
	}
	slot.payloadRead.Add(64 << 10)
	if result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(30*time.Second)); result.closed {
		t.Fatal("payload progress did not reset the forced-drain stall window")
	}
	if result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(59*time.Second)); result.closed {
		t.Fatal("connection closed less than 30 seconds after payload progress")
	}
	result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(60*time.Second))
	if !result.closed || result.blockedWrites != 1 || result.stalledFor != http3ForcedDrainStallTimeout {
		t.Fatalf("forced close result = %+v", result)
	}

	manager.mu.Lock()
	closed := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "forced_drain_closed",
	}]
	retained := manager.containsSlotLocked(key, slot)
	manager.mu.Unlock()
	if closed != 1 || retained || slot.lifecycle != http3TransportFailed {
		t.Fatalf("forced close state = metric:%d retained:%t lifecycle:%s", closed, retained, slot.lifecycle)
	}
}

func TestHTTP3ForcedDrainDoesNotKillIdleSevereTunnel(t *testing.T) {
	manager, _, slot, monitor, release := prepareHTTP3ForcedDrainTest(
		t, http3DegradationReasonSevereLossAndWrite, false,
	)
	defer release()
	result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(10*time.Minute))
	if result.closed || result.blockedWrites != 0 {
		t.Fatalf("idle severe drain was closed: %+v", result)
	}
	if slot.lifecycle != http3TransportDraining {
		t.Fatalf("idle source lifecycle = %s, want draining", slot.lifecycle)
	}
}

func TestHTTP3ConnectionErrorForcesCloseAfterNoProgressBound(t *testing.T) {
	manager, key, slot, monitor, release := prepareHTTP3ForcedDrainTest(
		t, http3DegradationReasonConnectionError, false,
	)
	defer release()
	if result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(29*time.Second)); result.closed {
		t.Fatal("connection-error drain closed before the stall bound")
	}
	result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3ForcedDrainStallTimeout))
	if !result.closed || result.closeReason != "connection_error_no_payload_progress" {
		t.Fatalf("connection-error forced close = %+v", result)
	}
	manager.mu.Lock()
	retained := manager.containsSlotLocked(key, slot)
	manager.mu.Unlock()
	if retained {
		t.Fatal("connection-error source remained in the transport pool")
	}
}

func TestHTTP3OrdinaryDegradationNeverArmsForcedDrain(t *testing.T) {
	manager, _, slot, _, release := prepareHTTP3ForcedDrainTest(
		t, http3DegradationReasonSustainedSignals, false,
	)
	defer release()
	manager.mu.Lock()
	monitor := manager.prepareHTTP3ForcedDrainLocked(
		http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"},
		slot,
		time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC),
	)
	manager.mu.Unlock()
	if monitor != nil {
		t.Fatal("ordinary sustained-signal degradation armed forced drain")
	}
}

func TestHTTP3RuleBreakerArmsSevereServingSlotsBeforeLazyCandidatePromotion(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	manager.h3.now = func() time.Time { return now }
	firstTarget := &config.Target{
		Address: "first.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	secondTarget := &config.Target{
		Address: "second.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	firstKey := http3ConnectTransportKey{address: firstTarget.Address}
	secondKey := http3ConnectTransportKey{address: secondTarget.Address}
	manager.registerHTTP3RuleTarget("mixed", firstTarget)
	manager.registerHTTP3RuleTarget("mixed", secondTarget)

	_, first, releaseFirst, err := manager.h3.acquireTransport(firstKey)
	if err != nil {
		t.Fatalf("acquire first source: %v", err)
	}
	_, second, releaseSecond, err := manager.h3.acquireTransport(secondKey)
	if err != nil {
		t.Fatalf("acquire second source: %v", err)
	}
	attachHTTP3TestConnection(t, manager.h3, firstKey, first, now.Add(-time.Minute))
	attachHTTP3TestConnection(t, manager.h3, secondKey, second, now.Add(-time.Minute))
	manager.h3.mu.Lock()
	first.health = http3TransportDegraded
	first.rotationReason = http3DegradationReasonSevereLossAndWrite
	firstCandidate, err := manager.h3.ensureHTTP3RotationCandidateLocked(firstKey, first, now)
	second.health = http3TransportDegraded
	second.rotationReason = http3DegradationReasonConnectionError
	manager.h3.mu.Unlock()
	if err != nil || firstCandidate == nil {
		t.Fatalf("create lazy first candidate: candidate=%p err=%v", firstCandidate, err)
	}

	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: firstKey, remoteIP: "192.0.2.10", generationID: 101, at: now,
	})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: secondKey, remoteIP: "192.0.2.11", generationID: 102, at: now.Add(time.Second),
	})
	validationToken, _, validationAllowed := manager.beginHTTP3RuleAttempt(context.Background(), "mixed", firstTarget)
	if validationToken == 0 || validationAllowed {
		t.Fatalf("rule H2 validation admission = token:%d allowed:%t", validationToken, validationAllowed)
	}
	manager.observeHTTP3RuleValidation("mixed", validationToken, nil, true)

	manager.h3.mu.Lock()
	firstArmed := manager.h3.rotationEvents[http3RotationMetricKey{
		target: firstKey.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "forced_drain_armed",
	}]
	secondArmed := manager.h3.rotationEvents[http3RotationMetricKey{
		target: secondKey.address, reason: string(http3DegradationReasonConnectionError), outcome: "forced_drain_armed",
	}]
	firstState, secondState := first.lifecycle, second.lifecycle
	firstFlag, secondFlag := first.forcedDrainArmed, second.forcedDrainArmed
	manager.h3.mu.Unlock()
	if firstArmed != 1 || secondArmed != 1 || !firstFlag || !secondFlag ||
		firstState != http3TransportDraining || secondState != http3TransportDraining {
		t.Fatalf("breaker forced drains = first(metric:%d flag:%t state:%s) second(metric:%d flag:%t state:%s)",
			firstArmed, firstFlag, firstState, secondArmed, secondFlag, secondState)
	}

	// A candidate that was already in flight may still promote after the rule
	// moved to H2. That promotion must not create a second monitor or metric.
	_, selected, releaseCandidate, err := manager.h3.acquireTransport(firstKey)
	if err != nil {
		t.Fatalf("acquire pre-existing lazy candidate: %v", err)
	}
	if selected != firstCandidate {
		t.Fatal("pre-existing warming candidate was not selected")
	}
	manager.h3.promoteHTTP3Candidate(firstKey, firstCandidate)
	manager.h3.armHTTP3ForcedDrainsForBreaker([]http3ConnectTransportKey{firstKey, secondKey}, now.Add(2*time.Second))
	manager.h3.mu.Lock()
	firstArmedAfter := manager.h3.rotationEvents[http3RotationMetricKey{
		target: firstKey.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "forced_drain_armed",
	}]
	secondArmedAfter := manager.h3.rotationEvents[http3RotationMetricKey{
		target: secondKey.address, reason: string(http3DegradationReasonConnectionError), outcome: "forced_drain_armed",
	}]
	manager.h3.mu.Unlock()
	if firstArmedAfter != 1 || secondArmedAfter != 1 {
		t.Fatalf("forced-drain arming was not idempotent: first=%d second=%d", firstArmedAfter, secondArmedAfter)
	}

	releaseCandidate()
	releaseFirst()
	releaseSecond()
}

func prepareHTTP3ForcedDrainTest(
	t *testing.T,
	reason http3DegradationReason,
	blocked bool,
) (*http3ConnectManager, http3ConnectTransportKey, *http3ConnectTransportSlot, *http3ForcedDrainMonitor, func()) {
	t.Helper()
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, slot, release, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	started := time.Date(2026, 8, 28, 8, 30, 0, 0, time.UTC)
	attachHTTP3TestConnection(t, manager, key, slot, started)
	if blocked {
		tunnel := manager.registerHTTP3Tunnel(slot)
		tunnel.pending.Store(1)
		tunnel.writeStarted.Store(started.Add(-http3ForcedDrainStallTimeout).UnixNano())
		slot.pendingWrites.Store(1)
	}
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = reason
	slot.lastPayloadProgress.Store(started.UnixNano())
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started)
	manager.mu.Unlock()
	if isHTTP3ForcedDrainReason(reason) && monitor == nil {
		t.Fatalf("reason %s did not create forced-drain monitor", reason)
	}
	return manager, key, slot, monitor, release
}
