package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"sync"
	"sync/atomic"
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

func TestHTTP3UDPBlackholeUsesEightSecondStreamFastFailBound(t *testing.T) {
	var canceled atomic.Int64
	manager, key, slot, tunnel, monitor, release := prepareHTTP3StreamFastFailTest(
		t, "mixed", []string{"mixed"}, func() bool {
			canceled.Add(1)
			return true
		},
	)
	defer release()
	manager.mu.Lock()
	slot.rotationReason = http3DegradationReasonUDPBlackhole
	monitor.reason = http3DegradationReasonUDPBlackhole
	old := monitor.startedAt.Add(-http3UDPBlackholeStallTimeout)
	tunnel.writeStarted.Store(old.UnixNano())
	tunnel.lastPayloadProgress.Store(old.UnixNano())
	monitor.tunnels[tunnel] = newHTTP3ForcedDrainTunnelState(tunnel, monitor.startedAt)
	manager.mu.Unlock()
	if result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt); result.fastFailedTunnels != 0 {
		t.Fatalf("first blackhole confirmation fast-failed: %+v", result)
	}
	result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || canceled.Load() != 1 {
		t.Fatalf("blackhole stream fast fail = result:%+v canceled:%d", result, canceled.Load())
	}
	manager.mu.Lock()
	metric := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonUDPBlackhole), outcome: "stream_fast_failed",
	}]
	manager.mu.Unlock()
	if metric != 1 {
		t.Fatalf("blackhole stream fast-fail metric = %d", metric)
	}
}

func TestHTTP3UDPBlackholeFastFailsReadOnlyStreamOnlyForValidatedRule(t *testing.T) {
	var mixedCanceled atomic.Int64
	var h3OnlyCanceled atomic.Int64
	manager, _, slot, mixed, monitor, release := prepareHTTP3StreamFastFailTest(
		t, "mixed", []string{"mixed"}, func() bool {
			mixedCanceled.Add(1)
			return true
		},
	)
	defer release()
	mixed.finishWrite(0)
	manager.mu.Lock()
	slot.rotationReason = http3DegradationReasonUDPBlackhole
	monitor.reason = http3DegradationReasonUDPBlackhole
	old := monitor.startedAt.Add(-http3UDPBlackholeStallTimeout)
	mixed.pendingReads.Store(1)
	mixed.readStarted.Store(old.UnixNano())
	mixed.payloadRead.Store(http3UDPBlackholeRecentReadMinBytes)
	mixed.lastReadProgress.Store(old.UnixNano())
	mixed.lastPayloadProgress.Store(old.UnixNano())
	monitor.tunnels[mixed] = newHTTP3ForcedDrainTunnelState(mixed, monitor.startedAt)
	manager.mu.Unlock()

	h3Only := &http3TunnelStats{slot: slot, ruleName: "h3-only", fastFail: func() bool {
		h3OnlyCanceled.Add(1)
		return true
	}}
	manager.registerHTTP3Tunnel(h3Only)
	manager.mu.Lock()
	h3Only.pendingReads.Store(1)
	h3Only.readStarted.Store(old.UnixNano())
	h3Only.payloadRead.Store(http3UDPBlackholeRecentReadMinBytes)
	h3Only.lastReadProgress.Store(old.UnixNano())
	h3Only.lastPayloadProgress.Store(old.UnixNano())
	monitor.tunnels[h3Only] = newHTTP3ForcedDrainTunnelState(h3Only, monitor.startedAt)
	manager.mu.Unlock()
	defer manager.unregisterHTTP3Tunnel(slot, h3Only)

	if result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt); result.fastFailedTunnels != 0 {
		t.Fatalf("first read-only confirmation fast-failed: %+v", result)
	}
	result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || mixedCanceled.Load() != 1 || h3OnlyCanceled.Load() != 0 {
		t.Fatalf("rule-scoped read fast fail = result:%+v mixed:%d h3-only:%d",
			result, mixedCanceled.Load(), h3OnlyCanceled.Load())
	}
}

func TestHTTP3UDPBlackholeReadProgressResetsFastFailConfirmations(t *testing.T) {
	var canceled atomic.Int64
	manager, _, slot, tunnel, monitor, release := prepareHTTP3StreamFastFailTest(
		t, "mixed", []string{"mixed"}, func() bool {
			canceled.Add(1)
			return true
		},
	)
	defer release()
	tunnel.finishWrite(0)
	manager.mu.Lock()
	slot.rotationReason = http3DegradationReasonUDPBlackhole
	monitor.reason = http3DegradationReasonUDPBlackhole
	old := monitor.startedAt.Add(-http3UDPBlackholeStallTimeout)
	tunnel.pendingReads.Store(1)
	tunnel.readStarted.Store(old.UnixNano())
	tunnel.payloadRead.Store(http3UDPBlackholeRecentReadMinBytes)
	tunnel.lastReadProgress.Store(old.UnixNano())
	tunnel.lastPayloadProgress.Store(old.UnixNano())
	monitor.tunnels[tunnel] = newHTTP3ForcedDrainTunnelState(tunnel, monitor.startedAt)
	manager.mu.Unlock()

	if result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt); result.fastFailedTunnels != 0 {
		t.Fatalf("first read-only confirmation fast-failed: %+v", result)
	}
	progressAt := monitor.startedAt.Add(http3DegradationSampleInterval)
	tunnel.payloadRead.Add(1)
	slot.payloadRead.Add(1)
	tunnel.lastReadProgress.Store(progressAt.UnixNano())
	tunnel.lastPayloadProgress.Store(progressAt.UnixNano())
	tunnel.readStarted.Store(progressAt.UnixNano())
	if result := manager.checkHTTP3ForcedDrainAt(monitor, progressAt); result.fastFailedTunnels != 0 {
		t.Fatalf("read progress did not reset confirmation: %+v", result)
	}
	if result := manager.checkHTTP3ForcedDrainAt(monitor, progressAt.Add(http3DegradationSampleInterval)); result.fastFailedTunnels != 0 {
		t.Fatalf("freshly blocked Read fast-failed after progress: %+v", result)
	}
	if canceled.Load() != 0 {
		t.Fatalf("progressing read was canceled %d times", canceled.Load())
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
		nil,
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
	manager.h3.armHTTP3ForcedDrainsForBreaker(
		[]http3ConnectTransportKey{firstKey, secondKey},
		[]string{"mixed"},
		now.Add(2*time.Second),
	)
	manager.h3.mu.Lock()
	firstArmedAfter := manager.h3.rotationEvents[http3RotationMetricKey{
		target: firstKey.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "forced_drain_armed",
	}]
	secondArmedAfter := manager.h3.rotationEvents[http3RotationMetricKey{
		target: secondKey.address, reason: string(http3DegradationReasonConnectionError), outcome: "forced_drain_armed",
	}]
	firstFastFailAll := first.forcedDrainMonitor != nil && first.forcedDrainMonitor.fastFailAll
	secondFastFailAll := second.forcedDrainMonitor != nil && second.forcedDrainMonitor.fastFailAll
	manager.h3.mu.Unlock()
	if firstArmedAfter != 1 || secondArmedAfter != 1 {
		t.Fatalf("forced-drain arming was not idempotent: first=%d second=%d", firstArmedAfter, secondArmedAfter)
	}
	if !firstFastFailAll || secondFastFailAll {
		t.Fatalf("promotion fast-fail scope = promoted-all:%t breaker-only-all:%t", firstFastFailAll, secondFastFailAll)
	}

	releaseCandidate()
	releaseFirst()
	releaseSecond()
}

func TestHTTP3UnreachableH2ValidationDoesNotArmStreamFastFail(t *testing.T) {
	now := time.Date(2026, 8, 28, 11, 0, 0, 0, time.UTC)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.now = func() time.Time { return now }
	manager.h3.now = func() time.Time { return now }
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	manager.registerHTTP3RuleTarget("mixed", target)
	_, source, release, err := manager.h3.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	defer release()
	attachHTTP3TestConnection(t, manager.h3, key, source, now.Add(-time.Minute))
	manager.h3.mu.Lock()
	source.health = http3TransportDegraded
	source.rotationReason = http3DegradationReasonSevereLossAndWrite
	manager.h3.mu.Unlock()
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.20", generationID: 201, at: now,
	})
	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: key, remoteIP: "192.0.2.21", generationID: 202, at: now.Add(time.Second),
	})
	token, _, h3Allowed := manager.beginHTTP3RuleAttempt(context.Background(), "mixed", target)
	if token == 0 || h3Allowed {
		t.Fatalf("H2 validation admission = token:%d h3Allowed:%t", token, h3Allowed)
	}
	manager.observeHTTP3RuleValidation("mixed", token, errors.New("H2 unavailable"), false)
	manager.h3.mu.Lock()
	armed := source.forcedDrainArmed
	lifecycle := source.lifecycle
	manager.h3.mu.Unlock()
	if armed || lifecycle != http3TransportServing {
		t.Fatalf("unreachable H2 armed stream fast fail: armed=%t lifecycle=%s", armed, lifecycle)
	}
}

func TestHTTP3StreamFastFailUsesPerTunnelProgressDespiteHealthySiblingTraffic(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return started }
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, slot, releaseBad, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire bad tunnel: %v", err)
	}
	_, siblingSlot, releaseSibling, err := manager.acquireTransport(key)
	if err != nil {
		releaseBad()
		t.Fatalf("acquire sibling tunnel: %v", err)
	}
	if siblingSlot != slot {
		releaseSibling()
		releaseBad()
		t.Fatal("test tunnels did not share a physical QUIC slot")
	}
	attachHTTP3TestConnection(t, manager, key, slot, started.Add(-time.Minute))

	var badCanceled atomic.Int64
	bad := &http3TunnelStats{
		slot: slot,
		fastFail: func() bool {
			badCanceled.Add(1)
			return true
		},
	}
	var siblingCanceled atomic.Int64
	sibling := &http3TunnelStats{
		slot: slot,
		fastFail: func() bool {
			siblingCanceled.Add(1)
			return true
		},
	}
	manager.registerHTTP3Tunnel(bad)
	manager.registerHTTP3Tunnel(sibling)
	defer func() {
		bad.finishWrite(0)
		sibling.finishWrite(0)
		manager.unregisterHTTP3Tunnel(slot, bad)
		manager.unregisterHTTP3Tunnel(slot, sibling)
		releaseSibling()
		releaseBad()
	}()

	oldProgress := started.Add(-http3StreamFastFailStallTimeout)
	for _, tunnel := range []*http3TunnelStats{bad, sibling} {
		tunnel.pending.Store(1)
		tunnel.writeStarted.Store(oldProgress.UnixNano())
		tunnel.lastPayloadProgress.Store(oldProgress.UnixNano())
	}
	slot.pendingWrites.Store(2)
	slot.lastPayloadProgress.Store(oldProgress.UnixNano())
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, nil)
	manager.mu.Unlock()
	if monitor == nil {
		t.Fatal("severe draining slot did not arm a monitor")
	}

	advanceSibling := func(at time.Time) {
		sibling.payloadRead.Add(32 << 10)
		slot.payloadRead.Add(32 << 10)
		sibling.lastPayloadProgress.Store(at.UnixNano())
	}
	advanceSibling(started)
	if result := manager.checkHTTP3ForcedDrainAt(monitor, started); result.fastFailedTunnels != 0 {
		t.Fatalf("first stalled sample fast-failed a tunnel: %+v", result)
	}
	advanceSibling(started.Add(http3DegradationSampleInterval))
	result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || badCanceled.Load() != 1 || siblingCanceled.Load() != 0 {
		t.Fatalf("per-tunnel fast fail = result:%+v bad:%d sibling:%d",
			result, badCanceled.Load(), siblingCanceled.Load())
	}
	advanceSibling(started.Add(2 * http3DegradationSampleInterval))
	manager.checkHTTP3ForcedDrainAt(monitor, started.Add(2*http3DegradationSampleInterval))
	if badCanceled.Load() != 1 {
		t.Fatalf("bad tunnel cancellation count = %d, want 1", badCanceled.Load())
	}
}

func TestHTTP3StreamFastFailOwnProgressResetsConsecutiveConfirmation(t *testing.T) {
	var canceled atomic.Int64
	manager, key, slot, tunnel, monitor, release := prepareHTTP3StreamFastFailTest(t, "", nil, func() bool {
		canceled.Add(1)
		return true
	})
	defer release()
	started := monitor.startedAt

	manager.checkHTTP3ForcedDrainAt(monitor, started)
	progressAt := started.Add(http3DegradationSampleInterval)
	tunnel.payloadRead.Add(1)
	slot.payloadRead.Add(1)
	tunnel.lastPayloadProgress.Store(progressAt.UnixNano())
	if result := manager.checkHTTP3ForcedDrainAt(monitor, progressAt); result.fastFailedTunnels != 0 {
		t.Fatalf("payload progress did not reset fast-fail confirmation: %+v", result)
	}
	firstEligible := progressAt.Add(http3StreamFastFailStallTimeout)
	if result := manager.checkHTTP3ForcedDrainAt(monitor, firstEligible); result.fastFailedTunnels != 0 {
		t.Fatalf("first post-progress stalled sample fast-failed tunnel: %+v", result)
	}
	result := manager.checkHTTP3ForcedDrainAt(monitor, firstEligible.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || canceled.Load() != 1 {
		t.Fatalf("post-progress fast fail = result:%+v canceled:%d", result, canceled.Load())
	}
	manager.mu.Lock()
	count := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "stream_fast_failed",
	}]
	manager.mu.Unlock()
	if count != 1 {
		t.Fatalf("stream fast-fail metric = %d, want 1", count)
	}
}

func TestHTTP3StreamFastFailConcurrentChecksCancelExactlyOnce(t *testing.T) {
	var canceled atomic.Int64
	manager, key, _, _, monitor, release := prepareHTTP3StreamFastFailTest(t, "", nil, func() bool {
		canceled.Add(1)
		return true
	})
	defer release()
	manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt)

	const checks = 32
	var wait sync.WaitGroup
	var reported atomic.Int64
	for range checks {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3DegradationSampleInterval))
			reported.Add(int64(result.fastFailedTunnels))
		}()
	}
	wait.Wait()
	manager.mu.Lock()
	count := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "stream_fast_failed",
	}]
	manager.mu.Unlock()
	if canceled.Load() != 1 || reported.Load() != 1 || count != 1 {
		t.Fatalf("concurrent fast fail = canceled:%d reported:%d metric:%d",
			canceled.Load(), reported.Load(), count)
	}
}

func TestHTTP3StreamFastFailNaturalCloseWinnerIsNotCounted(t *testing.T) {
	manager, key, _, _, monitor, release := prepareHTTP3StreamFastFailTest(t, "", nil, func() bool { return false })
	defer release()
	manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt)
	result := manager.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3DegradationSampleInterval))
	manager.mu.Lock()
	count := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonSevereLossAndWrite), outcome: "stream_fast_failed",
	}]
	manager.mu.Unlock()
	if result.fastFailedTunnels != 0 || count != 0 {
		t.Fatalf("lost fast-fail close race was counted: result=%+v metric=%d", result, count)
	}
}

func TestHTTP3ConnectionErrorKeepsThirtySecondConnectionFallback(t *testing.T) {
	var canceled atomic.Int64
	manager, _, _, _, monitor, release := prepareHTTP3StreamFastFailTest(
		t, "", []string{"mixed"}, func() bool {
			canceled.Add(1)
			return true
		})
	defer release()
	monitor.reason = http3DegradationReasonConnectionError
	monitor.slot.rotationReason = http3DegradationReasonConnectionError
	if result := manager.checkHTTP3ForcedDrainAt(
		monitor, monitor.startedAt.Add(http3StreamFastFailStallTimeout+http3DegradationSampleInterval),
	); result.fastFailedTunnels != 0 || result.closed {
		t.Fatalf("connection error used 12-second stream fast fail: %+v", result)
	}
	if canceled.Load() != 0 {
		t.Fatalf("connection-error stream cancellation count = %d", canceled.Load())
	}
}

func TestHTTP3RuleScopedFastFailProtectsSharedH3OnlyTunnelUntilPromotion(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return started }
	key := http3ConnectTransportKey{address: "shared.example:443", serverName: "shared.example"}
	_, slot, releaseMixed, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire mixed tunnel: %v", err)
	}
	_, _, releaseH3Only, err := manager.acquireTransport(key)
	if err != nil {
		releaseMixed()
		t.Fatalf("acquire H3-only tunnel: %v", err)
	}
	attachHTTP3TestConnection(t, manager, key, slot, started.Add(-time.Minute))
	var mixedCanceled atomic.Int64
	var h3OnlyCanceled atomic.Int64
	mixed := &http3TunnelStats{slot: slot, ruleName: "mixed", fastFail: func() bool {
		mixedCanceled.Add(1)
		return true
	}}
	h3Only := &http3TunnelStats{slot: slot, ruleName: "h3-only", fastFail: func() bool {
		h3OnlyCanceled.Add(1)
		return true
	}}
	manager.registerHTTP3Tunnel(mixed)
	manager.registerHTTP3Tunnel(h3Only)
	defer func() {
		mixed.finishWrite(0)
		h3Only.finishWrite(0)
		manager.unregisterHTTP3Tunnel(slot, mixed)
		manager.unregisterHTTP3Tunnel(slot, h3Only)
		releaseH3Only()
		releaseMixed()
	}()
	oldProgress := started.Add(-http3StreamFastFailStallTimeout)
	for _, tunnel := range []*http3TunnelStats{mixed, h3Only} {
		tunnel.pending.Store(1)
		tunnel.writeStarted.Store(oldProgress.UnixNano())
		tunnel.lastPayloadProgress.Store(oldProgress.UnixNano())
	}
	slot.pendingWrites.Store(2)
	slot.lastPayloadProgress.Store(oldProgress.UnixNano())
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, []string{"mixed"})
	manager.mu.Unlock()
	if monitor == nil {
		t.Fatal("rule-scoped breaker did not arm drain monitor")
	}
	manager.checkHTTP3ForcedDrainAt(monitor, started)
	result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || mixedCanceled.Load() != 1 || h3OnlyCanceled.Load() != 0 {
		t.Fatalf("rule-scoped fast fail = result:%+v mixed:%d h3-only:%d",
			result, mixedCanceled.Load(), h3OnlyCanceled.Load())
	}
	// A successfully promoted replacement is safe for every stream on the old
	// slot, including an H3-only rule. Promotion broadens the existing monitor
	// instead of starting a duplicate drain goroutine.
	manager.mu.Lock()
	duplicate := manager.prepareHTTP3ForcedDrainLocked(key, slot, started.Add(3*time.Second), nil)
	manager.mu.Unlock()
	if duplicate != nil {
		t.Fatal("promotion broadening created a duplicate forced-drain monitor")
	}
	manager.checkHTTP3ForcedDrainAt(monitor, started.Add(4*time.Second))
	result = manager.checkHTTP3ForcedDrainAt(monitor, started.Add(6*time.Second))
	if result.fastFailedTunnels != 1 || h3OnlyCanceled.Load() != 1 {
		t.Fatalf("promoted replacement did not release H3-only stalled stream: result:%+v canceled:%d",
			result, h3OnlyCanceled.Load())
	}
}

func TestHTTP3FailedWarmingCandidateDoesNotArmStreamFastFail(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, release, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	defer release()
	attachHTTP3TestConnection(t, manager, key, source, started.Add(-time.Minute))
	stats := &http3TunnelStats{slot: source, fastFail: func() bool {
		t.Fatal("unarmed serving stream was fast-failed")
		return true
	}}
	manager.registerHTTP3Tunnel(stats)
	defer manager.unregisterHTTP3Tunnel(source, stats)
	manager.mu.Lock()
	source.health = http3TransportDegraded
	source.rotationReason = http3DegradationReasonSevereLossAndWrite
	candidate, err := manager.ensureHTTP3RotationCandidateLocked(key, source, started)
	manager.mu.Unlock()
	if err != nil || candidate == nil {
		t.Fatalf("create warming candidate: candidate=%p err=%v", candidate, err)
	}
	if _, accepted := manager.markHTTP3CandidateFailed(key, candidate, context.DeadlineExceeded); !accepted {
		t.Fatal("warming candidate failure was not recorded")
	}
	manager.mu.Lock()
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, source, started, nil)
	armed := source.forcedDrainArmed
	manager.mu.Unlock()
	if monitor != nil || armed || source.lifecycle != http3TransportServing {
		t.Fatalf("failed candidate armed stream fast fail: monitor=%p armed=%t lifecycle=%s",
			monitor, armed, source.lifecycle)
	}
}

func TestHTTP3RuleScopedFastFailAppliesToLateRegisteredMatchingTunnel(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return started }
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, slot, release, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire in-flight source: %v", err)
	}
	defer release()
	attachHTTP3TestConnection(t, manager, key, slot, started.Add(-time.Minute))
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, []string{"mixed"})
	manager.mu.Unlock()
	if monitor == nil {
		t.Fatal("rule-scoped drain was not armed for in-flight CONNECT")
	}

	var canceled atomic.Int64
	late := &http3TunnelStats{slot: slot, ruleName: "mixed", fastFail: func() bool {
		canceled.Add(1)
		return true
	}}
	manager.registerHTTP3Tunnel(late)
	defer manager.unregisterHTTP3Tunnel(slot, late)
	oldProgress := started.Add(-http3StreamFastFailStallTimeout)
	late.pending.Store(1)
	late.writeStarted.Store(oldProgress.UnixNano())
	late.lastPayloadProgress.Store(oldProgress.UnixNano())
	slot.pendingWrites.Store(1)
	slot.lastPayloadProgress.Store(oldProgress.UnixNano())
	defer late.finishWrite(0)
	manager.checkHTTP3ForcedDrainAt(monitor, started)
	result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(http3DegradationSampleInterval))
	if result.fastFailedTunnels != 1 || canceled.Load() != 1 {
		t.Fatalf("late registered tunnel fast fail = result:%+v canceled:%d", result, canceled.Load())
	}
}

func TestHTTP3RuleScopedThirtySecondFallbackProtectsSharedRuleUntilAllScopeReady(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return started }
	key := http3ConnectTransportKey{address: "shared.example:443", serverName: "shared.example"}
	_, slot, releaseMixed, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire mixed: %v", err)
	}
	_, _, releaseH3Only, err := manager.acquireTransport(key)
	if err != nil {
		releaseMixed()
		t.Fatalf("acquire H3-only: %v", err)
	}
	attachHTTP3TestConnection(t, manager, key, slot, started.Add(-time.Minute))
	mixed := &http3TunnelStats{slot: slot, ruleName: "mixed", fastFail: func() bool { return true }}
	h3Only := &http3TunnelStats{slot: slot, ruleName: "h3-only", fastFail: func() bool { return true }}
	manager.registerHTTP3Tunnel(mixed)
	manager.registerHTTP3Tunnel(h3Only)
	defer func() {
		mixed.finishWrite(0)
		h3Only.finishWrite(0)
		manager.unregisterHTTP3Tunnel(slot, mixed)
		manager.unregisterHTTP3Tunnel(slot, h3Only)
		releaseH3Only()
		releaseMixed()
	}()
	oldProgress := started.Add(-http3ForcedDrainStallTimeout)
	for _, tunnel := range []*http3TunnelStats{mixed, h3Only} {
		tunnel.pending.Store(1)
		tunnel.writeStarted.Store(oldProgress.UnixNano())
		tunnel.lastPayloadProgress.Store(oldProgress.UnixNano())
	}
	slot.pendingWrites.Store(2)
	slot.lastPayloadProgress.Store(oldProgress.UnixNano())
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, []string{"mixed"})
	manager.mu.Unlock()
	if monitor == nil {
		t.Fatal("rule-scoped forced drain was not armed")
	}
	if result := manager.checkHTTP3ForcedDrainAt(monitor, started); result.closed {
		t.Fatal("mixed-rule H2 fallback closed a physical QUIC shared by H3-only traffic")
	}
	manager.mu.Lock()
	manager.prepareHTTP3ForcedDrainLocked(key, slot, started.Add(time.Second), nil)
	manager.mu.Unlock()
	result := manager.checkHTTP3ForcedDrainAt(monitor, started.Add(time.Second))
	if !result.closed {
		t.Fatalf("all-scope replacement did not preserve 30-second physical fallback: %+v", result)
	}
}

func TestHTTP3TunnelFastFailUsesUnifiedCloseOnceAndExpectedRelayError(t *testing.T) {
	responseReader, responseWriter := io.Pipe()
	requestReader, requestWriter := io.Pipe()
	defer responseWriter.Close()
	defer requestReader.Close()
	streamCtx, cancelStream := context.WithCancel(context.Background())
	var releases atomic.Int64
	conn := &http3TunnelConn{
		reader: responseReader,
		writer: requestWriter,
		cancel: cancelStream,
		release: func() {
			releases.Add(1)
		},
		stats: &http3TunnelStats{},
	}

	closeErr, won := conn.closeWithCause(errHTTP3TunnelFastFailed)
	if !won || closeErr != nil {
		t.Fatalf("fast-fail close = won:%t err:%v", won, closeErr)
	}
	const concurrentCloses = 32
	var wait sync.WaitGroup
	for range concurrentCloses {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = conn.Close()
		}()
	}
	wait.Wait()
	if releases.Load() != 1 {
		t.Fatalf("tunnel release count = %d, want 1", releases.Load())
	}
	if streamCtx.Err() != context.Canceled {
		t.Fatalf("stream context = %v, want canceled", streamCtx.Err())
	}
	if !errors.Is(errHTTP3TunnelFastFailed, net.ErrClosed) {
		t.Fatalf("fast-fail error %q does not wrap net.ErrClosed", errHTTP3TunnelFastFailed)
	}
	relay := relayResult{
		ClientToTarget: relayDirectionResult{Err: errHTTP3TunnelFastFailed, Origin: relayErrorOriginPrimary},
		StopCause:      relayStopCause{Kind: relayStopCopyError, Direction: relayDirectionClientToTarget},
	}
	if relayInvalidatesBoostWinner(relay) {
		t.Fatal("controlled H3 stream fast fail invalidated the Boost winner")
	}
	decision := classifyRelayError(relay, relayDirectionClientToTarget, errHTTP3TunnelFastFailed)
	if decision.Class != relayLogClassExpectedClose {
		t.Fatalf("fast-fail relay class = %s, want %s", decision.Class, relayLogClassExpectedClose)
	}
}

func TestHTTP3TunnelFastFailUnblocksWriteAndBalancesPendingCounters(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	defer requestReader.Close()
	slot := &http3ConnectTransportSlot{}
	stats := &http3TunnelStats{slot: slot}
	var releases atomic.Int64
	conn := &http3TunnelConn{
		reader: io.NopCloser(bytes.NewReader(nil)),
		writer: requestWriter,
		cancel: func() {},
		release: func() {
			releases.Add(1)
		},
		stats: stats,
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked payload"))
		writeDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for stats.pending.Load() != 1 || slot.pendingWrites.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("Write did not block: tunnel=%d slot=%d", stats.pending.Load(), slot.pendingWrites.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if _, won := conn.closeWithCause(errHTTP3TunnelFastFailed); !won {
		t.Fatal("stream fast fail did not win closeOnce")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, errHTTP3TunnelFastFailed) {
			t.Fatalf("blocked Write error = %v, want controlled fast fail", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream fast fail did not unblock Write")
	}
	if stats.pending.Load() != 0 || slot.pendingWrites.Load() != 0 {
		t.Fatalf("pending counters leaked: tunnel=%d slot=%d", stats.pending.Load(), slot.pendingWrites.Load())
	}
	if releases.Load() != 1 {
		t.Fatalf("release count = %d, want 1", releases.Load())
	}
}

func TestHTTP3TunnelFastFailUnblocksReadAndBalancesPendingCounters(t *testing.T) {
	responseReader, responseWriter := io.Pipe()
	defer responseWriter.Close()
	requestReader, requestWriter := io.Pipe()
	defer requestReader.Close()
	slot := &http3ConnectTransportSlot{}
	stats := &http3TunnelStats{slot: slot}
	var releases atomic.Int64
	conn := &http3TunnelConn{
		reader: responseReader,
		writer: requestWriter,
		cancel: func() {},
		release: func() {
			releases.Add(1)
		},
		stats: stats,
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()

	deadline := time.Now().Add(time.Second)
	for stats.pendingReads.Load() != 1 || stats.readStarted.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("Read did not block: pending=%d started=%d", stats.pendingReads.Load(), stats.readStarted.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if _, won := conn.closeWithCause(errHTTP3TunnelFastFailed); !won {
		t.Fatal("stream fast fail did not win closeOnce")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, errHTTP3TunnelFastFailed) {
			t.Fatalf("blocked Read error = %v, want controlled fast fail", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream fast fail did not unblock Read")
	}
	if stats.pendingReads.Load() != 0 || stats.readStarted.Load() != 0 {
		t.Fatalf("pending Read counters leaked: pending=%d started=%d", stats.pendingReads.Load(), stats.readStarted.Load())
	}
	if releases.Load() != 1 {
		t.Fatalf("release count = %d, want 1", releases.Load())
	}
}

func TestHTTP3TunnelNaturalCloseAndFastFailHaveSingleConcurrentWinner(t *testing.T) {
	const iterations = 64
	for index := range iterations {
		requestReader, requestWriter := io.Pipe()
		var releases atomic.Int64
		conn := &http3TunnelConn{
			reader: io.NopCloser(bytes.NewReader(nil)),
			writer: requestWriter,
			cancel: func() {},
			release: func() {
				releases.Add(1)
			},
			stats: &http3TunnelStats{},
		}
		start := make(chan struct{})
		fastWon := make(chan bool, 1)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, won := conn.closeWithCause(errHTTP3TunnelFastFailed)
			fastWon <- won
		}()
		go func() {
			defer wait.Done()
			<-start
			_ = conn.Close()
		}()
		close(start)
		wait.Wait()
		won := <-fastWon
		_ = requestReader.Close()
		if releases.Load() != 1 {
			t.Fatalf("iteration %d release count = %d, want 1", index, releases.Load())
		}
		if conn.fastFailed.Load() != won {
			t.Fatalf("iteration %d fast-fail state = %t, winner = %t", index, conn.fastFailed.Load(), won)
		}
	}
}

func prepareHTTP3StreamFastFailTest(
	t *testing.T,
	ruleName string,
	fastFailRules []string,
	fastFail func() bool,
) (*http3ConnectManager, http3ConnectTransportKey, *http3ConnectTransportSlot, *http3TunnelStats, *http3ForcedDrainMonitor, func()) {
	t.Helper()
	manager := newHTTP3RotationTestManager(t)
	started := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return started }
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, slot, releaseTransport, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	attachHTTP3TestConnection(t, manager, key, slot, started.Add(-time.Minute))
	if fastFail == nil {
		fastFail = func() bool { return true }
	}
	tunnel := &http3TunnelStats{slot: slot, ruleName: ruleName, fastFail: fastFail}
	manager.registerHTTP3Tunnel(tunnel)
	oldProgress := started.Add(-http3StreamFastFailStallTimeout)
	tunnel.pending.Store(1)
	tunnel.writeStarted.Store(oldProgress.UnixNano())
	tunnel.lastPayloadProgress.Store(oldProgress.UnixNano())
	slot.pendingWrites.Store(1)
	slot.lastPayloadProgress.Store(oldProgress.UnixNano())
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, fastFailRules)
	manager.mu.Unlock()
	if monitor == nil {
		t.Fatal("severe draining slot did not arm a monitor")
	}
	cleanup := func() {
		if tunnel.pending.Load() > 0 {
			tunnel.finishWrite(0)
		}
		manager.unregisterHTTP3Tunnel(slot, tunnel)
		releaseTransport()
	}
	return manager, key, slot, tunnel, monitor, cleanup
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
		tunnel := &http3TunnelStats{slot: slot}
		manager.registerHTTP3Tunnel(tunnel)
		tunnel.pending.Store(1)
		tunnel.writeStarted.Store(started.Add(-http3ForcedDrainStallTimeout).UnixNano())
		slot.pendingWrites.Store(1)
	}
	manager.mu.Lock()
	slot.lifecycle = http3TransportDraining
	slot.health = http3TransportDegraded
	slot.rotationReason = reason
	slot.lastPayloadProgress.Store(started.UnixNano())
	monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, started, nil)
	manager.mu.Unlock()
	if isHTTP3ForcedDrainReason(reason) && monitor == nil {
		t.Fatalf("reason %s did not create forced-drain monitor", reason)
	}
	return manager, key, slot, monitor, release
}
