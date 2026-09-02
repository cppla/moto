package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestHTTP3UDPBlackholeValidationArmsOnlyExactSlotAndReusesCooldown(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls.Add(1)
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	}

	firstTarget := mixedHTTP3BlackholeTarget("first.example:443")
	secondTarget := mixedHTTP3BlackholeTarget("second.example:443")
	firstEvent := prepareHTTP3BlackholeEvent(t, manager, "mixed", firstTarget, "upload.example:443", 101)
	secondEvent := prepareHTTP3BlackholeEvent(t, manager, "mixed", secondTarget, "upload.example:443", 102)

	manager.noteHTTP3UDPBlackhole(firstEvent)
	waitForHTTP3BlackholeCondition(t, func() bool {
		return blackholeRulePhase(manager, "mixed") == http3RuleBreakerCooldown &&
			blackholeSlotLifecycle(manager.h3, firstEvent) == http3TransportDraining
	})
	if lifecycle := blackholeSlotLifecycle(manager.h3, secondEvent); lifecycle != http3TransportServing {
		t.Fatalf("unrelated endpoint lifecycle = %s, want serving", lifecycle)
	}
	if got := h2Calls.Load(); got != 1 {
		t.Fatalf("initial H2 probes = %d, want 1", got)
	}

	manager.noteHTTP3UDPBlackhole(secondEvent)
	waitForHTTP3BlackholeCondition(t, func() bool {
		return blackholeSlotLifecycle(manager.h3, secondEvent) == http3TransportDraining
	})
	if got := h2Calls.Load(); got != 1 {
		t.Fatalf("cooldown repeated H2 probe: calls=%d, want 1", got)
	}
}

func TestHTTP3UDPBlackholeH2StatusReachabilityPolicy(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		reachable bool
	}{
		{name: "policy denied", status: http.StatusForbidden, reachable: true},
		{name: "destination bad gateway", status: http.StatusBadGateway, reachable: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, reachable: true},
		{name: "destination timeout", status: http.StatusGatewayTimeout, reachable: true},
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "proxy auth required", status: http.StatusProxyAuthRequired},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "method not allowed", status: http.StatusMethodNotAllowed},
		{name: "not implemented", status: http.StatusNotImplemented},
		{name: "HTTP version unsupported", status: http.StatusHTTPVersionNotSupported},
		{name: "unknown status", status: http.StatusTeapot},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newConnectProxyManager()
			t.Cleanup(manager.close)
			var h2Calls atomic.Int64
			manager.dialers[config.ConnectProxyH2] = func(_ context.Context, target *config.Target, _ string) (net.Conn, error) {
				h2Calls.Add(1)
				return nil, &connectProxyStatusError{
					protocol: config.ConnectProxyH2, target: target.Address, statusCode: test.status,
				}
			}
			target := mixedHTTP3BlackholeTarget("proxy-" + test.name + ".example:443")
			event := prepareHTTP3BlackholeEvent(
				t, manager, "mixed", target, "destination.example:443", uint64(200+index),
			)

			manager.noteHTTP3UDPBlackhole(event)
			manager.maintenanceWG.Wait()

			if got := h2Calls.Load(); got != 1 {
				t.Fatalf("H2 validation calls = %d, want 1", got)
			}
			phase := blackholeRulePhase(manager, "mixed")
			manager.h3.mu.Lock()
			lifecycle := event.slot.lifecycle
			armed := event.slot.forcedDrainArmed
			manager.h3.mu.Unlock()
			if test.reachable {
				if phase != http3RuleBreakerCooldown || lifecycle != http3TransportDraining || !armed {
					t.Fatalf("reachable H2 status %d = phase:%d lifecycle:%s armed:%t, want cooldown/draining/true",
						test.status, phase, lifecycle, armed)
				}
				return
			}
			if phase != http3RuleBreakerClosed || lifecycle != http3TransportServing || armed {
				t.Fatalf("unusable H2 status %d = phase:%d lifecycle:%s armed:%t, want closed/serving/false",
					test.status, phase, lifecycle, armed)
			}
		})
	}
}

func TestHTTP3UDPBlackholeUpgradePublishesOnceWithoutRepeatedRoutePenalty(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	_, slot, release, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	defer release()
	start := time.Date(2026, 9, 1, 7, 45, 0, 0, time.UTC)
	connection := attachHTTP3TestConnection(t, manager, key, slot, start.Add(-time.Minute))
	initial := quic.ConnectionStats{
		MinRTT: 80 * time.Millisecond, SmoothedRTT: 80 * time.Millisecond,
		PacketsSent: 20, BytesSent: 20 << 10, PacketsReceived: 20, BytesReceived: 20 << 10,
	}
	manager.mu.Lock()
	slot.generationID = 88
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonSevereLossAndWrite
	slot.detector.initialize(http3DegradationSample{At: start, Stats: initial, PayloadBytes: 4096})
	slot.detector.latched = http3DegradationDecision{Rotate: true, Reason: http3DegradationReasonSevereLossAndWrite}
	slot.detector.blackholeNoReceiveSince = start.Add(-http3UDPBlackholeStallTimeout)
	slot.detector.blackholeSentBytes = 2400
	slot.detector.blackholeSentPackets = 2
	slot.detector.blackholeSendSamples = 2
	slot.detector.blackholeWindows = http3UDPBlackholeConfirmations - 1
	connectionID := slot.connectionID
	manager.mu.Unlock()
	target := mixedHTTP3BlackholeTarget(key.address)
	old := start.Add(-http3UDPBlackholeStallTimeout)
	tunnel := &http3TunnelStats{slot: slot, ruleName: "mixed", target: target, destination: "upload.example:443"}
	tunnel.pending.Store(1)
	tunnel.writeStarted.Store(old.UnixNano())
	tunnel.lastPayloadProgress.Store(old.UnixNano())
	idleTunnel := &http3TunnelStats{
		slot: slot, ruleName: "idle-rule", target: target, destination: "idle.example:443",
	}
	manager.registerHTTP3Tunnel(tunnel)
	manager.registerHTTP3Tunnel(idleTunnel)
	defer manager.unregisterHTTP3Tunnel(slot, tunnel)
	defer manager.unregisterHTTP3Tunnel(slot, idleTunnel)
	tunnel.lastPayloadProgress.Store(old.UnixNano())

	var routePenalties atomic.Int64
	var ruleStrikes atomic.Int64
	var blackholes atomic.Int64
	manager.onDegraded = func(http3ConnectTransportKey, http3DegradationReason) { routePenalties.Add(1) }
	manager.onConnectionDegraded = func(http3RuleDegradationEvent) { ruleStrikes.Add(1) }
	manager.onUDPBlackhole = func(event http3UDPBlackholeEvent) {
		rules := make(map[string]bool, len(event.probes))
		for _, probe := range event.probes {
			rules[probe.ruleName] = true
		}
		if event.connectionID != connectionID || len(event.probes) != 2 || !rules["mixed"] || !rules["idle-rule"] {
			t.Errorf("blackhole event = %+v", event)
		}
		blackholes.Add(1)
	}
	stats := initial
	stats.PacketsSent++
	stats.BytesSent += 1200
	snapshot := http3DegradationSnapshot{
		key: key, slot: slot, connection: connection, connectionID: connectionID,
		// idleTunnel was registered after this synthetic sampler snapshot. apply
		// must inspect the live slot registry so that it still joins the event.
		payloadBytes: 4096, blocked: 1, peakBlocked: 1, tunnels: []*http3TunnelStats{tunnel},
	}
	sample := http3DegradationSample{
		At: start.Add(http3DegradationSampleInterval), Stats: stats, PayloadBytes: 4096,
		BlockedWrites: 1, OldestBlockedFor: http3UDPBlackholeStallTimeout,
		LastPayloadProgressAt: old,
	}
	manager.applyHTTP3DegradationSample(snapshot, sample)
	stats.PacketsSent++
	stats.BytesSent += 1200
	sample.At = sample.At.Add(http3DegradationSampleInterval)
	sample.Stats = stats
	manager.applyHTTP3DegradationSample(snapshot, sample)

	manager.mu.Lock()
	reason := slot.rotationReason
	candidate := slot.replacement
	candidateReason := http3DegradationReason("")
	if candidate != nil {
		candidateReason = candidate.rotationReason
	}
	detected := manager.rotationEvents[http3RotationMetricKey{
		target: key.address, reason: string(http3DegradationReasonUDPBlackhole), outcome: "detected",
	}]
	manager.mu.Unlock()
	if reason != http3DegradationReasonUDPBlackhole || detected != 1 || blackholes.Load() != 1 {
		t.Fatalf("upgrade state = reason:%s detected:%d callbacks:%d", reason, detected, blackholes.Load())
	}
	if candidate == nil || candidateReason != http3DegradationReasonUDPBlackhole {
		t.Fatalf("warming candidate did not inherit upgraded reason: candidate=%p reason=%s", candidate, candidateReason)
	}
	if routePenalties.Load() != 0 || ruleStrikes.Load() != 0 {
		t.Fatalf("upgrade repeated route feedback = penalty:%d strike:%d", routePenalties.Load(), ruleStrikes.Load())
	}
}

func TestHTTP3UDPBlackholeUnreachableH2KeepsH3FailOpen(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls.Add(1)
		return nil, errors.New("H2 unavailable")
	}
	target := mixedHTTP3BlackholeTarget("proxy.example:443")
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", target, "upload.example:443", 201)

	manager.noteHTTP3UDPBlackhole(event)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 1 {
		t.Fatalf("H2 probes = %d, want 1", got)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerClosed {
		t.Fatalf("failed validation phase = %d, want closed", phase)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, event); lifecycle != http3TransportServing {
		t.Fatalf("H2 failure drained H3 slot: %s", lifecycle)
	}
	manager.h3.mu.Lock()
	failed := manager.h3.rotationEvents[http3RotationMetricKey{
		target: event.key.address, reason: string(http3DegradationReasonUDPBlackhole), outcome: "h2_validation_failed",
	}]
	manager.h3.mu.Unlock()
	if failed != 1 {
		t.Fatalf("failed validation metric = %d, want 1", failed)
	}
}

func TestHTTP3UDPBlackholeH3OnlyNeverProbesOrFastFails(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls.Add(1)
		return nil, errors.New("unexpected H2 probe")
	}
	target := &config.Target{Address: "h3-only.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3},
	}}
	event := prepareHTTP3BlackholeEvent(t, manager, "h3-only", target, "upload.example:443", 301)
	manager.noteHTTP3UDPBlackhole(event)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 0 {
		t.Fatalf("H3-only H2 probes = %d", got)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, event); lifecycle != http3TransportServing {
		t.Fatalf("H3-only slot lifecycle = %s, want serving", lifecycle)
	}
}

func TestHTTP3UDPBlackholeStaleGenerationCannotCommitCooldown(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	release := make(chan struct{})
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		close(started)
		select {
		case <-release:
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	target := mixedHTTP3BlackholeTarget("proxy.example:443")
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", target, "upload.example:443", 401)
	manager.noteHTTP3UDPBlackhole(event)
	<-started
	manager.h3.mu.Lock()
	event.slot.connectionID++
	manager.h3.mu.Unlock()
	close(release)
	manager.maintenanceWG.Wait()
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerClosed {
		t.Fatalf("stale generation committed phase %d", phase)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, event); lifecycle != http3TransportServing {
		t.Fatalf("stale generation drained slot: %s", lifecycle)
	}
}

func TestHTTP3UDPBlackholeSuccessfulH3PromotionMakesH2ProbeStale(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	releaseProbe := make(chan struct{})
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		close(started)
		select {
		case <-releaseProbe:
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", mixedHTTP3BlackholeTarget("proxy.example:443"), "upload.example:443", 451)
	manager.noteHTTP3UDPBlackhole(event)
	<-started

	manager.h3.mu.Lock()
	candidate, err := manager.h3.ensureHTTP3RotationCandidateLocked(event.key, event.slot, time.Now())
	manager.h3.mu.Unlock()
	if err != nil || candidate == nil {
		t.Fatalf("create recovered H3 candidate: candidate=%p err=%v", candidate, err)
	}
	manager.h3.promoteHTTP3Candidate(event.key, candidate)
	close(releaseProbe)
	manager.maintenanceWG.Wait()

	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerClosed {
		t.Fatalf("late H2 result overrode recovered H3: phase=%d", phase)
	}
	manager.h3.mu.Lock()
	candidateLifecycle := candidate.lifecycle
	manager.h3.mu.Unlock()
	manager.h3RuleBreaker.mu.Lock()
	opened := manager.h3RuleBreaker.rules["mixed"].events["opened"]
	manager.h3RuleBreaker.mu.Unlock()
	if candidateLifecycle != http3TransportServing || opened != 0 {
		t.Fatalf("recovery state = candidate:%s opened:%d", candidateLifecycle, opened)
	}
}

func TestHTTP3UDPBlackholeH3PromotionDrainCannotCommitCooldown(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	releaseProbe := make(chan struct{})
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		close(started)
		select {
		case <-releaseProbe:
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", mixedHTTP3BlackholeTarget("proxy.example:443"), "upload.example:443", 452)
	manager.noteHTTP3UDPBlackhole(event)
	<-started

	// Reproduce the narrow middle of candidate promotion: the recovered H3 is
	// already serving and the source has an all-stream drain, but the recovery
	// callback has not yet canceled the rule evaluation.
	manager.h3.mu.Lock()
	event.slot.lifecycle = http3TransportDraining
	monitor := manager.h3.prepareHTTP3ForcedDrainLocked(event.key, event.slot, time.Now(), nil)
	manager.h3.mu.Unlock()
	if monitor == nil || !monitor.fastFailAll {
		t.Fatalf("promotion drain = monitor:%p fastFailAll:%t", monitor, monitor != nil && monitor.fastFailAll)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerEvaluating {
		t.Fatalf("test did not preserve evaluation race window: phase=%d", phase)
	}

	close(releaseProbe)
	manager.maintenanceWG.Wait()
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerClosed {
		t.Fatalf("promotion drain committed stale H2 evidence: phase=%d", phase)
	}
	manager.h3RuleBreaker.mu.Lock()
	opened := manager.h3RuleBreaker.rules["mixed"].events["opened"]
	manager.h3RuleBreaker.mu.Unlock()
	if opened != 0 {
		t.Fatalf("promotion drain opened cooldown %d times", opened)
	}
}

func TestHTTP3UDPBlackholeOneProbeCoversMultipleActiveExactScopes(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	release := make(chan struct{})
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		if h2Calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	first := prepareHTTP3BlackholeEvent(t, manager, "mixed", mixedHTTP3BlackholeTarget("first.example:443"), "upload.example:443", 501)
	second := prepareHTTP3BlackholeEvent(t, manager, "mixed", mixedHTTP3BlackholeTarget("second.example:443"), "upload.example:443", 502)
	manager.noteHTTP3UDPBlackhole(first)
	<-started
	manager.noteHTTP3UDPBlackhole(second)
	manager.h3.mu.Lock()
	first.slot.lifecycle = http3TransportDraining // a fresh H3 generation replaced only A
	manager.h3.mu.Unlock()
	close(release)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 1 {
		t.Fatalf("concurrent blackhole probes = %d, want one rule-scoped singleflight", got)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerCooldown {
		t.Fatalf("active second scope did not commit cooldown: phase=%d", phase)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, second); lifecycle != http3TransportDraining {
		t.Fatalf("active second scope lifecycle = %s, want draining", lifecycle)
	}
}

func TestHTTP3UDPBlackholeSharedQUICArmsEveryValidatedRule(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls.Add(1)
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	}
	target := mixedHTTP3BlackholeTarget("shared.example:443")
	event := prepareHTTP3BlackholeEvent(t, manager, "rule-a", target, "upload.example:443", 551)
	manager.registerHTTP3RuleTarget("rule-b", target)
	_, sharedSlot, releaseRuleB, err := manager.h3.acquireTransport(event.key)
	if err != nil || sharedSlot != event.slot {
		t.Fatalf("acquire shared rule-b transport: slot=%p want=%p err=%v", sharedSlot, event.slot, err)
	}
	defer releaseRuleB()
	var ruleBCanceled atomic.Int64
	ruleBTunnel := &http3TunnelStats{
		slot: event.slot, ruleName: "rule-b", target: target, destination: "upload.example:443",
		fastFail: func() bool {
			ruleBCanceled.Add(1)
			return true
		},
	}
	manager.h3.registerHTTP3Tunnel(ruleBTunnel)
	defer func() {
		if ruleBTunnel.pending.Load() > 0 {
			ruleBTunnel.finishWrite(0)
		}
		manager.h3.unregisterHTTP3Tunnel(event.slot, ruleBTunnel)
	}()
	event.probes = append(event.probes, http3UDPBlackholeProbe{
		ruleName: "rule-b", target: target, destination: "upload.example:443",
	})

	manager.noteHTTP3UDPBlackhole(event)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 2 {
		t.Fatalf("shared QUIC H2 probes = %d, want one per rule", got)
	}
	if phase := blackholeRulePhase(manager, "rule-a"); phase != http3RuleBreakerCooldown {
		t.Fatalf("rule-a phase = %d, want cooldown", phase)
	}
	if phase := blackholeRulePhase(manager, "rule-b"); phase != http3RuleBreakerCooldown {
		t.Fatalf("rule-b phase = %d, want cooldown", phase)
	}
	manager.h3.mu.Lock()
	monitor := event.slot.forcedDrainMonitor
	ruleAEligible := monitor != nil && monitor.streamFastFailEligibleLocked(&http3TunnelStats{ruleName: "rule-a"})
	ruleBEligible := monitor != nil && monitor.streamFastFailEligibleLocked(&http3TunnelStats{ruleName: "rule-b"})
	manager.h3.mu.Unlock()
	if !ruleAEligible || !ruleBEligible {
		t.Fatalf("shared drain eligibility = rule-a:%t rule-b:%t", ruleAEligible, ruleBEligible)
	}
	if ruleBCanceled.Load() != 0 {
		t.Fatal("idle rule-b tunnel was fast-failed")
	}
	ruleBTunnel.beginWrite()
	ruleBTunnel.writeStarted.Store(monitor.startedAt.UnixNano())
	ruleBTunnel.lastPayloadProgress.Store(monitor.startedAt.UnixNano())
	first := manager.h3.checkHTTP3ForcedDrainAt(monitor, monitor.startedAt.Add(http3UDPBlackholeStallTimeout))
	if ruleBCanceled.Load() != 0 {
		t.Fatalf("rule-b fast-failed without two confirmations: result=%+v canceled=%d", first, ruleBCanceled.Load())
	}
	second := manager.h3.checkHTTP3ForcedDrainAt(
		monitor,
		monitor.startedAt.Add(http3UDPBlackholeStallTimeout+http3DegradationSampleInterval),
	)
	if second.fastFailedTunnels == 0 || ruleBCanceled.Load() != 1 {
		t.Fatalf("rule-b did not fast-fail after its own stall: result=%+v canceled=%d", second, ruleBCanceled.Load())
	}
}

func TestHTTP3UDPBlackholeConcurrentReusePreventsCommitRollback(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	first := prepareHTTP3BlackholeEvent(
		t, manager, "mixed", mixedHTTP3BlackholeTarget("first.example:443"), "upload.example:443", 561,
	)
	second := prepareHTTP3BlackholeEvent(
		t, manager, "mixed", mixedHTTP3BlackholeTarget("second.example:443"), "upload.example:443", 562,
	)
	firstScope := http3UDPBlackholeScope{key: first.key, slot: first.slot, connectionID: first.connectionID}
	secondScope := http3UDPBlackholeScope{key: second.key, slot: second.slot, connectionID: second.connectionID}
	token, claimed, _ := manager.h3RuleBreaker.beginUDPBlackholeValidation("mixed", firstScope)
	if token == 0 || !claimed {
		t.Fatalf("initial validation = token:%d claimed:%t", token, claimed)
	}
	if result := manager.h3RuleBreaker.completeUDPBlackholeValidation("mixed", token, true); result != http3UDPBlackholeValidationCommitted {
		t.Fatalf("commit result = %d", result)
	}
	originalScopes := manager.h3RuleBreaker.takeCommittedUDPBlackholes("mixed")

	// A recovered H3 candidate has already made the original scope stale.
	manager.h3.mu.Lock()
	first.slot.lifecycle = http3TransportDraining
	promotionMonitor := manager.h3.prepareHTTP3ForcedDrainLocked(first.key, first.slot, time.Now(), nil)
	manager.h3.mu.Unlock()
	if promotionMonitor == nil || !promotionMonitor.fastFailAll {
		t.Fatalf("promotion drain = monitor:%p", promotionMonitor)
	}

	reuseToken, reuseClaimed, reused := manager.h3RuleBreaker.beginUDPBlackholeValidation("mixed", secondScope)
	if reuseToken != token || reuseClaimed || !reused {
		t.Fatalf("concurrent reuse = token:%d claimed:%t reused:%t", reuseToken, reuseClaimed, reused)
	}
	secondArmed := manager.h3.armHTTP3ForcedDrainForBlackhole(secondScope, []string{"mixed"}, time.Now())
	if !manager.h3RuleBreaker.finishUDPBlackholeArming("mixed", reuseToken, secondArmed) || !secondArmed {
		t.Fatal("concurrent reused scope did not retain cooldown")
	}
	originalArmed := false
	for _, scope := range originalScopes {
		originalArmed = manager.h3.armHTTP3ForcedDrainForBlackhole(scope, []string{"mixed"}, time.Now()) || originalArmed
	}
	if originalArmed {
		t.Fatal("stale original scope unexpectedly armed")
	}
	if !manager.h3RuleBreaker.finishUDPBlackholeArming("mixed", token, false) {
		t.Fatal("stale original owner rolled back a concurrently armed cooldown")
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerCooldown {
		t.Fatalf("concurrent arm phase = %d, want cooldown", phase)
	}
}

func TestHTTP3UDPBlackholeExpiredCooldownIsExtended(t *testing.T) {
	now := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.mu.Lock()
	state := breaker.rules["mixed"]
	state.phase = http3RuleBreakerCooldown
	state.failures = 1
	state.retryAt = now
	breaker.mu.Unlock()
	scope := http3UDPBlackholeScope{key: key, slot: &http3ConnectTransportSlot{}, connectionID: 1}
	token, claimed, reused := breaker.beginUDPBlackholeValidation("mixed", scope)
	if token != 0 || claimed || !reused {
		t.Fatalf("expired cooldown blackhole = token:%d claimed:%t reused:%t", token, claimed, reused)
	}
	breaker.mu.Lock()
	phase := state.phase
	failures := state.failures
	retryAt := state.retryAt
	extended := state.events["cooldown_extended"]
	breaker.mu.Unlock()
	if phase != http3RuleBreakerCooldown || failures != 2 || retryAt.Sub(now) != http3RuleCooldownSteps[1] || extended != 1 {
		t.Fatalf("extended cooldown = phase:%d failures:%d retry:%s events:%d", phase, failures, retryAt.Sub(now), extended)
	}
}

func TestHTTP3UDPBlackholeRecoveryRetainsOtherSlotOnSameKey(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	releaseProbe := make(chan struct{})
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		if h2Calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-releaseProbe:
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	target := mixedHTTP3BlackholeTarget("shared.example:443")
	first := prepareHTTP3BlackholeEvent(t, manager, "mixed", target, "upload-a.example:443", 571)
	manager.h3.mu.Lock()
	secondSlot, err := manager.h3.newTransportSlotLocked(first.key, http3TransportServing, http3ConnectStreamsPerTransport)
	if err == nil {
		secondSlot.active = 1
	}
	manager.h3.mu.Unlock()
	if err != nil {
		t.Fatalf("create second serving slot: %v", err)
	}
	attachHTTP3TestConnection(t, manager.h3, first.key, secondSlot, time.Now().Add(-time.Minute))
	manager.h3.mu.Lock()
	secondSlot.generationID = 572
	secondSlot.health = http3TransportDegraded
	secondSlot.rotationReason = http3DegradationReasonUDPBlackhole
	secondConnectionID := secondSlot.connectionID
	manager.h3.mu.Unlock()
	secondTunnel := &http3TunnelStats{
		slot: secondSlot, ruleName: "mixed", target: target, destination: "upload-b.example:443", fastFail: func() bool { return true },
	}
	manager.h3.registerHTTP3Tunnel(secondTunnel)
	old := time.Now().Add(-http3UDPBlackholeStallTimeout - http3DegradationSampleInterval)
	secondTunnel.pending.Store(1)
	secondTunnel.writeStarted.Store(old.UnixNano())
	secondTunnel.lastPayloadProgress.Store(old.UnixNano())
	secondSlot.pendingWrites.Store(1)
	secondSlot.lastPayloadProgress.Store(old.UnixNano())
	defer func() {
		if secondTunnel.pending.Load() > 0 {
			secondTunnel.finishWrite(0)
		}
		manager.h3.unregisterHTTP3Tunnel(secondSlot, secondTunnel)
	}()
	second := http3UDPBlackholeEvent{
		key: first.key, slot: secondSlot, connectionID: secondConnectionID, generationID: 572,
		probes: []http3UDPBlackholeProbe{{ruleName: "mixed", target: target, destination: secondTunnel.destination}},
	}

	manager.noteHTTP3UDPBlackhole(first)
	<-started
	manager.noteHTTP3UDPBlackhole(second)
	manager.h3.mu.Lock()
	candidate, candidateErr := manager.h3.ensureHTTP3RotationCandidateLocked(first.key, first.slot, time.Now())
	manager.h3.mu.Unlock()
	if candidateErr != nil || candidate == nil {
		t.Fatalf("create recovered candidate: candidate=%p err=%v", candidate, candidateErr)
	}
	manager.h3.promoteHTTP3Candidate(first.key, candidate)
	close(releaseProbe)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 1 {
		t.Fatalf("same-key H2 probes = %d, want 1", got)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerCooldown {
		t.Fatalf("same-key remaining scope phase = %d, want cooldown", phase)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, second); lifecycle != http3TransportDraining {
		t.Fatalf("same-key remaining slot = %s, want draining", lifecycle)
	}
}

func TestHTTP3UDPBlackholeDuringCrossEndpointProbationReentersCooldown(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	var h2Calls atomic.Int64
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls.Add(1)
		return nil, errors.New("unexpected duplicate H2 probe")
	}
	firstTarget := mixedHTTP3BlackholeTarget("first.example:443")
	secondTarget := mixedHTTP3BlackholeTarget("second.example:443")
	manager.registerHTTP3RuleTarget("mixed", firstTarget)
	second := prepareHTTP3BlackholeEvent(t, manager, "mixed", secondTarget, "upload.example:443", 552)
	firstKey := http3ConnectTransportKey{address: firstTarget.Address}
	manager.h3RuleBreaker.mu.Lock()
	state := manager.h3RuleBreaker.rules["mixed"]
	state.phase = http3RuleBreakerProbation
	state.failures = 1
	state.probation = http3RuleProbationState{
		token: 41, key: firstKey, generationID: 551, established: true,
	}
	manager.h3RuleBreaker.mu.Unlock()

	manager.noteHTTP3RuleDegradation(http3RuleDegradationEvent{
		key: second.key, generationID: second.generationID, at: time.Now(),
		reason: http3DegradationReasonUDPBlackhole,
	})
	manager.noteHTTP3UDPBlackhole(second)
	manager.maintenanceWG.Wait()
	if got := h2Calls.Load(); got != 0 {
		t.Fatalf("probation blackhole repeated H2 probe: calls=%d", got)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerCooldown {
		t.Fatalf("probation blackhole phase = %d, want cooldown", phase)
	}
	if lifecycle := blackholeSlotLifecycle(manager.h3, second); lifecycle != http3TransportDraining {
		t.Fatalf("probation blackhole slot lifecycle = %s, want draining", lifecycle)
	}
	manager.h3RuleBreaker.mu.Lock()
	probationFailed := manager.h3RuleBreaker.rules["mixed"].events["probation_failed"]
	manager.h3RuleBreaker.mu.Unlock()
	if probationFailed != 1 {
		t.Fatalf("probation_failed events = %d, want 1", probationFailed)
	}
}

func TestHTTP3UDPBlackholeConcurrentRealH2CommitIsNotReportedFailed(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	release := make(chan struct{})
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		close(started)
		select {
		case <-release:
			return nil, errors.New("maintenance H2 lost the race")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	target := mixedHTTP3BlackholeTarget("proxy.example:443")
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", target, "upload.example:443", 601)
	manager.noteHTTP3UDPBlackhole(event)
	<-started
	token, _, allowed := manager.h3RuleBreaker.begin("mixed", event.key)
	if token == 0 || allowed {
		t.Fatalf("real H2 participant = token:%d allowed:%t", token, allowed)
	}
	manager.observeHTTP3RuleValidation("mixed", token, nil, true)
	close(release)
	manager.maintenanceWG.Wait()
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerCooldown {
		t.Fatalf("real H2 commit phase = %d", phase)
	}
	manager.h3.mu.Lock()
	failed := manager.h3.rotationEvents[http3RotationMetricKey{
		target: event.key.address, reason: string(http3DegradationReasonUDPBlackhole), outcome: "h2_validation_failed",
	}]
	joined := manager.h3.rotationEvents[http3RotationMetricKey{
		target: event.key.address, reason: string(http3DegradationReasonUDPBlackhole), outcome: "h2_validation_joined",
	}]
	manager.h3.mu.Unlock()
	if failed != 0 || joined != 1 {
		t.Fatalf("maintenance completion metrics = failed:%d joined:%d", failed, joined)
	}
}

func TestHTTP3UDPBlackholeLateH2SuccessCannotCommit(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	scope := http3UDPBlackholeScope{key: key, slot: &http3ConnectTransportSlot{}, connectionID: 1}
	token, claimed, _ := breaker.beginUDPBlackholeValidation("mixed", scope)
	if token == 0 || !claimed {
		t.Fatalf("blackhole validation = token:%d claimed:%t", token, claimed)
	}
	now = now.Add(http3UDPBlackholeH2ProbeTimeout)
	if result := breaker.completeUDPBlackholeValidation("mixed", token, true); result != http3UDPBlackholeValidationStale {
		t.Fatalf("late validation result = %d, want stale", result)
	}
	if state := breaker.rules["mixed"]; state.phase != http3RuleBreakerClosed || state.events["opened"] != 0 {
		t.Fatalf("late success changed breaker: %+v", state)
	}
}

func TestHTTP3UDPBlackholeRetireCancelsAndWaitsForProbe(t *testing.T) {
	manager := newConnectProxyManager()
	t.Cleanup(manager.close)
	started := make(chan struct{})
	manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	event := prepareHTTP3BlackholeEvent(t, manager, "mixed", mixedHTTP3BlackholeTarget("proxy.example:443"), "upload.example:443", 701)
	manager.noteHTTP3UDPBlackhole(event)
	<-started
	startedRetire := time.Now()
	manager.retire()
	if elapsed := time.Since(startedRetire); elapsed > time.Second {
		t.Fatalf("retire waited %s for canceled maintenance probe", elapsed)
	}
	if phase := blackholeRulePhase(manager, "mixed"); phase != http3RuleBreakerClosed {
		t.Fatalf("retire left breaker phase %d", phase)
	}
}

func mixedHTTP3BlackholeTarget(address string) *config.Target {
	return &config.Target{Address: address, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
}

func prepareHTTP3BlackholeEvent(
	t *testing.T,
	manager *connectProxyManager,
	rule string,
	target *config.Target,
	destination string,
	generation uint64,
) http3UDPBlackholeEvent {
	t.Helper()
	manager.registerHTTP3RuleTarget(rule, target)
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	_, slot, release, err := manager.h3.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire H3 transport: %v", err)
	}
	now := time.Now()
	attachHTTP3TestConnection(t, manager.h3, key, slot, now.Add(-time.Minute))
	manager.h3.mu.Lock()
	slot.generationID = generation
	slot.health = http3TransportDegraded
	slot.rotationReason = http3DegradationReasonUDPBlackhole
	connectionID := slot.connectionID
	manager.h3.mu.Unlock()
	tunnel := &http3TunnelStats{
		slot: slot, ruleName: rule, target: target, destination: destination, fastFail: func() bool { return true },
	}
	manager.h3.registerHTTP3Tunnel(tunnel)
	old := now.Add(-http3UDPBlackholeStallTimeout - http3DegradationSampleInterval)
	tunnel.pending.Store(1)
	tunnel.writeStarted.Store(old.UnixNano())
	tunnel.lastPayloadProgress.Store(old.UnixNano())
	slot.pendingWrites.Store(1)
	slot.lastPayloadProgress.Store(old.UnixNano())
	t.Cleanup(func() {
		if tunnel.pending.Load() > 0 {
			tunnel.finishWrite(0)
		}
		manager.h3.unregisterHTTP3Tunnel(slot, tunnel)
		release()
	})
	return http3UDPBlackholeEvent{
		key: key, slot: slot, connectionID: connectionID, generationID: generation,
		probes: []http3UDPBlackholeProbe{{ruleName: rule, target: target, destination: destination}},
	}
}

func waitForHTTP3BlackholeCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for HTTP/3 blackhole transition")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func blackholeRulePhase(manager *connectProxyManager, rule string) http3RuleBreakerPhase {
	manager.h3RuleBreaker.mu.Lock()
	defer manager.h3RuleBreaker.mu.Unlock()
	state := manager.h3RuleBreaker.rules[rule]
	if state == nil {
		return http3RuleBreakerClosed
	}
	return state.phase
}

func blackholeSlotLifecycle(manager *http3ConnectManager, event http3UDPBlackholeEvent) http3TransportLifecycle {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return event.slot.lifecycle
}
