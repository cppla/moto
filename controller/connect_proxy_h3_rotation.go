package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"moto/utils"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const (
	http3RotationBackoffBase = 30 * time.Second
	http3RotationBackoffMax  = 5 * time.Minute
)

type http3TransportLifecycle string

const (
	http3TransportWarming  http3TransportLifecycle = "warming"
	http3TransportServing  http3TransportLifecycle = "serving"
	http3TransportDraining http3TransportLifecycle = "draining"
	http3TransportFailed   http3TransportLifecycle = "failed"
)

type http3TransportHealth string

const (
	http3TransportHealthy  http3TransportHealth = "healthy"
	http3TransportSuspect  http3TransportHealth = "suspect"
	http3TransportDegraded http3TransportHealth = "degraded"
)

type http3StatsConnection interface {
	ConnectionStats() quic.ConnectionStats
	Context() context.Context
}

type http3RotationMetricKey struct {
	target  string
	reason  string
	outcome string
}

type http3TunnelStats struct {
	slot                *http3ConnectTransportSlot
	ruleName            string
	target              *config.Target
	destination         string
	userAgent           string
	probation           http3RuleProbationBinding
	pending             atomic.Int64
	writeStarted        atomic.Int64
	pendingReads        atomic.Int64
	readStarted         atomic.Int64
	payloadRead         atomic.Uint64
	payloadWritten      atomic.Uint64
	lastReadProgress    atomic.Int64
	lastPayloadProgress atomic.Int64
	fastFailSelected    atomic.Bool
	closed              atomic.Bool
	fastFail            func() bool
}

type http3UDPBlackholeProbe struct {
	ruleName    string
	target      *config.Target
	destination string
	userAgent   string
}

type http3UDPBlackholeEvent struct {
	key          http3ConnectTransportKey
	slot         *http3ConnectTransportSlot
	connectionID uint64
	generationID uint64
	probes       []http3UDPBlackholeProbe
}

type http3DegradationSnapshot struct {
	key          http3ConnectTransportKey
	slot         *http3ConnectTransportSlot
	connection   http3StatsConnection
	connectionID uint64
	payloadBytes uint64
	payloadRead  uint64
	blocked      int
	peakBlocked  int
	tunnels      []*http3TunnelStats
	historical   time.Duration
}

func (manager *http3ConnectManager) timeNow() time.Time {
	if manager != nil && manager.now != nil {
		return manager.now()
	}
	return time.Now()
}

// newTransportSlotLocked creates only a lazy HTTP/3 transport. A warming
// replacement performs its physical QUIC handshake when exactly one later
// CONNECT request is admitted as the canary.
func (manager *http3ConnectManager) newTransportSlotLocked(
	key http3ConnectTransportKey,
	lifecycle http3TransportLifecycle,
	limit int,
) (*http3ConnectTransportSlot, error) {
	setupOwner, cancelSetup := context.WithCancel(manager.dialCtx)
	transport := manager.newTransport(key, setupOwner)
	if transport == nil {
		cancelSetup()
		return nil, errors.New("HTTP/3 CONNECT transport factory returned nil")
	}
	tracker := &http3SetupFlightTracker{}
	slot := &http3ConnectTransportSlot{
		transport:    transport,
		setupFlights: tracker,
		cancelSetup:  cancelSetup,
		limit:        limit,
		lifecycle:    lifecycle,
		health:       http3TransportHealthy,
		tunnels:      make(map[*http3TunnelStats]struct{}),
	}
	instrumentHTTP3SetupFlights(key, transport, tracker, func(connection *quic.Conn, err error) {
		manager.observeHTTP3PhysicalDial(key, slot, connection, err)
	})
	manager.transports[key] = append(manager.transports[key], slot)
	manager.startHTTP3SamplerLocked()
	return slot, nil
}

func (manager *http3ConnectManager) observeHTTP3PhysicalDial(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	connection *quic.Conn,
	err error,
) {
	if manager == nil || slot == nil || connection == nil || err != nil {
		return
	}
	now := manager.timeNow()
	var closeCandidate *http3ConnectTransportSlot
	var recovered func(http3ConnectTransportKey)
	manager.mu.Lock()
	if !manager.containsSlotLocked(key, slot) {
		manager.mu.Unlock()
		return
	}
	slot.connection = connection
	slot.connectionID++
	manager.nextGenerationID++
	if manager.nextGenerationID == 0 {
		manager.nextGenerationID++
	}
	slot.generationID = manager.nextGenerationID
	slot.remoteIP = http3RemoteIP(connection.RemoteAddr())
	connectionID := slot.connectionID
	slot.detector = newHTTP3DegradationDetector(now)
	slot.lastDecision = http3DegradationDecision{}
	if slot.lifecycle == http3TransportServing {
		wasDegraded := slot.health == http3TransportDegraded
		slot.health = http3TransportHealthy
		slot.rotationFailures = 0
		slot.retryAt = time.Time{}
		if wasDegraded && slot.replacement != nil && slot.replacement.lifecycle == http3TransportWarming &&
			slot.replacement.active == 0 {
			closeCandidate = slot.replacement
			slot.replacement = nil
			closeCandidate.replaces = nil
			closeCandidate.lifecycle = http3TransportFailed
			manager.removeSlotLocked(key, closeCandidate)
			manager.recordHTTP3RotationEventLocked(key, string(slot.rotationReason), "recovered")
		}
		if wasDegraded {
			recovered = manager.onRecovered
		}
	}
	if slot.lastPayloadProgress.Load() == 0 {
		slot.lastPayloadProgress.Store(now.UnixNano())
	}
	if recovered != nil {
		// Reserve publication order while the transport state lock still defines
		// it, then invoke the cross-manager callback only after releasing mu.
		manager.observerMu.Lock()
	}
	manager.mu.Unlock()
	if closeCandidate != nil {
		closeCandidate.close()
	}
	if recovered != nil {
		recovered(key)
		manager.observerMu.Unlock()
	}

	go func() {
		<-connection.Context().Done()
		manager.observeHTTP3ConnectionClosed(key, slot, connection, connectionID, context.Cause(connection.Context()))
	}()
}

func (manager *http3ConnectManager) observeHTTP3ConnectionClosed(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	connection http3StatsConnection,
	connectionID uint64,
	cause error,
) {
	if cause == nil {
		cause = context.Canceled
	}
	manager.applyHTTP3DegradationSample(http3DegradationSnapshot{
		key:          key,
		slot:         slot,
		connection:   connection,
		connectionID: connectionID,
	}, http3DegradationSample{
		At:            manager.timeNow(),
		ConnectionErr: cause,
	})
	manager.publishHTTP3RuleSample(http3DegradationSnapshot{
		key:          key,
		slot:         slot,
		connection:   connection,
		connectionID: connectionID,
	}, http3DegradationSample{
		At:            manager.timeNow(),
		ConnectionErr: cause,
	})
}

func (manager *http3ConnectManager) startHTTP3SamplerLocked() {
	if manager == nil || manager.retired || manager.samplerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	manager.samplerCancel = cancel
	manager.samplerDone = done
	go func() {
		defer close(done)
		ticker := time.NewTicker(http3DegradationSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Ticker values are scheduled timestamps and may be stale after the
				// process is descheduled or the host resumes from sleep. Sampling at
				// processing time lets the detector reset on the real long gap.
				manager.sampleHTTP3DegradationAt(manager.timeNow())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (manager *http3ConnectManager) detachHTTP3SamplerLocked() (context.CancelFunc, <-chan struct{}) {
	if manager == nil {
		return nil, nil
	}
	cancel := manager.samplerCancel
	done := manager.samplerDone
	manager.samplerCancel = nil
	manager.samplerDone = nil
	return cancel, done
}

func stopHTTP3Sampler(cancel context.CancelFunc, done <-chan struct{}) {
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (manager *http3ConnectManager) sampleHTTP3DegradationAt(now time.Time) {
	if manager == nil || now.IsZero() {
		return
	}
	manager.mu.Lock()
	if manager.retired {
		manager.mu.Unlock()
		return
	}
	snapshots := make([]http3DegradationSnapshot, 0)
	for key, slots := range manager.transports {
		for _, slot := range slots {
			if slot == nil || slot.lifecycle != http3TransportServing || slot.connection == nil {
				continue
			}
			pending := int(slot.pendingWrites.Load())
			peakBlocked := int(slot.maxBlockedWrites.Swap(int64(pending)))
			if pending > peakBlocked {
				peakBlocked = pending
			}
			tunnels := make([]*http3TunnelStats, 0, len(slot.tunnels))
			for tunnel := range slot.tunnels {
				tunnels = append(tunnels, tunnel)
			}
			payloadBytes := saturatingAdd(slot.payloadRead.Load(), slot.payloadWritten.Load())
			payloadRead := slot.payloadRead.Load()
			if payloadBytes > slot.lastSampledPayload {
				slot.lastPayloadProgress.Store(now.UnixNano())
			}
			slot.lastSampledPayload = payloadBytes
			snapshots = append(snapshots, http3DegradationSnapshot{
				key:          key,
				slot:         slot,
				connection:   slot.connection,
				connectionID: slot.connectionID,
				payloadBytes: payloadBytes,
				payloadRead:  payloadRead,
				blocked:      pending,
				peakBlocked:  peakBlocked,
				tunnels:      tunnels,
				historical:   manager.healthyRTT[key],
			})
		}
	}
	manager.mu.Unlock()

	for _, snapshot := range snapshots {
		sample := http3DegradationSample{
			At:                    now,
			Stats:                 snapshot.connection.ConnectionStats(),
			PayloadBytes:          snapshot.payloadBytes,
			PayloadReadBytes:      snapshot.payloadRead,
			BlockedWrites:         snapshot.blocked,
			PeakBlockedWrites:     snapshot.peakBlocked,
			HistoricalBaselineRTT: snapshot.historical,
		}
		sample.OldestBlockedFor, sample.LongBlockedWrites = http3BlockedWriteDurations(now, snapshot.tunnels)
		sample.BlockedReads, sample.OldestReadBlockedFor, sample.RecentReadDemand =
			http3BlockedReadDemand(now, snapshot.tunnels)
		lastProgress := snapshot.slot.lastPayloadProgress.Load()
		if demandStarted := snapshot.slot.demandStarted.Load(); demandStarted > lastProgress {
			lastProgress = demandStarted
		}
		if lastProgress > 0 {
			sample.LastPayloadProgressAt = time.Unix(0, lastProgress)
		}
		if err := context.Cause(snapshot.connection.Context()); err != nil {
			sample.ConnectionErr = err
		}
		manager.applyHTTP3DegradationSample(snapshot, sample)
		manager.publishHTTP3RuleSample(snapshot, sample)
	}
}

func (manager *http3ConnectManager) applyHTTP3DegradationSample(
	snapshot http3DegradationSnapshot,
	sample http3DegradationSample,
) {
	if manager == nil || snapshot.slot == nil {
		return
	}
	var transition *http3DegradationLogEvent
	var degraded func(http3ConnectTransportKey, http3DegradationReason)
	var connectionDegraded func(http3RuleDegradationEvent)
	var connectionEvent http3RuleDegradationEvent
	var udpBlackhole func(http3UDPBlackholeEvent)
	var udpBlackholeEvent http3UDPBlackholeEvent
	manager.mu.Lock()
	slot := snapshot.slot
	if manager.retired || !manager.containsSlotLocked(snapshot.key, slot) ||
		slot.connection != snapshot.connection || slot.connectionID != snapshot.connectionID ||
		slot.lifecycle != http3TransportServing {
		manager.mu.Unlock()
		return
	}
	if slot.detector == nil {
		slot.detector = newHTTP3DegradationDetector(sample.At)
	}
	sample.HistoricalBaselineRTT = manager.healthyRTT[snapshot.key]
	decision := slot.detector.observe(sample)
	slot.lastDecision = decision
	if decision.Signals.Sampled && !decision.Signals.Warmup && !decision.Signals.RTTBad &&
		!decision.Signals.LossBad && !decision.Signals.PayloadStalled && sample.Stats.MinRTT > 0 {
		manager.learnHealthyHTTP3RTTLocked(snapshot.key, sample.Stats.MinRTT)
	}
	if !decision.Rotate {
		if decision.Signals.Warmup {
			slot.health = http3TransportHealthy
		} else if decision.Signals.BadSignalCount > 0 {
			slot.health = http3TransportSuspect
		} else {
			slot.health = http3TransportHealthy
		}
		manager.mu.Unlock()
		return
	}
	firstDegradation := slot.health != http3TransportDegraded
	blackholeUpgrade := !firstDegradation && decision.Reason == http3DegradationReasonUDPBlackhole &&
		slot.rotationReason != http3DegradationReasonUDPBlackhole
	if firstDegradation || blackholeUpgrade {
		slot.health = http3TransportDegraded
		slot.rotationReason = decision.Reason
		manager.recordHTTP3RotationEventLocked(snapshot.key, string(decision.Reason), "detected")
		transition = &http3DegradationLogEvent{key: snapshot.key, decision: decision}
		if firstDegradation {
			if !manager.hasHealthyHTTP3ServingSlotLocked(snapshot.key) {
				degraded = manager.onDegraded
			}
			connectionDegraded = manager.onConnectionDegraded
			connectionEvent = http3RuleDegradationEvent{
				key:          snapshot.key,
				remoteIP:     slot.remoteIP,
				generationID: slot.generationID,
				at:           sample.At,
				reason:       decision.Reason,
			}
		}
		if decision.Reason == http3DegradationReasonUDPBlackhole {
			udpBlackhole = manager.onUDPBlackhole
			udpBlackholeEvent = http3UDPBlackholeEvent{
				key:          snapshot.key,
				slot:         slot,
				connectionID: slot.connectionID,
				generationID: slot.generationID,
				probes:       make([]http3UDPBlackholeProbe, 0, len(slot.tunnels)),
			}
			for tunnel := range slot.tunnels {
				if tunnel == nil || tunnel.closed.Load() {
					continue
				}
				// A complete UDP blackhole is physical-connection scoped. Include
				// every active rule on this QUIC generation, even if this stream is
				// idle or only just blocked. The drain monitor still applies the full
				// per-stream stall timeout and confirmations before cancellation.
				udpBlackholeEvent.probes = append(udpBlackholeEvent.probes, http3UDPBlackholeProbe{
					ruleName:    tunnel.ruleName,
					target:      tunnel.target,
					destination: tunnel.destination,
					userAgent:   tunnel.userAgent,
				})
			}
		}
	}
	candidate, err := manager.ensureHTTP3RotationCandidateLocked(snapshot.key, slot, sample.At)
	if err != nil {
		manager.recordHTTP3RotationEventLocked(snapshot.key, string(decision.Reason), "candidate_failed")
		if transition == nil {
			transition = &http3DegradationLogEvent{key: snapshot.key, decision: decision, err: err}
		} else {
			transition.err = err
		}
	} else if transition != nil {
		transition.candidateCreated = candidate != nil
		if candidate == nil {
			manager.recordHTTP3RotationEventLocked(snapshot.key, string(decision.Reason), "candidate_deferred")
		}
	}
	if degraded != nil {
		manager.observerMu.Lock()
	}
	manager.mu.Unlock()
	if transition != nil {
		logHTTP3DegradationTransition(*transition)
	}
	if degraded != nil {
		degraded(snapshot.key, transition.decision.Reason)
		manager.observerMu.Unlock()
	}
	if connectionDegraded != nil {
		connectionDegraded(connectionEvent)
	}
	if udpBlackhole != nil && len(udpBlackholeEvent.probes) > 0 {
		udpBlackhole(udpBlackholeEvent)
	}
}

func (manager *http3ConnectManager) hasHealthyHTTP3ServingSlotLocked(key http3ConnectTransportKey) bool {
	for _, slot := range manager.transports[key] {
		if slot != nil && slot.lifecycle == http3TransportServing && slot.health == http3TransportHealthy {
			return true
		}
	}
	return false
}

func http3BlockedWriteDurations(now time.Time, tunnels []*http3TunnelStats) (time.Duration, int) {
	var oldest time.Duration
	longBlocked := 0
	for _, tunnel := range tunnels {
		if tunnel == nil {
			continue
		}
		started := tunnel.writeStarted.Load()
		if started <= 0 {
			continue
		}
		blockedFor := now.Sub(time.Unix(0, started))
		if blockedFor > oldest {
			oldest = blockedFor
		}
		if blockedFor >= http3DegradationMultiWriteBlock {
			longBlocked++
		}
	}
	return oldest, longBlocked
}

// http3BlockedReadDemand distinguishes an actively interrupted downstream flow
// from an ordinary idle CONNECT. Every idle tunnel can have a Read blocked in
// relayBidirectional, so a pending Read alone is never demand. The stream must
// also have transferred a meaningful amount of downstream payload recently.
func http3BlockedReadDemand(
	now time.Time,
	tunnels []*http3TunnelStats,
) (blocked int, oldest time.Duration, recent bool) {
	for _, tunnel := range tunnels {
		blockedFor, ok := http3TunnelReadBlockedFor(tunnel, now)
		if !ok {
			continue
		}
		blocked++
		if blockedFor > oldest {
			oldest = blockedFor
		}
		if http3TunnelHasRecentReadDemand(tunnel, now) {
			recent = true
		}
	}
	return blocked, oldest, recent
}

func http3TunnelReadBlockedFor(tunnel *http3TunnelStats, now time.Time) (time.Duration, bool) {
	if tunnel == nil || tunnel.pendingReads.Load() <= 0 {
		return 0, false
	}
	startedUnix := tunnel.readStarted.Load()
	if startedUnix <= 0 {
		return 0, false
	}
	started := time.Unix(0, startedUnix)
	if started.After(now) {
		return 0, false
	}
	return now.Sub(started), true
}

func http3TunnelHasRecentReadDemand(tunnel *http3TunnelStats, now time.Time) bool {
	if _, blocked := http3TunnelReadBlockedFor(tunnel, now); !blocked ||
		tunnel.payloadRead.Load() < http3UDPBlackholeRecentReadMinBytes {
		return false
	}
	progressUnix := tunnel.lastReadProgress.Load()
	if progressUnix <= 0 {
		return false
	}
	progressAt := time.Unix(0, progressUnix)
	return !progressAt.After(now) && now.Sub(progressAt) <= http3UDPBlackholeRecentReadWindow
}

func (manager *http3ConnectManager) learnHealthyHTTP3RTTLocked(key http3ConnectTransportKey, observed time.Duration) {
	if observed <= 0 {
		return
	}
	previous := manager.healthyRTT[key]
	if previous <= 0 {
		manager.healthyRTT[key] = observed
		return
	}
	manager.healthyRTT[key] = (previous*7 + observed) / 8
}

func (manager *http3ConnectManager) ensureHTTP3RotationCandidateLocked(
	key http3ConnectTransportKey,
	source *http3ConnectTransportSlot,
	now time.Time,
) (*http3ConnectTransportSlot, error) {
	if manager.retired || source == nil || source.lifecycle != http3TransportServing {
		return nil, nil
	}
	if source.replacement != nil && source.replacement.lifecycle == http3TransportWarming {
		source.replacement.rotationReason = source.rotationReason
		return source.replacement, nil
	}
	for _, slot := range manager.transports[key] {
		if slot != nil && slot.lifecycle == http3TransportWarming {
			if slot.replaces == source {
				slot.rotationReason = source.rotationReason
			}
			return slot, nil
		}
	}
	if now.Before(source.retryAt) {
		return nil, nil
	}
	maxTransports := manager.maxTransportsPerKey
	if maxTransports <= 0 {
		maxTransports = http3ConnectMaxTransportsPerKey
	}
	if len(manager.transports[key]) >= maxTransports {
		return nil, nil
	}
	limit := source.limit
	if limit <= 0 {
		limit = manager.streamsPerTransport
	}
	candidate, err := manager.newTransportSlotLocked(key, http3TransportWarming, limit)
	if err != nil {
		source.rotationFailures++
		source.retryAt = now.Add(http3RotationBackoff(source.rotationFailures))
		return nil, err
	}
	candidate.replaces = source
	candidate.rotationReason = source.rotationReason
	source.replacement = candidate
	manager.recordHTTP3RotationEventLocked(key, string(source.rotationReason), "candidate_created")
	return candidate, nil
}

func http3RotationBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := http3RotationBackoffBase
	for step := 1; step < failures && delay < http3RotationBackoffMax; step++ {
		delay *= 2
		if delay > http3RotationBackoffMax {
			delay = http3RotationBackoffMax
		}
	}
	return delay
}

func (manager *http3ConnectManager) markHTTP3CandidateFailed(
	key http3ConnectTransportKey,
	candidate *http3ConnectTransportSlot,
	cause error,
) (*http3ConnectTransportSlot, bool) {
	if manager == nil || candidate == nil {
		return nil, false
	}
	manager.mu.Lock()
	if candidate.lifecycle != http3TransportWarming || !manager.containsSlotLocked(key, candidate) {
		manager.mu.Unlock()
		return nil, false
	}
	candidate.lifecycle = http3TransportFailed
	source := candidate.replaces
	var retrySource *http3ConnectTransportSlot
	if source != nil && source.replacement == candidate {
		source.replacement = nil
		if source.lifecycle == http3TransportServing && manager.containsSlotLocked(key, source) && source.transport != nil {
			source.rotationFailures++
			source.retryAt = manager.timeNow().Add(http3RotationBackoff(source.rotationFailures))
			retrySource = source
		}
	}
	candidate.replaces = nil
	manager.recordHTTP3RotationEventLocked(key, string(candidate.rotationReason), "candidate_failed")
	retryAfter := http3RotationBackoff(max(1, sourceRotationFailures(source)))
	manager.mu.Unlock()
	if retrySource != nil {
		utils.Logger.Warn("HTTP/3 轮换候选建立失败，继续使用旧连接",
			zap.String("targetAddr", key.address),
			zap.Duration("retryAfter", retryAfter),
			zap.Error(cause))
	} else {
		utils.Logger.Warn("HTTP/3 轮换候选建立失败，旧连接已不可复用",
			zap.String("targetAddr", key.address),
			zap.Error(cause))
	}
	return retrySource, true
}

func sourceRotationFailures(source *http3ConnectTransportSlot) int {
	if source == nil {
		return 1
	}
	return source.rotationFailures
}

func (manager *http3ConnectManager) promoteHTTP3Candidate(
	key http3ConnectTransportKey,
	candidate *http3ConnectTransportSlot,
) {
	if manager == nil || candidate == nil {
		return
	}
	var closeSource *http3ConnectTransportSlot
	var forcedDrain *http3ForcedDrainMonitor
	var recovered func(http3ConnectTransportKey)
	manager.mu.Lock()
	if candidate.lifecycle != http3TransportWarming || !manager.containsSlotLocked(key, candidate) {
		manager.mu.Unlock()
		return
	}
	source := candidate.replaces
	candidate.replaces = nil
	candidate.health = http3TransportHealthy
	candidate.rotationFailures = 0
	candidate.retryAt = time.Time{}
	if manager.retired {
		candidate.lifecycle = http3TransportDraining
	} else {
		candidate.lifecycle = http3TransportServing
	}
	if source != nil {
		if source.replacement == candidate {
			source.replacement = nil
		}
		source.lifecycle = http3TransportDraining
		source.retryAt = time.Time{}
		source.rotationFailures = 0
		if source.active == 0 {
			manager.removeSlotLocked(key, source)
			closeSource = source
		} else {
			forcedDrain = manager.prepareHTTP3ForcedDrainLocked(key, source, manager.timeNow(), nil)
		}
	}
	manager.recordHTTP3RotationEventLocked(key, string(candidate.rotationReason), "promoted")
	newState := candidate.lifecycle
	if newState == http3TransportServing {
		recovered = manager.onRecovered
	}
	if recovered != nil {
		manager.observerMu.Lock()
	}
	manager.mu.Unlock()
	if closeSource != nil {
		closeSource.close()
	}
	if forcedDrain != nil {
		manager.startHTTP3ForcedDrainMonitor(forcedDrain)
	}
	if recovered != nil {
		recovered(key)
		manager.observerMu.Unlock()
	}
	utils.Logger.Info("HTTP/3 退化连接已平滑轮换",
		zap.String("targetAddr", key.address),
		zap.String("newState", string(newState)),
		zap.String("oldState", string(http3TransportDraining)))
}

func (manager *http3ConnectManager) registerHTTP3Tunnel(
	stats *http3TunnelStats,
) *http3TunnelStats {
	if manager == nil || stats == nil || stats.slot == nil {
		return nil
	}
	slot := stats.slot
	now := manager.timeNow()
	manager.mu.Lock()
	binding := http3RuleProbationBinding{}
	if slot.connection != nil && slot.generationID != 0 {
		binding = http3RuleProbationBinding{
			generationID: slot.generationID,
			remoteIP:     slot.remoteIP,
			stats:        slot.connection.ConnectionStats(),
			payloadBytes: saturatingAdd(slot.payloadRead.Load(), slot.payloadWritten.Load()),
		}
	}
	stats.probation = binding
	stats.lastPayloadProgress.Store(now.UnixNano())
	if slot.tunnels == nil {
		slot.tunnels = make(map[*http3TunnelStats]struct{})
	}
	slot.tunnels[stats] = struct{}{}
	manager.mu.Unlock()
	return stats
}

func (manager *http3ConnectManager) unregisterHTTP3Tunnel(slot *http3ConnectTransportSlot, stats *http3TunnelStats) {
	if manager == nil || slot == nil || stats == nil {
		return
	}
	stats.closed.Store(true)
	manager.mu.Lock()
	delete(slot.tunnels, stats)
	manager.mu.Unlock()
}

func (stats *http3TunnelStats) recordRead(bytes int) {
	if stats == nil || stats.slot == nil || bytes <= 0 {
		return
	}
	stats.payloadRead.Add(uint64(bytes))
	stats.slot.payloadRead.Add(uint64(bytes))
	now := time.Now().UnixNano()
	stats.lastReadProgress.Store(now)
	stats.lastPayloadProgress.Store(now)
}

func (stats *http3TunnelStats) beginRead() {
	if stats == nil || stats.slot == nil {
		return
	}
	now := time.Now().UnixNano()
	if stats.pendingReads.Add(1) == 1 {
		stats.readStarted.Store(now)
	}
}

func (stats *http3TunnelStats) finishRead(bytes int) {
	if stats == nil || stats.slot == nil {
		return
	}
	stats.recordRead(bytes)
	started := stats.readStarted.Load()
	if stats.pendingReads.Add(-1) == 0 {
		stats.readStarted.CompareAndSwap(started, 0)
	}
}

func (stats *http3TunnelStats) beginWrite() {
	if stats == nil || stats.slot == nil {
		return
	}
	now := time.Now().UnixNano()
	if stats.pending.Add(1) == 1 {
		stats.writeStarted.Store(now)
	}
	pending := stats.slot.pendingWrites.Add(1)
	if pending == 1 {
		stats.slot.demandStarted.Store(now)
	}
	for {
		maximum := stats.slot.maxBlockedWrites.Load()
		if pending <= maximum || stats.slot.maxBlockedWrites.CompareAndSwap(maximum, pending) {
			break
		}
	}
}

func (stats *http3TunnelStats) finishWrite(bytes int) {
	if stats == nil || stats.slot == nil {
		return
	}
	if bytes > 0 {
		stats.payloadWritten.Add(uint64(bytes))
		stats.slot.payloadWritten.Add(uint64(bytes))
		stats.lastPayloadProgress.Store(time.Now().UnixNano())
	}
	started := stats.writeStarted.Load()
	if stats.pending.Add(-1) == 0 {
		stats.writeStarted.CompareAndSwap(started, 0)
	}
	// beginWrite and finishWrite are strictly paired. A trailing Store(0) here
	// would be wrong: another tunnel may have incremented the shared counter
	// after this Add returned zero. demandStarted is overwritten whenever the
	// next 0->1 transition begins, so it needs no racy clearing operation.
	stats.slot.pendingWrites.Add(-1)
}

func (stats *http3TunnelStats) payloadBytes() uint64 {
	if stats == nil {
		return 0
	}
	return saturatingAdd(stats.payloadRead.Load(), stats.payloadWritten.Load())
}

// selectFastFail reserves the one stream-scoped cancellation. The hook is
// intentionally invoked by the drain monitor only after manager.mu is
// released; context cancellation and response-body closing may synchronously
// enter quic-go and must never run while the transport registry is locked.
func (stats *http3TunnelStats) selectFastFail() (func() bool, bool) {
	if stats == nil || stats.fastFail == nil || stats.closed.Load() ||
		!stats.fastFailSelected.CompareAndSwap(false, true) {
		return nil, false
	}
	return stats.fastFail, true
}

func (manager *http3ConnectManager) containsSlotLocked(key http3ConnectTransportKey, slot *http3ConnectTransportSlot) bool {
	for _, candidate := range manager.transports[key] {
		if candidate == slot {
			return true
		}
	}
	return false
}

func (manager *http3ConnectManager) removeSlotLocked(key http3ConnectTransportKey, slot *http3ConnectTransportSlot) bool {
	slots := manager.transports[key]
	for index, candidate := range slots {
		if candidate != slot {
			continue
		}
		last := len(slots) - 1
		slots[index] = slots[last]
		slots[last] = nil
		slots = slots[:last]
		if len(slots) == 0 {
			delete(manager.transports, key)
		} else {
			manager.transports[key] = slots
		}
		return true
	}
	return false
}

func (manager *http3ConnectManager) recordHTTP3RotationEventLocked(key http3ConnectTransportKey, reason, outcome string) {
	if reason == "" {
		reason = "unknown"
	}
	manager.rotationEvents[http3RotationMetricKey{target: key.address, reason: reason, outcome: outcome}]++
}

type http3DegradationLogEvent struct {
	key              http3ConnectTransportKey
	decision         http3DegradationDecision
	candidateCreated bool
	err              error
}

func logHTTP3DegradationTransition(event http3DegradationLogEvent) {
	signals := event.decision.Signals
	fields := []zap.Field{
		zap.String("targetAddr", event.key.address),
		zap.String("reason", string(event.decision.Reason)),
		zap.Duration("baselineRTT", signals.BaselineRTT),
		zap.Duration("smoothedRTT", signals.SmoothedRTT),
		zap.Float64("lossRate", signals.LossRate),
		zap.Int("blockedWrites", signals.BlockedWrites),
		zap.Int("blockedReads", signals.BlockedReads),
		zap.Duration("oldestBlockedFor", signals.OldestBlockedFor),
		zap.Bool("recentReadDemand", signals.ReadDemand),
		zap.Duration("oldestReadBlockedFor", signals.OldestReadBlockedFor),
		zap.Float64("payloadBytesPerSecond", signals.PayloadBytesPerSecond),
		zap.Bool("sentWithoutReceive", signals.SentNoReceive),
		zap.Duration("noReceiveFor", signals.NoReceiveFor),
		zap.Int("blackholeWindows", signals.BlackholeWindows),
	}
	if event.err != nil {
		fields = append(fields, zap.Error(event.err))
	}
	if event.err != nil {
		utils.Logger.Warn("检测到 HTTP/3 连接持续退化，但轮换候选创建失败", fields...)
		return
	}
	if event.candidateCreated {
		utils.Logger.Warn("检测到 HTTP/3 连接持续退化，已创建单个轮换候选", fields...)
		return
	}
	utils.Logger.Warn("检测到 HTTP/3 连接持续退化，轮换候选暂缓创建", fields...)
}

func (manager *http3ConnectManager) validateHTTP3RotationState() error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for key, slots := range manager.transports {
		warming := 0
		for _, slot := range slots {
			if slot != nil && slot.lifecycle == http3TransportWarming {
				warming++
			}
		}
		if warming > 1 {
			return fmt.Errorf("HTTP/3 target %s has %d warming candidates", key.address, warming)
		}
	}
	return nil
}
