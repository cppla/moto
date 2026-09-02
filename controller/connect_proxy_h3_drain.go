package controller

import (
	"time"

	"moto/utils"

	"go.uber.org/zap"
)

const (
	http3StreamFastFailStallTimeout  = 12 * time.Second
	http3StreamFastFailConfirmations = 2
	http3ForcedDrainStallTimeout     = 30 * time.Second
)

type http3ForcedDrainTunnelState struct {
	lastPayload    uint64
	lastProgressAt time.Time
	stalledSamples int
}

// http3ForcedDrainMonitor belongs to one physical QUIC connection for which a
// replacement path is already ready. Severe loss can cancel an individual
// stream after its own Write and payload progress both stall; a confirmed UDP
// blackhole can also cancel a recently active downstream Read. Connection errors
// retain only the existing 30-second whole-connection fallback. Ordinary
// multi-signal degradation keeps the original graceful, unbounded drain.
type http3ForcedDrainMonitor struct {
	key            http3ConnectTransportKey
	slot           *http3ConnectTransportSlot
	connectionID   uint64
	reason         http3DegradationReason
	startedAt      time.Time
	lastPayload    uint64
	lastProgressAt time.Time
	tunnels        map[*http3TunnelStats]*http3ForcedDrainTunnelState
	fastFailAll    bool
	fastFailRules  map[string]struct{}
}

type http3ForcedDrainResult struct {
	closed               bool
	activeTunnels        int
	blockedWrites        int
	blockedReads         int
	oldestBlocked        time.Duration
	oldestReadBlocked    time.Duration
	stalledFor           time.Duration
	drainingFor          time.Duration
	closeReason          string
	fastFailedTunnels    int
	fastFailedBlockedFor time.Duration
	fastFailedStalledFor time.Duration
}

func isHTTP3ForcedDrainReason(reason http3DegradationReason) bool {
	return reason == http3DegradationReasonSevereLossAndWrite ||
		reason == http3DegradationReasonUDPBlackhole ||
		reason == http3DegradationReasonConnectionError
}

func http3StreamFastFailTimeout(reason http3DegradationReason) time.Duration {
	if reason == http3DegradationReasonUDPBlackhole {
		return http3UDPBlackholeStallTimeout
	}
	return http3StreamFastFailStallTimeout
}

// A replacement QUIC promotion passes nil and makes every stream on the old
// physical connection eligible. A rule-level H2 breaker passes the validated
// mixed-protocol rules, so another rule sharing the same endpoint (including
// H3-only traffic) is never fast-failed merely because H2 was proven for its
// neighbor.
func (monitor *http3ForcedDrainMonitor) allowFastFailRulesLocked(rules []string) {
	if monitor == nil || monitor.fastFailAll {
		return
	}
	if rules == nil {
		monitor.fastFailAll = true
		clear(monitor.fastFailRules)
		return
	}
	if monitor.fastFailRules == nil {
		monitor.fastFailRules = make(map[string]struct{}, len(rules))
	}
	for _, rule := range rules {
		if rule != "" {
			monitor.fastFailRules[rule] = struct{}{}
		}
	}
}

func (monitor *http3ForcedDrainMonitor) streamFastFailEligibleLocked(tunnel *http3TunnelStats) bool {
	if monitor == nil || tunnel == nil {
		return false
	}
	if monitor.fastFailAll {
		return true
	}
	_, ok := monitor.fastFailRules[tunnel.ruleName]
	return ok
}

// prepareHTTP3ForcedDrainLocked snapshots the last observed payload progress
// while manager.mu still protects the promotion transition. A payload update
// that occurred after the last sampler tick is treated as fresh progress.
func (manager *http3ConnectManager) prepareHTTP3ForcedDrainLocked(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	now time.Time,
	fastFailRules []string,
) *http3ForcedDrainMonitor {
	if manager == nil || manager.retired || slot == nil || slot.active <= 0 ||
		slot.lifecycle != http3TransportDraining || !isHTTP3ForcedDrainReason(slot.rotationReason) {
		return nil
	}
	if slot.forcedDrainArmed && slot.forcedDrainConnID == slot.connectionID {
		if slot.forcedDrainMonitor != nil {
			slot.forcedDrainMonitor.allowFastFailRulesLocked(fastFailRules)
		}
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	payload := saturatingAdd(slot.payloadRead.Load(), slot.payloadWritten.Load())
	lastProgressAt := now
	if progressUnix := slot.lastPayloadProgress.Load(); progressUnix > 0 && payload <= slot.lastSampledPayload {
		observed := time.Unix(0, progressUnix)
		if !observed.After(now) {
			lastProgressAt = observed
		}
	}
	monitor := &http3ForcedDrainMonitor{
		key:            key,
		slot:           slot,
		connectionID:   slot.connectionID,
		reason:         slot.rotationReason,
		startedAt:      now,
		lastPayload:    payload,
		lastProgressAt: lastProgressAt,
		tunnels:        make(map[*http3TunnelStats]*http3ForcedDrainTunnelState, len(slot.tunnels)),
		fastFailRules:  make(map[string]struct{}),
	}
	monitor.allowFastFailRulesLocked(fastFailRules)
	for tunnel := range slot.tunnels {
		monitor.tunnels[tunnel] = newHTTP3ForcedDrainTunnelState(tunnel, now)
	}
	slot.forcedDrainArmed = true
	slot.forcedDrainConnID = slot.connectionID
	slot.forcedDrainMonitor = monitor
	manager.recordHTTP3RotationEventLocked(key, string(slot.rotationReason), "forced_drain_armed")
	return monitor
}

// armHTTP3ForcedDrainsForBreaker covers the case where a rule-level breaker
// starts bypassing H3 before a lazy rotation candidate receives a real CONNECT
// and can be promoted. Severe serving connections are moved to draining here;
// future requests for the cooled rule use H2, while an already in-flight H3
// candidate (or another rule sharing the endpoint) can still establish a fresh
// physical connection. Per-slot connection IDs make this operation idempotent.
func (manager *http3ConnectManager) armHTTP3ForcedDrainsForBreaker(
	keys []http3ConnectTransportKey,
	rules []string,
	now time.Time,
) {
	if manager == nil || len(keys) == 0 {
		return
	}
	if now.IsZero() {
		now = manager.timeNow()
	}
	wanted := make(map[http3ConnectTransportKey]struct{}, len(keys))
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	var monitors []*http3ForcedDrainMonitor
	var closeSlots []*http3ConnectTransportSlot
	manager.mu.Lock()
	if manager.retired {
		manager.mu.Unlock()
		return
	}
	for key := range wanted {
		for _, slot := range append([]*http3ConnectTransportSlot(nil), manager.transports[key]...) {
			if slot == nil || slot.health != http3TransportDegraded || !isHTTP3ForcedDrainReason(slot.rotationReason) ||
				(slot.lifecycle != http3TransportServing && slot.lifecycle != http3TransportDraining) {
				continue
			}
			slot.lifecycle = http3TransportDraining
			if slot.active == 0 {
				if manager.removeSlotLocked(key, slot) {
					closeSlots = append(closeSlots, slot)
				}
				continue
			}
			if monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, now, rules); monitor != nil {
				monitors = append(monitors, monitor)
			}
		}
	}
	manager.mu.Unlock()
	for _, slot := range closeSlots {
		slot.close()
	}
	for _, monitor := range monitors {
		manager.startHTTP3ForcedDrainMonitor(monitor)
	}
}

// armHTTP3ForcedDrainForBlackhole applies H2 reachability evidence only to the
// exact QUIC generation that produced the blackhole signal. A late probe can
// therefore never drain a recovered replacement or an unrelated target that
// merely belongs to the same routing rule.
func (manager *http3ConnectManager) armHTTP3ForcedDrainForBlackhole(
	scope http3UDPBlackholeScope,
	rules []string,
	now time.Time,
) bool {
	if manager == nil || scope.slot == nil {
		return false
	}
	if now.IsZero() {
		now = manager.timeNow()
	}
	var monitor *http3ForcedDrainMonitor
	var closeSlot *http3ConnectTransportSlot
	manager.mu.Lock()
	slot := scope.slot
	ruleScopedDraining := slot.lifecycle == http3TransportDraining &&
		slot.forcedDrainMonitor != nil && slot.forcedDrainConnID == scope.connectionID &&
		!slot.forcedDrainMonitor.fastFailAll
	if manager.retired || !manager.containsSlotLocked(scope.key, slot) ||
		slot.connectionID != scope.connectionID ||
		(slot.lifecycle != http3TransportServing && !ruleScopedDraining) ||
		slot.health != http3TransportDegraded || slot.rotationReason != http3DegradationReasonUDPBlackhole {
		manager.mu.Unlock()
		return false
	}
	wasServing := slot.lifecycle == http3TransportServing
	if wasServing {
		slot.lifecycle = http3TransportDraining
	}
	if slot.active == 0 {
		if manager.removeSlotLocked(scope.key, slot) {
			closeSlot = slot
		}
	} else {
		monitor = manager.prepareHTTP3ForcedDrainLocked(scope.key, slot, now, rules)
		// Another rule sharing this exact QUIC generation may finish its H2
		// validation after the first rule already armed the drain. In that case
		// prepareHTTP3ForcedDrainLocked extends the existing monitor's rule set
		// and intentionally returns nil so no duplicate goroutine is started.
		if !wasServing && slot.forcedDrainMonitor != nil &&
			slot.forcedDrainConnID == scope.connectionID {
			manager.mu.Unlock()
			return true
		}
	}
	manager.mu.Unlock()
	if closeSlot != nil {
		closeSlot.close()
	}
	if monitor != nil {
		manager.startHTTP3ForcedDrainMonitor(monitor)
	}
	return closeSlot != nil || monitor != nil
}

func (manager *http3ConnectManager) http3BlackholeStillActive(scope http3UDPBlackholeScope) bool {
	if manager == nil || scope.slot == nil {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	slot := scope.slot
	ruleScopedDraining := slot.lifecycle == http3TransportDraining &&
		slot.forcedDrainMonitor != nil && slot.forcedDrainConnID == scope.connectionID &&
		!slot.forcedDrainMonitor.fastFailAll
	return !manager.retired && manager.containsSlotLocked(scope.key, slot) &&
		slot.connectionID == scope.connectionID &&
		(slot.lifecycle == http3TransportServing || ruleScopedDraining) &&
		slot.health == http3TransportDegraded && slot.rotationReason == http3DegradationReasonUDPBlackhole
}

// noteHTTP3ServingTakeoverValidated broadens a rule-scoped drain only after a
// different serving QUIC has returned a syntactically valid CONNECT response.
// This covers an H3-only request that creates a normal serving slot after a
// mixed rule moved the shared old endpoint into H2 cooldown. Merely creating a
// slot or completing its QUIC handshake is not sufficient evidence.
func (manager *http3ConnectManager) noteHTTP3ServingTakeoverValidated(
	key http3ConnectTransportKey,
	serving *http3ConnectTransportSlot,
) {
	if manager == nil || serving == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.retired || serving.lifecycle != http3TransportServing ||
		!manager.containsSlotLocked(key, serving) {
		return
	}
	for _, slot := range manager.transports[key] {
		if slot == nil || slot == serving || slot.lifecycle != http3TransportDraining ||
			slot.forcedDrainMonitor == nil || slot.forcedDrainConnID != slot.connectionID {
			continue
		}
		slot.forcedDrainMonitor.allowFastFailRulesLocked(nil)
	}
}

func (manager *http3ConnectManager) startHTTP3ForcedDrainMonitor(monitor *http3ForcedDrainMonitor) {
	if manager == nil || monitor == nil {
		return
	}
	utils.Logger.Info("HTTP/3 严重退化旧连接进入限时排空",
		zap.String("targetAddr", monitor.key.address),
		zap.String("reason", string(monitor.reason)),
		zap.Duration("streamStallTimeout", http3StreamFastFailTimeout(monitor.reason)),
		zap.Int("streamConfirmations", http3StreamFastFailConfirmations),
		zap.Duration("connectionStallTimeout", http3ForcedDrainStallTimeout))

	// Check once before starting the ticker. An old stream may already have
	// exceeded the full stall bound while the replacement handshake completed.
	if manager.checkHTTP3ForcedDrainAt(monitor, manager.timeNow()).closed {
		return
	}
	go func() {
		ticker := time.NewTicker(http3DegradationSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case sampledAt := <-ticker.C:
				result := manager.checkHTTP3ForcedDrainAt(monitor, sampledAt)
				if result.closed || !manager.http3ForcedDrainStillActive(monitor) {
					return
				}
			case <-manager.dialCtx.Done():
				return
			}
		}
	}()
}

func (manager *http3ConnectManager) http3ForcedDrainStillActive(monitor *http3ForcedDrainMonitor) bool {
	if manager == nil || monitor == nil || monitor.slot == nil {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return !manager.retired && manager.containsSlotLocked(monitor.key, monitor.slot) &&
		monitor.slot.lifecycle == http3TransportDraining &&
		monitor.slot.connectionID == monitor.connectionID && monitor.slot.active > 0
}

// checkHTTP3ForcedDrainAt first selects severe-loss streams whose own Write and
// payload progress have both stalled for 12 seconds across consecutive samples.
// The cancellation hooks run only after manager.mu is released. The existing
// 30-second physical-connection fallback remains as a final bound; idle tunnels
// and actively progressing downloads stay on the graceful draining path.
func (manager *http3ConnectManager) checkHTTP3ForcedDrainAt(
	monitor *http3ForcedDrainMonitor,
	now time.Time,
) http3ForcedDrainResult {
	var result http3ForcedDrainResult
	type streamFastFail struct {
		cancel     func() bool
		blockedFor time.Duration
		stalledFor time.Duration
	}
	var fastFails []streamFastFail
	if manager == nil || monitor == nil || monitor.slot == nil || now.IsZero() {
		return result
	}
	slot := monitor.slot
	manager.mu.Lock()
	if manager.retired || !manager.containsSlotLocked(monitor.key, slot) ||
		slot.lifecycle != http3TransportDraining || slot.connectionID != monitor.connectionID || slot.active <= 0 {
		manager.mu.Unlock()
		return result
	}

	payload := saturatingAdd(slot.payloadRead.Load(), slot.payloadWritten.Load())
	if payload != monitor.lastPayload {
		monitor.lastPayload = payload
		monitor.lastProgressAt = now
	}
	if monitor.lastProgressAt.IsZero() || monitor.lastProgressAt.After(now) {
		monitor.lastProgressAt = now
	}
	result.activeTunnels = slot.active
	result.blockedWrites = int(slot.pendingWrites.Load())
	tunnels := make([]*http3TunnelStats, 0, len(slot.tunnels))
	for tunnel := range slot.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	result.oldestBlocked, _ = http3BlockedWriteDurations(now, tunnels)
	for tunnel := range monitor.tunnels {
		blockedFor, blocked := http3TunnelReadBlockedFor(tunnel, now)
		if !blocked {
			continue
		}
		result.blockedReads++
		if blockedFor > result.oldestReadBlocked {
			result.oldestReadBlocked = blockedFor
		}
	}
	result.stalledFor = now.Sub(monitor.lastProgressAt)
	result.drainingFor = now.Sub(monitor.startedAt)

	closeOld := false
	switch monitor.reason {
	case http3DegradationReasonConnectionError:
		closeOld = result.stalledFor >= http3ForcedDrainStallTimeout
		result.closeReason = "connection_error_no_payload_progress"
	case http3DegradationReasonSevereLossAndWrite:
		closeOld = result.blockedWrites > 0 &&
			result.oldestBlocked >= http3ForcedDrainStallTimeout &&
			result.stalledFor >= http3ForcedDrainStallTimeout
		result.closeReason = "severe_loss_blocked_write_no_payload_progress"
	case http3DegradationReasonUDPBlackhole:
		writeStalled := result.blockedWrites > 0 && result.oldestBlocked >= http3ForcedDrainStallTimeout
		readStalled := result.blockedReads > 0 && result.oldestReadBlocked >= http3ForcedDrainStallTimeout
		closeOld = (writeStalled || readStalled) &&
			result.stalledFor >= http3ForcedDrainStallTimeout
		result.closeReason = "udp_blackhole_blocked_stream_no_payload_progress"
	}
	if closeOld && !monitor.fastFailAll {
		eligible := 0
		for tunnel := range slot.tunnels {
			if monitor.streamFastFailEligibleLocked(tunnel) {
				eligible++
			}
		}
		// active also includes a CONNECT that acquired this transport but has not
		// published its tunnel stats yet. A rule-scoped H2 breaker cannot prove
		// that request belongs to the validated mixed rule, so keep the physical
		// QUIC alive unless every active user is known to be eligible.
		if eligible != slot.active {
			closeOld = false
		}
	}
	if !closeOld && (monitor.reason == http3DegradationReasonSevereLossAndWrite ||
		monitor.reason == http3DegradationReasonUDPBlackhole) {
		streamStallTimeout := http3StreamFastFailTimeout(monitor.reason)
		activeTunnels := make(map[*http3TunnelStats]struct{}, len(slot.tunnels))
		for tunnel := range slot.tunnels {
			activeTunnels[tunnel] = struct{}{}
			if !monitor.streamFastFailEligibleLocked(tunnel) {
				continue
			}
			state := monitor.tunnels[tunnel]
			if state == nil {
				state = newHTTP3ForcedDrainTunnelState(tunnel, now)
				monitor.tunnels[tunnel] = state
			}
			payload := tunnel.payloadBytes()
			if payload != state.lastPayload {
				state.lastPayload = payload
				state.lastProgressAt = now
				state.stalledSamples = 0
			} else if observed := http3TunnelLastProgressAt(tunnel, now); observed.After(state.lastProgressAt) {
				state.lastProgressAt = observed
				state.stalledSamples = 0
			}

			writeBlockedFor := time.Duration(0)
			startedUnix := tunnel.writeStarted.Load()
			if tunnel.pending.Load() > 0 && startedUnix > 0 {
				started := time.Unix(0, startedUnix)
				if !started.After(now) {
					writeBlockedFor = now.Sub(started)
				}
			}
			readBlockedFor := time.Duration(0)
			if monitor.reason == http3DegradationReasonUDPBlackhole {
				if duration, blocked := http3TunnelReadBlockedFor(tunnel, now); blocked {
					readBlockedFor = duration
				}
			}
			blockedFor := max(writeBlockedFor, readBlockedFor)
			stalledFor := time.Duration(0)
			if !state.lastProgressAt.IsZero() && !state.lastProgressAt.After(now) {
				stalledFor = now.Sub(state.lastProgressAt)
			}
			if blockedFor < streamStallTimeout || stalledFor < streamStallTimeout ||
				tunnel.fastFailSelected.Load() || tunnel.closed.Load() {
				state.stalledSamples = 0
				continue
			}
			state.stalledSamples++
			if state.stalledSamples < http3StreamFastFailConfirmations {
				continue
			}
			cancel, selected := tunnel.selectFastFail()
			if !selected {
				continue
			}
			fastFails = append(fastFails, streamFastFail{
				cancel:     cancel,
				blockedFor: blockedFor,
				stalledFor: stalledFor,
			})
		}
		for tunnel := range monitor.tunnels {
			if _, active := activeTunnels[tunnel]; !active {
				delete(monitor.tunnels, tunnel)
			}
		}
	}
	if !closeOld {
		manager.mu.Unlock()
		for _, fastFail := range fastFails {
			if !fastFail.cancel() {
				continue
			}
			result.fastFailedTunnels++
			if fastFail.blockedFor > result.fastFailedBlockedFor {
				result.fastFailedBlockedFor = fastFail.blockedFor
			}
			if fastFail.stalledFor > result.fastFailedStalledFor {
				result.fastFailedStalledFor = fastFail.stalledFor
			}
		}
		if result.fastFailedTunnels > 0 {
			manager.mu.Lock()
			for range result.fastFailedTunnels {
				manager.recordHTTP3RotationEventLocked(monitor.key, string(monitor.reason), "stream_fast_failed")
			}
			manager.mu.Unlock()
			utils.Logger.Warn("HTTP/3 退化旧连接中的阻塞隧道长期无数据推进，已快速失败",
				zap.String("targetAddr", monitor.key.address),
				zap.String("reason", string(monitor.reason)),
				zap.Int("tunnels", result.fastFailedTunnels),
				zap.Duration("oldestBlockedFor", result.fastFailedBlockedFor),
				zap.Duration("oldestStalledFor", result.fastFailedStalledFor))
		}
		return result
	}

	slot.lifecycle = http3TransportFailed
	manager.removeSlotLocked(monitor.key, slot)
	manager.recordHTTP3RotationEventLocked(monitor.key, string(monitor.reason), "forced_drain_closed")
	result.closed = true
	manager.mu.Unlock()

	slot.close()
	utils.Logger.Warn("HTTP/3 严重退化旧连接长期无数据推进，已强制排空",
		zap.String("targetAddr", monitor.key.address),
		zap.String("reason", string(monitor.reason)),
		zap.String("closeReason", result.closeReason),
		zap.Int("activeTunnels", result.activeTunnels),
		zap.Int("blockedWrites", result.blockedWrites),
		zap.Int("blockedReads", result.blockedReads),
		zap.Duration("oldestBlockedFor", result.oldestBlocked),
		zap.Duration("oldestReadBlockedFor", result.oldestReadBlocked),
		zap.Duration("stalledFor", result.stalledFor),
		zap.Duration("drainingFor", result.drainingFor))
	return result
}

func newHTTP3ForcedDrainTunnelState(
	tunnel *http3TunnelStats,
	now time.Time,
) *http3ForcedDrainTunnelState {
	return &http3ForcedDrainTunnelState{
		lastPayload:    tunnel.payloadBytes(),
		lastProgressAt: http3TunnelLastProgressAt(tunnel, now),
	}
}

func http3TunnelLastProgressAt(tunnel *http3TunnelStats, now time.Time) time.Time {
	if tunnel != nil {
		if progressUnix := tunnel.lastPayloadProgress.Load(); progressUnix > 0 {
			observed := time.Unix(0, progressUnix)
			if !observed.After(now) {
				return observed
			}
		}
	}
	return now
}
