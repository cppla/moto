package controller

import (
	"time"

	"moto/utils"

	"go.uber.org/zap"
)

const http3ForcedDrainStallTimeout = 30 * time.Second

// http3ForcedDrainMonitor belongs to one already-replaced physical QUIC
// connection. It is intentionally created only for terminal connection errors
// and severe loss accompanied by a blocked application write. Ordinary
// multi-signal degradation keeps the original graceful, unbounded drain.
type http3ForcedDrainMonitor struct {
	key            http3ConnectTransportKey
	slot           *http3ConnectTransportSlot
	connectionID   uint64
	reason         http3DegradationReason
	startedAt      time.Time
	lastPayload    uint64
	lastProgressAt time.Time
}

type http3ForcedDrainResult struct {
	closed        bool
	activeTunnels int
	blockedWrites int
	oldestBlocked time.Duration
	stalledFor    time.Duration
	drainingFor   time.Duration
	closeReason   string
}

func isHTTP3ForcedDrainReason(reason http3DegradationReason) bool {
	return reason == http3DegradationReasonSevereLossAndWrite ||
		reason == http3DegradationReasonConnectionError
}

// prepareHTTP3ForcedDrainLocked snapshots the last observed payload progress
// while manager.mu still protects the promotion transition. A payload update
// that occurred after the last sampler tick is treated as fresh progress.
func (manager *http3ConnectManager) prepareHTTP3ForcedDrainLocked(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	now time.Time,
) *http3ForcedDrainMonitor {
	if manager == nil || manager.retired || slot == nil || slot.active <= 0 ||
		slot.lifecycle != http3TransportDraining || !isHTTP3ForcedDrainReason(slot.rotationReason) {
		return nil
	}
	if slot.forcedDrainArmed && slot.forcedDrainConnID == slot.connectionID {
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
	}
	slot.forcedDrainArmed = true
	slot.forcedDrainConnID = slot.connectionID
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
			if monitor := manager.prepareHTTP3ForcedDrainLocked(key, slot, now); monitor != nil {
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

func (manager *http3ConnectManager) startHTTP3ForcedDrainMonitor(monitor *http3ForcedDrainMonitor) {
	if manager == nil || monitor == nil {
		return
	}
	utils.Logger.Info("HTTP/3 严重退化旧连接进入限时排空",
		zap.String("targetAddr", monitor.key.address),
		zap.String("reason", string(monitor.reason)),
		zap.Duration("stallTimeout", http3ForcedDrainStallTimeout))

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

// checkHTTP3ForcedDrainAt closes only when an affected old physical connection
// has active streams and no successful payload progress for the full bound.
// Severe-loss rotations additionally require a currently blocked Write that is
// itself at least as old as the bound. Idle tunnels and actively progressing
// downloads therefore remain on the graceful draining path.
func (manager *http3ConnectManager) checkHTTP3ForcedDrainAt(
	monitor *http3ForcedDrainMonitor,
	now time.Time,
) http3ForcedDrainResult {
	var result http3ForcedDrainResult
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
	}
	if !closeOld {
		manager.mu.Unlock()
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
		zap.Duration("oldestBlockedFor", result.oldestBlocked),
		zap.Duration("stalledFor", result.stalledFor),
		zap.Duration("drainingFor", result.drainingFor))
	return result
}
