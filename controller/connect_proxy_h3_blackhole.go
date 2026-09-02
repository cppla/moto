package controller

import (
	"context"
	"errors"
	"moto/config"
	"moto/utils"
	"time"

	"go.uber.org/zap"
)

const http3UDPBlackholeH2ProbeTimeout = 3 * time.Second

type http3UDPBlackholeScope struct {
	key          http3ConnectTransportKey
	slot         *http3ConnectTransportSlot
	connectionID uint64
}

type http3UDPBlackholeValidationResult uint8

const (
	http3UDPBlackholeValidationStale http3UDPBlackholeValidationResult = iota
	http3UDPBlackholeValidationPending
	http3UDPBlackholeValidationFailedOpen
	http3UDPBlackholeValidationCommitted
	http3UDPBlackholeValidationAlreadyCommitted
)

// noteHTTP3UDPBlackhole starts one bounded, internal H2 CONNECT validation per
// affected mixed-protocol rule. It is invoked by the sampler itself, so an
// already-stalled sole tunnel doesn't need a later client request to discover
// that H2 is usable. H3-only and H2-first targets deliberately stay fail-open.
func (manager *connectProxyManager) noteHTTP3UDPBlackhole(event http3UDPBlackholeEvent) {
	if manager == nil || manager.h3RuleBreaker == nil || len(event.probes) == 0 {
		return
	}
	seenRules := make(map[string]struct{}, len(event.probes))
	scope := http3UDPBlackholeScope{key: event.key, slot: event.slot, connectionID: event.connectionID}
	for _, probe := range event.probes {
		if probe.ruleName == "" || probe.destination == "" || !targetUsesMixedHTTP3First(probe.target) {
			continue
		}
		if _, seen := seenRules[probe.ruleName]; seen {
			continue
		}
		seenRules[probe.ruleName] = struct{}{}
		if !manager.beginMaintenanceWork() {
			return
		}
		token, claimed, alreadyValidated := manager.h3RuleBreaker.beginUDPBlackholeValidation(probe.ruleName, scope)
		if alreadyValidated {
			// A prior H2 response already proved the fallback. Arm the newly
			// blackholed physical slot immediately; repeating CONNECT would add
			// latency and unnecessary upstream work.
			armed := false
			if manager.h3 != nil {
				armed = manager.h3.armHTTP3ForcedDrainForBlackhole(scope, []string{probe.ruleName}, manager.timeNow())
			}
			retained := manager.h3RuleBreaker.finishUDPBlackholeArming(probe.ruleName, token, armed)
			outcome := "h2_validation_reused"
			if !armed || !retained {
				outcome = "h2_validation_stale"
			}
			manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, outcome)
			manager.maintenanceWG.Done()
			continue
		}
		if !claimed {
			manager.maintenanceWG.Done()
			continue
		}
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_started")
		go func() {
			defer manager.maintenanceWG.Done()
			manager.validateHTTP3UDPBlackholeFallback(event, probe, token)
		}()
	}
}

func (manager *connectProxyManager) validateHTTP3UDPBlackholeFallback(
	event http3UDPBlackholeEvent,
	probe http3UDPBlackholeProbe,
	token uint64,
) {
	base := manager.maintenanceCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, http3UDPBlackholeH2ProbeTimeout)
	defer cancel()
	ctx = withConnectProxyRuleName(ctx, probe.ruleName)
	ctx = withConnectProxyUserAgent(ctx, probe.userAgent)
	if manager.h3 == nil || !manager.retainActiveUDPBlackholeScopes(probe.ruleName, token) {
		return
	}

	dial := manager.dialers[config.ConnectProxyH2]
	var err error
	var reachable bool
	if dial == nil {
		err = errConnectProxyProtocolUnavailable
	} else {
		connection, dialErr := dial(ctx, probe.target, probe.destination)
		err = dialErr
		if connection != nil {
			reachable = true
			_ = connection.Close()
		}
		var statusErr *connectProxyStatusError
		if errors.As(dialErr, &statusErr) && connectProxyStatusProvesFallbackReachable(statusErr.statusCode) {
			// Route-neutral policy/DNS/service responses prove that the H2
			// forward-proxy handler is reachable, while this particular probe
			// tunnel still fails and is never reported as SOCKS success. Auth,
			// rate-limit, capability, and unknown responses are not usable fallback
			// evidence and leave H3 fail-open.
			reachable = true
		}
	}
	if ctx.Err() != nil {
		manager.h3RuleBreaker.abandonUDPBlackholeProbe(probe.ruleName, token)
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_stale")
		return
	}

	if !manager.retainActiveUDPBlackholeScopes(probe.ruleName, token) {
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_stale")
		return
	}
	result := manager.h3RuleBreaker.completeUDPBlackholeValidation(probe.ruleName, token, reachable)
	switch result {
	case http3UDPBlackholeValidationPending:
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_joined")
		return
	case http3UDPBlackholeValidationStale:
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_stale")
		return
	case http3UDPBlackholeValidationFailedOpen:
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_failed")
		utils.Logger.Warn("HTTP/3 UDP 黑洞后的 HTTP/2 回退验证不可达，保留旧 HTTP/3 隧道",
			zap.String("ruleName", probe.ruleName),
			zap.String("targetAddr", event.key.address),
			zap.Uint64("generation", event.generationID),
			zap.Error(err))
		return
	case http3UDPBlackholeValidationAlreadyCommitted:
		// A concurrent real H2 request already committed the same rule and
		// armed its drains through observeHTTP3RuleValidation. Do not mislabel
		// this maintenance completion as a failed probe.
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_joined")
		return
	case http3UDPBlackholeValidationCommitted:
		// Continue below and publish the transition owned by this probe.
	}
	scopes := manager.h3RuleBreaker.takeCommittedUDPBlackholes(probe.ruleName)
	armed := 0
	for _, committedScope := range scopes {
		if manager.h3.armHTTP3ForcedDrainForBlackhole(committedScope, []string{probe.ruleName}, manager.timeNow()) {
			armed++
		}
	}
	retained := manager.h3RuleBreaker.finishUDPBlackholeArming(probe.ruleName, token, armed > 0)
	if armed == 0 || !retained {
		manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_stale")
		return
	}
	manager.recordHTTP3MaintenanceEvent(event.key, http3DegradationReasonUDPBlackhole, "h2_validation_reachable")
	utils.Logger.Warn("HTTP/3 UDP 黑洞已确认，HTTP/2 回退可达并开始快速释放阻塞隧道",
		zap.String("ruleName", probe.ruleName),
		zap.String("targetAddr", event.key.address),
		zap.Uint64("generation", event.generationID),
		zap.Duration("retryAfter", http3RuleCooldownSteps[0]))
}

func (manager *connectProxyManager) retainActiveUDPBlackholeScopes(rule string, token uint64) bool {
	if manager == nil || manager.h3 == nil || manager.h3RuleBreaker == nil {
		return false
	}
	scopes := manager.h3RuleBreaker.udpBlackholeEvaluationScopes(rule, token)
	if len(scopes) == 0 && manager.h3RuleBreaker.udpBlackholeCommitMatches(rule, token) {
		return true
	}
	active := scopes[:0]
	for _, scope := range scopes {
		if manager.h3.http3BlackholeStillActive(scope) {
			active = append(active, scope)
		}
	}
	return manager.h3RuleBreaker.retainUDPBlackholeEvaluationScopes(rule, token, active)
}

func (breaker *http3RuleBreaker) udpBlackholeCommitMatches(rule string, token uint64) bool {
	if breaker == nil || rule == "" || token == 0 {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	return state != nil && state.phase == http3RuleBreakerCooldown && state.udpBlackholeCommitToken == token
}

func (manager *connectProxyManager) beginMaintenanceWork() bool {
	if manager == nil {
		return false
	}
	manager.maintenanceMu.Lock()
	defer manager.maintenanceMu.Unlock()
	if manager.maintenanceClosed {
		return false
	}
	manager.maintenanceWG.Add(1)
	return true
}

func (manager *connectProxyManager) stopMaintenance() {
	if manager == nil {
		return
	}
	manager.maintenanceMu.Lock()
	if !manager.maintenanceClosed {
		manager.maintenanceClosed = true
		if manager.cancelMaintenance != nil {
			manager.cancelMaintenance()
		}
	}
	manager.maintenanceMu.Unlock()
	manager.maintenanceWG.Wait()
}

func (manager *connectProxyManager) recordHTTP3MaintenanceEvent(
	key http3ConnectTransportKey,
	reason http3DegradationReason,
	outcome string,
) {
	if manager == nil || manager.h3 == nil {
		return
	}
	manager.h3.mu.Lock()
	manager.h3.recordHTTP3RotationEventLocked(key, string(reason), outcome)
	manager.h3.mu.Unlock()
}

// beginUDPBlackholeValidation owns the single proactive H2 probe for a rule.
// It also makes concurrent real requests bypass H3 while that bounded probe is
// running. An existing validation participant wins instead of being duplicated.
func (breaker *http3RuleBreaker) beginUDPBlackholeValidation(
	rule string,
	scope http3UDPBlackholeScope,
) (uint64, bool, bool) {
	if breaker == nil || rule == "" {
		return 0, false, false
	}
	now := breaker.now()
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	memberships := breaker.endpointRules[scope.key]
	if state == nil || scope.slot == nil {
		return 0, false, false
	}
	if _, registered := memberships[rule]; !registered {
		return 0, false, false
	}
	breaker.expireEvaluationLocked(state, now)
	switch state.phase {
	case http3RuleBreakerClosed:
		state.phase = http3RuleBreakerEvaluating
		state.evaluationToken = breaker.nextTokenLocked()
		state.evaluationInFlight = 0
		state.evaluationReachable = false
		state.evaluationDeadline = time.Time{}
		state.evaluationBlackholes = nil
		state.committedBlackholes = nil
		state.evaluationBlackholeOwned = true
		state.events["validation_started"]++
	case http3RuleBreakerEvaluating:
		breaker.appendUDPBlackholeScopeLocked(state, scope)
		if state.evaluationInFlight > 0 {
			return state.evaluationToken, false, false
		}
	case http3RuleBreakerCooldown:
		if !now.Before(state.retryAt) {
			breaker.reenterCooldownLocked(state)
			state.events["cooldown_extended"]++
			return 0, false, true
		}
		if state.udpBlackholeCommitToken != 0 {
			state.udpBlackholeArmInFlight++
			return state.udpBlackholeCommitToken, false, true
		}
		return 0, false, true
	case http3RuleBreakerProbation:
		// Probation is only entered after H2 has already been proven reachable.
		// A blackhole on another endpoint or QUIC generation therefore needs no
		// duplicate H2 probe: extend cooldown and arm this exact generation.
		breaker.reenterCooldownLocked(state)
		state.events["probation_failed"]++
		return 0, false, true
	default:
		return 0, false, false
	}
	breaker.appendUDPBlackholeScopeLocked(state, scope)
	state.evaluationInFlight++
	state.evaluationDeadline = now.Add(http3UDPBlackholeH2ProbeTimeout)
	return state.evaluationToken, true, false
}

// completeUDPBlackholeValidation commits cooldown only with positive H2
// transport evidence. If this was the last validation participant and H2 was
// unreachable, it immediately fails open to H3 instead of waiting for another
// request or a lazy metrics scrape to expire the evaluating phase.
func (breaker *http3RuleBreaker) completeUDPBlackholeValidation(
	rule string,
	token uint64,
	h2Reachable bool,
) http3UDPBlackholeValidationResult {
	if breaker == nil || rule == "" || token == 0 {
		return http3UDPBlackholeValidationStale
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state != nil && state.phase == http3RuleBreakerCooldown {
		return http3UDPBlackholeValidationAlreadyCommitted
	}
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationToken != token ||
		state.evaluationInFlight <= 0 {
		return http3UDPBlackholeValidationStale
	}
	if breaker.expireEvaluationLocked(state, breaker.now()) {
		return http3UDPBlackholeValidationStale
	}
	state.evaluationInFlight--
	if h2Reachable {
		state.committedBlackholes = append(state.committedBlackholes[:0], state.evaluationBlackholes...)
		state.phase = http3RuleBreakerCooldown
		state.failures = 1
		state.retryAt = breaker.now().Add(http3RuleCooldownSteps[0])
		state.evaluationToken = 0
		state.evaluationInFlight = 0
		state.evaluationReachable = false
		state.evaluationDeadline = time.Time{}
		state.evaluationBlackholes = nil
		state.evaluationBlackholeOwned = false
		state.udpBlackholeCommitToken = token
		state.udpBlackholeArmInFlight = 1
		state.udpBlackholeArmed = false
		state.routeProbeToken = 0
		state.routeProbeKey = http3ConnectTransportKey{}
		state.events["opened"]++
		return http3UDPBlackholeValidationCommitted
	}
	if state.evaluationInFlight > 0 {
		return http3UDPBlackholeValidationPending
	}
	state.phase = http3RuleBreakerClosed
	state.failures = 0
	state.retryAt = time.Time{}
	state.evaluationToken = 0
	state.evaluationReachable = false
	state.evaluationDeadline = time.Time{}
	state.evaluationBlackholes = nil
	state.evaluationBlackholeOwned = false
	state.committedBlackholes = nil
	state.udpBlackholeCommitToken = 0
	state.udpBlackholeArmInFlight = 0
	state.udpBlackholeArmed = false
	state.routeProbeToken = 0
	state.routeProbeKey = http3ConnectTransportKey{}
	state.events["validation_failed"]++
	return http3UDPBlackholeValidationFailedOpen
}

func (breaker *http3RuleBreaker) appendUDPBlackholeScopeLocked(
	state *http3RuleBreakerState,
	scope http3UDPBlackholeScope,
) {
	if state == nil || scope.slot == nil {
		return
	}
	for _, existing := range state.evaluationBlackholes {
		if existing.key == scope.key && existing.slot == scope.slot && existing.connectionID == scope.connectionID {
			return
		}
	}
	state.evaluationBlackholes = append(state.evaluationBlackholes, scope)
}

func (breaker *http3RuleBreaker) takeCommittedUDPBlackholes(rule string) []http3UDPBlackholeScope {
	if breaker == nil || rule == "" {
		return nil
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || len(state.committedBlackholes) == 0 {
		return nil
	}
	scopes := append([]http3UDPBlackholeScope(nil), state.committedBlackholes...)
	state.committedBlackholes = nil
	return scopes
}

func (breaker *http3RuleBreaker) udpBlackholeEvaluationScopes(
	rule string,
	token uint64,
) []http3UDPBlackholeScope {
	if breaker == nil || rule == "" || token == 0 {
		return nil
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationToken != token {
		return nil
	}
	return append([]http3UDPBlackholeScope(nil), state.evaluationBlackholes...)
}

func (breaker *http3RuleBreaker) retainUDPBlackholeEvaluationScopes(
	rule string,
	token uint64,
	active []http3UDPBlackholeScope,
) bool {
	if breaker == nil || rule == "" || token == 0 {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationToken != token {
		return false
	}
	state.evaluationBlackholes = append(state.evaluationBlackholes[:0], active...)
	if len(active) > 0 {
		return true
	}
	if state.evaluationInFlight > 0 {
		state.evaluationInFlight--
	}
	if state.evaluationBlackholeOwned {
		breaker.resetUDPBlackholeEvaluationLocked(state)
	}
	return false
}

func (breaker *http3RuleBreaker) abandonUDPBlackholeProbe(rule string, token uint64) {
	if breaker == nil || rule == "" || token == 0 {
		return
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationToken != token {
		return
	}
	if state.evaluationInFlight > 0 {
		state.evaluationInFlight--
	}
	if state.evaluationBlackholeOwned {
		breaker.resetUDPBlackholeEvaluationLocked(state)
	}
}

func (breaker *http3RuleBreaker) resetUDPBlackholeEvaluationLocked(state *http3RuleBreakerState) {
	if state == nil {
		return
	}
	state.phase = http3RuleBreakerClosed
	state.failures = 0
	state.retryAt = time.Time{}
	state.evaluationToken = 0
	state.evaluationInFlight = 0
	state.evaluationReachable = false
	state.evaluationDeadline = time.Time{}
	state.evaluationBlackholes = nil
	state.evaluationBlackholeOwned = false
	state.committedBlackholes = nil
	state.udpBlackholeCommitToken = 0
	state.udpBlackholeArmInFlight = 0
	state.udpBlackholeArmed = false
	state.routeProbeToken = 0
	state.routeProbeKey = http3ConnectTransportKey{}
}

func (breaker *http3RuleBreaker) finishUDPBlackholeArming(rule string, token uint64, armed bool) bool {
	if token == 0 {
		return true
	}
	if breaker == nil || rule == "" || token == 0 {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerCooldown || state.udpBlackholeCommitToken != token {
		return false
	}
	if state.udpBlackholeArmInFlight > 0 {
		state.udpBlackholeArmInFlight--
	}
	if armed {
		state.udpBlackholeArmed = true
	}
	if state.udpBlackholeArmInFlight == 0 && !state.udpBlackholeArmed {
		breaker.resetUDPBlackholeEvaluationLocked(state)
		state.events["validation_stale"]++
		return false
	}
	return true
}
