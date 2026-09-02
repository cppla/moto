package controller

import (
	"context"
	"moto/config"
	"moto/utils"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

const (
	http3RuleDegradationWindow     = time.Minute
	http3RuleValidationGrace       = 30 * time.Second
	http3RuleProbationAbortDelay   = 30 * time.Second
	http3RuleProbationMinDuration  = 30 * time.Second
	http3RuleProbationMaxDuration  = 90 * time.Second
	http3RuleProbationMinPayload   = uint64(512 << 10)
	http3RuleProbationMinPackets   = uint64(256)
	http3RuleProbationHealthyCount = 3
	http3RuleRouteProbeTokenMask   = uint64(1) << 63
)

var http3RuleCooldownSteps = [...]time.Duration{
	5 * time.Minute,
	10 * time.Minute,
	20 * time.Minute,
	30 * time.Minute,
}

type http3RuleProbationContextKey struct{}

func withHTTP3RuleProbation(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, http3RuleProbationContextKey{}, true)
}

func http3RuleProbationFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	probation, _ := ctx.Value(http3RuleProbationContextKey{}).(bool)
	return probation
}

type http3RuleDegradationEvent struct {
	key          http3ConnectTransportKey
	remoteIP     string
	generationID uint64
	at           time.Time
	reason       http3DegradationReason
}

type http3RuleSampleEvent struct {
	key           http3ConnectTransportKey
	remoteIP      string
	generationID  uint64
	at            time.Time
	stats         quic.ConnectionStats
	payloadBytes  uint64
	decision      http3DegradationDecision
	connectionErr error
}

type http3RuleProbationBinding struct {
	generationID uint64
	remoteIP     string
	stats        quic.ConnectionStats
	payloadBytes uint64
}

type http3RuleProbationBindable interface {
	http3RuleProbationBinding() (http3RuleProbationBinding, bool)
}

type http3RuleBreakerPhase uint8

const (
	http3RuleBreakerClosed http3RuleBreakerPhase = iota
	http3RuleBreakerEvaluating
	http3RuleBreakerCooldown
	http3RuleBreakerProbation
)

type http3RuleProbationState struct {
	token          uint64
	key            http3ConnectTransportKey
	generationID   uint64
	remoteIP       string
	establishedAt  time.Time
	initialStats   quic.ConnectionStats
	initialPayload uint64
	payloadBytes   uint64
	packetsSent    uint64
	healthySamples int
	lastHealthyAt  time.Time
	established    bool
}

type http3RuleBreakerState struct {
	phase                    http3RuleBreakerPhase
	failures                 int
	retryAt                  time.Time
	recent                   []http3RuleDegradationEvent
	probation                http3RuleProbationState
	evaluationToken          uint64
	evaluationInFlight       int
	evaluationReachable      bool
	evaluationDeadline       time.Time
	evaluationBlackholes     []http3UDPBlackholeScope
	evaluationBlackholeOwned bool
	committedBlackholes      []http3UDPBlackholeScope
	udpBlackholeCommitToken  uint64
	udpBlackholeArmInFlight  int
	udpBlackholeArmed        bool
	routeProbeToken          uint64
	routeProbeKey            http3ConnectTransportKey
	events                   map[string]uint64
}

type http3RuleBreaker struct {
	mu            sync.Mutex
	now           func() time.Time
	nextToken     uint64
	rules         map[string]*http3RuleBreakerState
	endpointRules map[http3ConnectTransportKey]map[string]struct{}
}

func newHTTP3RuleBreaker(now func() time.Time) *http3RuleBreaker {
	if now == nil {
		now = time.Now
	}
	return &http3RuleBreaker{
		now:           now,
		rules:         make(map[string]*http3RuleBreakerState),
		endpointRules: make(map[http3ConnectTransportKey]map[string]struct{}),
	}
}

func targetUsesMixedHTTP3First(target *config.Target) bool {
	if target == nil || target.ConnectProxy == nil || len(target.ConnectProxy.Protocols) == 0 ||
		target.ConnectProxy.Protocols[0] != config.ConnectProxyH3 {
		return false
	}
	return protocolAppearsAfter(target.ConnectProxy.Protocols, 0, config.ConnectProxyH2)
}

func (manager *connectProxyManager) registerHTTP3RuleTarget(rule string, target *config.Target) {
	if manager == nil || manager.h3RuleBreaker == nil || rule == "" || !targetUsesMixedHTTP3First(target) {
		return
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3RuleBreaker.register(rule, key)
}

func (breaker *http3RuleBreaker) register(rule string, key http3ConnectTransportKey) {
	if breaker == nil || rule == "" {
		return
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	if breaker.endpointRules[key] == nil {
		breaker.endpointRules[key] = make(map[string]struct{})
	}
	breaker.endpointRules[key][rule] = struct{}{}
	if breaker.rules[rule] == nil {
		breaker.rules[rule] = &http3RuleBreakerState{events: make(map[string]uint64)}
	}
}

func (manager *connectProxyManager) beginHTTP3RuleAttempt(ctx context.Context, rule string, target *config.Target) (uint64, bool, bool) {
	if manager == nil || manager.h3RuleBreaker == nil || rule == "" || !targetUsesMixedHTTP3First(target) {
		return 0, false, true
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	return manager.h3RuleBreaker.beginWithLease(rule, key, routeProtocolProbeTokenFromContext(ctx))
}

func (breaker *http3RuleBreaker) begin(rule string, key http3ConnectTransportKey) (uint64, bool, bool) {
	return breaker.beginWithLease(rule, key, 0)
}

func (breaker *http3RuleBreaker) beginWithLease(
	rule string,
	key http3ConnectTransportKey,
	routeProbeToken uint64,
) (uint64, bool, bool) {
	if breaker == nil || rule == "" {
		return 0, false, true
	}
	now := breaker.now()
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase == http3RuleBreakerClosed {
		return 0, false, true
	}
	if state.phase == http3RuleBreakerEvaluating {
		if breaker.expireEvaluationLocked(state, now) {
			return 0, false, true
		}
		// A cached Boost route can fail before its serial fallback target is
		// started. Keep the validation cohort open for a short, bounded grace
		// period so that fallback can join the same token instead of trying H3
		// again. The deadline starts with the first real H2 attempt, not with the
		// degradation event, because traffic may be idle when degradation is
		// detected.
		if state.evaluationDeadline.IsZero() {
			state.evaluationDeadline = now.Add(http3RuleValidationGrace)
		}
		state.evaluationInFlight++
		return state.evaluationToken, false, false
	}
	if state.phase == http3RuleBreakerProbation || now.Before(state.retryAt) {
		return 0, false, false
	}
	if state.routeProbeToken != 0 &&
		(state.routeProbeToken != routeProbeToken || state.routeProbeKey != key) {
		return 0, false, false
	}
	state.routeProbeToken = 0
	state.routeProbeKey = http3ConnectTransportKey{}
	token := breaker.nextTokenLocked()
	state.phase = http3RuleBreakerProbation
	state.retryAt = time.Time{}
	state.probation = http3RuleProbationState{
		token:         token,
		key:           key,
		establishedAt: now,
	}
	state.evaluationBlackholes = nil
	state.evaluationBlackholeOwned = false
	state.committedBlackholes = nil
	state.udpBlackholeCommitToken = 0
	state.udpBlackholeArmInFlight = 0
	state.udpBlackholeArmed = false
	state.events["probation_started"]++
	return token, true, true
}

func (breaker *http3RuleBreaker) bypassing(rule string) bool {
	if breaker == nil || rule == "" {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state != nil {
		breaker.expireEvaluationLocked(state, breaker.now())
	}
	return state != nil && (state.phase == http3RuleBreakerEvaluating ||
		state.phase == http3RuleBreakerCooldown && (breaker.now().Before(state.retryAt) || state.routeProbeToken != 0) ||
		state.phase == http3RuleBreakerProbation)
}

func (breaker *http3RuleBreaker) recoveryProbeDue(rule string, now time.Time) bool {
	if breaker == nil || rule == "" {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	return state != nil && state.phase == http3RuleBreakerCooldown && !now.Before(state.retryAt) &&
		state.routeProbeToken == 0
}

// restrictsOrdinaryH3 reports whether a rule-level breaker currently allows at
// most its single mixed-protocol recovery probation to use H3. Route selection
// uses this only to avoid an H3-only target bypassing the rule-wide decision;
// the protocol dialer remains the source of truth and still fails open when no
// H2-capable route is available.
func (breaker *http3RuleBreaker) restrictsOrdinaryH3(rule string, now time.Time) bool {
	if breaker == nil || rule == "" {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil {
		return false
	}
	breaker.expireEvaluationLocked(state, now)
	return state.phase == http3RuleBreakerEvaluating || state.phase == http3RuleBreakerCooldown ||
		state.phase == http3RuleBreakerProbation
}

func (breaker *http3RuleBreaker) claimRecoveryRouteProbe(
	rule string,
	key http3ConnectTransportKey,
	now time.Time,
) (uint64, bool) {
	if breaker == nil || rule == "" {
		return 0, false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerCooldown || now.Before(state.retryAt) ||
		state.routeProbeToken != 0 {
		return 0, false
	}
	token := breaker.nextTokenLocked() | http3RuleRouteProbeTokenMask
	state.routeProbeToken = token
	state.routeProbeKey = key
	return token, true
}

func (breaker *http3RuleBreaker) releaseRecoveryRouteProbe(rule string, token uint64) bool {
	if breaker == nil || rule == "" || token&http3RuleRouteProbeTokenMask == 0 {
		return false
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state != nil && state.routeProbeToken == token {
		state.routeProbeToken = 0
		state.routeProbeKey = http3ConnectTransportKey{}
		// The lease was released before beginWithLease consumed it, so no H3
		// packet reached the network. Briefly defer another route probe just like
		// a non-network probation abort; this also lets selectors that lost the
		// claim refresh to stable H2-safe penalties instead of admitting H3-only.
		state.retryAt = breaker.now().Add(http3RuleProbationAbortDelay)
		state.events["probation_aborted"]++
	}
	return true
}

func (breaker *http3RuleBreaker) nextTokenLocked() uint64 {
	breaker.nextToken++
	if breaker.nextToken == 0 {
		breaker.nextToken++
	}
	return breaker.nextToken
}

func (manager *connectProxyManager) establishHTTP3RuleProbation(
	rule string,
	target *config.Target,
	token uint64,
	connection net.Conn,
) net.Conn {
	if manager == nil || manager.h3RuleBreaker == nil || token == 0 || connection == nil || target == nil || target.ConnectProxy == nil {
		return connection
	}
	bindable, ok := connection.(http3RuleProbationBindable)
	if !ok {
		manager.failHTTP3RuleProbation(rule, token, "missing_transport_evidence")
		return connection
	}
	binding, ok := bindable.http3RuleProbationBinding()
	if !ok {
		manager.failHTTP3RuleProbation(rule, token, "missing_transport_evidence")
		return connection
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	if !manager.h3RuleBreaker.establish(rule, token, key, binding) {
		return connection
	}
	return &http3RuleProbationConn{
		Conn: connection,
		onClose: func() {
			manager.failHTTP3RuleProbation(rule, token, "insufficient_evidence")
		},
	}
}

func (breaker *http3RuleBreaker) establish(
	rule string,
	token uint64,
	key http3ConnectTransportKey,
	binding http3RuleProbationBinding,
) bool {
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerProbation || state.probation.token != token ||
		state.probation.key != key || binding.generationID == 0 {
		return false
	}
	state.probation.generationID = binding.generationID
	state.probation.remoteIP = binding.remoteIP
	state.probation.initialStats = binding.stats
	state.probation.initialPayload = binding.payloadBytes
	state.probation.establishedAt = breaker.now()
	state.probation.established = true
	return true
}

func (manager *connectProxyManager) failHTTP3RuleProbation(rule string, token uint64, reason string) {
	if manager == nil || manager.h3RuleBreaker == nil || token == 0 {
		return
	}
	manager.h3RuleBreaker.failProbation(rule, token, reason)
}

func (manager *connectProxyManager) abortHTTP3RuleProbation(rule string, token uint64, reason string) {
	if manager == nil || manager.h3RuleBreaker == nil || token == 0 {
		return
	}
	manager.h3RuleBreaker.abortProbation(rule, token, reason)
}

func (breaker *http3RuleBreaker) abortProbation(rule string, token uint64, reason string) {
	if breaker == nil || rule == "" || token == 0 {
		return
	}
	breaker.mu.Lock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerProbation || state.probation.token != token {
		breaker.mu.Unlock()
		return
	}
	state.phase = http3RuleBreakerCooldown
	state.retryAt = breaker.now().Add(http3RuleProbationAbortDelay)
	state.probation = http3RuleProbationState{}
	state.evaluationBlackholes = nil
	state.evaluationBlackholeOwned = false
	state.committedBlackholes = nil
	state.udpBlackholeCommitToken = 0
	state.udpBlackholeArmInFlight = 0
	state.udpBlackholeArmed = false
	state.routeProbeToken = 0
	state.routeProbeKey = http3ConnectTransportKey{}
	state.events["probation_aborted"]++
	breaker.mu.Unlock()
	utils.Logger.Info("HTTP/3 规则级恢复探测未触达网络，稍后重试",
		zap.String("ruleName", rule),
		zap.String("reason", reason),
		zap.Duration("retryAfter", http3RuleProbationAbortDelay))
}

func (manager *connectProxyManager) observeHTTP3RuleValidation(
	rule string,
	token uint64,
	parentErr error,
	h2Reachable bool,
) {
	if manager == nil || manager.h3RuleBreaker == nil || token == 0 {
		return
	}
	if manager.h3RuleBreaker.observeValidation(rule, token, parentErr, h2Reachable) && manager.h3 != nil {
		scopes := manager.h3RuleBreaker.takeCommittedUDPBlackholes(rule)
		if len(scopes) > 0 {
			armed := 0
			for _, scope := range scopes {
				if manager.h3.armHTTP3ForcedDrainForBlackhole(scope, []string{rule}, manager.timeNow()) {
					armed++
				}
			}
			manager.h3RuleBreaker.finishUDPBlackholeArming(rule, token, armed > 0)
		} else {
			manager.h3.armHTTP3ForcedDrainsForBreaker(
				manager.h3RuleBreaker.endpointKeysForRules([]string{rule}),
				[]string{rule},
				manager.timeNow(),
			)
		}
	}
}

func (breaker *http3RuleBreaker) observeValidation(
	rule string,
	token uint64,
	_ error,
	h2Reachable bool,
) bool {
	if breaker == nil || rule == "" || token == 0 {
		return false
	}
	committed := false
	aborted := false
	breaker.mu.Lock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationToken != token ||
		state.evaluationInFlight <= 0 {
		breaker.mu.Unlock()
		return false
	}
	// Enforce the validation deadline before accepting transport evidence. A
	// response that arrives after the bounded serial grace belongs to a stale
	// cohort and must not reopen cooldown merely because no newer request (or
	// metrics scrape) happened to expire the state first.
	if breaker.expireEvaluationLocked(state, breaker.now()) {
		breaker.mu.Unlock()
		utils.Logger.Warn("HTTP/2 回退路径验证已超时，规则级 HTTP/3 保持可用",
			zap.String("ruleName", rule))
		return false
	}
	state.evaluationInFlight--
	// Receiving any syntactically valid H2 response already proves that the
	// fallback transport is reachable. A sibling Boost winner may cancel this
	// request immediately afterwards; that cancellation must not discard the
	// transport evidence that was already observed.
	if h2Reachable {
		state.evaluationReachable = true
	}
	if state.evaluationReachable {
		committingToken := state.evaluationToken
		state.phase = http3RuleBreakerCooldown
		state.failures = 1
		state.retryAt = breaker.now().Add(http3RuleCooldownSteps[0])
		state.evaluationToken = 0
		state.evaluationInFlight = 0
		state.evaluationReachable = false
		state.evaluationDeadline = time.Time{}
		state.committedBlackholes = append(state.committedBlackholes[:0], state.evaluationBlackholes...)
		state.evaluationBlackholes = nil
		state.evaluationBlackholeOwned = false
		if len(state.committedBlackholes) > 0 {
			state.udpBlackholeCommitToken = committingToken
			state.udpBlackholeArmInFlight = 1
			state.udpBlackholeArmed = false
		} else {
			state.udpBlackholeCommitToken = 0
			state.udpBlackholeArmInFlight = 0
			state.udpBlackholeArmed = false
		}
		state.routeProbeToken = 0
		state.routeProbeKey = http3ConnectTransportKey{}
		state.events["opened"]++
		committed = true
	} else if breaker.expireEvaluationLocked(state, breaker.now()) {
		aborted = true
	}
	breaker.mu.Unlock()
	if committed {
		utils.Logger.Warn("HTTP/2 回退路径验证可达，规则级 HTTP/3 进入冷却",
			zap.String("ruleName", rule),
			zap.Duration("retryAfter", http3RuleCooldownSteps[0]))
	} else if aborted {
		utils.Logger.Warn("HTTP/2 回退路径不可达，规则级 HTTP/3 保持可用",
			zap.String("ruleName", rule))
	}
	return committed
}

// expireEvaluationLocked enforces a hard upper bound on H2 validation. Once the
// serial-fallback grace period elapses, new requests must be allowed to fail
// open to H3 even if older H2 participants are still completing. Their stale
// token observations become harmless no-ops. The caller must hold breaker.mu.
func (breaker *http3RuleBreaker) expireEvaluationLocked(state *http3RuleBreakerState, now time.Time) bool {
	if state == nil || state.phase != http3RuleBreakerEvaluating || state.evaluationDeadline.IsZero() ||
		now.Before(state.evaluationDeadline) {
		return false
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
	state.events["validation_failed"]++
	return true
}

func (breaker *http3RuleBreaker) failProbation(rule string, token uint64, reason string) {
	if breaker == nil || rule == "" || token == 0 {
		return
	}
	breaker.mu.Lock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerProbation || state.probation.token != token {
		breaker.mu.Unlock()
		return
	}
	delay := breaker.reenterCooldownLocked(state)
	state.events["probation_failed"]++
	breaker.mu.Unlock()
	utils.Logger.Warn("HTTP/3 规则级恢复探测未通过，继续使用 HTTP/2",
		zap.String("ruleName", rule),
		zap.String("reason", reason),
		zap.Duration("retryAfter", delay))
}

func (breaker *http3RuleBreaker) reenterCooldownLocked(state *http3RuleBreakerState) time.Duration {
	if state.failures < len(http3RuleCooldownSteps) {
		state.failures++
	}
	if state.failures < 1 {
		state.failures = 1
	}
	delay := http3RuleCooldownSteps[min(state.failures, len(http3RuleCooldownSteps))-1]
	state.phase = http3RuleBreakerCooldown
	state.retryAt = breaker.now().Add(delay)
	state.probation = http3RuleProbationState{}
	state.evaluationBlackholes = nil
	state.evaluationBlackholeOwned = false
	state.committedBlackholes = nil
	state.udpBlackholeCommitToken = 0
	state.udpBlackholeArmInFlight = 0
	state.udpBlackholeArmed = false
	state.routeProbeToken = 0
	state.routeProbeKey = http3ConnectTransportKey{}
	return delay
}

func (manager *connectProxyManager) noteHTTP3RuleDegradation(event http3RuleDegradationEvent) {
	if manager == nil || manager.h3RuleBreaker == nil {
		return
	}
	openedRules := manager.h3RuleBreaker.noteDegradation(event)
	if len(openedRules) == 0 || manager.h3 == nil {
		return
	}
	if event.reason == http3DegradationReasonUDPBlackhole {
		// The dedicated callback runs immediately after this state transition and
		// scopes the drain to the exact blackholed QUIC generation. The generic
		// rule-wide drain would unnecessarily touch unrelated degraded endpoints.
		return
	}
	for _, rule := range openedRules {
		manager.h3.armHTTP3ForcedDrainsForBreaker(
			manager.h3RuleBreaker.endpointKeysForRules([]string{rule}),
			[]string{rule},
			manager.timeNow(),
		)
	}
}

func (breaker *http3RuleBreaker) noteDegradation(event http3RuleDegradationEvent) []string {
	if breaker == nil || event.key.address == "" {
		return nil
	}
	if event.at.IsZero() {
		event.at = breaker.now()
	}
	type openedRule struct {
		name       string
		delay      time.Duration
		evaluating bool
	}
	var opened []openedRule
	breaker.mu.Lock()
	for rule := range breaker.endpointRules[event.key] {
		state := breaker.rules[rule]
		if state == nil {
			continue
		}
		breaker.expireEvaluationLocked(state, event.at)
		if state.phase == http3RuleBreakerProbation && state.probation.generationID == event.generationID &&
			state.probation.key == event.key {
			delay := breaker.reenterCooldownLocked(state)
			state.events["probation_failed"]++
			opened = append(opened, openedRule{name: rule, delay: delay})
			continue
		}
		if state.phase != http3RuleBreakerClosed {
			continue
		}
		cutoff := event.at.Add(-http3RuleDegradationWindow)
		kept := state.recent[:0]
		duplicateGeneration := false
		for _, previous := range state.recent {
			if !previous.at.Before(cutoff) {
				kept = append(kept, previous)
				if previous.key == event.key && previous.generationID != 0 && previous.generationID == event.generationID {
					duplicateGeneration = true
				}
			}
		}
		state.recent = kept
		if duplicateGeneration {
			continue
		}
		state.recent = append(state.recent, event)
		if !http3RuleShouldOpen(state.recent, event) {
			continue
		}
		state.failures = 0
		state.phase = http3RuleBreakerEvaluating
		state.retryAt = time.Time{}
		state.probation = http3RuleProbationState{}
		state.evaluationToken = breaker.nextTokenLocked()
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
		state.events["validation_started"]++
		opened = append(opened, openedRule{name: rule, evaluating: true})
	}
	breaker.mu.Unlock()
	openedRules := make([]string, 0, len(opened))
	for _, transition := range opened {
		if transition.evaluating {
			utils.Logger.Warn("检测到规则级 HTTP/3 路径持续退化，开始验证 HTTP/2 回退路径",
				zap.String("ruleName", transition.name),
				zap.String("targetAddr", event.key.address),
				zap.String("remoteIP", event.remoteIP),
				zap.String("reason", string(event.reason)))
			continue
		}
		openedRules = append(openedRules, transition.name)
		utils.Logger.Warn("检测到规则级 HTTP/3 路径持续退化，新连接暂时使用 HTTP/2",
			zap.String("ruleName", transition.name),
			zap.String("targetAddr", event.key.address),
			zap.String("remoteIP", event.remoteIP),
			zap.String("reason", string(event.reason)),
			zap.Duration("retryAfter", transition.delay))
	}
	return openedRules
}

func (breaker *http3RuleBreaker) endpointKeysForRules(rules []string) []http3ConnectTransportKey {
	if breaker == nil || len(rules) == 0 {
		return nil
	}
	wanted := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		wanted[rule] = struct{}{}
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	keys := make([]http3ConnectTransportKey, 0)
	for key, memberships := range breaker.endpointRules {
		for rule := range memberships {
			if _, ok := wanted[rule]; ok {
				keys = append(keys, key)
				break
			}
		}
	}
	return keys
}

func http3RuleShouldOpen(events []http3RuleDegradationEvent, current http3RuleDegradationEvent) bool {
	for _, previous := range events {
		if previous.generationID == current.generationID && previous.key == current.key {
			continue
		}
		distance := current.at.Sub(previous.at)
		if distance < 0 {
			distance = -distance
		}
		if distance > http3RuleDegradationWindow {
			continue
		}
		if current.remoteIP != "" && previous.remoteIP != "" && current.remoteIP != previous.remoteIP {
			return true
		}
		if previous.generationID != 0 && current.generationID != 0 && previous.generationID != current.generationID &&
			(previous.key == current.key || current.remoteIP != "" && current.remoteIP == previous.remoteIP) {
			return true
		}
	}
	return false
}

func (manager *connectProxyManager) noteHTTP3RuleSample(event http3RuleSampleEvent) {
	if manager == nil || manager.h3RuleBreaker == nil {
		return
	}
	manager.h3RuleBreaker.noteSample(event)
}

func (breaker *http3RuleBreaker) noteSample(event http3RuleSampleEvent) {
	if breaker == nil || event.generationID == 0 {
		return
	}
	if event.at.IsZero() {
		event.at = breaker.now()
	}
	var recovered []string
	type failedRule struct {
		name   string
		delay  time.Duration
		reason string
	}
	var failed []failedRule
	breaker.mu.Lock()
	for rule := range breaker.endpointRules[event.key] {
		state := breaker.rules[rule]
		if state == nil || state.phase != http3RuleBreakerProbation || !state.probation.established ||
			state.probation.key != event.key || state.probation.generationID != event.generationID {
			continue
		}
		probe := &state.probation
		if event.connectionErr != nil || event.decision.Rotate {
			delay := breaker.reenterCooldownLocked(state)
			state.events["probation_failed"]++
			failed = append(failed, failedRule{name: rule, delay: delay, reason: "transport_degraded"})
			continue
		}
		if event.payloadBytes >= probe.initialPayload {
			probe.payloadBytes = event.payloadBytes - probe.initialPayload
		}
		if event.stats.PacketsSent >= probe.initialStats.PacketsSent {
			probe.packetsSent = event.stats.PacketsSent - probe.initialStats.PacketsSent
		}
		signals := event.decision.Signals
		// The transport sampler may wake a fraction before the minimum interval.
		// The degradation detector deliberately marks that observation unsampled;
		// it carries no path-quality evidence and must not erase healthy probation
		// samples collected on the surrounding ticks.
		if !signals.Sampled {
			continue
		}
		healthy := !signals.Warmup && !signals.RTTBad && !signals.LossBad &&
			!signals.PayloadStalled && signals.BlockedWrites == 0
		if healthy && (probe.lastHealthyAt.IsZero() || event.at.Sub(probe.lastHealthyAt) >= http3DegradationSampleInterval) {
			probe.healthySamples++
			probe.lastHealthyAt = event.at
		} else if !healthy {
			probe.healthySamples = 0
			probe.lastHealthyAt = time.Time{}
		}
		elapsed := event.at.Sub(probe.establishedAt)
		enoughData := probe.payloadBytes >= http3RuleProbationMinPayload || probe.packetsSent >= http3RuleProbationMinPackets
		if elapsed >= http3RuleProbationMinDuration && enoughData && probe.healthySamples >= http3RuleProbationHealthyCount {
			state.phase = http3RuleBreakerClosed
			state.failures = 0
			state.retryAt = time.Time{}
			state.recent = nil
			state.probation = http3RuleProbationState{}
			state.evaluationBlackholes = nil
			state.evaluationBlackholeOwned = false
			state.committedBlackholes = nil
			state.udpBlackholeCommitToken = 0
			state.udpBlackholeArmInFlight = 0
			state.udpBlackholeArmed = false
			state.routeProbeToken = 0
			state.routeProbeKey = http3ConnectTransportKey{}
			state.events["recovered"]++
			recovered = append(recovered, rule)
			continue
		}
		if elapsed >= http3RuleProbationMaxDuration {
			delay := breaker.reenterCooldownLocked(state)
			state.events["probation_failed"]++
			failed = append(failed, failedRule{name: rule, delay: delay, reason: "insufficient_evidence"})
		}
	}
	breaker.mu.Unlock()
	for _, rule := range recovered {
		utils.Logger.Info("HTTP/3 规则级数据面验证通过，恢复新连接使用 HTTP/3",
			zap.String("ruleName", rule))
	}
	for _, transition := range failed {
		utils.Logger.Warn("HTTP/3 规则级数据面验证未通过，继续使用 HTTP/2",
			zap.String("ruleName", transition.name),
			zap.String("reason", transition.reason),
			zap.Duration("retryAfter", transition.delay))
	}
}

func (manager *http3ConnectManager) publishHTTP3RuleSample(
	snapshot http3DegradationSnapshot,
	sample http3DegradationSample,
) {
	if manager == nil || snapshot.slot == nil {
		return
	}
	manager.mu.Lock()
	slot := snapshot.slot
	if !manager.containsSlotLocked(snapshot.key, slot) || slot.connection != snapshot.connection ||
		slot.connectionID != snapshot.connectionID {
		manager.mu.Unlock()
		return
	}
	callback := manager.onConnectionSample
	event := http3RuleSampleEvent{
		key:           snapshot.key,
		remoteIP:      slot.remoteIP,
		generationID:  slot.generationID,
		at:            sample.At,
		stats:         sample.Stats,
		payloadBytes:  sample.PayloadBytes,
		decision:      slot.lastDecision,
		connectionErr: sample.ConnectionErr,
	}
	manager.mu.Unlock()
	if callback != nil {
		callback(event)
	}
}

func (manager *http3ConnectManager) acquireHTTP3RuleProbationTransport(
	key http3ConnectTransportKey,
) (*http3.Transport, *http3ConnectTransportSlot, func(), error) {
	manager.mu.Lock()
	var selected *http3ConnectTransportSlot
	warmingExists := false
	for _, slot := range manager.transports[key] {
		if slot != nil && slot.lifecycle == http3TransportWarming {
			warmingExists = true
			if slot.active == 0 {
				selected = slot
				break
			}
		}
	}
	if selected == nil {
		if warmingExists {
			manager.mu.Unlock()
			return nil, nil, nil, errConnectProxyProtocolCapacity
		}
		maximum := manager.maxTransportsPerKey
		if maximum <= 0 {
			maximum = http3ConnectMaxTransportsPerKey
		}
		if len(manager.transports[key]) >= maximum {
			manager.mu.Unlock()
			return nil, nil, nil, errConnectProxyProtocolCapacity
		}
		limit := manager.streamsPerTransport
		if limit <= 0 {
			limit = http3ConnectStreamsPerTransport
		}
		var err error
		selected, err = manager.newTransportSlotLocked(key, http3TransportWarming, limit)
		if err != nil {
			manager.mu.Unlock()
			return nil, nil, nil, err
		}
		selected.rotationReason = http3DegradationReason("rule_probation")
		for _, source := range manager.transports[key] {
			if source != nil && source != selected && source.lifecycle == http3TransportServing && source.replacement == nil {
				selected.replaces = source
				source.replacement = selected
				break
			}
		}
	}
	selected.active++
	manager.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() { manager.releaseTransport(key, selected) })
	}
	return selected.transport, selected, release, nil
}

func http3RemoteIP(address net.Addr) string {
	if address == nil {
		return ""
	}
	if udp, ok := address.(*net.UDPAddr); ok && udp.IP != nil {
		return udp.IP.String()
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		host = address.String()
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

type http3RuleProbationConn struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (conn *http3RuleProbationConn) Close() error {
	if conn == nil || conn.Conn == nil {
		return nil
	}
	err := conn.Conn.Close()
	conn.closeOnce.Do(func() {
		if conn.onClose != nil {
			conn.onClose()
		}
	})
	return err
}

func (conn *http3RuleProbationConn) CloseWrite() error {
	if conn == nil || conn.Conn == nil {
		return nil
	}
	if closeWriter, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

type http3RuleBreakerGauge struct {
	rule           string
	phase          string
	cooldown       bool
	remaining      time.Duration
	probeDue       bool
	probeInFlight  bool
	evaluating     bool
	probation      bool
	healthySamples int
	payloadBytes   uint64
	packetsSent    uint64
	events         map[string]uint64
}

func (breaker *http3RuleBreaker) snapshot() []http3RuleBreakerGauge {
	if breaker == nil {
		return nil
	}
	now := breaker.now()
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	result := make([]http3RuleBreakerGauge, 0, len(breaker.rules))
	for rule, state := range breaker.rules {
		if state == nil {
			continue
		}
		breaker.expireEvaluationLocked(state, now)
		gauge := http3RuleBreakerGauge{
			rule:           rule,
			phase:          state.phase.String(),
			cooldown:       state.phase == http3RuleBreakerCooldown && now.Before(state.retryAt),
			probeDue:       state.phase == http3RuleBreakerCooldown && !now.Before(state.retryAt) && state.routeProbeToken == 0,
			probeInFlight:  state.routeProbeToken != 0,
			evaluating:     state.phase == http3RuleBreakerEvaluating,
			probation:      state.phase == http3RuleBreakerProbation,
			healthySamples: state.probation.healthySamples,
			payloadBytes:   state.probation.payloadBytes,
			packetsSent:    state.probation.packetsSent,
			events:         make(map[string]uint64, len(state.events)),
		}
		if gauge.cooldown && now.Before(state.retryAt) {
			gauge.remaining = state.retryAt.Sub(now)
		}
		for outcome, count := range state.events {
			gauge.events[outcome] = count
		}
		result = append(result, gauge)
	}
	return result
}

func (phase http3RuleBreakerPhase) String() string {
	switch phase {
	case http3RuleBreakerEvaluating:
		return "evaluating"
	case http3RuleBreakerCooldown:
		return "cooldown"
	case http3RuleBreakerProbation:
		return "probation"
	default:
		return "closed"
	}
}
