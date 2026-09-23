package controller

import (
	"context"
	"errors"
	"moto/config"
	"sort"
	"sync"
	"time"

	xhttp2 "golang.org/x/net/http2"
)

const (
	routeLearningExploreInterval = 30 * time.Second
	routeLearningPreferenceHold  = 15 * time.Second
	routeLearningExploreMaxWait  = time.Second
	routeLearningConfirmLimit    = 2
	routeLearningPolicyLimit     = 256
)

type routeLearningContextKey struct{}
type routeLearningExplorerContextKey struct{}

func routeLearningExplorer(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	explorer, _ := ctx.Value(routeLearningExplorerContextKey{}).(bool)
	return explorer
}

func (runtime *routingRuntime) reconcileLearningBoostWinner(key string, token boostWinnerToken, choice routeLearningChoice, outcome cachedBoostOutcome, succeeded bool) (bool, boostWinnerToken) {
	// Exploration proves one alternative, not a new global best. It must not
	// overwrite the normal winner merely because it was deliberately first.
	if choice.reason == "explore" {
		return false, boostWinnerToken{}
	}
	if choice.reason == "quality" && token.generation == 0 {
		if succeeded && !outcome.cachedFailureNeutral {
			return false, runtime.storeBoostWinner(key, outcome.winner.addr)
		}
		return false, boostWinnerToken{}
	}
	return runtime.reconcileCachedBoostWinner(key, token, outcome, succeeded)
}

type routeLearningScope struct {
	learner *routeLearner
	rule    string
}

func withRouteLearningScope(ctx context.Context, learner *routeLearner, rule *config.Rule) context.Context {
	return context.WithValue(ctx, routeLearningContextKey{}, routeLearningScope{learner: learner, rule: boostRuleKey(rule)})
}

func observeRouteLearningSetup(ctx context.Context, target *config.Target, protocol string, elapsed time.Duration, err error, now time.Time) {
	scope, ok := ctx.Value(routeLearningContextKey{}).(routeLearningScope)
	if !ok || scope.learner == nil || target == nil || target.ConnectProxy == nil || errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	endpoint := routeLearningEndpoint{serverName: target.ConnectProxy.ServerName}
	if protocol == config.ConnectProxyH2 {
		endpoint.userAgent, _ = connectProxyUserAgentFromContext(ctx)
		endpoint.tlsProfile = http2TLSProfileForUserAgent(endpoint.userAgent)
	}
	scope.learner.observeEndpointSetup(routeLearningKey{rule: scope.rule, target: target.Address, protocol: protocol}, endpoint, elapsed, err, now)
}

// Only physical, independently confirmed events enter data-plane learning.
// Arbitrary relay EOF/reset and low payload volume are intentionally excluded.
func (runtime *routingRuntime) installRouteLearningObservers() {
	manager := runtime.connectProxy
	degraded := manager.h3.onConnectionDegraded
	manager.h3.onConnectionDegraded = func(event http3RuleDegradationEvent) {
		if runtime.ctx.Err() == nil {
			runtime.learning.observeEndpointDegradation(event.key.address, config.ConnectProxyH3,
				routeLearningEndpoint{serverName: event.key.serverName}, event.at)
		}
		if degraded != nil {
			degraded(event)
		}
	}
	manager.h2.newTransport = func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		previous := transport.CountError
		transport.CountError = func(kind string) {
			if previous != nil {
				previous(kind)
			}
			// The physical pool's PING observer deduplicates this callback.
			if kind == "conn_close_lost_ping" && runtime.ctx.Err() == nil {
				runtime.learning.observeEndpointDegradation(key.address, config.ConnectProxyH2,
					routeLearningEndpoint{serverName: key.serverName, userAgent: key.userAgent, tlsProfile: key.tlsProfile}, time.Now())
			}
		}
		return transport
	}
}

type routeLearningChoice struct {
	address  string
	protocol string
	reason   string
	token    uint64
}

type routeLearningPolicyState struct {
	rule         *config.Rule
	preferred    string
	protocol     string
	preferredAt  time.Time
	lastExplore  time.Time
	exploreToken uint64
	exploreUntil time.Time
	explored     map[string]time.Time
	decisions    map[string]uint64
	confirmation routeLearningConfirmation
}

// A promising backup gets a small, consecutive confirmation budget within the
// existing exploration schedule. Pure round-robin over many targets can space
// observations farther apart than confidence decay, so the best tail route
// would never become known. This does not increase requests or relax evidence.
type routeLearningConfirmation struct {
	address, protocol string
	observedBefore    time.Time
	attemptedAt       time.Time
	remaining         int
}

func routeLearningMaterialAdvantage(candidate, current time.Duration) bool {
	return current-candidate >= 20*time.Millisecond && float64(candidate) <= float64(current)*0.8
}

func (confirmation routeLearningConfirmation) eligible(candidate, current *routeLearningCandidate) bool {
	if current == nil || confirmation.remaining <= 0 || candidate.address != confirmation.address || candidate.protocol != confirmation.protocol {
		return false
	}
	estimate := candidate.estimate
	return !estimate.Known && !estimate.Degraded && estimate.FailureRatio <= 0.15 &&
		estimate.LastSuccess.After(confirmation.observedBefore) && !estimate.LastSuccess.Before(confirmation.attemptedAt) &&
		estimate.LastFailure.Before(confirmation.attemptedAt) && routeLearningMaterialAdvantage(estimate.Cost, current.estimate.Cost)
}

type routeLearningPolicy struct {
	mu        sync.Mutex
	rules     map[string]*routeLearningPolicyState
	nextToken uint64
}

func newRouteLearningPolicy() *routeLearningPolicy {
	return &routeLearningPolicy{rules: make(map[string]*routeLearningPolicyState)}
}

// learningProtocol predicts only an ordinary attempt's protocol. It does not
// acquire a half-open lease or override protocol order. Recovery is selected
// before learning and retains its existing exclusive ownership.
func (runtime *routingRuntime) learningProtocol(rule *config.Rule, target *config.Target, now time.Time) string {
	if target == nil || target.ConnectProxy == nil || len(target.ConnectProxy.Protocols) == 0 {
		return ""
	}
	protocol := target.ConnectProxy.Protocols[0]
	if protocol != config.ConnectProxyH3 || !targetUsesMixedHTTP3First(target) {
		return protocol
	}
	manager := runtime.connectProxy
	if manager.h3RuleBreaker.restrictsOrdinaryH3(rule.Name, now) {
		return config.ConnectProxyH2
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	state := manager.h3Fallback[key]
	cooling := state != nil && (state.pending || state.probing || state.failures > 0 && now.Before(state.retryAt))
	manager.h3FallbackMu.Unlock()
	if cooling {
		return config.ConnectProxyH2
	}
	return protocol
}

type routeLearningCandidate struct {
	address  string
	protocol string
	estimate routeLearningEstimate
}

func (runtime *routingRuntime) chooseLearningRoute(rule *config.Rule, now time.Time) routeLearningChoice {
	if runtime == nil || runtime.learning == nil || rule == nil || rule.Mode != config.ModeBoost || !config.IsConnectProtocol(rule.Protocol) || len(rule.Targets) < 2 {
		return routeLearningChoice{}
	}
	if runtime.connectProxy.h3RuleBreaker.recoveryProbeDue(rule.Name, now) {
		return routeLearningChoice{}
	}
	key := boostRuleKey(rule)
	cache, hasCache := runtime.loadBoostWinnerToken(key)
	candidates := make([]routeLearningCandidate, 0, len(rule.Targets))
	hasProtocolRecovery := false
	for _, target := range rule.Targets {
		if target == nil || runtime.health.unhealthy(rule, target.Address) || runtime.routes.snapshot(rule, target.Address, now).CircuitOpen {
			continue
		}
		if runtime.routes.protocolPenalty(rule, target, now) != 0 {
			hasProtocolRecovery = true
			continue
		}
		protocol := runtime.learningProtocol(rule, target, now)
		if protocol == "" {
			continue
		}
		candidates = append(candidates, routeLearningCandidate{target.Address, protocol, runtime.learning.estimate(routeLearningKey{key, target.Address, protocol}, now)})
	}
	if !hasCache && hasProtocolRecovery {
		// Cache expiry is also the existing selector's opportunity to reserve an
		// endpoint's exclusive H3 warming canary. Recreating a synthetic quality
		// cache here could keep a healthy fast winner ahead of that canary forever.
		// Leave timing and ownership to selectTargetSelections: it already checks
		// the canary interval and in-flight lease atomically, and selects healthy
		// alternatives when another request owns recovery. Do not claim a probe
		// merely to inspect eligibility, nor maintain a second recovery schedule.
		return routeLearningChoice{}
	}
	if len(candidates) == 0 {
		return routeLearningChoice{}
	}
	policy := runtime.learningPolicy
	policy.mu.Lock()
	defer policy.mu.Unlock()
	state := policy.rules[key]
	if state == nil {
		if len(policy.rules) >= routeLearningPolicyLimit {
			// Avoid evicting another rule's live ownership merely to learn a new one.
			return routeLearningChoice{}
		}
		state = &routeLearningPolicyState{rule: rule, lastExplore: now, explored: make(map[string]time.Time), decisions: make(map[string]uint64)}
		policy.rules[key] = state
	}
	if now.Before(state.lastExplore) {
		state.lastExplore = now
	}
	var current, best *routeLearningCandidate
	for index := range candidates {
		candidate := &candidates[index]
		if candidate.address == state.preferred && candidate.protocol == state.protocol {
			current = candidate
		}
		if candidate.estimate.Known && (best == nil || candidate.estimate.Cost < best.estimate.Cost) {
			best = candidate
		}
	}
	if current == nil && hasCache {
		for index := range candidates {
			if candidates[index].address == cache.addr {
				current = &candidates[index]
				break
			}
		}
	}
	if current == nil {
		current = best
	}
	if current != nil && best != nil && current.address != best.address && (current.estimate.Known || current.estimate.Degraded || current.estimate.FailureRatio > 0.15) {
		// A new route needs both a material relative and absolute advantage.
		// An independently observed failure bypasses only the hold time, never
		// the health gates or the alternative's evidence requirement.
		better := routeLearningMaterialAdvantage(best.estimate.Cost, current.estimate.Cost)
		adverse := current.estimate.FailureRatio > best.estimate.FailureRatio+0.15 || current.estimate.Degraded
		if better && (now.Sub(state.preferredAt) >= routeLearningPreferenceHold || adverse) {
			current = best
		}
	}
	if current != nil && current.estimate.Known {
		if state.preferred != current.address || state.protocol != current.protocol {
			state.preferred, state.protocol, state.preferredAt = current.address, current.protocol, now
		}
	} else {
		state.preferred, state.protocol = "", ""
	}
	// A cache hit does not suppress exploration. Only one incoming request
	// per rule gets a probe; siblings keep their ordinary preferred/cache path.
	if len(candidates) > 1 && now.Sub(state.lastExplore) >= routeLearningExploreInterval && (state.exploreToken == 0 || !now.Before(state.exploreUntil)) {
		primary := state.preferred
		if primary == "" && hasCache {
			primary = cache.addr
		}
		var explorer *routeLearningCandidate
		var oldest time.Time
		confirming := false
		for index := range candidates {
			candidate := &candidates[index]
			if candidate.address == primary {
				continue
			}
			if state.confirmation.eligible(candidate, current) {
				explorer, confirming = candidate, true
				break
			}
			last := candidate.estimate.LastObservation
			if explicit := state.explored[candidate.address+"\x00"+candidate.protocol]; explicit.After(last) {
				last = explicit
			}
			if explorer == nil || last.Before(oldest) {
				explorer, oldest = candidate, last
			}
		}
		if explorer != nil {
			remaining := routeLearningConfirmLimit
			if confirming {
				remaining = state.confirmation.remaining - 1
			}
			state.confirmation = routeLearningConfirmation{
				address: explorer.address, protocol: explorer.protocol,
				observedBefore: explorer.estimate.LastObservation, attemptedAt: now, remaining: remaining,
			}
			policy.nextToken++
			if policy.nextToken == 0 {
				policy.nextToken++
			}
			state.lastExplore, state.exploreUntil, state.exploreToken = now, now.Add(boostDecisionTimeout(rule)+time.Second), policy.nextToken
			state.explored[explorer.address+"\x00"+explorer.protocol] = now
			state.decisions["explore"]++
			return routeLearningChoice{explorer.address, explorer.protocol, "explore", state.exploreToken}
		}
	}
	if state.preferred != "" {
		state.decisions["quality"]++
		return routeLearningChoice{address: state.preferred, protocol: state.protocol, reason: "quality"}
	}
	return routeLearningChoice{}
}

func (runtime *routingRuntime) releaseLearningChoice(rule *config.Rule, choice routeLearningChoice) {
	if choice.token == 0 || runtime.learningPolicy == nil {
		return
	}
	policy := runtime.learningPolicy
	policy.mu.Lock()
	if state := policy.rules[boostRuleKey(rule)]; state != nil && state.exploreToken == choice.token {
		state.exploreToken = 0
	}
	policy.mu.Unlock()
}

func learningExplorationHedgeDelay(rule *config.Rule) time.Duration {
	// Reserve at least half of the existing total budget for the backup.
	// This changes only a low-frequency explorer, never normal traffic.
	return min(routeLearningExploreMaxWait, boostDecisionTimeout(rule)/2)
}

type routeLearningGauge struct {
	rule, target, protocol string
	estimate               routeLearningEstimate
	preferred              bool
}
type routeLearningDecisionGauge struct {
	rule, reason string
	count        uint64
}

func (runtime *routingRuntime) snapshotLearningGauges(now time.Time) ([]routeLearningGauge, []routeLearningDecisionGauge) {
	if runtime.learningPolicy == nil || runtime.learning == nil {
		return nil, nil
	}
	policy := runtime.learningPolicy
	policy.mu.Lock()
	var gauges []routeLearningGauge
	var decisions []routeLearningDecisionGauge
	for key, state := range policy.rules {
		for _, target := range state.rule.Targets {
			if target == nil || target.ConnectProxy == nil {
				continue
			}
			for _, protocol := range target.ConnectProxy.Protocols {
				estimate := runtime.learning.estimate(routeLearningKey{key, target.Address, protocol}, now)
				gauges = append(gauges, routeLearningGauge{state.rule.Name, target.Address, protocol, estimate, estimate.Known && state.preferred == target.Address && state.protocol == protocol})
			}
		}
		for reason, count := range state.decisions {
			decisions = append(decisions, routeLearningDecisionGauge{state.rule.Name, reason, count})
		}
	}
	policy.mu.Unlock()
	sort.Slice(gauges, func(i, j int) bool {
		a, b := gauges[i], gauges[j]
		if a.rule != b.rule {
			return a.rule < b.rule
		}
		if a.target != b.target {
			return a.target < b.target
		}
		return a.protocol < b.protocol
	})
	sort.Slice(decisions, func(i, j int) bool {
		a, b := decisions[i], decisions[j]
		if a.rule != b.rule {
			return a.rule < b.rule
		}
		return a.reason < b.reason
	})
	return gauges, decisions
}
