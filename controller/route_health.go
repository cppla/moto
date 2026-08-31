package controller

import (
	"context"
	"errors"
	"moto/config"
	"sort"
	"sync"
	"time"
)

const (
	routeFailureThreshold = 3
	routeInitialCooldown  = 5 * time.Second
	routeMaximumCooldown  = 60 * time.Second
	routeFailurePenalty   = time.Second
	routeExplorationAfter = 30 * time.Second
)

// ErrCircuitOpen is returned when a route is cooling down or another caller
// already owns its single half-open probe.
var ErrCircuitOpen = errors.New("route circuit open")

// errRouteReachable marks a completed route attempt that reached the upstream
// service but could not establish the requested tunnel. Unlike a successful
// tunnel it must not contribute a latency sample, but it is conclusive proof
// that the shared route is reachable and may recover an open circuit.
var errRouteReachable = errors.New("route reachable")

type routeHealthState struct {
	ruleName            string
	mode                string
	observed            bool
	hasEWMA             bool
	ewma                time.Duration
	lastAttempt         time.Time
	consecutiveFailures int
	relayFailures       int
	circuitOpen         bool
	openUntil           time.Time
	cooldown            time.Duration
	halfOpen            bool
	halfOpenAttempt     uint64
	minValidAttempt     uint64
}

// routeHealthSnapshot is a read-only copy of one route's health. CircuitOpen
// remains true while the route is waiting for, or running, a half-open probe.
type routeHealthSnapshot struct {
	Observed            bool
	HasEWMA             bool
	EWMA                time.Duration
	LastAttempt         time.Time
	ConsecutiveFailures int
	CircuitOpen         bool
	HalfOpen            bool
	ProbeRequired       bool
	OpenUntil           time.Time
	Cooldown            time.Duration
}

func newRouteHealthState(rule *config.Rule) *routeHealthState {
	state := &routeHealthState{}
	if rule != nil {
		state.ruleName = rule.Name
		state.mode = rule.Mode
	}
	return state
}

type routeHealthKey struct {
	rule string
	addr string
}

type routeFailureClaimKey struct {
	registry *routeHealthRegistry
	route    routeHealthKey
}

// routeFailureGroup represents one physical setup failure shared by multiple
// logical route attempts. Claims are scoped to a routing registry and route so
// different rules and reload generations each observe the physical failure
// once, while concurrent waiters cannot amplify it into an immediate circuit.
type routeFailureGroup struct {
	mu      sync.Mutex
	claimed map[routeFailureClaimKey]struct{}
}

type routeFailureObservation struct {
	cause error
	group *routeFailureGroup
}

func newRouteFailureGroup() *routeFailureGroup {
	return &routeFailureGroup{claimed: make(map[routeFailureClaimKey]struct{})}
}

func (group *routeFailureGroup) claim(registry *routeHealthRegistry, route routeHealthKey) bool {
	if group == nil || registry == nil {
		return true
	}
	key := routeFailureClaimKey{registry: registry, route: route}
	group.mu.Lock()
	defer group.mu.Unlock()
	if _, exists := group.claimed[key]; exists {
		return false
	}
	group.claimed[key] = struct{}{}
	return true
}

func (observation *routeFailureObservation) Error() string {
	if observation == nil || observation.cause == nil {
		return "route failure"
	}
	return observation.cause.Error()
}

func (observation *routeFailureObservation) Unwrap() error {
	if observation == nil {
		return nil
	}
	return observation.cause
}

func routeObservationFailureGroup(err error) *routeFailureGroup {
	var observation *routeFailureObservation
	if errors.As(err, &observation) && observation != nil {
		return observation.group
	}
	return nil
}

type routeAttempt struct {
	registry *routeHealthRegistry
	key      routeHealthKey
	id       uint64
	valid    bool
}

// routeProtocolPenaltySource overlays protocol-specific, transfer-time health
// on top of the target-wide route circuit. It is deliberately read-only: an H3
// path may be degraded while the same target remains perfectly usable over H2,
// so protocol penalties must never mutate routeHealthState.
type routeProtocolPenaltySource func(*config.Rule, *config.Target, time.Time) time.Duration

// routeProtocolProbeClaimSource atomically reserves one bounded protocol
// recovery canary. It is separate from the read-only penalty source so metrics
// and score inspection never consume the canary meant for a real connection.
// The token gives the selected dial explicit ownership until completion.
type routeProtocolProbeClaimSource func(*config.Rule, *config.Target, time.Time) (uint64, bool)
type routeProtocolProbeReleaseSource func(*config.Rule, *config.Target, uint64)

type routeProtocolProbeLease struct {
	token uint64
}

type routeProtocolProbeContextKey struct{}

func withRouteProtocolProbeLease(ctx context.Context, lease routeProtocolProbeLease) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if lease.token == 0 {
		return ctx
	}
	return context.WithValue(ctx, routeProtocolProbeContextKey{}, lease.token)
}

func routeProtocolProbeTokenFromContext(ctx context.Context) uint64 {
	if ctx == nil {
		return 0
	}
	token, _ := ctx.Value(routeProtocolProbeContextKey{}).(uint64)
	return token
}

type routeTargetSelection struct {
	target        *config.Target
	protocolProbe routeProtocolProbeLease
}

type routeHealthRegistry struct {
	sync.Mutex
	states                map[routeHealthKey]*routeHealthState
	nextAttempt           uint64
	protocolPenaltySource routeProtocolPenaltySource
	protocolProbeClaim    routeProtocolProbeClaimSource
	protocolProbeRelease  routeProtocolProbeReleaseSource
}

func newRouteHealthRegistry(sources ...routeProtocolPenaltySource) *routeHealthRegistry {
	registry := &routeHealthRegistry{states: make(map[routeHealthKey]*routeHealthState)}
	if len(sources) > 0 {
		registry.protocolPenaltySource = sources[0]
	}
	return registry
}

// protocolPenalty invokes the immutable protocol-health source without taking
// the route registry lock. The source owns different state and may have its own
// lock, so keeping the two lock domains separate avoids lock-order cycles.
func (registry *routeHealthRegistry) protocolPenalty(rule *config.Rule, target *config.Target, now time.Time) time.Duration {
	if registry == nil || registry.protocolPenaltySource == nil || rule == nil || target == nil {
		return 0
	}
	penalty := registry.protocolPenaltySource(rule, target, now)
	if penalty < 0 {
		return 0
	}
	return penalty
}

func (registry *routeHealthRegistry) claimProtocolProbe(rule *config.Rule, target *config.Target, now time.Time) (routeProtocolProbeLease, bool) {
	if registry == nil || registry.protocolProbeClaim == nil || rule == nil || target == nil {
		return routeProtocolProbeLease{}, false
	}
	token, ok := registry.protocolProbeClaim(rule, target, now)
	if !ok || token == 0 {
		return routeProtocolProbeLease{}, false
	}
	return routeProtocolProbeLease{token: token}, true
}

func (registry *routeHealthRegistry) releaseProtocolProbe(rule *config.Rule, target *config.Target, lease routeProtocolProbeLease) {
	if registry == nil || registry.protocolProbeRelease == nil || rule == nil || target == nil || lease.token == 0 {
		return
	}
	registry.protocolProbeRelease(rule, target, lease.token)
}

func routeKey(rule *config.Rule, addr string) (routeHealthKey, bool) {
	if rule == nil || addr == "" {
		return routeHealthKey{}, false
	}
	return routeHealthKey{rule: boostRuleKey(rule), addr: addr}, true
}

// routeBegin atomically admits a regular attempt or claims the sole half-open
// probe after a circuit's cooldown. Every admitted attempt should eventually
// be paired with routeObserve.
func routeBegin(rule *config.Rule, addr string, now time.Time) (routeAttempt, error) {
	return defaultRoutingRuntime.routes.begin(rule, addr, now)
}

func (registry *routeHealthRegistry) begin(rule *config.Rule, addr string, now time.Time) (routeAttempt, error) {
	key, ok := routeKey(rule, addr)
	if !ok {
		return routeAttempt{}, nil
	}

	registry.Lock()
	defer registry.Unlock()
	state := registry.states[key]
	if state == nil {
		state = newRouteHealthState(rule)
		registry.states[key] = state
	}
	if state.circuitOpen && (now.Before(state.openUntil) || state.halfOpen) {
		return routeAttempt{}, ErrCircuitOpen
	}
	registry.nextAttempt++
	attempt := routeAttempt{registry: registry, key: key, id: registry.nextAttempt, valid: true}
	state.lastAttempt = now
	if state.circuitOpen {
		state.halfOpen = true
		state.halfOpenAttempt = attempt.id
	}
	return attempt, nil
}

// routeObserve records the outcome of an admitted route attempt. A cancelled
// attempt is neutral: in particular, losing dials cancelled by a boost race do
// not make a healthy route look faulty. errRouteReachable is a third outcome:
// it resets route failure state without adding a successful-tunnel latency
// sample. DeadlineExceeded remains a failure, since a route that cannot meet
// its dial deadline is unhealthy for routing.
func routeObserve(attempt routeAttempt, latency time.Duration, err error, now time.Time) {
	registry := attempt.registry
	if !attempt.valid || registry == nil {
		return
	}

	if errors.Is(err, context.Canceled) || isDialBulkheadError(err) {
		registry.Lock()
		if state := registry.states[attempt.key]; state != nil && state.circuitOpen &&
			state.halfOpen && state.halfOpenAttempt == attempt.id {
			state.halfOpen = false
			state.halfOpenAttempt = 0
		}
		registry.Unlock()
		return
	}

	registry.Lock()
	defer registry.Unlock()
	state := registry.states[attempt.key]
	if state == nil {
		return
	}
	if attempt.id < state.minValidAttempt {
		return
	}
	wasHalfOpenProbe := state.circuitOpen && state.halfOpen && state.halfOpenAttempt == attempt.id
	if state.circuitOpen && !wasHalfOpenProbe {
		// Results from attempts admitted before the circuit opened cannot close
		// it or extend its cooldown. Only the explicitly claimed probe may
		// transition an open circuit.
		return
	}
	if group := routeObservationFailureGroup(err); group != nil && !group.claim(registry, attempt.key) {
		// A duplicate result from the same physical setup is neutral. If this
		// logical attempt happened to own half-open probing, release ownership so
		// a genuinely new physical setup can probe immediately.
		if wasHalfOpenProbe {
			state.halfOpen = false
			state.halfOpenAttempt = 0
		}
		return
	}
	state.observed = true

	if errors.Is(err, errRouteReachable) {
		state.consecutiveFailures = 0
		state.relayFailures = 0
		state.circuitOpen = false
		state.openUntil = time.Time{}
		state.cooldown = 0
		state.halfOpen = false
		state.halfOpenAttempt = 0
		if wasHalfOpenProbe {
			// As with a successful half-open tunnel, outcomes from attempts that
			// predate this conclusive reachability observation must not reopen the
			// recovered circuit.
			state.minValidAttempt = attempt.id
		}
		return
	}

	if err == nil {
		if latency < 0 {
			latency = 0
		}
		if !state.hasEWMA {
			state.ewma = latency
			state.hasEWMA = true
		} else {
			// alpha = 0.2, expressed with integer duration arithmetic so tests
			// and routing decisions do not depend on floating-point rounding.
			state.ewma = (4*state.ewma + latency) / 5
		}
		state.consecutiveFailures = 0
		state.circuitOpen = false
		state.openUntil = time.Time{}
		if !wasHalfOpenProbe {
			state.cooldown = 0
		}
		state.halfOpen = false
		state.halfOpenAttempt = 0
		if wasHalfOpenProbe {
			// Ignore late outcomes from every pre-recovery attempt. New attempts
			// receive larger IDs from routeBegin.
			state.minValidAttempt = attempt.id
		}
		return
	}

	// Failures from attempts admitted before another goroutine opened the
	// circuit must not extend its cooldown. Only the claimed probe can reopen
	// an already-open circuit.
	if state.circuitOpen {
		state.consecutiveFailures++
		state.halfOpen = false
		state.halfOpenAttempt = 0
		state.cooldown = nextRouteCooldown(state.cooldown)
		state.openUntil = now.Add(state.cooldown)
		return
	}
	state.consecutiveFailures++
	if state.consecutiveFailures >= routeFailureThreshold {
		state.circuitOpen = true
		state.cooldown = nextRouteCooldown(state.cooldown)
		state.openUntil = now.Add(state.cooldown)
	}
}

// routeReportFailure feeds a confirmed upstream-side relay failure back into
// the circuit breaker. The originating attempt token prevents an old stream
// from corrupting a newer recovery generation.
func routeReportFailure(attempt routeAttempt, err error, now time.Time) {
	registry := attempt.registry
	if !attempt.valid || registry == nil || err == nil || errors.Is(err, context.Canceled) {
		return
	}
	registry.Lock()
	defer registry.Unlock()
	state := registry.states[attempt.key]
	if state == nil || attempt.id < state.minValidAttempt || state.circuitOpen {
		return
	}
	state.observed = true
	state.relayFailures++
	if state.relayFailures >= routeFailureThreshold {
		state.circuitOpen = true
		state.cooldown = nextRouteCooldown(state.cooldown)
		state.openUntil = now.Add(state.cooldown)
	}
}

func routeReportSuccess(attempt routeAttempt) {
	registry := attempt.registry
	if !attempt.valid || registry == nil {
		return
	}
	registry.Lock()
	defer registry.Unlock()
	state := registry.states[attempt.key]
	if state == nil || attempt.id < state.minValidAttempt || state.circuitOpen {
		return
	}
	// A connection that carried real traffic proves the route is usable even
	// when it came from the prewarm pool and therefore had no fresh dial outcome.
	// Both failure streaks must be cleared or two old replenishment failures plus
	// one later failure would be misreported as three consecutive failures.
	state.observed = true
	state.consecutiveFailures = 0
	state.relayFailures = 0
	state.cooldown = 0
}

func nextRouteCooldown(previous time.Duration) time.Duration {
	if previous < routeInitialCooldown {
		return routeInitialCooldown
	}
	next := previous * 2
	if next > routeMaximumCooldown {
		return routeMaximumCooldown
	}
	return next
}

func routeSnapshot(rule *config.Rule, addr string, now time.Time) routeHealthSnapshot {
	return defaultRoutingRuntime.routes.snapshot(rule, addr, now)
}

func (registry *routeHealthRegistry) snapshot(rule *config.Rule, addr string, now time.Time) routeHealthSnapshot {
	key, ok := routeKey(rule, addr)
	if !ok {
		return routeHealthSnapshot{}
	}

	registry.Lock()
	defer registry.Unlock()
	state := registry.states[key]
	if state == nil {
		return routeHealthSnapshot{}
	}
	return routeHealthSnapshot{
		Observed:            state.observed,
		HasEWMA:             state.hasEWMA,
		EWMA:                state.ewma,
		LastAttempt:         state.lastAttempt,
		ConsecutiveFailures: max(state.consecutiveFailures, state.relayFailures),
		CircuitOpen:         state.circuitOpen,
		HalfOpen:            state.halfOpen,
		ProbeRequired:       state.circuitOpen && !state.halfOpen && !now.Before(state.openUntil),
		OpenUntil:           state.openUntil,
		Cooldown:            state.cooldown,
	}
}

func (registry *routeHealthRegistry) clear(rules []*config.Rule) {
	keys := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule != nil {
			keys[boostRuleKey(rule)] = struct{}{}
		}
	}
	registry.Lock()
	for key := range registry.states {
		if _, ok := keys[key.rule]; ok {
			delete(registry.states, key)
		}
	}
	registry.Unlock()
}

type routeCandidate struct {
	target      *config.Target
	index       int
	score       time.Duration
	penalty     time.Duration
	lastAttempt time.Time
	hasEWMA     bool
}

// selectRouteTargets returns at most limit currently admissible targets. Once
// a healthy EWMA exists it keeps the best-known route and spends the second
// slot on the least-recently attempted unknown route. Fully observed routes use
// EWMA latency plus a failure penalty and periodic exploration. Callers must
// still use routeBegin, which atomically excludes duplicate half-open probes.
func selectRouteTargets(rule *config.Rule, limit int, now time.Time) []*config.Target {
	return defaultRoutingRuntime.routes.selectTargetsExcluding(rule, limit, now, nil)
}

// selectTargetsExcluding is the batching form used by Boost. Exclusions are
// keyed by address so a target is attempted at most once per inbound stream.
func (registry *routeHealthRegistry) selectTargetsExcluding(rule *config.Rule, limit int, now time.Time, excluded map[string]struct{}) []*config.Target {
	selections := registry.selectTargetSelections(rule, limit, now, excluded, false)
	targets := make([]*config.Target, 0, len(selections))
	for _, selection := range selections {
		targets = append(targets, selection.target)
	}
	return targets
}

func (registry *routeHealthRegistry) selectTargetSelectionsExcluding(
	rule *config.Rule,
	limit int,
	now time.Time,
	excluded map[string]struct{},
) []routeTargetSelection {
	return registry.selectTargetSelections(rule, limit, now, excluded, true)
}

func (registry *routeHealthRegistry) selectTargetSelections(
	rule *config.Rule,
	limit int,
	now time.Time,
	excluded map[string]struct{},
	reserveProtocolProbe bool,
) []routeTargetSelection {
	if rule == nil || limit <= 0 || len(rule.Targets) == 0 {
		return nil
	}
	// Query protocol health before taking registry.Lock. H3 degradation is
	// maintained by connectProxyManager under a separate lock and must never be
	// allowed to invert that lock order with route health updates.
	protocolPenalties := make(map[*config.Target]time.Duration, len(rule.Targets))
	for _, target := range rule.Targets {
		if target == nil {
			continue
		}
		protocolPenalties[target] = registry.protocolPenalty(rule, target, now)
	}

	ruleID := boostRuleKey(rule)
	unobserved := make([]routeCandidate, 0, len(rule.Targets))
	observed := make([]routeCandidate, 0, len(rule.Targets))
	seenAddresses := make(map[string]struct{}, len(rule.Targets))
	hasUnpenalized := false

	registry.Lock()
	for index, target := range rule.Targets {
		if target == nil || target.Address == "" {
			continue
		}
		if _, skip := excluded[target.Address]; skip {
			continue
		}
		if _, duplicate := seenAddresses[target.Address]; duplicate {
			continue
		}
		seenAddresses[target.Address] = struct{}{}
		penalty := protocolPenalties[target]
		state := registry.states[routeHealthKey{rule: ruleID, addr: target.Address}]
		if state == nil || !state.observed {
			candidate := routeCandidate{target: target, index: index, score: penalty, penalty: penalty}
			if state != nil {
				candidate.lastAttempt = state.lastAttempt
			}
			unobserved = append(unobserved, candidate)
			if penalty == 0 {
				hasUnpenalized = true
			}
			continue
		}
		if state.circuitOpen && (now.Before(state.openUntil) || state.halfOpen) {
			continue
		}
		score := routeFailurePenalty
		if state.hasEWMA {
			score = state.ewma
		}
		failures := max(state.consecutiveFailures, state.relayFailures)
		observed = append(observed, routeCandidate{
			target:      target,
			index:       index,
			score:       score + time.Duration(failures)*routeFailurePenalty + penalty,
			penalty:     penalty,
			lastAttempt: state.lastAttempt,
			hasEWMA:     state.hasEWMA,
		})
		if penalty == 0 {
			hasUnpenalized = true
		}
	}
	registry.Unlock()

	// Atomically reserve at most one due protocol canary and put that target
	// first. Usually an unpenalized alternative exists; a rule-wide H3 recovery
	// probe is the exception because every target in that rule is deliberately
	// penalized until one exclusive data-plane probation is admitted.
	var protocolProbe routeTargetSelection
	if reserveProtocolProbe {
		probeCandidates := make([]routeCandidate, 0, len(unobserved)+len(observed))
		for _, candidate := range unobserved {
			if candidate.penalty > 0 {
				probeCandidates = append(probeCandidates, candidate)
			}
		}
		for _, candidate := range observed {
			if candidate.penalty > 0 {
				probeCandidates = append(probeCandidates, candidate)
			}
		}
		sort.SliceStable(probeCandidates, func(i, j int) bool {
			if probeCandidates[i].score == probeCandidates[j].score {
				return probeCandidates[i].index < probeCandidates[j].index
			}
			return probeCandidates[i].score < probeCandidates[j].score
		})
		for _, candidate := range probeCandidates {
			if lease, claimed := registry.claimProtocolProbe(rule, candidate.target, now); claimed {
				protocolProbe = routeTargetSelection{target: candidate.target, protocolProbe: lease}
				break
			}
		}
		if protocolProbe.target == nil && len(probeCandidates) > 0 {
			// A concurrent selector may have claimed the protocol lease after our
			// initial penalty snapshot but before this claim loop. Refresh outside
			// the route lock so siblings immediately see H2-capable targets as safe
			// and keep an H3-only target from bypassing the exclusive probation.
			hasUnpenalized = false
			refresh := func(candidates []routeCandidate) {
				for index := range candidates {
					candidate := &candidates[index]
					penalty := registry.protocolPenalty(rule, candidate.target, now)
					candidate.score += penalty - candidate.penalty
					candidate.penalty = penalty
					if penalty == 0 {
						hasUnpenalized = true
					}
				}
			}
			refresh(unobserved)
			refresh(observed)
		}
		if protocolProbe.target != nil {
			unobserved = filterRouteCandidateAddress(unobserved, protocolProbe.target.Address)
			observed = filterRouteCandidateAddress(observed, protocolProbe.target.Address)
		}
		if hasUnpenalized {
			unobserved = filterUnpenalizedRouteCandidates(unobserved)
			observed = filterUnpenalizedRouteCandidates(observed)
		}
	} else if hasUnpenalized {
		unobserved = filterUnpenalizedRouteCandidates(unobserved)
		observed = filterUnpenalizedRouteCandidates(observed)
	}

	sort.SliceStable(observed, func(i, j int) bool {
		if observed[i].score == observed[j].score {
			return observed[i].index < observed[j].index
		}
		return observed[i].score < observed[j].score
	})
	sort.SliceStable(unobserved, func(i, j int) bool {
		if unobserved[i].score != unobserved[j].score {
			return unobserved[i].score < unobserved[j].score
		}
		if unobserved[i].lastAttempt.IsZero() != unobserved[j].lastAttempt.IsZero() {
			return unobserved[i].lastAttempt.IsZero()
		}
		if !unobserved[i].lastAttempt.Equal(unobserved[j].lastAttempt) {
			return unobserved[i].lastAttempt.Before(unobserved[j].lastAttempt)
		}
		return unobserved[i].index < unobserved[j].index
	})

	available := len(unobserved) + len(observed)
	if protocolProbe.target != nil {
		available++
	}
	if limit > available {
		limit = available
	}
	selected := make([]routeTargetSelection, 0, limit)
	if protocolProbe.target != nil {
		selected = append(selected, protocolProbe)
	}
	bestKnownIndex := -1
	for index, candidate := range observed {
		if candidate.hasEWMA {
			bestKnownIndex = index
			break
		}
	}
	if len(selected) < limit && len(unobserved) > 0 && bestKnownIndex >= 0 {
		selected = append(selected, routeTargetSelection{target: observed[bestKnownIndex].target})
	}
	for _, candidate := range unobserved {
		if len(selected) == limit {
			return selected
		}
		selected = append(selected, routeTargetSelection{target: candidate.target})
	}
	for index, candidate := range observed {
		if len(selected) == limit {
			break
		}
		if index == bestKnownIndex && len(unobserved) > 0 {
			continue
		}
		selected = append(selected, routeTargetSelection{target: candidate.target})
	}
	// Once every route has been tried, reserve the second Top-2 slot for the
	// stalest eligible route at a bounded interval. This lets a formerly slow
	// path prove that it recovered without sacrificing the best-known route.
	// Boost asks for the full ordered candidate list so it can refill slots
	// around health exclusions. Keep that fallback list, but move the explorer
	// into its actual second launch position instead of only considering routes
	// omitted by a selector limit of two.
	if len(unobserved) == 0 && len(selected) > 1 {
		bestAddress := selected[0].target.Address
		var explorer *routeCandidate
		for i := range observed {
			candidate := &observed[i]
			if candidate.target.Address == bestAddress {
				continue
			}
			if !candidate.lastAttempt.IsZero() && now.Sub(candidate.lastAttempt) < routeExplorationAfter {
				continue
			}
			if explorer == nil || candidate.lastAttempt.Before(explorer.lastAttempt) ||
				(candidate.lastAttempt.Equal(explorer.lastAttempt) && candidate.index < explorer.index) {
				explorer = candidate
			}
		}
		if explorer != nil {
			explorerIndex := -1
			for index := 1; index < len(selected); index++ {
				if selected[index].target.Address == explorer.target.Address {
					explorerIndex = index
					break
				}
			}
			if explorerIndex >= 0 {
				selected[1], selected[explorerIndex] = selected[explorerIndex], selected[1]
			} else {
				selected[1] = routeTargetSelection{target: explorer.target}
			}
		}
	}
	return selected
}

func filterUnpenalizedRouteCandidates(candidates []routeCandidate) []routeCandidate {
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if candidate.penalty == 0 {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func filterRouteCandidateAddress(candidates []routeCandidate, address string) []routeCandidate {
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if candidate.target == nil || candidate.target.Address != address {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}
