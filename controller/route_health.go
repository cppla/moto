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

type routeAttempt struct {
	registry *routeHealthRegistry
	key      routeHealthKey
	id       uint64
	valid    bool
}

type routeHealthRegistry struct {
	sync.Mutex
	states      map[routeHealthKey]*routeHealthState
	nextAttempt uint64
}

func newRouteHealthRegistry() *routeHealthRegistry {
	return &routeHealthRegistry{states: make(map[routeHealthKey]*routeHealthState)}
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
// not make a healthy route look faulty. DeadlineExceeded remains a failure,
// since a route that cannot meet its dial deadline is unhealthy for routing.
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
	state.observed = true

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
	if rule == nil || limit <= 0 || len(rule.Targets) == 0 {
		return nil
	}
	ruleID := boostRuleKey(rule)
	unobserved := make([]routeCandidate, 0, len(rule.Targets))
	observed := make([]routeCandidate, 0, len(rule.Targets))
	seenAddresses := make(map[string]struct{}, len(rule.Targets))

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
		state := registry.states[routeHealthKey{rule: ruleID, addr: target.Address}]
		if state == nil || !state.observed {
			candidate := routeCandidate{target: target, index: index}
			if state != nil {
				candidate.lastAttempt = state.lastAttempt
			}
			unobserved = append(unobserved, candidate)
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
			score:       score + time.Duration(failures)*routeFailurePenalty,
			lastAttempt: state.lastAttempt,
			hasEWMA:     state.hasEWMA,
		})
	}
	registry.Unlock()

	sort.SliceStable(observed, func(i, j int) bool {
		if observed[i].score == observed[j].score {
			return observed[i].index < observed[j].index
		}
		return observed[i].score < observed[j].score
	})
	sort.SliceStable(unobserved, func(i, j int) bool {
		if unobserved[i].lastAttempt.IsZero() != unobserved[j].lastAttempt.IsZero() {
			return unobserved[i].lastAttempt.IsZero()
		}
		if !unobserved[i].lastAttempt.Equal(unobserved[j].lastAttempt) {
			return unobserved[i].lastAttempt.Before(unobserved[j].lastAttempt)
		}
		return unobserved[i].index < unobserved[j].index
	})

	if limit > len(unobserved)+len(observed) {
		limit = len(unobserved) + len(observed)
	}
	selected := make([]*config.Target, 0, limit)
	bestKnownIndex := -1
	for index, candidate := range observed {
		if candidate.hasEWMA {
			bestKnownIndex = index
			break
		}
	}
	if len(unobserved) > 0 && bestKnownIndex >= 0 {
		selected = append(selected, observed[bestKnownIndex].target)
	}
	for _, candidate := range unobserved {
		if len(selected) == limit {
			return selected
		}
		selected = append(selected, candidate.target)
	}
	for index, candidate := range observed {
		if len(selected) == limit {
			break
		}
		if index == bestKnownIndex && len(unobserved) > 0 {
			continue
		}
		selected = append(selected, candidate.target)
	}
	// Once every route has been tried, reserve the second Top-2 slot for the
	// stalest eligible route at a bounded interval. This lets a formerly slow
	// path prove that it recovered without sacrificing the best-known route.
	if len(unobserved) == 0 && len(selected) > 1 {
		selectedAddresses := make(map[string]struct{}, len(selected))
		for _, target := range selected {
			selectedAddresses[target.Address] = struct{}{}
		}
		var explorer *routeCandidate
		for i := range observed {
			candidate := &observed[i]
			if _, alreadySelected := selectedAddresses[candidate.target.Address]; alreadySelected {
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
			selected[len(selected)-1] = explorer.target
		}
	}
	return selected
}
