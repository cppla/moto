package controller

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

const (
	routeLearningWindow             = time.Second
	routeLearningHalfLife           = 2 * time.Minute
	routeLearningTTL                = 10 * time.Minute
	routeLearningMaxEntries         = 1024
	routeLearningMaxSamples         = 32
	routeLearningMinSamples         = 1.5
	routeLearningMinWindows         = 3
	routeLearningMaxLatency         = 5 * time.Second
	routeLearningUnknownLatency     = 250 * time.Millisecond
	routeLearningFailurePenalty     = 2 * time.Second
	routeLearningDegradationPenalty = 750 * time.Millisecond
	routeLearningDegradationMemory  = 2 * time.Minute
)

type routeLearningKey struct {
	rule, target, protocol string
}

// The target and protocol live in routeLearningKey; these are the remaining
// physical-pool identity fields. H3 pools have no user-agent/profile dimension.
// Keeping the identity inside the bounded state also preserves it on reload
// without maintaining a second endpoint-to-rule registry.
type routeLearningEndpoint struct {
	serverName string
	userAgent  string
	tlsProfile http2TLSClientHelloProfile
}

type routeLearningEstimate struct {
	Known           bool
	Degraded        bool
	Samples         float64
	Latency         time.Duration
	FailureRatio    float64
	Cost            time.Duration
	LastObservation time.Time
	LastSuccess     time.Time
	LastFailure     time.Time
}

// A window contributes at most one sample, regardless of how many multiplexed
// tunnels finish together. The window's successful latencies are averaged;
// one or more failures supply one bounded adverse observation. This learns
// setup quality and reliability, never link bandwidth from application B/s.
type routeLearningState struct {
	endpoint        routeLearningEndpoint
	latency         time.Duration
	hasLatency      bool
	failureRatio    float64
	samples         float64
	windows         int
	updatedAt       time.Time
	lastObservation time.Time
	lastSuccess     time.Time
	lastFailure     time.Time
	degradedAt      time.Time
	window          int64
	baseLatency     time.Duration
	baseHasLatency  bool
	baseFailure     float64
	windowMean      time.Duration
	windowSuccesses uint64
	windowFailed    bool
}

type routeLearner struct {
	mu     sync.Mutex
	states map[routeLearningKey]*routeLearningState
	// Group claims must have an independent namespace. Sharing the actual
	// circuit registry would consume its claim and suppress circuit accounting.
	failureIdentity *routeHealthRegistry
}

func newRouteLearner() *routeLearner {
	return &routeLearner{
		states:          make(map[routeLearningKey]*routeLearningState),
		failureIdentity: &routeHealthRegistry{},
	}
}

func routeLearningNeutral(err error) bool {
	if err == nil {
		return false
	}
	var status *connectProxyStatusError
	return errors.As(err, &status) || errors.Is(err, context.Canceled) ||
		errors.Is(err, errConnectProxyProtocolCapacity) || isDialBulkheadError(err) ||
		errors.Is(err, errDialBulkheadSaturated) || errors.Is(err, ErrCircuitOpen) ||
		errors.Is(err, ErrActiveHealthUnhealthy) || errors.Is(err, errRouteReachable) ||
		errors.Is(err, errConnectProxyProtocolCoolingDown) || errors.Is(err, errConnectProxyProtocolUnavailable)
}

func (learner *routeLearner) observeSetup(key routeLearningKey, latency time.Duration, err error, now time.Time) {
	learner.observeEndpointSetup(key, routeLearningEndpoint{}, latency, err, now)
}

func (learner *routeLearner) observeEndpointSetup(key routeLearningKey, endpoint routeLearningEndpoint, latency time.Duration, err error, now time.Time) {
	if learner == nil || key.rule == "" || key.target == "" || key.protocol == "" || routeLearningNeutral(err) {
		return
	}
	if group := http3SetupFailureGroup(err); group != nil {
		if !group.claim(learner.failureIdentity, routeHealthKey{rule: key.rule, addr: key.target + "\x00" + key.protocol}) {
			return
		}
	}
	latency = min(max(latency, 0), routeLearningMaxLatency)
	learner.mu.Lock()
	defer learner.mu.Unlock()
	state := learner.states[key]
	if state != nil && now.Before(state.lastObservation) {
		return // Delayed events cannot overwrite newer evidence.
	}
	if state == nil || state.endpoint != endpoint || now.Sub(state.lastObservation) >= routeLearningTTL {
		learner.makeRoomLocked(key)
		state = &routeLearningState{endpoint: endpoint, window: now.UnixNano()/int64(routeLearningWindow) - 1}
		learner.states[key] = state
	}
	window := now.UnixNano() / int64(routeLearningWindow)
	if window != state.window {
		decay := routeLearningDecay(now.Sub(state.updatedAt))
		state.samples = min(float64(routeLearningMaxSamples), state.samples*decay+1)
		state.windows = min(routeLearningMaxSamples, state.windows+1)
		state.baseLatency, state.baseHasLatency = state.latency, state.hasLatency
		state.baseFailure = state.failureRatio * decay
		state.window = window
		state.windowMean, state.windowSuccesses, state.windowFailed = 0, 0, false
		state.updatedAt = now
	}
	state.lastObservation = now
	if err != nil {
		state.windowFailed = true
		state.lastFailure = now
	} else {
		state.lastSuccess = now
		// A bounded accumulator avoids both overflow and burst-driven confidence.
		state.windowSuccesses = min(state.windowSuccesses+1, 1024)
		state.windowMean += (latency - state.windowMean) / time.Duration(state.windowSuccesses)
	}
	state.failureRatio = 0.75 * state.baseFailure
	if state.windowFailed {
		state.failureRatio += 0.25
	}
	if state.windowSuccesses > 0 {
		state.hasLatency = true
		if state.baseHasLatency {
			state.latency = (3*state.baseLatency + state.windowMean) / 4
		} else {
			state.latency = state.windowMean
		}
	}
}

// Confirmed physical-connection degradation is a soft selection signal only.
// No circuit, protocol order or cooldown is changed. Repeated observations do
// not increase confidence or multiply the bounded penalty.
func (learner *routeLearner) observeDegradation(target, protocol string, now time.Time) {
	learner.observeEndpointDegradation(target, protocol, routeLearningEndpoint{}, now)
}

func (learner *routeLearner) observeEndpointDegradation(target, protocol string, endpoint routeLearningEndpoint, now time.Time) {
	if learner == nil {
		return
	}
	learner.mu.Lock()
	defer learner.mu.Unlock()
	for key, state := range learner.states {
		if key.target == target && key.protocol == protocol && state.endpoint == endpoint && !now.Before(state.lastObservation) &&
			now.Sub(state.lastObservation) < routeLearningTTL {
			state.degradedAt = now
			state.lastObservation = now
		}
	}
}

// Cost remains meaningful for a newly observed failure even before Known is
// true. Known means the latency/reliability ranking has enough independent
// windows; an immediate adverse signal need not wait for that confidence.
func (learner *routeLearner) estimate(key routeLearningKey, now time.Time) routeLearningEstimate {
	if learner == nil {
		return routeLearningEstimate{}
	}
	learner.mu.Lock()
	defer learner.mu.Unlock()
	state := learner.states[key]
	if state == nil {
		return routeLearningEstimate{}
	}
	if now.Sub(state.lastObservation) >= routeLearningTTL {
		delete(learner.states, key)
		return routeLearningEstimate{}
	}
	decay := routeLearningDecay(now.Sub(state.updatedAt))
	estimate := routeLearningEstimate{
		Samples: state.samples * decay, Latency: state.latency,
		FailureRatio: state.failureRatio * decay, LastObservation: state.lastObservation,
		LastSuccess: state.lastSuccess, LastFailure: state.lastFailure,
	}
	// Confidence needs both distinct observations and fresh weighted evidence.
	// The separate window count prevents two busy windows from qualifying.
	// When many backups make round-robin evidence too sparse, the policy gives
	// a promising backup bounded confirmation turns without weakening freshness.
	estimate.Known = state.hasLatency && state.windows >= routeLearningMinWindows &&
		estimate.Samples >= routeLearningMinSamples
	estimate.Cost = routeLearningUnknownLatency
	if state.hasLatency {
		estimate.Cost = state.latency
	}
	estimate.Cost += time.Duration(float64(routeLearningFailurePenalty) * estimate.FailureRatio)
	if !state.degradedAt.IsZero() {
		age := max(time.Duration(0), now.Sub(state.degradedAt))
		if age < routeLearningDegradationMemory {
			estimate.Degraded = true
			estimate.Cost += time.Duration(float64(routeLearningDegradationPenalty) *
				(1 - float64(age)/float64(routeLearningDegradationMemory)))
		}
	}
	return estimate
}

func routeLearningDecay(elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 1
	}
	return math.Exp2(-float64(elapsed) / float64(routeLearningHalfLife))
}

func (learner *routeLearner) makeRoomLocked(key routeLearningKey) {
	if learner.states[key] != nil || len(learner.states) < routeLearningMaxEntries {
		return
	}
	var oldest routeLearningKey
	var oldestAt time.Time
	for candidate, state := range learner.states {
		if oldestAt.IsZero() || state.lastObservation.Before(oldestAt) {
			oldest, oldestAt = candidate, state.lastObservation
		}
	}
	delete(learner.states, oldest)
}

func (learner *routeLearner) clearRule(rule string) {
	if learner == nil {
		return
	}
	learner.mu.Lock()
	defer learner.mu.Unlock()
	for key := range learner.states {
		if key.rule == rule {
			delete(learner.states, key)
		}
	}
}

// inherit copies data only for caller-verified unchanged rule identities.
// The new runtime retains independent synchronization and failure deduplication.
func (learner *routeLearner) inherit(previous *routeLearner, rules map[string]struct{}) {
	if learner == nil || previous == nil || learner == previous || len(rules) == 0 {
		return
	}
	copies := make(map[routeLearningKey]routeLearningState)
	previous.mu.Lock()
	for key, state := range previous.states {
		if _, keep := rules[key.rule]; keep {
			copies[key] = *state
		}
	}
	previous.mu.Unlock()
	learner.mu.Lock()
	defer learner.mu.Unlock()
	for key, state := range copies {
		learner.makeRoomLocked(key)
		clone := state
		learner.states[key] = &clone
	}
}
