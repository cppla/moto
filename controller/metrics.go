package controller

import (
	"context"
	"errors"
	"moto/config"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	prometheusContentType              = "text/plain; version=0.0.4; charset=utf-8"
	metricsMaxConcurrentScrapes        = 4
	boostHedgeScheduled                = "scheduled"
	boostHedgeLaunched                 = "launched"
	boostHedgeWon                      = "won"
	boostHedgeAvoided                  = "avoided"
	boostHedgeSkippedCapacity          = "skipped_capacity"
	boostHedgeSkippedDeadline          = "skipped_deadline"
	boostHedgeNoCandidate              = "no_candidate"
	connectProxyAttemptSuccess         = "success"
	connectProxyAttemptStatusError     = "status_error"
	connectProxyAttemptTransportError  = "transport_error"
	connectProxyAttemptCanceled        = "canceled"
	connectProxyAttemptTimeout         = "timeout"
	connectProxyAttemptUnavailable     = "unavailable"
	connectProxyAttemptCooldown        = "cooldown"
	connectProxyAttemptCapacity        = "capacity"
	connectProxyFallbackUnavailable    = "unavailable"
	connectProxyFallbackCooldown       = "cooldown"
	connectProxyFallbackCapacity       = "capacity"
	connectProxyFallbackStatus405      = "status_405"
	connectProxyFallbackStatus501      = "status_501"
	connectProxyFallbackStatus505      = "status_505"
	connectProxyFallbackCanceled       = "canceled"
	connectProxyFallbackTimeout        = "timeout"
	connectProxyFallbackTransportError = "transport_error"
)

type connectionMetricKey struct {
	rule string
	mode string
}

type rejectionMetricKey struct {
	rule   string
	mode   string
	reason string
}

type relayMetricKey struct {
	rule      string
	direction string
}

type dialMetricKey struct {
	rule   string
	target string
}

type boostHedgeMetricKey struct {
	rule    string
	outcome string
}

type connectProxyMetricKey struct {
	rule     string
	target   string
	protocol string
}

type connectProxyAttemptMetricKey struct {
	rule     string
	target   string
	protocol string
	outcome  string
}

type connectProxyFallbackMetricKey struct {
	rule   string
	target string
	from   string
	to     string
	reason string
}

type connectProxyPayloadMetricKey struct {
	connectProxyMetricKey
	direction string
}

// connectProxyTunnelMetrics is allocated once per live configured
// rule/target/protocol label set. Successful tunnel wrappers keep a direct
// pointer to it so payload accounting stays lock-free on the relay hot path.
type connectProxyTunnelMetrics struct {
	active              atomic.Int64
	clientToTargetBytes atomic.Uint64
	targetToClientBytes atomic.Uint64
	lastSuccessUnix     atomic.Int64
}

// metricRegistry is the process-wide in-memory metrics registry. Recording is
// deliberately cheap and dependency-free; rendering takes a snapshot so a
// slow scrape never holds the write lock used by traffic paths.
type metricRegistry struct {
	mu               sync.RWMutex
	ruleRefs         map[string]int
	connectionRefs   map[connectionMetricKey]int
	dialRefs         map[dialMetricKey]int
	connectProxyRefs map[connectProxyMetricKey]int

	connectionsAccepted    map[connectionMetricKey]uint64
	connectionsRejected    map[rejectionMetricKey]uint64
	connectionsActive      map[connectionMetricKey]int64
	relayBytes             map[relayMetricKey]uint64
	relayErrors            map[relayMetricKey]uint64
	relayDurationNanos     map[string]uint64
	relayDurationCount     map[string]uint64
	dialAttempts           map[dialMetricKey]uint64
	dialSuccess            map[dialMetricKey]uint64
	dialFailures           map[dialMetricKey]uint64
	dialCanceled           map[dialMetricKey]uint64
	dialLatencyNanos       map[dialMetricKey]uint64
	dialLatencyCount       map[dialMetricKey]uint64
	dialBulkheadWaitNanos  map[dialMetricKey]uint64
	dialBulkheadWaitCount  map[dialMetricKey]uint64
	dialBulkheadRejected   map[dialMetricKey]uint64
	boostCacheHits         map[string]uint64
	boostCacheMisses       map[string]uint64
	boostHedgeEvents       map[boostHedgeMetricKey]uint64
	boostHedgeDelayNanos   map[string]uint64
	boostHedgeDelayCount   map[string]uint64
	boostDecisionNanos     map[string]uint64
	boostDecisionCount     map[string]uint64
	connectProxyAttempts   map[connectProxyAttemptMetricKey]uint64
	connectProxyHandshakes map[connectProxyAttemptMetricKey]uint64
	connectProxySetupNanos map[connectProxyMetricKey]uint64
	connectProxySetupCount map[connectProxyMetricKey]uint64
	connectProxyFallbacks  map[connectProxyFallbackMetricKey]uint64
	connectProxyTunnels    map[connectProxyMetricKey]*connectProxyTunnelMetrics
}

type metricSnapshot struct {
	connectionsAccepted     map[connectionMetricKey]uint64
	connectionsRejected     map[rejectionMetricKey]uint64
	connectionsActive       map[connectionMetricKey]int64
	relayBytes              map[relayMetricKey]uint64
	relayErrors             map[relayMetricKey]uint64
	relayDurationNanos      map[string]uint64
	relayDurationCount      map[string]uint64
	dialAttempts            map[dialMetricKey]uint64
	dialSuccess             map[dialMetricKey]uint64
	dialFailures            map[dialMetricKey]uint64
	dialCanceled            map[dialMetricKey]uint64
	dialLatencyNanos        map[dialMetricKey]uint64
	dialLatencyCount        map[dialMetricKey]uint64
	dialBulkheadWaitNanos   map[dialMetricKey]uint64
	dialBulkheadWaitCount   map[dialMetricKey]uint64
	dialBulkheadRejected    map[dialMetricKey]uint64
	boostCacheHits          map[string]uint64
	boostCacheMisses        map[string]uint64
	boostHedgeEvents        map[boostHedgeMetricKey]uint64
	boostHedgeDelayNanos    map[string]uint64
	boostHedgeDelayCount    map[string]uint64
	boostDecisionNanos      map[string]uint64
	boostDecisionCount      map[string]uint64
	connectProxyAttempts    map[connectProxyAttemptMetricKey]uint64
	connectProxyHandshakes  map[connectProxyAttemptMetricKey]uint64
	connectProxySetupNanos  map[connectProxyMetricKey]uint64
	connectProxySetupCount  map[connectProxyMetricKey]uint64
	connectProxyFallbacks   map[connectProxyFallbackMetricKey]uint64
	connectProxyActive      map[connectProxyMetricKey]int64
	connectProxyPayload     map[connectProxyPayloadMetricKey]uint64
	connectProxyLastSuccess map[connectProxyMetricKey]int64
}

func newMetricRegistry() *metricRegistry {
	return &metricRegistry{
		ruleRefs:               make(map[string]int),
		connectionRefs:         make(map[connectionMetricKey]int),
		dialRefs:               make(map[dialMetricKey]int),
		connectProxyRefs:       make(map[connectProxyMetricKey]int),
		connectionsAccepted:    make(map[connectionMetricKey]uint64),
		connectionsRejected:    make(map[rejectionMetricKey]uint64),
		connectionsActive:      make(map[connectionMetricKey]int64),
		relayBytes:             make(map[relayMetricKey]uint64),
		relayErrors:            make(map[relayMetricKey]uint64),
		relayDurationNanos:     make(map[string]uint64),
		relayDurationCount:     make(map[string]uint64),
		dialAttempts:           make(map[dialMetricKey]uint64),
		dialSuccess:            make(map[dialMetricKey]uint64),
		dialFailures:           make(map[dialMetricKey]uint64),
		dialCanceled:           make(map[dialMetricKey]uint64),
		dialLatencyNanos:       make(map[dialMetricKey]uint64),
		dialLatencyCount:       make(map[dialMetricKey]uint64),
		dialBulkheadWaitNanos:  make(map[dialMetricKey]uint64),
		dialBulkheadWaitCount:  make(map[dialMetricKey]uint64),
		dialBulkheadRejected:   make(map[dialMetricKey]uint64),
		boostCacheHits:         make(map[string]uint64),
		boostCacheMisses:       make(map[string]uint64),
		boostHedgeEvents:       make(map[boostHedgeMetricKey]uint64),
		boostHedgeDelayNanos:   make(map[string]uint64),
		boostHedgeDelayCount:   make(map[string]uint64),
		boostDecisionNanos:     make(map[string]uint64),
		boostDecisionCount:     make(map[string]uint64),
		connectProxyAttempts:   make(map[connectProxyAttemptMetricKey]uint64),
		connectProxyHandshakes: make(map[connectProxyAttemptMetricKey]uint64),
		connectProxySetupNanos: make(map[connectProxyMetricKey]uint64),
		connectProxySetupCount: make(map[connectProxyMetricKey]uint64),
		connectProxyFallbacks:  make(map[connectProxyFallbackMetricKey]uint64),
		connectProxyTunnels:    make(map[connectProxyMetricKey]*connectProxyTunnelMetrics),
	}
}

// registerRules pins every label family a routing generation may emit. The
// reference counts let multiple servers and draining generations share labels
// while still reclaiming names and targets that disappear across hot reloads.
func (registry *metricRegistry) registerRules(rules []*config.Rule) {
	ruleNames, connectionKeys, dialKeys, connectProxyKeys := metricRuleKeys(rules)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for rule := range ruleNames {
		registry.ruleRefs[rule]++
	}
	for key := range connectionKeys {
		registry.connectionRefs[key]++
	}
	for key := range dialKeys {
		registry.dialRefs[key]++
	}
	for key := range connectProxyKeys {
		if registry.connectProxyRefs[key] == 0 {
			registry.connectProxyTunnels[key] = &connectProxyTunnelMetrics{}
		}
		registry.connectProxyRefs[key]++
	}
}

func (registry *metricRegistry) unregisterRules(rules []*config.Rule) {
	ruleNames, connectionKeys, dialKeys, connectProxyKeys := metricRuleKeys(rules)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	retiredConnectProxyKeys := make(map[connectProxyMetricKey]struct{}, len(connectProxyKeys))
	for key := range connectProxyKeys {
		if registry.connectProxyRefs[key] > 1 {
			registry.connectProxyRefs[key]--
			continue
		}
		delete(registry.connectProxyRefs, key)
		delete(registry.connectProxySetupNanos, key)
		delete(registry.connectProxySetupCount, key)
		delete(registry.connectProxyTunnels, key)
		retiredConnectProxyKeys[key] = struct{}{}
	}
	if len(retiredConnectProxyKeys) != 0 {
		// Sweep each variable-dimension family once. Re-scanning all series for
		// every retired key would make hot-reload cleanup quadratic while holding
		// the registry's global write lock.
		for attempt := range registry.connectProxyAttempts {
			key := connectProxyMetricKey{rule: attempt.rule, target: attempt.target, protocol: attempt.protocol}
			if _, retired := retiredConnectProxyKeys[key]; retired {
				delete(registry.connectProxyAttempts, attempt)
			}
		}
		for handshake := range registry.connectProxyHandshakes {
			key := connectProxyMetricKey{rule: handshake.rule, target: handshake.target, protocol: handshake.protocol}
			if _, retired := retiredConnectProxyKeys[key]; retired {
				delete(registry.connectProxyHandshakes, handshake)
			}
		}
		for fallback := range registry.connectProxyFallbacks {
			from := connectProxyMetricKey{rule: fallback.rule, target: fallback.target, protocol: fallback.from}
			to := connectProxyMetricKey{rule: fallback.rule, target: fallback.target, protocol: fallback.to}
			_, fromRetired := retiredConnectProxyKeys[from]
			_, toRetired := retiredConnectProxyKeys[to]
			if fromRetired || toRetired {
				delete(registry.connectProxyFallbacks, fallback)
			}
		}
	}
	for key := range dialKeys {
		if registry.dialRefs[key] > 1 {
			registry.dialRefs[key]--
			continue
		}
		delete(registry.dialRefs, key)
		delete(registry.dialAttempts, key)
		delete(registry.dialSuccess, key)
		delete(registry.dialFailures, key)
		delete(registry.dialCanceled, key)
		delete(registry.dialLatencyNanos, key)
		delete(registry.dialLatencyCount, key)
		delete(registry.dialBulkheadWaitNanos, key)
		delete(registry.dialBulkheadWaitCount, key)
		delete(registry.dialBulkheadRejected, key)
	}
	for key := range connectionKeys {
		if registry.connectionRefs[key] > 1 {
			registry.connectionRefs[key]--
			continue
		}
		delete(registry.connectionRefs, key)
		delete(registry.connectionsAccepted, key)
		delete(registry.connectionsActive, key)
		for rejected := range registry.connectionsRejected {
			if rejected.rule == key.rule && rejected.mode == key.mode {
				delete(registry.connectionsRejected, rejected)
			}
		}
	}
	for rule := range ruleNames {
		if registry.ruleRefs[rule] > 1 {
			registry.ruleRefs[rule]--
			continue
		}
		delete(registry.ruleRefs, rule)
		delete(registry.relayDurationNanos, rule)
		delete(registry.relayDurationCount, rule)
		delete(registry.boostCacheHits, rule)
		delete(registry.boostCacheMisses, rule)
		delete(registry.boostHedgeDelayNanos, rule)
		delete(registry.boostHedgeDelayCount, rule)
		delete(registry.boostDecisionNanos, rule)
		delete(registry.boostDecisionCount, rule)
		for key := range registry.boostHedgeEvents {
			if key.rule == rule {
				delete(registry.boostHedgeEvents, key)
			}
		}
		for key := range registry.relayBytes {
			if key.rule == rule {
				delete(registry.relayBytes, key)
			}
		}
		for key := range registry.relayErrors {
			if key.rule == rule {
				delete(registry.relayErrors, key)
			}
		}
	}
}

func metricRuleKeys(rules []*config.Rule) (
	map[string]struct{},
	map[connectionMetricKey]struct{},
	map[dialMetricKey]struct{},
	map[connectProxyMetricKey]struct{},
) {
	ruleNames := make(map[string]struct{})
	connections := make(map[connectionMetricKey]struct{})
	dials := make(map[dialMetricKey]struct{})
	connectProxies := make(map[connectProxyMetricKey]struct{})
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		ruleNames[rule.Name] = struct{}{}
		connections[connectionMetricKey{rule: rule.Name, mode: rule.Mode}] = struct{}{}
		for _, target := range rule.Targets {
			if target == nil {
				continue
			}
			dials[dialMetricKey{rule: rule.Name, target: target.Address}] = struct{}{}
			if target.ConnectProxy == nil {
				continue
			}
			protocols := target.ConnectProxy.Protocols
			if len(protocols) == 0 {
				protocols = []string{config.ConnectProxyH2}
			}
			for _, protocol := range protocols {
				if protocol == config.ConnectProxyH2 || protocol == config.ConnectProxyH3 {
					connectProxies[connectProxyMetricKey{rule: rule.Name, target: target.Address, protocol: protocol}] = struct{}{}
				}
			}
		}
	}
	return ruleNames, connections, dials, connectProxies
}

var processMetrics = newMetricRegistry()

// metricConnectionAccepted records a connection admitted by policy and
// connection limits.
func metricConnectionAccepted(rule, mode string) {
	key := connectionMetricKey{rule: rule, mode: mode}
	processMetrics.mu.Lock()
	processMetrics.connectionsAccepted[key]++
	processMetrics.mu.Unlock()
}

// metricConnectionRejected records a rejected connection. reason should be a
// bounded enum supplied by the caller, rather than client-controlled text.
func metricConnectionRejected(rule, mode, reason string) {
	key := rejectionMetricKey{rule: rule, mode: mode, reason: reason}
	processMetrics.mu.Lock()
	processMetrics.connectionsRejected[key]++
	processMetrics.mu.Unlock()
}

// metricConnectionActive applies delta to the active-connection gauge. The
// value is clamped at zero so a defensive cleanup cannot expose an impossible
// negative connection count.
func metricConnectionActive(rule, mode string, delta int64) {
	key := connectionMetricKey{rule: rule, mode: mode}
	processMetrics.mu.Lock()
	next := processMetrics.connectionsActive[key] + delta
	if next < 0 {
		next = 0
	}
	processMetrics.connectionsActive[key] = next
	processMetrics.mu.Unlock()
}

// metricRelay records bytes copied in one relay direction and, when non-nil,
// the error that ended that direction.
func metricRelay(rule, direction string, bytes int64, err error) {
	key := relayMetricKey{rule: rule, direction: direction}
	processMetrics.mu.Lock()
	// Keep the zero-valued series visible even for an immediate relay error.
	processMetrics.relayBytes[key] += nonNegativeUint64(bytes)
	if err != nil {
		processMetrics.relayErrors[key]++
	}
	processMetrics.mu.Unlock()
}

// metricRelayDuration records one completed bidirectional relay duration.
func metricRelayDuration(rule string, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	processMetrics.mu.Lock()
	processMetrics.relayDurationNanos[rule] += uint64(duration)
	processMetrics.relayDurationCount[rule]++
	processMetrics.mu.Unlock()
}

// metricDial records one complete dial attempt, including its outcome and
// elapsed time. Non-cancelled failures are included in latency; canceled race
// losers have only a lower-bound duration and are tracked separately.
func metricDial(rule, target string, latency time.Duration, err error) {
	if latency < 0 {
		latency = 0
	}
	key := dialMetricKey{rule: rule, target: target}
	canceled := errors.Is(err, context.Canceled)
	processMetrics.mu.Lock()
	processMetrics.dialAttempts[key]++
	if err == nil {
		processMetrics.dialSuccess[key]++
	} else if canceled {
		processMetrics.dialCanceled[key]++
	} else {
		processMetrics.dialFailures[key]++
	}
	if !canceled {
		processMetrics.dialLatencyNanos[key] += uint64(latency)
		processMetrics.dialLatencyCount[key]++
	}
	processMetrics.mu.Unlock()
}

// metricDialBulkhead records the local admission delay separately from network
// dial latency. Only expiry of the small capacity wait budget is a rejection;
// parent-context cancellation remains observable in the wait summary without
// being mislabeled as upstream failure or local overload.
func metricDialBulkhead(rule, target string, waited time.Duration, err error) {
	if waited < 0 {
		waited = 0
	}
	key := dialMetricKey{rule: rule, target: target}
	processMetrics.mu.Lock()
	processMetrics.dialBulkheadWaitNanos[key] += uint64(waited)
	processMetrics.dialBulkheadWaitCount[key]++
	if errors.Is(err, errDialBulkheadSaturated) {
		processMetrics.dialBulkheadRejected[key]++
	}
	processMetrics.mu.Unlock()
}

// metricConnectProxyAttempt records one bounded protocol outcome. setupObserved
// is false for local skips such as a cooldown or an unavailable transport; only
// actual CONNECT setup calls contribute to the duration summary. Requiring a
// live rule/target/protocol reference prevents stale generations or accidental
// call sites from creating unbounded label series.
func metricConnectProxyAttempt(rule, target, protocol, outcome string, setup time.Duration, setupObserved bool) {
	if rule == "" || target == "" || !connectProxyProtocolValid(protocol) || !connectProxyAttemptOutcomeValid(outcome) {
		return
	}
	if setup < 0 {
		setup = 0
	}
	baseKey := connectProxyMetricKey{rule: rule, target: target, protocol: protocol}
	attemptKey := connectProxyAttemptMetricKey{rule: rule, target: target, protocol: protocol, outcome: outcome}
	processMetrics.mu.Lock()
	if processMetrics.connectProxyRefs[baseKey] == 0 {
		processMetrics.mu.Unlock()
		return
	}
	processMetrics.connectProxyAttempts[attemptKey]++
	if setupObserved {
		processMetrics.connectProxySetupNanos[baseKey] += uint64(setup)
		processMetrics.connectProxySetupCount[baseKey]++
	}
	processMetrics.mu.Unlock()
}

// metricConnectProxyHandshake records one physical H3 DNS+QUIC setup. Logical
// request attempts remain separate: many requests may wait on one handshake,
// so this bounded family makes coalescing and failure amplification observable.
func metricConnectProxyHandshake(rule, target, outcome string) {
	if rule == "" || target == "" || !connectProxyAttemptOutcomeValid(outcome) {
		return
	}
	baseKey := connectProxyMetricKey{rule: rule, target: target, protocol: config.ConnectProxyH3}
	handshakeKey := connectProxyAttemptMetricKey{
		rule: rule, target: target, protocol: config.ConnectProxyH3, outcome: outcome,
	}
	processMetrics.mu.Lock()
	if processMetrics.connectProxyRefs[baseKey] != 0 {
		processMetrics.connectProxyHandshakes[handshakeKey]++
	}
	processMetrics.mu.Unlock()
}

// metricConnectProxyFallback records only the configured H3-to-H2 transition.
// The reason is a fixed enum; no status text or network error is used as a
// label. Both protocol references must still belong to a live generation.
func metricConnectProxyFallback(rule, target, reason string) {
	if rule == "" || target == "" || !connectProxyFallbackReasonValid(reason) {
		return
	}
	fromKey := connectProxyMetricKey{rule: rule, target: target, protocol: config.ConnectProxyH3}
	toKey := connectProxyMetricKey{rule: rule, target: target, protocol: config.ConnectProxyH2}
	key := connectProxyFallbackMetricKey{
		rule: rule, target: target,
		from: config.ConnectProxyH3, to: config.ConnectProxyH2,
		reason: reason,
	}
	processMetrics.mu.Lock()
	if processMetrics.connectProxyRefs[fromKey] == 0 || processMetrics.connectProxyRefs[toKey] == 0 {
		processMetrics.mu.Unlock()
		return
	}
	processMetrics.connectProxyFallbacks[key]++
	processMetrics.mu.Unlock()
}

// metricConnectProxyTunnelOpened returns the bounded metric series attached to
// one successfully established HTTP CONNECT tunnel. The caller retains the
// returned pointer for lock-free payload accounting until the tunnel closes.
func metricConnectProxyTunnelOpened(rule, target, protocol string, now time.Time) *connectProxyTunnelMetrics {
	if rule == "" || target == "" || !connectProxyProtocolValid(protocol) {
		return nil
	}
	key := connectProxyMetricKey{rule: rule, target: target, protocol: protocol}
	processMetrics.mu.RLock()
	metrics := processMetrics.connectProxyTunnels[key]
	if metrics != nil {
		metrics.active.Add(1)
		timestamp := max(int64(0), now.Unix())
		for previous := metrics.lastSuccessUnix.Load(); timestamp > previous; previous = metrics.lastSuccessUnix.Load() {
			if metrics.lastSuccessUnix.CompareAndSwap(previous, timestamp) {
				break
			}
		}
	}
	processMetrics.mu.RUnlock()
	if metrics == nil {
		return nil
	}
	return metrics
}

func connectProxyProtocolValid(protocol string) bool {
	return protocol == config.ConnectProxyH2 || protocol == config.ConnectProxyH3
}

func connectProxyAttemptOutcomeValid(outcome string) bool {
	switch outcome {
	case connectProxyAttemptSuccess, connectProxyAttemptStatusError,
		connectProxyAttemptTransportError, connectProxyAttemptCanceled,
		connectProxyAttemptTimeout, connectProxyAttemptUnavailable,
		connectProxyAttemptCooldown, connectProxyAttemptCapacity,
		string(connectProxyFailurePolicyDenied), string(connectProxyFailureProxyAuth),
		string(connectProxyFailureRateLimited), string(connectProxyFailureDestinationConnect),
		string(connectProxyFailureServiceUnavailable), string(connectProxyFailureProtocolUnsupported):
		return true
	default:
		return false
	}
}

func connectProxyFallbackReasonValid(reason string) bool {
	switch reason {
	case connectProxyFallbackUnavailable, connectProxyFallbackCooldown,
		connectProxyFallbackCapacity,
		connectProxyFallbackStatus405, connectProxyFallbackStatus501,
		connectProxyFallbackStatus505, connectProxyFallbackCanceled,
		connectProxyFallbackTimeout, connectProxyFallbackTransportError:
		return true
	default:
		return false
	}
}

// metricBoostCache records a winner-cache lookup for a boost rule.
func metricBoostCache(rule string, hit bool) {
	processMetrics.mu.Lock()
	if hit {
		processMetrics.boostCacheHits[rule]++
	} else {
		processMetrics.boostCacheMisses[rule]++
	}
	processMetrics.mu.Unlock()
}

// metricBoostHedgeEvent records one bounded scheduler outcome. Rejecting
// unknown outcomes keeps the Prometheus label cardinality independent of
// network or configuration input.
func metricBoostHedgeEvent(rule, outcome string) {
	switch outcome {
	case boostHedgeScheduled, boostHedgeLaunched, boostHedgeWon,
		boostHedgeAvoided, boostHedgeSkippedCapacity, boostHedgeSkippedDeadline,
		boostHedgeNoCandidate:
	default:
		return
	}
	key := boostHedgeMetricKey{rule: rule, outcome: outcome}
	processMetrics.mu.Lock()
	processMetrics.boostHedgeEvents[key]++
	processMetrics.mu.Unlock()
}

// metricBoostHedgeDelay records the adaptive delay chosen when scheduling an
// optional second dial. It does not include bulkhead admission wait time.
func metricBoostHedgeDelay(rule string, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	processMetrics.mu.Lock()
	processMetrics.boostHedgeDelayNanos[rule] += uint64(delay)
	processMetrics.boostHedgeDelayCount[rule]++
	processMetrics.mu.Unlock()
}

// metricBoostDecisionDuration measures the complete route decision, including
// cache lookup, local admission, network dial, and optional hedge scheduling.
func metricBoostDecisionDuration(rule string, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	processMetrics.mu.Lock()
	processMetrics.boostDecisionNanos[rule] += uint64(duration)
	processMetrics.boostDecisionCount[rule]++
	processMetrics.mu.Unlock()
}

func nonNegativeUint64(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func cloneMetricMap[K comparable, V any](source map[K]V) map[K]V {
	clone := make(map[K]V, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func (registry *metricRegistry) snapshot() metricSnapshot {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	connectProxyActive := make(map[connectProxyMetricKey]int64, len(registry.connectProxyTunnels))
	connectProxyPayload := make(map[connectProxyPayloadMetricKey]uint64, len(registry.connectProxyTunnels)*2)
	connectProxyLastSuccess := make(map[connectProxyMetricKey]int64, len(registry.connectProxyTunnels))
	for key, metrics := range registry.connectProxyTunnels {
		if metrics == nil {
			continue
		}
		active := metrics.active.Load()
		if active < 0 {
			active = 0
		}
		connectProxyActive[key] = active
		connectProxyPayload[connectProxyPayloadMetricKey{
			connectProxyMetricKey: key,
			direction:             string(relayDirectionClientToTarget),
		}] = metrics.clientToTargetBytes.Load()
		connectProxyPayload[connectProxyPayloadMetricKey{
			connectProxyMetricKey: key,
			direction:             string(relayDirectionTargetToClient),
		}] = metrics.targetToClientBytes.Load()
		connectProxyLastSuccess[key] = metrics.lastSuccessUnix.Load()
	}
	return metricSnapshot{
		connectionsAccepted:     cloneMetricMap(registry.connectionsAccepted),
		connectionsRejected:     cloneMetricMap(registry.connectionsRejected),
		connectionsActive:       cloneMetricMap(registry.connectionsActive),
		relayBytes:              cloneMetricMap(registry.relayBytes),
		relayErrors:             cloneMetricMap(registry.relayErrors),
		relayDurationNanos:      cloneMetricMap(registry.relayDurationNanos),
		relayDurationCount:      cloneMetricMap(registry.relayDurationCount),
		dialAttempts:            cloneMetricMap(registry.dialAttempts),
		dialSuccess:             cloneMetricMap(registry.dialSuccess),
		dialFailures:            cloneMetricMap(registry.dialFailures),
		dialCanceled:            cloneMetricMap(registry.dialCanceled),
		dialLatencyNanos:        cloneMetricMap(registry.dialLatencyNanos),
		dialLatencyCount:        cloneMetricMap(registry.dialLatencyCount),
		dialBulkheadWaitNanos:   cloneMetricMap(registry.dialBulkheadWaitNanos),
		dialBulkheadWaitCount:   cloneMetricMap(registry.dialBulkheadWaitCount),
		dialBulkheadRejected:    cloneMetricMap(registry.dialBulkheadRejected),
		boostCacheHits:          cloneMetricMap(registry.boostCacheHits),
		boostCacheMisses:        cloneMetricMap(registry.boostCacheMisses),
		boostHedgeEvents:        cloneMetricMap(registry.boostHedgeEvents),
		boostHedgeDelayNanos:    cloneMetricMap(registry.boostHedgeDelayNanos),
		boostHedgeDelayCount:    cloneMetricMap(registry.boostHedgeDelayCount),
		boostDecisionNanos:      cloneMetricMap(registry.boostDecisionNanos),
		boostDecisionCount:      cloneMetricMap(registry.boostDecisionCount),
		connectProxyAttempts:    cloneMetricMap(registry.connectProxyAttempts),
		connectProxyHandshakes:  cloneMetricMap(registry.connectProxyHandshakes),
		connectProxySetupNanos:  cloneMetricMap(registry.connectProxySetupNanos),
		connectProxySetupCount:  cloneMetricMap(registry.connectProxySetupCount),
		connectProxyFallbacks:   cloneMetricMap(registry.connectProxyFallbacks),
		connectProxyActive:      connectProxyActive,
		connectProxyPayload:     connectProxyPayload,
		connectProxyLastSuccess: connectProxyLastSuccess,
	}
}

var metricsGaugeRenderer struct {
	sync.RWMutex
	render func(*strings.Builder)
}

// setMetricsGaugeRenderer installs an optional renderer for process gauges
// owned by other subsystems (for example route health or prewarm pools). It is
// safe to replace or clear while scrapes are in flight. The renderer is called
// after the built-in metric families and must provide deterministic output.
func setMetricsGaugeRenderer(render func(*strings.Builder)) {
	metricsGaugeRenderer.Lock()
	metricsGaugeRenderer.render = render
	metricsGaugeRenderer.Unlock()
}

func currentMetricsGaugeRenderer() func(*strings.Builder) {
	metricsGaugeRenderer.RLock()
	render := metricsGaugeRenderer.render
	metricsGaugeRenderer.RUnlock()
	return render
}

type observabilityHandler struct {
	ready             func() bool
	renderGauges      func(*strings.Builder)
	useGlobalRenderer bool
	scrapes           chan struct{}
}

func newObservabilityHandler(ready func() bool, renderGauges ...func(*strings.Builder)) http.Handler {
	var render func(*strings.Builder)
	if len(renderGauges) > 0 {
		render = renderGauges[0]
	}
	return observabilityHandler{
		ready:             ready,
		renderGauges:      render,
		useGlobalRenderer: len(renderGauges) == 0,
		scrapes:           make(chan struct{}, metricsMaxConcurrentScrapes),
	}
}

func (handler observabilityHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch request.URL.Path {
	case "/healthz":
		writeObservabilityResponse(writer, request, http.StatusOK, "ok\n")
	case "/readyz":
		if handler.ready != nil && handler.ready() {
			writeObservabilityResponse(writer, request, http.StatusOK, "ready\n")
			return
		}
		writeObservabilityResponse(writer, request, http.StatusServiceUnavailable, "not ready\n")
	case "/metrics":
		if request.Method != http.MethodHead {
			select {
			case handler.scrapes <- struct{}{}:
				defer func() { <-handler.scrapes }()
			default:
				writeObservabilityResponse(writer, request, http.StatusServiceUnavailable, "too many concurrent scrapes\n")
				return
			}
		}
		writer.Header().Set("Content-Type", prometheusContentType)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			if handler.useGlobalRenderer {
				_, _ = writer.Write([]byte(renderPrometheusMetrics()))
			} else {
				_, _ = writer.Write([]byte(renderPrometheusMetrics(handler.renderGauges)))
			}
		}
	default:
		http.NotFound(writer, request)
	}
}

func writeObservabilityResponse(writer http.ResponseWriter, request *http.Request, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write([]byte(body))
	}
}

type prometheusLabel struct {
	name  string
	value string
}

func renderPrometheusMetrics(renderGauges ...func(*strings.Builder)) string {
	snapshot := processMetrics.snapshot()
	var output strings.Builder

	writeMetricHeader(&output, "moto_go_goroutines", "Current number of goroutines in the Moto process.", "gauge")
	writeMetricSample(&output, "moto_go_goroutines", nil, strconv.Itoa(runtime.NumGoroutine()))

	writeMetricHeader(&output, "moto_connections_accepted_total", "Connections accepted by rule and mode.", "counter")
	for _, key := range sortedConnectionKeys(snapshot.connectionsAccepted) {
		writeMetricSample(&output, "moto_connections_accepted_total", []prometheusLabel{{"rule", key.rule}, {"mode", key.mode}}, strconv.FormatUint(snapshot.connectionsAccepted[key], 10))
	}

	writeMetricHeader(&output, "moto_connections_rejected_total", "Connections rejected by rule, mode, and reason.", "counter")
	for _, key := range sortedRejectionKeys(snapshot.connectionsRejected) {
		writeMetricSample(&output, "moto_connections_rejected_total", []prometheusLabel{{"rule", key.rule}, {"mode", key.mode}, {"reason", key.reason}}, strconv.FormatUint(snapshot.connectionsRejected[key], 10))
	}

	writeMetricHeader(&output, "moto_connections_active", "Currently active connections by rule and mode.", "gauge")
	for _, key := range sortedConnectionKeys(snapshot.connectionsActive) {
		writeMetricSample(&output, "moto_connections_active", []prometheusLabel{{"rule", key.rule}, {"mode", key.mode}}, strconv.FormatInt(snapshot.connectionsActive[key], 10))
	}

	writeMetricHeader(&output, "moto_relay_bytes_total", "Bytes relayed by rule and direction.", "counter")
	for _, key := range sortedRelayKeys(snapshot.relayBytes) {
		writeMetricSample(&output, "moto_relay_bytes_total", []prometheusLabel{{"rule", key.rule}, {"direction", key.direction}}, strconv.FormatUint(snapshot.relayBytes[key], 10))
	}

	writeMetricHeader(&output, "moto_relay_errors_total", "Relay errors by rule and direction.", "counter")
	for _, key := range sortedRelayKeys(snapshot.relayErrors) {
		writeMetricSample(&output, "moto_relay_errors_total", []prometheusLabel{{"rule", key.rule}, {"direction", key.direction}}, strconv.FormatUint(snapshot.relayErrors[key], 10))
	}

	writeMetricHeader(&output, "moto_relay_duration_seconds", "Completed bidirectional relay duration in seconds by rule.", "summary")
	for _, rule := range sortedStringKeys(snapshot.relayDurationCount) {
		labels := []prometheusLabel{{"rule", rule}}
		seconds := float64(snapshot.relayDurationNanos[rule]) / float64(time.Second)
		writeMetricSample(&output, "moto_relay_duration_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_relay_duration_seconds_count", labels, strconv.FormatUint(snapshot.relayDurationCount[rule], 10))
	}

	writeMetricHeader(&output, "moto_dial_attempts_total", "Outbound dial attempts by rule and target.", "counter")
	writeDialCounterSamples(&output, "moto_dial_attempts_total", snapshot.dialAttempts)

	writeMetricHeader(&output, "moto_dial_success_total", "Successful outbound dials by rule and target.", "counter")
	writeDialCounterSamples(&output, "moto_dial_success_total", snapshot.dialSuccess)

	writeMetricHeader(&output, "moto_dial_failures_total", "Failed outbound dials by rule and target.", "counter")
	writeDialCounterSamples(&output, "moto_dial_failures_total", snapshot.dialFailures)

	writeMetricHeader(&output, "moto_dial_canceled_total", "Canceled outbound dials by rule and target.", "counter")
	writeDialCounterSamples(&output, "moto_dial_canceled_total", snapshot.dialCanceled)

	writeMetricHeader(&output, "moto_dial_latency_seconds", "Outbound dial latency in seconds by rule and target.", "summary")
	for _, key := range sortedDialKeys(snapshot.dialLatencyCount) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}}
		seconds := float64(snapshot.dialLatencyNanos[key]) / float64(time.Second)
		writeMetricSample(&output, "moto_dial_latency_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_dial_latency_seconds_count", labels, strconv.FormatUint(snapshot.dialLatencyCount[key], 10))
	}

	writeMetricHeader(&output, "moto_dial_bulkhead_wait_seconds", "Local foreground dial admission wait in seconds by rule and target.", "summary")
	for _, key := range sortedDialKeys(snapshot.dialBulkheadWaitCount) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}}
		seconds := float64(snapshot.dialBulkheadWaitNanos[key]) / float64(time.Second)
		writeMetricSample(&output, "moto_dial_bulkhead_wait_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_dial_bulkhead_wait_seconds_count", labels, strconv.FormatUint(snapshot.dialBulkheadWaitCount[key], 10))
	}

	writeMetricHeader(&output, "moto_dial_bulkhead_rejected_total", "Foreground dials rejected after the bounded local capacity wait expired.", "counter")
	writeDialCounterSamples(&output, "moto_dial_bulkhead_rejected_total", snapshot.dialBulkheadRejected)

	writeMetricHeader(&output, "moto_connect_proxy_attempts_total", "Native CONNECT protocol decisions by rule, target, protocol, and bounded outcome.", "counter")
	for _, key := range sortedConnectProxyAttemptKeys(snapshot.connectProxyAttempts) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}, {"outcome", key.outcome}}
		writeMetricSample(&output, "moto_connect_proxy_attempts_total", labels, strconv.FormatUint(snapshot.connectProxyAttempts[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_handshakes_total", "Physical native CONNECT handshakes by initiating rule, target, protocol, and bounded outcome.", "counter")
	for _, key := range sortedConnectProxyAttemptKeys(snapshot.connectProxyHandshakes) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}, {"outcome", key.outcome}}
		writeMetricSample(&output, "moto_connect_proxy_handshakes_total", labels, strconv.FormatUint(snapshot.connectProxyHandshakes[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_setup_duration_seconds", "Native CONNECT setup duration in seconds by rule, target, and protocol.", "summary")
	for _, key := range sortedConnectProxyKeys(snapshot.connectProxySetupCount) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}}
		seconds := float64(snapshot.connectProxySetupNanos[key]) / float64(time.Second)
		writeMetricSample(&output, "moto_connect_proxy_setup_duration_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_connect_proxy_setup_duration_seconds_count", labels, strconv.FormatUint(snapshot.connectProxySetupCount[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_active_tunnels", "Established HTTP CONNECT tunnels currently open by rule, target, and protocol.", "gauge")
	for _, key := range sortedConnectProxyKeys(snapshot.connectProxyActive) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}}
		writeMetricSample(&output, "moto_connect_proxy_active_tunnels", labels, strconv.FormatInt(snapshot.connectProxyActive[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_payload_bytes_total", "Application payload bytes transferred through successful HTTP CONNECT tunnels by direction.", "counter")
	for _, key := range sortedConnectProxyPayloadKeys(snapshot.connectProxyPayload) {
		labels := []prometheusLabel{
			{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}, {"direction", key.direction},
		}
		writeMetricSample(&output, "moto_connect_proxy_payload_bytes_total", labels, strconv.FormatUint(snapshot.connectProxyPayload[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_last_success_timestamp_seconds", "Unix timestamp of the latest successfully established HTTP CONNECT tunnel.", "gauge")
	for _, key := range sortedConnectProxyKeys(snapshot.connectProxyLastSuccess) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"protocol", key.protocol}}
		writeMetricSample(&output, "moto_connect_proxy_last_success_timestamp_seconds", labels, strconv.FormatInt(snapshot.connectProxyLastSuccess[key], 10))
	}

	writeMetricHeader(&output, "moto_connect_proxy_fallbacks_total", "Native CONNECT H3-to-H2 fallbacks by rule, target, and bounded reason.", "counter")
	for _, key := range sortedConnectProxyFallbackKeys(snapshot.connectProxyFallbacks) {
		labels := []prometheusLabel{{"rule", key.rule}, {"target", key.target}, {"from", key.from}, {"to", key.to}, {"reason", key.reason}}
		writeMetricSample(&output, "moto_connect_proxy_fallbacks_total", labels, strconv.FormatUint(snapshot.connectProxyFallbacks[key], 10))
	}

	writeMetricHeader(&output, "moto_boost_cache_hits_total", "Boost winner-cache hits by rule.", "counter")
	writeRuleCounterSamples(&output, "moto_boost_cache_hits_total", snapshot.boostCacheHits)

	writeMetricHeader(&output, "moto_boost_cache_misses_total", "Boost winner-cache misses by rule.", "counter")
	writeRuleCounterSamples(&output, "moto_boost_cache_misses_total", snapshot.boostCacheMisses)

	writeMetricHeader(&output, "moto_boost_hedge_events_total", "Adaptive Boost hedge scheduler events by rule and bounded outcome.", "counter")
	for _, key := range sortedBoostHedgeKeys(snapshot.boostHedgeEvents) {
		writeMetricSample(&output, "moto_boost_hedge_events_total", []prometheusLabel{{"rule", key.rule}, {"outcome", key.outcome}}, strconv.FormatUint(snapshot.boostHedgeEvents[key], 10))
	}

	writeMetricHeader(&output, "moto_boost_hedge_delay_seconds", "Adaptive delay selected before an optional Boost fallback dial.", "summary")
	for _, rule := range sortedStringKeys(snapshot.boostHedgeDelayCount) {
		labels := []prometheusLabel{{"rule", rule}}
		seconds := float64(snapshot.boostHedgeDelayNanos[rule]) / float64(time.Second)
		writeMetricSample(&output, "moto_boost_hedge_delay_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_boost_hedge_delay_seconds_count", labels, strconv.FormatUint(snapshot.boostHedgeDelayCount[rule], 10))
	}

	writeMetricHeader(&output, "moto_boost_decision_duration_seconds", "Complete Boost route-decision duration in seconds by rule.", "summary")
	for _, rule := range sortedStringKeys(snapshot.boostDecisionCount) {
		labels := []prometheusLabel{{"rule", rule}}
		seconds := float64(snapshot.boostDecisionNanos[rule]) / float64(time.Second)
		writeMetricSample(&output, "moto_boost_decision_duration_seconds_sum", labels, strconv.FormatFloat(seconds, 'g', -1, 64))
		writeMetricSample(&output, "moto_boost_decision_duration_seconds_count", labels, strconv.FormatUint(snapshot.boostDecisionCount[rule], 10))
	}

	var render func(*strings.Builder)
	if len(renderGauges) > 0 {
		render = renderGauges[0]
	} else {
		render = currentMetricsGaugeRenderer()
	}
	if render != nil {
		render(&output)
	}
	return output.String()
}

func writeMetricHeader(output *strings.Builder, name, help, metricType string) {
	output.WriteString("# HELP ")
	output.WriteString(name)
	output.WriteByte(' ')
	output.WriteString(help)
	output.WriteByte('\n')
	output.WriteString("# TYPE ")
	output.WriteString(name)
	output.WriteByte(' ')
	output.WriteString(metricType)
	output.WriteByte('\n')
}

func writeMetricSample(output *strings.Builder, name string, labels []prometheusLabel, value string) {
	output.WriteString(name)
	if len(labels) != 0 {
		output.WriteByte('{')
		for index, label := range labels {
			if index != 0 {
				output.WriteByte(',')
			}
			output.WriteString(label.name)
			output.WriteString("=\"")
			output.WriteString(escapePrometheusLabel(label.value))
			output.WriteByte('"')
		}
		output.WriteByte('}')
	}
	output.WriteByte(' ')
	output.WriteString(value)
	output.WriteByte('\n')
}

func escapePrometheusLabel(value string) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "\uFFFD")
	}
	var escaped strings.Builder
	for _, character := range value {
		switch character {
		case '\\':
			escaped.WriteString("\\\\")
		case '"':
			escaped.WriteString("\\\"")
		case '\n':
			escaped.WriteString("\\n")
		default:
			escaped.WriteRune(character)
		}
	}
	return escaped.String()
}

func sortedConnectionKeys[V any](values map[connectionMetricKey]V) []connectionMetricKey {
	keys := make([]connectionMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		return keys[left].mode < keys[right].mode
	})
	return keys
}

func sortedRejectionKeys[V any](values map[rejectionMetricKey]V) []rejectionMetricKey {
	keys := make([]rejectionMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		if keys[left].mode != keys[right].mode {
			return keys[left].mode < keys[right].mode
		}
		return keys[left].reason < keys[right].reason
	})
	return keys
}

func sortedRelayKeys[V any](values map[relayMetricKey]V) []relayMetricKey {
	keys := make([]relayMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		return keys[left].direction < keys[right].direction
	})
	return keys
}

func sortedDialKeys[V any](values map[dialMetricKey]V) []dialMetricKey {
	keys := make([]dialMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		return keys[left].target < keys[right].target
	})
	return keys
}

func sortedBoostHedgeKeys[V any](values map[boostHedgeMetricKey]V) []boostHedgeMetricKey {
	keys := make([]boostHedgeMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		return keys[left].outcome < keys[right].outcome
	})
	return keys
}

func sortedConnectProxyKeys[V any](values map[connectProxyMetricKey]V) []connectProxyMetricKey {
	keys := make([]connectProxyMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		if keys[left].target != keys[right].target {
			return keys[left].target < keys[right].target
		}
		return keys[left].protocol < keys[right].protocol
	})
	return keys
}

func sortedConnectProxyPayloadKeys[V any](values map[connectProxyPayloadMetricKey]V) []connectProxyPayloadMetricKey {
	keys := make([]connectProxyPayloadMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		if keys[left].target != keys[right].target {
			return keys[left].target < keys[right].target
		}
		if keys[left].protocol != keys[right].protocol {
			return keys[left].protocol < keys[right].protocol
		}
		return keys[left].direction < keys[right].direction
	})
	return keys
}

func sortedConnectProxyAttemptKeys[V any](values map[connectProxyAttemptMetricKey]V) []connectProxyAttemptMetricKey {
	keys := make([]connectProxyAttemptMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		if keys[left].target != keys[right].target {
			return keys[left].target < keys[right].target
		}
		if keys[left].protocol != keys[right].protocol {
			return keys[left].protocol < keys[right].protocol
		}
		return keys[left].outcome < keys[right].outcome
	})
	return keys
}

func sortedConnectProxyFallbackKeys[V any](values map[connectProxyFallbackMetricKey]V) []connectProxyFallbackMetricKey {
	keys := make([]connectProxyFallbackMetricKey, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].rule != keys[right].rule {
			return keys[left].rule < keys[right].rule
		}
		if keys[left].target != keys[right].target {
			return keys[left].target < keys[right].target
		}
		if keys[left].from != keys[right].from {
			return keys[left].from < keys[right].from
		}
		if keys[left].to != keys[right].to {
			return keys[left].to < keys[right].to
		}
		return keys[left].reason < keys[right].reason
	})
	return keys
}

func writeDialCounterSamples(output *strings.Builder, name string, values map[dialMetricKey]uint64) {
	for _, key := range sortedDialKeys(values) {
		writeMetricSample(output, name, []prometheusLabel{{"rule", key.rule}, {"target", key.target}}, strconv.FormatUint(values[key], 10))
	}
}

func writeRuleCounterSamples(output *strings.Builder, name string, values map[string]uint64) {
	keys := sortedStringKeys(values)
	for _, key := range keys {
		writeMetricSample(output, name, []prometheusLabel{{"rule", key}}, strconv.FormatUint(values[key], 10))
	}
}

func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
