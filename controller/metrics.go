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
	"time"
	"unicode/utf8"
)

const (
	prometheusContentType       = "text/plain; version=0.0.4; charset=utf-8"
	metricsMaxConcurrentScrapes = 4
	boostHedgeScheduled         = "scheduled"
	boostHedgeLaunched          = "launched"
	boostHedgeWon               = "won"
	boostHedgeAvoided           = "avoided"
	boostHedgeSkippedCapacity   = "skipped_capacity"
	boostHedgeSkippedDeadline   = "skipped_deadline"
	boostHedgeNoCandidate       = "no_candidate"
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

// metricRegistry is the process-wide in-memory metrics registry. Recording is
// deliberately cheap and dependency-free; rendering takes a snapshot so a
// slow scrape never holds the write lock used by traffic paths.
type metricRegistry struct {
	mu             sync.RWMutex
	ruleRefs       map[string]int
	connectionRefs map[connectionMetricKey]int
	dialRefs       map[dialMetricKey]int

	connectionsAccepted   map[connectionMetricKey]uint64
	connectionsRejected   map[rejectionMetricKey]uint64
	connectionsActive     map[connectionMetricKey]int64
	relayBytes            map[relayMetricKey]uint64
	relayErrors           map[relayMetricKey]uint64
	relayDurationNanos    map[string]uint64
	relayDurationCount    map[string]uint64
	dialAttempts          map[dialMetricKey]uint64
	dialSuccess           map[dialMetricKey]uint64
	dialFailures          map[dialMetricKey]uint64
	dialCanceled          map[dialMetricKey]uint64
	dialLatencyNanos      map[dialMetricKey]uint64
	dialLatencyCount      map[dialMetricKey]uint64
	dialBulkheadWaitNanos map[dialMetricKey]uint64
	dialBulkheadWaitCount map[dialMetricKey]uint64
	dialBulkheadRejected  map[dialMetricKey]uint64
	boostCacheHits        map[string]uint64
	boostCacheMisses      map[string]uint64
	boostHedgeEvents      map[boostHedgeMetricKey]uint64
	boostHedgeDelayNanos  map[string]uint64
	boostHedgeDelayCount  map[string]uint64
	boostDecisionNanos    map[string]uint64
	boostDecisionCount    map[string]uint64
}

type metricSnapshot struct {
	connectionsAccepted   map[connectionMetricKey]uint64
	connectionsRejected   map[rejectionMetricKey]uint64
	connectionsActive     map[connectionMetricKey]int64
	relayBytes            map[relayMetricKey]uint64
	relayErrors           map[relayMetricKey]uint64
	relayDurationNanos    map[string]uint64
	relayDurationCount    map[string]uint64
	dialAttempts          map[dialMetricKey]uint64
	dialSuccess           map[dialMetricKey]uint64
	dialFailures          map[dialMetricKey]uint64
	dialCanceled          map[dialMetricKey]uint64
	dialLatencyNanos      map[dialMetricKey]uint64
	dialLatencyCount      map[dialMetricKey]uint64
	dialBulkheadWaitNanos map[dialMetricKey]uint64
	dialBulkheadWaitCount map[dialMetricKey]uint64
	dialBulkheadRejected  map[dialMetricKey]uint64
	boostCacheHits        map[string]uint64
	boostCacheMisses      map[string]uint64
	boostHedgeEvents      map[boostHedgeMetricKey]uint64
	boostHedgeDelayNanos  map[string]uint64
	boostHedgeDelayCount  map[string]uint64
	boostDecisionNanos    map[string]uint64
	boostDecisionCount    map[string]uint64
}

func newMetricRegistry() *metricRegistry {
	return &metricRegistry{
		ruleRefs:              make(map[string]int),
		connectionRefs:        make(map[connectionMetricKey]int),
		dialRefs:              make(map[dialMetricKey]int),
		connectionsAccepted:   make(map[connectionMetricKey]uint64),
		connectionsRejected:   make(map[rejectionMetricKey]uint64),
		connectionsActive:     make(map[connectionMetricKey]int64),
		relayBytes:            make(map[relayMetricKey]uint64),
		relayErrors:           make(map[relayMetricKey]uint64),
		relayDurationNanos:    make(map[string]uint64),
		relayDurationCount:    make(map[string]uint64),
		dialAttempts:          make(map[dialMetricKey]uint64),
		dialSuccess:           make(map[dialMetricKey]uint64),
		dialFailures:          make(map[dialMetricKey]uint64),
		dialCanceled:          make(map[dialMetricKey]uint64),
		dialLatencyNanos:      make(map[dialMetricKey]uint64),
		dialLatencyCount:      make(map[dialMetricKey]uint64),
		dialBulkheadWaitNanos: make(map[dialMetricKey]uint64),
		dialBulkheadWaitCount: make(map[dialMetricKey]uint64),
		dialBulkheadRejected:  make(map[dialMetricKey]uint64),
		boostCacheHits:        make(map[string]uint64),
		boostCacheMisses:      make(map[string]uint64),
		boostHedgeEvents:      make(map[boostHedgeMetricKey]uint64),
		boostHedgeDelayNanos:  make(map[string]uint64),
		boostHedgeDelayCount:  make(map[string]uint64),
		boostDecisionNanos:    make(map[string]uint64),
		boostDecisionCount:    make(map[string]uint64),
	}
}

// registerRules pins every label family a routing generation may emit. The
// reference counts let multiple servers and draining generations share labels
// while still reclaiming names and targets that disappear across hot reloads.
func (registry *metricRegistry) registerRules(rules []*config.Rule) {
	ruleNames, connectionKeys, dialKeys := metricRuleKeys(rules)
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
}

func (registry *metricRegistry) unregisterRules(rules []*config.Rule) {
	ruleNames, connectionKeys, dialKeys := metricRuleKeys(rules)
	registry.mu.Lock()
	defer registry.mu.Unlock()
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

func metricRuleKeys(rules []*config.Rule) (map[string]struct{}, map[connectionMetricKey]struct{}, map[dialMetricKey]struct{}) {
	ruleNames := make(map[string]struct{})
	connections := make(map[connectionMetricKey]struct{})
	dials := make(map[dialMetricKey]struct{})
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		ruleNames[rule.Name] = struct{}{}
		connections[connectionMetricKey{rule: rule.Name, mode: rule.Mode}] = struct{}{}
		for _, target := range rule.Targets {
			if target != nil {
				dials[dialMetricKey{rule: rule.Name, target: target.Address}] = struct{}{}
			}
		}
	}
	return ruleNames, connections, dials
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
	return metricSnapshot{
		connectionsAccepted:   cloneMetricMap(registry.connectionsAccepted),
		connectionsRejected:   cloneMetricMap(registry.connectionsRejected),
		connectionsActive:     cloneMetricMap(registry.connectionsActive),
		relayBytes:            cloneMetricMap(registry.relayBytes),
		relayErrors:           cloneMetricMap(registry.relayErrors),
		relayDurationNanos:    cloneMetricMap(registry.relayDurationNanos),
		relayDurationCount:    cloneMetricMap(registry.relayDurationCount),
		dialAttempts:          cloneMetricMap(registry.dialAttempts),
		dialSuccess:           cloneMetricMap(registry.dialSuccess),
		dialFailures:          cloneMetricMap(registry.dialFailures),
		dialCanceled:          cloneMetricMap(registry.dialCanceled),
		dialLatencyNanos:      cloneMetricMap(registry.dialLatencyNanos),
		dialLatencyCount:      cloneMetricMap(registry.dialLatencyCount),
		dialBulkheadWaitNanos: cloneMetricMap(registry.dialBulkheadWaitNanos),
		dialBulkheadWaitCount: cloneMetricMap(registry.dialBulkheadWaitCount),
		dialBulkheadRejected:  cloneMetricMap(registry.dialBulkheadRejected),
		boostCacheHits:        cloneMetricMap(registry.boostCacheHits),
		boostCacheMisses:      cloneMetricMap(registry.boostCacheMisses),
		boostHedgeEvents:      cloneMetricMap(registry.boostHedgeEvents),
		boostHedgeDelayNanos:  cloneMetricMap(registry.boostHedgeDelayNanos),
		boostHedgeDelayCount:  cloneMetricMap(registry.boostHedgeDelayCount),
		boostDecisionNanos:    cloneMetricMap(registry.boostDecisionNanos),
		boostDecisionCount:    cloneMetricMap(registry.boostDecisionCount),
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
