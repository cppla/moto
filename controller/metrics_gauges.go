package controller

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

type routeGauge struct {
	rule                     string
	mode                     string
	target                   string
	ewma                     time.Duration
	observed                 bool
	consecutiveFailures      int
	circuitOpen              bool
	halfOpen                 bool
	circuitCooldownRemaining time.Duration
	probeDue                 bool
	lastRecovery             time.Time
	lastAttempt              time.Time
}

type prewarmGauge struct {
	target   string
	desired  int
	idle     int
	warming  int
	failures int
}

type activeHealthGauge struct {
	rule      string
	mode      string
	target    string
	unhealthy bool
}

// http3TransportGauge is an aggregate over physical QUIC transports with the
// same configured proxy endpoint, lifecycle, and detector health. Keeping the
// key bounded to configured endpoints and enum values avoids connection- or
// destination-level label cardinality.
type http3TransportGauge struct {
	target                string
	state                 string
	health                string
	transports            int
	activeTunnels         int
	smoothedRTT           time.Duration
	baselineRTT           time.Duration
	lossRatio             float64
	blockedWrites         int
	oldestBlockedFor      time.Duration
	payloadBytesPerSecond float64
	healthyBytesPerSecond float64
}

type http3RotationGauge struct {
	target  string
	reason  string
	outcome string
	count   uint64
}

type http3PolicyGauge struct {
	target             string
	degradationStrikes int
	protocolPenalty    time.Duration
	cooldownActive     bool
	cooldownRemaining  time.Duration
	halfOpen           bool
	boostCanary        bool
	fallbackPending    bool
}

type http3GaugeSnapshot struct {
	transports   []http3TransportGauge
	rotations    []http3RotationGauge
	policies     []http3PolicyGauge
	ruleBreakers []http3RuleBreakerGauge
}

// renderOperationalGauges snapshots route-health and prewarm state without
// holding their locks while Prometheus text is written.
func renderOperationalGauges(output *strings.Builder) {
	defaultRoutingRuntime.renderOperationalGauges(output)
}

func (runtime *routingRuntime) renderOperationalGauges(output *strings.Builder) {
	routes := runtime.routes.snapshotGauges()
	prewarm := runtime.prewarm.snapshotGauges()
	activeHealth := snapshotActiveHealthGauges(runtime.health)
	dialCapacity := runtime.trafficDials.snapshot()
	http3 := snapshotHTTP3Gauges(runtime.connectProxy)

	writeMetricHeader(output, "moto_route_latency_ewma_seconds", "EWMA dial latency for a configured route in seconds.", "gauge")
	for _, route := range routes {
		labels := routeGaugeLabels(route)
		writeMetricSample(output, "moto_route_latency_ewma_seconds", labels, strconv.FormatFloat(float64(route.ewma)/float64(time.Second), 'g', -1, 64))
	}

	writeMetricHeader(output, "moto_route_observed", "Whether a route has produced a completed non-cancelled dial outcome.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_observed", routeGaugeLabels(route), boolMetric(route.observed))
	}

	writeMetricHeader(output, "moto_route_consecutive_failures", "Consecutive dial failures recorded for a route.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_consecutive_failures", routeGaugeLabels(route), strconv.Itoa(route.consecutiveFailures))
	}

	writeMetricHeader(output, "moto_route_circuit_open", "Whether the route circuit breaker is open.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_circuit_open", routeGaugeLabels(route), boolMetric(route.circuitOpen))
	}

	writeMetricHeader(output, "moto_route_half_open", "Whether one recovery probe currently owns the route circuit.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_half_open", routeGaugeLabels(route), boolMetric(route.halfOpen))
	}

	writeMetricHeader(output, "moto_route_circuit_cooldown_remaining_seconds", "Seconds remaining before an open route circuit may run one recovery probe.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_circuit_cooldown_remaining_seconds", routeGaugeLabels(route), strconv.FormatFloat(float64(route.circuitCooldownRemaining)/float64(time.Second), 'g', -1, 64))
	}

	writeMetricHeader(output, "moto_route_probe_due", "Whether an open route circuit is waiting for its single half-open recovery probe.", "gauge")
	for _, route := range routes {
		writeMetricSample(output, "moto_route_probe_due", routeGaugeLabels(route), boolMetric(route.probeDue))
	}

	writeMetricHeader(output, "moto_route_last_recovery_timestamp_seconds", "Unix timestamp of the latest successful half-open route recovery.", "gauge")
	for _, route := range routes {
		value := int64(0)
		if !route.lastRecovery.IsZero() {
			value = route.lastRecovery.Unix()
		}
		writeMetricSample(output, "moto_route_last_recovery_timestamp_seconds", routeGaugeLabels(route), strconv.FormatInt(value, 10))
	}

	writeMetricHeader(output, "moto_route_last_attempt_timestamp_seconds", "Unix timestamp of the latest admitted dial attempt.", "gauge")
	for _, route := range routes {
		value := int64(0)
		if !route.lastAttempt.IsZero() {
			value = route.lastAttempt.Unix()
		}
		writeMetricSample(output, "moto_route_last_attempt_timestamp_seconds", routeGaugeLabels(route), strconv.FormatInt(value, 10))
	}

	writeMetricHeader(output, "moto_prewarm_desired_connections", "Configured idle connection target for a prewarm pool.", "gauge")
	for _, pool := range prewarm {
		writeMetricSample(output, "moto_prewarm_desired_connections", []prometheusLabel{{"target", pool.target}}, strconv.Itoa(pool.desired))
	}
	writeMetricHeader(output, "moto_prewarm_idle_connections", "Currently idle connections in a prewarm pool.", "gauge")
	for _, pool := range prewarm {
		writeMetricSample(output, "moto_prewarm_idle_connections", []prometheusLabel{{"target", pool.target}}, strconv.Itoa(pool.idle))
	}
	writeMetricHeader(output, "moto_prewarm_warming_connections", "In-flight connection attempts for a prewarm pool.", "gauge")
	for _, pool := range prewarm {
		writeMetricSample(output, "moto_prewarm_warming_connections", []prometheusLabel{{"target", pool.target}}, strconv.Itoa(pool.warming))
	}
	writeMetricHeader(output, "moto_prewarm_consecutive_failures", "Consecutive replenishment failures for a prewarm pool.", "gauge")
	for _, pool := range prewarm {
		writeMetricSample(output, "moto_prewarm_consecutive_failures", []prometheusLabel{{"target", pool.target}}, strconv.Itoa(pool.failures))
	}

	writeMetricHeader(output, "moto_active_health_unhealthy", "Whether a target is excluded by threshold-confirmed active health checks.", "gauge")
	for _, target := range activeHealth {
		writeMetricSample(output, "moto_active_health_unhealthy", []prometheusLabel{{"rule", target.rule}, {"mode", target.mode}, {"target", target.target}}, boolMetric(target.unhealthy))
	}

	writeMetricHeader(output, "moto_dial_bulkhead_in_flight", "Foreground network dials currently holding capacity.", "gauge")
	writeMetricSample(output, "moto_dial_bulkhead_in_flight", nil, strconv.Itoa(dialCapacity.Active))
	writeMetricHeader(output, "moto_dial_bulkhead_waiting", "Foreground dials currently waiting for bounded local capacity.", "gauge")
	writeMetricSample(output, "moto_dial_bulkhead_waiting", nil, strconv.Itoa(dialCapacity.Waiting))
	writeMetricHeader(output, "moto_dial_bulkhead_global_limit", "Maximum concurrent foreground network dials for this Moto server.", "gauge")
	writeMetricSample(output, "moto_dial_bulkhead_global_limit", nil, strconv.Itoa(dialCapacity.GlobalLimit))
	writeMetricHeader(output, "moto_dial_bulkhead_per_target_limit", "Maximum concurrent foreground network dials to one configured target.", "gauge")
	writeMetricSample(output, "moto_dial_bulkhead_per_target_limit", nil, strconv.Itoa(dialCapacity.PerTargetLimit))
	writeMetricHeader(output, "moto_dial_bulkhead_target_in_flight", "Foreground network dials currently holding capacity by configured target.", "gauge")
	for _, target := range sortedStringKeys(dialCapacity.ActiveByTarget) {
		writeMetricSample(output, "moto_dial_bulkhead_target_in_flight", []prometheusLabel{{"target", target}}, strconv.Itoa(dialCapacity.ActiveByTarget[target]))
	}

	writeMetricHeader(output, "moto_connect_proxy_h3_transports", "Physical HTTP/3 transports in the current routing generation by configured proxy target and state.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_transports", http3TransportGaugeLabels(transport), strconv.Itoa(transport.transports))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_active_tunnels", "Established HTTP/3 CONNECT tunnels by configured proxy target and transport state.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_active_tunnels", http3TransportGaugeLabels(transport), strconv.Itoa(transport.activeTunnels))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_smoothed_rtt_seconds", "Highest sampled smoothed QUIC RTT among HTTP/3 transports in the same target and state group.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_smoothed_rtt_seconds", http3TransportGaugeLabels(transport), strconv.FormatFloat(float64(transport.smoothedRTT)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_baseline_rtt_seconds", "Lowest healthy RTT baseline used by HTTP/3 degradation detection in the same target and state group.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_baseline_rtt_seconds", http3TransportGaugeLabels(transport), strconv.FormatFloat(float64(transport.baselineRTT)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_loss_ratio", "Highest sampled QUIC loss ratio among HTTP/3 transports in the same target and state group.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_loss_ratio", http3TransportGaugeLabels(transport), strconv.FormatFloat(transport.lossRatio, 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_blocked_writes", "Blocked application writes observed at the latest HTTP/3 degradation samples.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_blocked_writes", http3TransportGaugeLabels(transport), strconv.Itoa(transport.blockedWrites))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_oldest_blocked_write_seconds", "Longest blocked application write observed by the latest HTTP/3 degradation sample.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_oldest_blocked_write_seconds", http3TransportGaugeLabels(transport), strconv.FormatFloat(float64(transport.oldestBlockedFor)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_payload_bytes_per_second", "Effective HTTP/3 CONNECT payload throughput over the detector sliding window.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_payload_bytes_per_second", http3TransportGaugeLabels(transport), strconv.FormatFloat(transport.payloadBytesPerSecond, 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_healthy_payload_bytes_per_second", "Learned healthy busy application payload throughput for HTTP/3 degradation comparison.", "gauge")
	for _, transport := range http3.transports {
		writeMetricSample(output, "moto_connect_proxy_h3_healthy_payload_bytes_per_second", http3TransportGaugeLabels(transport), strconv.FormatFloat(transport.healthyBytesPerSecond, 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rotation_events", "Cumulative HTTP/3 degradation, rotation, and bounded forced-drain events in the current routing generation.", "gauge")
	for _, rotation := range http3.rotations {
		writeMetricSample(output, "moto_connect_proxy_h3_rotation_events", []prometheusLabel{{"target", rotation.target}, {"reason", rotation.reason}, {"outcome", rotation.outcome}}, strconv.FormatUint(rotation.count, 10))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_degradation_strikes", "Independent degraded HTTP/3 connection generations observed inside the recent strike window.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_degradation_strikes", []prometheusLabel{{"target", policy.target}}, strconv.Itoa(policy.degradationStrikes))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_protocol_penalty_seconds", "Raw HTTP/3 degradation score in seconds; mixed-protocol cooldown may admit the same target over HTTP/2 with an effective zero Boost penalty.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_protocol_penalty_seconds", []prometheusLabel{{"target", policy.target}}, strconv.FormatFloat(float64(policy.protocolPenalty)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_cooldown_active", "Whether new mixed-protocol connections currently bypass HTTP/3 and use HTTP/2.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_cooldown_active", []prometheusLabel{{"target", policy.target}}, boolMetric(policy.cooldownActive))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_cooldown_remaining_seconds", "Time remaining before the next single HTTP/3 half-open recovery probe.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_cooldown_remaining_seconds", []prometheusLabel{{"target", policy.target}}, strconv.FormatFloat(float64(policy.cooldownRemaining)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_half_open", "Whether one request currently owns the HTTP/3 recovery probe for this target.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_half_open", []prometheusLabel{{"target", policy.target}}, boolMetric(policy.halfOpen))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_boost_canary_in_flight", "Whether one Boost request currently owns the pre-cooldown HTTP/3 rotation canary for this target.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_boost_canary_in_flight", []prometheusLabel{{"target", policy.target}}, boolMetric(policy.boostCanary))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_fallback_pending", "Whether Moto is validating HTTP/2 reachability before committing HTTP/3 cooldown.", "gauge")
	for _, policy := range http3.policies {
		writeMetricSample(output, "moto_connect_proxy_h3_fallback_pending", []prometheusLabel{{"target", policy.target}}, boolMetric(policy.fallbackPending))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_cooldown_active", "Whether a mixed-protocol rule is routing new connections over HTTP/2 after path-wide HTTP/3 degradation.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_cooldown_active", []prometheusLabel{{"rule", rule.rule}}, boolMetric(rule.cooldown))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_cooldown_remaining_seconds", "Time remaining before a mixed-protocol rule may admit one HTTP/3 data-plane probation connection.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_cooldown_remaining_seconds", []prometheusLabel{{"rule", rule.rule}}, strconv.FormatFloat(float64(rule.remaining)/float64(time.Second), 'g', -1, 64))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_fallback_validation_active", "Whether a mixed-protocol rule is validating HTTP/2 reachability before committing an HTTP/3 cooldown.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_fallback_validation_active", []prometheusLabel{{"rule", rule.rule}}, boolMetric(rule.evaluating))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probe_due", "Whether a mixed-protocol rule is ready for one exclusive HTTP/3 data-plane probation attempt.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probe_due", []prometheusLabel{{"rule", rule.rule}}, boolMetric(rule.probeDue))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probe_in_flight", "Whether one Boost route owns the exclusive HTTP/3 probation setup lease for a mixed-protocol rule.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probe_in_flight", []prometheusLabel{{"rule", rule.rule}}, boolMetric(rule.probeInFlight))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probation_active", "Whether exactly one HTTP/3 data-plane probation connection owns recovery for a mixed-protocol rule.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probation_active", []prometheusLabel{{"rule", rule.rule}}, boolMetric(rule.probation))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probation_healthy_samples", "Consecutive healthy two-second samples collected by the current rule-level HTTP/3 probation connection.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probation_healthy_samples", []prometheusLabel{{"rule", rule.rule}}, strconv.Itoa(rule.healthySamples))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probation_payload_bytes", "Application payload bytes transferred by the current rule-level HTTP/3 probation connection.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probation_payload_bytes", []prometheusLabel{{"rule", rule.rule}}, strconv.FormatUint(rule.payloadBytes, 10))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_probation_packets_sent", "QUIC packets sent by the current rule-level HTTP/3 probation connection.", "gauge")
	for _, rule := range http3.ruleBreakers {
		writeMetricSample(output, "moto_connect_proxy_h3_rule_probation_packets_sent", []prometheusLabel{{"rule", rule.rule}}, strconv.FormatUint(rule.packetsSent, 10))
	}
	writeMetricHeader(output, "moto_connect_proxy_h3_rule_breaker_events", "Cumulative rule-level HTTP/3 breaker transitions in the current routing generation.", "gauge")
	for _, rule := range http3.ruleBreakers {
		outcomes := make([]string, 0, len(rule.events))
		for outcome := range rule.events {
			outcomes = append(outcomes, outcome)
		}
		sort.Strings(outcomes)
		for _, outcome := range outcomes {
			writeMetricSample(output, "moto_connect_proxy_h3_rule_breaker_events", []prometheusLabel{{"rule", rule.rule}, {"outcome", outcome}}, strconv.FormatUint(rule.events[outcome], 10))
		}
	}
}

func snapshotHTTP3Gauges(manager *connectProxyManager) http3GaugeSnapshot {
	if manager == nil {
		return http3GaugeSnapshot{}
	}
	snapshot := http3GaugeSnapshot{}
	if manager.h3 != nil {
		snapshot = manager.h3.snapshotGauges()
	}
	if manager.h3RuleBreaker != nil {
		snapshot.ruleBreakers = manager.h3RuleBreaker.snapshot()
		sort.Slice(snapshot.ruleBreakers, func(i, j int) bool {
			return snapshot.ruleBreakers[i].rule < snapshot.ruleBreakers[j].rule
		})
	}
	now := manager.timeNow()
	manager.h3FallbackMu.Lock()
	aggregates := make(map[string]*http3PolicyGauge, len(manager.h3Fallback))
	for key, state := range manager.h3Fallback {
		if state == nil {
			continue
		}
		policy := aggregates[key.address]
		if policy == nil {
			policy = &http3PolicyGauge{target: key.address}
			aggregates[key.address] = policy
		}
		policy.degradationStrikes = max(policy.degradationStrikes, state.degradationStrikes)
		if penalty := manager.http3DegradationPenaltyLocked(state); penalty > policy.protocolPenalty {
			policy.protocolPenalty = penalty
		}
		if state.failures > 0 && now.Before(state.retryAt) {
			policy.cooldownActive = true
			if remaining := state.retryAt.Sub(now); remaining > policy.cooldownRemaining {
				policy.cooldownRemaining = remaining
			}
		}
		policy.halfOpen = policy.halfOpen || state.probing
		policy.boostCanary = policy.boostCanary || state.boostCanaryInFlight
		// pending alone means repeated degradation made this endpoint eligible
		// for H2 validation. fallbackPending counts requests that actually joined
		// the validation window, including H2 siblings of a half-open H3 probe.
		policy.fallbackPending = policy.fallbackPending || state.fallbackPending > 0
	}
	manager.h3FallbackMu.Unlock()
	for _, policy := range aggregates {
		snapshot.policies = append(snapshot.policies, *policy)
	}
	sort.Slice(snapshot.policies, func(i, j int) bool {
		return snapshot.policies[i].target < snapshot.policies[j].target
	})
	return snapshot
}

func (manager *http3ConnectManager) snapshotGauges() http3GaugeSnapshot {
	if manager == nil {
		return http3GaugeSnapshot{}
	}
	type aggregateKey struct {
		target string
		state  string
		health string
	}

	manager.mu.Lock()
	aggregates := make(map[aggregateKey]*http3TransportGauge)
	for key, slots := range manager.transports {
		for _, slot := range slots {
			if slot == nil {
				continue
			}
			state := string(slot.lifecycle)
			if state == "" {
				state = "unknown"
			}
			health := string(slot.health)
			if health == "" {
				health = "unknown"
			}
			groupKey := aggregateKey{target: key.address, state: state, health: health}
			aggregate := aggregates[groupKey]
			if aggregate == nil {
				aggregate = &http3TransportGauge{target: key.address, state: state, health: health}
				aggregates[groupKey] = aggregate
			}
			aggregate.transports++
			aggregate.activeTunnels += len(slot.tunnels)
			signals := slot.lastDecision.Signals
			if signals.SmoothedRTT > aggregate.smoothedRTT {
				aggregate.smoothedRTT = signals.SmoothedRTT
			}
			if aggregate.baselineRTT == 0 || signals.BaselineRTT > 0 && signals.BaselineRTT < aggregate.baselineRTT {
				aggregate.baselineRTT = signals.BaselineRTT
			}
			if signals.LossRate > aggregate.lossRatio {
				aggregate.lossRatio = signals.LossRate
			}
			aggregate.blockedWrites += signals.BlockedWrites
			if signals.OldestBlockedFor > aggregate.oldestBlockedFor {
				aggregate.oldestBlockedFor = signals.OldestBlockedFor
			}
			aggregate.payloadBytesPerSecond += signals.PayloadBytesPerSecond
			aggregate.healthyBytesPerSecond += signals.HealthyBytesPerSecond
		}
	}
	snapshot := http3GaugeSnapshot{
		transports: make([]http3TransportGauge, 0, len(aggregates)),
		rotations:  make([]http3RotationGauge, 0, len(manager.rotationEvents)),
	}
	for _, aggregate := range aggregates {
		snapshot.transports = append(snapshot.transports, *aggregate)
	}
	for key, count := range manager.rotationEvents {
		snapshot.rotations = append(snapshot.rotations, http3RotationGauge{
			target:  key.target,
			reason:  key.reason,
			outcome: key.outcome,
			count:   count,
		})
	}
	manager.mu.Unlock()

	sort.Slice(snapshot.transports, func(i, j int) bool {
		left, right := snapshot.transports[i], snapshot.transports[j]
		if left.target != right.target {
			return left.target < right.target
		}
		if left.state != right.state {
			return left.state < right.state
		}
		return left.health < right.health
	})
	sort.Slice(snapshot.rotations, func(i, j int) bool {
		left, right := snapshot.rotations[i], snapshot.rotations[j]
		if left.target != right.target {
			return left.target < right.target
		}
		if left.reason != right.reason {
			return left.reason < right.reason
		}
		return left.outcome < right.outcome
	})
	return snapshot
}

func http3TransportGaugeLabels(transport http3TransportGauge) []prometheusLabel {
	return []prometheusLabel{{"target", transport.target}, {"state", transport.state}, {"health", transport.health}}
}

func snapshotActiveHealthGauges(manager *activeHealthManager) []activeHealthGauge {
	if manager == nil {
		return nil
	}
	manager.mu.RLock()
	snapshots := make([]activeHealthGauge, 0, len(manager.states))
	for key, state := range manager.states {
		if key.rule == nil || state == nil {
			continue
		}
		snapshots = append(snapshots, activeHealthGauge{
			rule:      key.rule.Name,
			mode:      key.rule.Mode,
			target:    key.address,
			unhealthy: state.unhealthy,
		})
	}
	manager.mu.RUnlock()
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].rule != snapshots[j].rule {
			return snapshots[i].rule < snapshots[j].rule
		}
		if snapshots[i].mode != snapshots[j].mode {
			return snapshots[i].mode < snapshots[j].mode
		}
		return snapshots[i].target < snapshots[j].target
	})
	return snapshots
}

func routeGaugeLabels(route routeGauge) []prometheusLabel {
	return []prometheusLabel{{"rule", route.rule}, {"mode", route.mode}, {"target", route.target}}
}

func boolMetric(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func (registry *routeHealthRegistry) snapshotGauges() []routeGauge {
	registry.Lock()
	now := time.Now()
	routes := make([]routeGauge, 0, len(registry.states))
	for key, state := range registry.states {
		cooldownRemaining := time.Duration(0)
		if state.circuitOpen && now.Before(state.openUntil) {
			cooldownRemaining = state.openUntil.Sub(now)
		}
		routes = append(routes, routeGauge{
			rule:                     state.ruleName,
			mode:                     state.mode,
			target:                   key.addr,
			ewma:                     state.ewma,
			observed:                 state.observed,
			consecutiveFailures:      max(state.consecutiveFailures, state.relayFailures),
			circuitOpen:              state.circuitOpen,
			halfOpen:                 state.halfOpen,
			circuitCooldownRemaining: cooldownRemaining,
			probeDue:                 state.circuitOpen && !state.halfOpen && cooldownRemaining == 0,
			lastRecovery:             state.lastRecovery,
			lastAttempt:              state.lastAttempt,
		})
	}
	registry.Unlock()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].rule != routes[j].rule {
			return routes[i].rule < routes[j].rule
		}
		if routes[i].mode != routes[j].mode {
			return routes[i].mode < routes[j].mode
		}
		return routes[i].target < routes[j].target
	})
	return routes
}

func (manager *prewarmManager) snapshotGauges() []prewarmGauge {
	manager.mu.Lock()
	pools := make([]*prewarmPool, 0, len(manager.pools))
	for _, pool := range manager.pools {
		pools = append(pools, pool)
	}
	manager.mu.Unlock()

	snapshots := make([]prewarmGauge, 0, len(pools))
	for _, pool := range pools {
		pool.mu.Lock()
		snapshots = append(snapshots, prewarmGauge{
			target:   pool.addr,
			desired:  pool.desired,
			idle:     len(pool.idle),
			warming:  pool.warming,
			failures: pool.failures,
		})
		pool.mu.Unlock()
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].target < snapshots[j].target })
	return snapshots
}
