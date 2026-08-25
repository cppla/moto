package controller

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

type routeGauge struct {
	rule                string
	mode                string
	target              string
	ewma                time.Duration
	observed            bool
	consecutiveFailures int
	circuitOpen         bool
	halfOpen            bool
	lastAttempt         time.Time
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
	routes := make([]routeGauge, 0, len(registry.states))
	for key, state := range registry.states {
		routes = append(routes, routeGauge{
			rule:                state.ruleName,
			mode:                state.mode,
			target:              key.addr,
			ewma:                state.ewma,
			observed:            state.observed,
			consecutiveFailures: max(state.consecutiveFailures, state.relayFailures),
			circuitOpen:         state.circuitOpen,
			halfOpen:            state.halfOpen,
			lastAttempt:         state.lastAttempt,
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
