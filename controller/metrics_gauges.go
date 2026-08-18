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

// renderOperationalGauges snapshots route-health and prewarm state without
// holding their locks while Prometheus text is written.
func renderOperationalGauges(output *strings.Builder) {
	routes := snapshotRouteGauges()
	prewarm := snapshotPrewarmGauges()

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

func snapshotRouteGauges() []routeGauge {
	routeHealth.Lock()
	routes := make([]routeGauge, 0, len(routeHealth.states))
	for key, state := range routeHealth.states {
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
	routeHealth.Unlock()
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

func snapshotPrewarmGauges() []prewarmGauge {
	prewarmPoolsMu.Lock()
	pools := make([]*prewarmPool, 0, len(prewarmPools))
	for _, pool := range prewarmPools {
		pools = append(pools, pool)
	}
	prewarmPoolsMu.Unlock()

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
