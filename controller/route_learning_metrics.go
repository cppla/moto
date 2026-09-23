package controller

import (
	"strconv"
	"strings"
	"time"
)

// Learning labels describe configured routes only. In particular, the internal
// rule identity contains configuration material and must never be exported.
func learningGaugeLabels(gauge routeLearningGauge) []prometheusLabel {
	return []prometheusLabel{{"rule", gauge.rule}, {"target", gauge.target}, {"protocol", gauge.protocol}}
}

func learningConfidence(estimate routeLearningEstimate) float64 {
	if estimate.Known {
		return 1
	}
	if estimate.Latency <= 0 || estimate.LastObservation.IsZero() {
		return 0
	}
	return min(0.99, max(0, estimate.Samples/routeLearningMinSamples))
}

func (runtime *routingRuntime) renderLearningGauges(output *strings.Builder) {
	gauges, decisions := runtime.snapshotLearningGauges(time.Now())
	renderLearningSnapshot(output, gauges, decisions)
}

func renderLearningSnapshot(output *strings.Builder, gauges []routeLearningGauge, decisions []routeLearningDecisionGauge) {
	metrics := []struct {
		name, help string
		value      func(routeLearningGauge) float64
	}{
		{"samples", "Freshness-weighted independent observation windows, not tunnel or packet counts.", func(g routeLearningGauge) float64 { return g.estimate.Samples }},
		{"confidence", "Sample sufficiency from 0 to 1; 1 means ranking evidence is sufficient, not a success probability.", func(g routeLearningGauge) float64 { return learningConfidence(g.estimate) }},
		{"setup_seconds", "Learned successful CONNECT setup latency in seconds; zero when unavailable.", func(g routeLearningGauge) float64 { return g.estimate.Latency.Seconds() }},
		{"cost_seconds", "Learned selection cost including bounded reliability penalties in seconds; not measured transfer latency.", func(g routeLearningGauge) float64 { return g.estimate.Cost.Seconds() }},
		{"last_observation_timestamp_seconds", "Unix timestamp of the latest retained learning observation; zero when unavailable.", func(g routeLearningGauge) float64 {
			if g.estimate.LastObservation.IsZero() {
				return 0
			}
			return float64(g.estimate.LastObservation.Unix())
		}},
		{"preferred", "Whether learning currently prefers this route; not an actual traffic winner or a health guarantee.", func(g routeLearningGauge) float64 {
			if g.preferred {
				return 1
			}
			return 0
		}},
	}
	for _, metric := range metrics {
		name := "moto_route_learning_" + metric.name
		writeMetricHeader(output, name, metric.help, "gauge")
		for _, gauge := range gauges {
			writeMetricSample(output, name, learningGaugeLabels(gauge), strconv.FormatFloat(metric.value(gauge), 'g', -1, 64))
		}
	}
	writeMetricHeader(output, "moto_route_learning_decisions_total", "Learning selection decisions in this routing generation, not successful tunnels or final winners.", "counter")
	for _, decision := range decisions {
		if decision.reason != "quality" && decision.reason != "explore" {
			continue
		}
		writeMetricSample(output, "moto_route_learning_decisions_total", []prometheusLabel{{"rule", decision.rule}, {"reason", decision.reason}}, strconv.FormatUint(decision.count, 10))
	}
}
