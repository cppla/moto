package controller

import (
	"errors"
	"moto/config"
	"strings"
	"testing"
	"time"
)

func TestOperationalGaugesExposeRouteAndPrewarmState(t *testing.T) {
	resetProcessMetricsForTest()
	defer setMetricsGaugeRenderer(nil)
	resetRouteHealthForTest()
	defer resetRouteHealthForTest()
	shutdownPrewarm()
	defer shutdownPrewarm()

	rule := &config.Rule{
		Name:    "gauges",
		Listen:  "127.0.0.1:10010",
		Mode:    config.ModeBoost,
		Targets: []*config.Target{{Address: "upstream:443"}},
	}
	now := time.Unix(1_800_000_000, 0)
	observeRoute(t, rule, "upstream:443", 25*time.Millisecond, nil, now)
	observeRoute(t, rule, "upstream:443", 10*time.Millisecond, errors.New("dial failed"), now.Add(time.Second))

	pool := newPrewarmPool("upstream:443", 3)
	pool.mu.Lock()
	pool.warming = 1
	pool.failures = 2
	pool.mu.Unlock()
	prewarmPoolsMu.Lock()
	prewarmPools[pool.addr] = pool
	prewarmPoolsMu.Unlock()

	setMetricsGaugeRenderer(renderOperationalGauges)
	body := renderPrometheusMetrics()
	wants := []string{
		`moto_route_latency_ewma_seconds{rule="gauges",mode="boost",target="upstream:443"} 0.025`,
		`moto_route_consecutive_failures{rule="gauges",mode="boost",target="upstream:443"} 1`,
		`moto_route_circuit_open{rule="gauges",mode="boost",target="upstream:443"} 0`,
		`moto_prewarm_desired_connections{target="upstream:443"} 3`,
		`moto_prewarm_warming_connections{target="upstream:443"} 1`,
		`moto_prewarm_consecutive_failures{target="upstream:443"} 2`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}
}
