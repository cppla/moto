package controller

import (
	"context"
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
	originalBulkhead := defaultRoutingRuntime.trafficDials
	bulkhead := newDialBulkhead(2, 1, time.Second)
	defaultRoutingRuntime.trafficDials = bulkhead
	defer func() { defaultRoutingRuntime.trafficDials = originalBulkhead }()
	permit, _, err := bulkhead.acquire(context.Background(), "upstream:443")
	if err != nil {
		t.Fatal(err)
	}
	defer permit.release()
	waitCtx, cancelWait := context.WithCancel(context.Background())
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		_, _, _ = bulkhead.acquire(waitCtx, "upstream:443")
	}()
	deadline := time.Now().Add(time.Second)
	for bulkhead.snapshot().Waiting != 1 {
		if time.Now().After(deadline) {
			cancelWait()
			<-waitDone
			t.Fatal("dial bulkhead waiter did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	defer func() {
		cancelWait()
		<-waitDone
	}()

	rule := &config.Rule{
		Name:    "gauges",
		Listen:  "127.0.0.1:10010",
		Mode:    config.ModeBoost,
		Targets: []*config.Target{{Address: "upstream:443"}},
	}
	now := time.Now().Add(-10 * time.Second)
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
		`moto_dial_bulkhead_in_flight 1`,
		`moto_dial_bulkhead_waiting 1`,
		`moto_dial_bulkhead_global_limit 2`,
		`moto_dial_bulkhead_per_target_limit 1`,
		`moto_dial_bulkhead_target_in_flight{target="upstream:443"} 1`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}
}
