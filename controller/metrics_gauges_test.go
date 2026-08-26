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

func TestOperationalGaugesExposeAggregatedHTTP3DegradationState(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	metricsNow := time.Date(2026, 8, 26, 16, 0, 0, 0, time.UTC)
	runtime.connectProxy.now = func() time.Time { return metricsNow }

	key := http3ConnectTransportKey{
		address:    "proxy.example:443",
		serverName: "private-server-name.example",
	}
	firstTunnel := &http3TunnelStats{}
	secondTunnel := &http3TunnelStats{}
	thirdTunnel := &http3TunnelStats{}
	runtime.connectProxy.h3.mu.Lock()
	runtime.connectProxy.h3.transports[key] = []*http3ConnectTransportSlot{
		{
			lifecycle: http3TransportServing,
			health:    http3TransportSuspect,
			tunnels: map[*http3TunnelStats]struct{}{
				firstTunnel:  {},
				secondTunnel: {},
			},
			lastDecision: http3DegradationDecision{Signals: http3DegradationSignals{
				BaselineRTT:           90 * time.Millisecond,
				SmoothedRTT:           250 * time.Millisecond,
				LossRate:              0.06,
				BlockedWrites:         1,
				OldestBlockedFor:      5 * time.Second,
				PayloadBytesPerSecond: 1000,
				HealthyBytesPerSecond: 5000,
			}},
		},
		{
			lifecycle: http3TransportServing,
			health:    http3TransportSuspect,
			tunnels: map[*http3TunnelStats]struct{}{
				thirdTunnel: {},
			},
			lastDecision: http3DegradationDecision{Signals: http3DegradationSignals{
				BaselineRTT:           80 * time.Millisecond,
				SmoothedRTT:           400 * time.Millisecond,
				LossRate:              0.12,
				BlockedWrites:         2,
				OldestBlockedFor:      7 * time.Second,
				PayloadBytesPerSecond: 2500,
				HealthyBytesPerSecond: 8000,
			}},
		},
	}
	runtime.connectProxy.h3.rotationEvents[http3RotationMetricKey{
		target:  key.address,
		reason:  string(http3DegradationReasonSustainedSignals),
		outcome: "detected",
	}] = 9
	runtime.connectProxy.h3.mu.Unlock()
	runtime.connectProxy.h3FallbackMu.Lock()
	runtime.connectProxy.h3Fallback[key] = &http3FallbackState{
		failures:            1,
		retryAt:             metricsNow.Add(45 * time.Second),
		cooldownCause:       http3FallbackCauseDegradation,
		degradationStrikes:  2,
		degradationActive:   true,
		boostCanaryInFlight: true,
	}
	runtime.connectProxy.h3FallbackMu.Unlock()

	var output strings.Builder
	runtime.renderOperationalGauges(&output)
	body := output.String()
	labels := `target="proxy.example:443",state="serving",health="suspect"`
	wants := []string{
		`moto_connect_proxy_h3_transports{` + labels + `} 2`,
		`moto_connect_proxy_h3_active_tunnels{` + labels + `} 3`,
		`moto_connect_proxy_h3_smoothed_rtt_seconds{` + labels + `} 0.4`,
		`moto_connect_proxy_h3_baseline_rtt_seconds{` + labels + `} 0.08`,
		`moto_connect_proxy_h3_loss_ratio{` + labels + `} 0.12`,
		`moto_connect_proxy_h3_blocked_writes{` + labels + `} 3`,
		`moto_connect_proxy_h3_oldest_blocked_write_seconds{` + labels + `} 7`,
		`moto_connect_proxy_h3_payload_bytes_per_second{` + labels + `} 3500`,
		`moto_connect_proxy_h3_healthy_payload_bytes_per_second{` + labels + `} 13000`,
		`# TYPE moto_connect_proxy_h3_rotation_events gauge`,
		`moto_connect_proxy_h3_rotation_events{target="proxy.example:443",reason="sustained_signals",outcome="detected"} 9`,
		`moto_connect_proxy_h3_degradation_strikes{target="proxy.example:443"} 2`,
		`moto_connect_proxy_h3_protocol_penalty_seconds{target="proxy.example:443"} 2`,
		`moto_connect_proxy_h3_cooldown_active{target="proxy.example:443"} 1`,
		`moto_connect_proxy_h3_cooldown_remaining_seconds{target="proxy.example:443"} 45`,
		`moto_connect_proxy_h3_half_open{target="proxy.example:443"} 0`,
		`moto_connect_proxy_h3_boost_canary_in_flight{target="proxy.example:443"} 1`,
		`moto_connect_proxy_h3_fallback_pending{target="proxy.example:443"} 0`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}
	if strings.Contains(body, key.serverName) {
		t.Fatalf("metrics leaked HTTP/3 TLS server name %q", key.serverName)
	}
}
