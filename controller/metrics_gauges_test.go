package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"strconv"
	"strings"
	"sync"
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
		`moto_route_circuit_cooldown_remaining_seconds{rule="gauges",mode="boost",target="upstream:443"} 0`,
		`moto_route_probe_due{rule="gauges",mode="boost",target="upstream:443"} 0`,
		`moto_route_last_recovery_timestamp_seconds{rule="gauges",mode="boost",target="upstream:443"} 0`,
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

func TestOperationalGaugesExposeRouteCircuitRecoveryPhases(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	now := time.Now()
	recoveredAt := time.Unix(1788256000, 0)
	runtime.routes.Lock()
	runtime.routes.states[routeHealthKey{rule: "phase-rule", addr: "cooling:443"}] = &routeHealthState{
		ruleName:    "phase-rule",
		mode:        config.ModeBoost,
		observed:    true,
		circuitOpen: true,
		openUntil:   now.Add(30 * time.Second),
	}
	runtime.routes.states[routeHealthKey{rule: "phase-rule", addr: "due:443"}] = &routeHealthState{
		ruleName:    "phase-rule",
		mode:        config.ModeBoost,
		observed:    true,
		circuitOpen: true,
		openUntil:   now.Add(-time.Second),
	}
	runtime.routes.states[routeHealthKey{rule: "phase-rule", addr: "probing:443"}] = &routeHealthState{
		ruleName:    "phase-rule",
		mode:        config.ModeBoost,
		observed:    true,
		circuitOpen: true,
		halfOpen:    true,
		openUntil:   now.Add(-time.Second),
	}
	runtime.routes.states[routeHealthKey{rule: "phase-rule", addr: "recovered:443"}] = &routeHealthState{
		ruleName:     "phase-rule",
		mode:         config.ModeBoost,
		observed:     true,
		lastRecovery: recoveredAt,
	}
	runtime.routes.Unlock()

	var output strings.Builder
	runtime.renderOperationalGauges(&output)
	body := output.String()
	wants := []string{
		`moto_route_probe_due{rule="phase-rule",mode="boost",target="cooling:443"} 0`,
		`moto_route_probe_due{rule="phase-rule",mode="boost",target="due:443"} 1`,
		`moto_route_probe_due{rule="phase-rule",mode="boost",target="probing:443"} 0`,
		`moto_route_half_open{rule="phase-rule",mode="boost",target="probing:443"} 1`,
		`moto_route_last_recovery_timestamp_seconds{rule="phase-rule",mode="boost",target="recovered:443"} 1788256000`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}

	prefix := `moto_route_circuit_cooldown_remaining_seconds{rule="phase-rule",mode="boost",target="cooling:443"} `
	remaining := -1.0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimPrefix(line, prefix), 64)
		if err != nil {
			t.Fatalf("parse cooldown metric %q: %v", line, err)
		}
		remaining = value
		break
	}
	if remaining <= 0 || remaining > 30 {
		t.Fatalf("cooldown remaining = %v, want (0, 30]", remaining)
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

func TestHTTP3FallbackPendingGaugeRequiresActiveMixedValidation(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	manager := runtime.connectProxy
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	const address = "shared-proxy.example:443"
	h3Only := &config.Target{
		Address:      address,
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}},
	}
	mixed := &config.Target{
		Address: address,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: address}

	h3Calls := 0
	h2Calls := 0
	firstH2Started := make(chan struct{})
	releaseFirstH2 := make(chan struct{})
	h3ProbeStarted := make(chan struct{})
	releaseH3Probe := make(chan struct{})
	siblingH2Started := make(chan struct{})
	releaseSiblingH2 := make(chan struct{})
	var releaseFirstH2Once sync.Once
	var releaseH3ProbeOnce sync.Once
	var releaseSiblingH2Once sync.Once
	releaseFirstH2Dial := func() { releaseFirstH2Once.Do(func() { close(releaseFirstH2) }) }
	releaseH3ProbeDial := func() { releaseH3ProbeOnce.Do(func() { close(releaseH3Probe) }) }
	releaseSiblingH2Dial := func() { releaseSiblingH2Once.Do(func() { close(releaseSiblingH2) }) }
	t.Cleanup(func() {
		releaseFirstH2Dial()
		releaseH3ProbeDial()
		releaseSiblingH2Dial()
	})
	newConnection := func() net.Conn {
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection
	}
	manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h3Calls++
		if h3Calls == 2 {
			close(h3ProbeStarted)
			<-releaseH3Probe
		}
		return newConnection(), nil
	}
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		h2Calls++
		switch h2Calls {
		case 1:
			close(firstH2Started)
			<-releaseFirstH2
		case 2:
			close(siblingH2Started)
			<-releaseSiblingH2
		}
		return newConnection(), nil
	}

	assertFallbackPending := func(want string) {
		t.Helper()
		var output strings.Builder
		runtime.renderOperationalGauges(&output)
		line := `moto_connect_proxy_h3_fallback_pending{target="` + address + `"} ` + want
		if !strings.Contains(output.String(), line) {
			t.Fatalf("metrics output missing %q\noutput:\n%s", line, output.String())
		}
	}

	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	manager.noteHTTP3Recovery(key)
	manager.noteHTTP3Degradation(key, http3DegradationReasonSevereLossAndWrite)
	assertFallbackPending("0")

	// The H3-only rule sharing this endpoint remains fail-open and does not
	// create a fictitious H2 validation participant.
	connection, err := manager.dial(context.Background(), h3Only, "h3-only.example:443")
	if err != nil {
		t.Fatalf("H3-only shared-endpoint dial: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 0 {
		t.Fatalf("H3-only calls = h3:%d h2:%d, want 1/0", h3Calls, h2Calls)
	}
	assertFallbackPending("0")

	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		connection, err := manager.dial(context.Background(), mixed, "mixed.example:443")
		result <- dialResult{connection: connection, err: err}
	}()
	<-firstH2Started
	assertFallbackPending("1")
	releaseFirstH2Dial()
	completed := <-result
	if completed.err != nil {
		t.Fatalf("mixed H2 validation: %v", completed.err)
	}
	_ = completed.connection.Close()
	if h3Calls != 1 || h2Calls != 1 {
		t.Fatalf("shared-endpoint calls = h3:%d h2:%d, want 1/1", h3Calls, h2Calls)
	}
	assertFallbackPending("0")

	// When a half-open H3 probe owns recovery, a concurrent mixed request joins
	// through H2 with pending=false. The participant counter must still expose
	// that real validation while both attempts are in flight.
	manager.h3FallbackMu.Lock()
	now = manager.h3Fallback[key].retryAt
	manager.h3FallbackMu.Unlock()
	probeResult := make(chan dialResult, 1)
	go func() {
		connection, err := manager.dial(context.Background(), mixed, "half-open.example:443")
		probeResult <- dialResult{connection: connection, err: err}
	}()
	<-h3ProbeStarted
	siblingResult := make(chan dialResult, 1)
	go func() {
		connection, err := manager.dial(context.Background(), mixed, "half-open-sibling.example:443")
		siblingResult <- dialResult{connection: connection, err: err}
	}()
	<-siblingH2Started
	assertFallbackPending("1")

	releaseH3ProbeDial()
	probe := <-probeResult
	if probe.err != nil {
		t.Fatalf("half-open H3 validation: %v", probe.err)
	}
	_ = probe.connection.Close()
	releaseSiblingH2Dial()
	sibling := <-siblingResult
	if sibling.err != nil {
		t.Fatalf("half-open sibling H2 validation: %v", sibling.err)
	}
	_ = sibling.connection.Close()
	if h3Calls != 2 || h2Calls != 2 {
		t.Fatalf("half-open calls = h3:%d h2:%d, want 2/2 total", h3Calls, h2Calls)
	}
	assertFallbackPending("0")
}
