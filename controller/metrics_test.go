package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetProcessMetricsForTest keeps tests isolated without swapping the global
// pointer while application goroutines may still refer to it.
func resetProcessMetricsForTest() {
	processMetrics.mu.Lock()
	processMetrics.ruleRefs = make(map[string]int)
	processMetrics.connectionRefs = make(map[connectionMetricKey]int)
	processMetrics.dialRefs = make(map[dialMetricKey]int)
	processMetrics.connectProxyRefs = make(map[connectProxyMetricKey]int)
	processMetrics.connectionsAccepted = make(map[connectionMetricKey]uint64)
	processMetrics.connectionsRejected = make(map[rejectionMetricKey]uint64)
	processMetrics.connectionsActive = make(map[connectionMetricKey]int64)
	processMetrics.relayBytes = make(map[relayMetricKey]uint64)
	processMetrics.relayErrors = make(map[relayMetricKey]uint64)
	processMetrics.relayDurationNanos = make(map[string]uint64)
	processMetrics.relayDurationCount = make(map[string]uint64)
	processMetrics.dialAttempts = make(map[dialMetricKey]uint64)
	processMetrics.dialSuccess = make(map[dialMetricKey]uint64)
	processMetrics.dialFailures = make(map[dialMetricKey]uint64)
	processMetrics.dialCanceled = make(map[dialMetricKey]uint64)
	processMetrics.dialLatencyNanos = make(map[dialMetricKey]uint64)
	processMetrics.dialLatencyCount = make(map[dialMetricKey]uint64)
	processMetrics.dialBulkheadWaitNanos = make(map[dialMetricKey]uint64)
	processMetrics.dialBulkheadWaitCount = make(map[dialMetricKey]uint64)
	processMetrics.dialBulkheadRejected = make(map[dialMetricKey]uint64)
	processMetrics.boostCacheHits = make(map[string]uint64)
	processMetrics.boostCacheMisses = make(map[string]uint64)
	processMetrics.boostHedgeEvents = make(map[boostHedgeMetricKey]uint64)
	processMetrics.boostHedgeDelayNanos = make(map[string]uint64)
	processMetrics.boostHedgeDelayCount = make(map[string]uint64)
	processMetrics.boostDecisionNanos = make(map[string]uint64)
	processMetrics.boostDecisionCount = make(map[string]uint64)
	processMetrics.connectProxyAttempts = make(map[connectProxyAttemptMetricKey]uint64)
	processMetrics.connectProxyHandshakes = make(map[connectProxyAttemptMetricKey]uint64)
	processMetrics.connectProxySetupNanos = make(map[connectProxyMetricKey]uint64)
	processMetrics.connectProxySetupCount = make(map[connectProxyMetricKey]uint64)
	processMetrics.connectProxyFallbacks = make(map[connectProxyFallbackMetricKey]uint64)
	processMetrics.mu.Unlock()
	setMetricsGaugeRenderer(nil)
}

func TestObservabilityHandlerStatus(t *testing.T) {
	resetProcessMetricsForTest()
	var ready atomic.Bool
	handler := newObservabilityHandler(ready.Load)

	tests := []struct {
		name        string
		method      string
		path        string
		wantStatus  int
		wantBody    string
		contentType string
	}{
		{name: "health", method: http.MethodGet, path: "/healthz", wantStatus: http.StatusOK, wantBody: "ok\n", contentType: "text/plain; charset=utf-8"},
		{name: "not ready", method: http.MethodGet, path: "/readyz", wantStatus: http.StatusServiceUnavailable, wantBody: "not ready\n", contentType: "text/plain; charset=utf-8"},
		{name: "metrics", method: http.MethodGet, path: "/metrics", wantStatus: http.StatusOK, contentType: prometheusContentType},
		{name: "unknown", method: http.MethodGet, path: "/missing", wantStatus: http.StatusNotFound, wantBody: "404 page not found\n", contentType: "text/plain; charset=utf-8"},
		{name: "method", method: http.MethodPost, path: "/healthz", wantStatus: http.StatusMethodNotAllowed, wantBody: "method not allowed\n", contentType: "text/plain; charset=utf-8"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if body := response.Body.String(); test.wantBody != "" && body != test.wantBody {
				t.Fatalf("body = %q, want %q", body, test.wantBody)
			}
			if contentType := response.Header().Get("Content-Type"); contentType != test.contentType {
				t.Fatalf("Content-Type = %q, want %q", contentType, test.contentType)
			}
		})
	}

	ready.Store(true)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "ready\n" {
		t.Fatalf("ready response = (%d, %q), want (200, %q)", response.Code, response.Body.String(), "ready\n")
	}

	headRequest := httptest.NewRequest(http.MethodHead, "/metrics", nil)
	headResponse := httptest.NewRecorder()
	handler.ServeHTTP(headResponse, headRequest)
	if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 {
		t.Fatalf("HEAD /metrics response = (%d, %q), want (200, empty)", headResponse.Code, headResponse.Body.String())
	}
}

func TestMetricsConcurrentRecordingAndLabelEscaping(t *testing.T) {
	resetProcessMetricsForTest()
	rule := "edge\"\\\nline"
	mode := "boost\\mode"
	reason := "policy\"\nblocked\\rule"
	direction := "client\n\"to\\target"
	target := "upstream\"\\\n:443"

	const (
		workers    = 16
		iterations = 100
	)
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				metricConnectionAccepted(rule, mode)
				metricConnectionRejected(rule, mode, reason)
				metricConnectionActive(rule, mode, 1)
				metricConnectionActive(rule, mode, -1)
				metricRelay(rule, direction, 3, errors.New("relay failed"))
				metricRelayDuration(rule, 250*time.Millisecond)
				metricDial(rule, target, 100*time.Millisecond, nil)
				metricDial(rule, target, 200*time.Millisecond, errors.New("dial failed"))
				metricDial(rule, target, 0, context.Canceled)
				metricDialBulkhead(rule, target, 50*time.Millisecond, nil)
				metricDialBulkhead(rule, target, 100*time.Millisecond, &dialBulkheadError{target: target, saturated: true})
				metricBoostCache(rule, true)
				metricBoostCache(rule, false)
				metricBoostHedgeEvent(rule, boostHedgeScheduled)
				metricBoostHedgeEvent(rule, boostHedgeLaunched)
				metricBoostHedgeDelay(rule, 125*time.Millisecond)
				metricBoostDecisionDuration(rule, 175*time.Millisecond)
			}
		}()
	}
	wait.Wait()

	response := httptest.NewRecorder()
	newObservabilityHandler(func() bool { return true }).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	body := response.Body.String()
	goroutinePrefix := "\nmoto_go_goroutines "
	goroutineIndex := strings.Index(body, goroutinePrefix)
	if goroutineIndex < 0 {
		t.Fatalf("metrics output missing %q\noutput:\n%s", goroutinePrefix, body)
	}
	goroutineLine := strings.SplitN(body[goroutineIndex+len(goroutinePrefix):], "\n", 2)[0]
	goroutineCount, err := strconv.Atoi(goroutineLine)
	if err != nil || goroutineCount < 1 {
		t.Fatalf("moto_go_goroutines = %q, want a positive integer", goroutineLine)
	}
	total := uint64(workers * iterations)
	dialTotal := total * 3
	dialLatencyTotal := total * 2
	bulkheadWaitTotal := total * 2

	labels := `{rule="` + escapePrometheusLabel(rule) + `",mode="` + escapePrometheusLabel(mode) + `"}`
	rejectionLabels := `{rule="` + escapePrometheusLabel(rule) + `",mode="` + escapePrometheusLabel(mode) + `",reason="` + escapePrometheusLabel(reason) + `"}`
	relayLabels := `{rule="` + escapePrometheusLabel(rule) + `",direction="` + escapePrometheusLabel(direction) + `"}`
	dialLabels := `{rule="` + escapePrometheusLabel(rule) + `",target="` + escapePrometheusLabel(target) + `"}`
	ruleLabel := `{rule="` + escapePrometheusLabel(rule) + `"}`
	hedgeLabel := `{rule="` + escapePrometheusLabel(rule) + `",outcome="` + boostHedgeLaunched + `"}`

	wants := []string{
		"moto_connections_accepted_total" + labels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_connections_rejected_total" + rejectionLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_connections_active" + labels + " 0\n",
		"moto_relay_bytes_total" + relayLabels + " " + strconv.FormatUint(total*3, 10) + "\n",
		"moto_relay_errors_total" + relayLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_relay_duration_seconds_sum" + ruleLabel + " 400\n",
		"moto_relay_duration_seconds_count" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_dial_attempts_total" + dialLabels + " " + strconv.FormatUint(dialTotal, 10) + "\n",
		"moto_dial_success_total" + dialLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_dial_failures_total" + dialLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_dial_canceled_total" + dialLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_dial_latency_seconds_sum" + dialLabels + " 480\n",
		"moto_dial_latency_seconds_count" + dialLabels + " " + strconv.FormatUint(dialLatencyTotal, 10) + "\n",
		"moto_dial_bulkhead_wait_seconds_sum" + dialLabels + " 240\n",
		"moto_dial_bulkhead_wait_seconds_count" + dialLabels + " " + strconv.FormatUint(bulkheadWaitTotal, 10) + "\n",
		"moto_dial_bulkhead_rejected_total" + dialLabels + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_cache_hits_total" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_cache_misses_total" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_hedge_events_total" + hedgeLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_hedge_delay_seconds_sum" + ruleLabel + " 200\n",
		"moto_boost_hedge_delay_seconds_count" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_decision_duration_seconds_sum" + ruleLabel + " 280\n",
		"moto_boost_decision_duration_seconds_count" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}
	if strings.Contains(body, rule) || strings.Contains(body, reason) || strings.Contains(body, target) {
		t.Fatal("metrics output contains an unescaped label value")
	}
}

func TestMetricsOutputIsDeterministic(t *testing.T) {
	resetProcessMetricsForTest()
	metricConnectionAccepted("z-rule", "normal")
	metricConnectionAccepted("a-rule", "boost")
	metricConnectionRejected("z-rule", "normal", "limit")
	metricConnectionRejected("a-rule", "boost", "policy")

	first := renderPrometheusMetrics()
	second := renderPrometheusMetrics()
	stripRuntimeGauge := func(rendered string) string {
		lines := strings.SplitAfter(rendered, "\n")
		kept := lines[:0]
		for _, line := range lines {
			if !strings.Contains(line, "moto_go_goroutines") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "")
	}
	if stripRuntimeGauge(first) != stripRuntimeGauge(second) {
		t.Fatal("unchanged registry rendered different output")
	}
	acceptedA := strings.Index(first, `moto_connections_accepted_total{rule="a-rule"`)
	acceptedZ := strings.Index(first, `moto_connections_accepted_total{rule="z-rule"`)
	if acceptedA < 0 || acceptedZ < 0 || acceptedA >= acceptedZ {
		t.Fatalf("accepted series are not sorted by label:\n%s", first)
	}
}

func TestConnectProxyMetricsCaptureSetupOutcomeAndFallback(t *testing.T) {
	resetProcessMetricsForTest()
	const (
		ruleName      = "native-connect"
		targetAddress = "proxy.example:443"
	)
	target := &config.Target{
		Address: targetAddress,
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
			config.ConnectProxyH3,
			config.ConnectProxyH2,
		}},
	}
	rules := []*config.Rule{{Name: ruleName, Targets: []*config.Target{target}}}
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)

	manager := newConnectProxyManager()
	defer manager.close()
	var peer net.Conn
	manager.dialers = map[string]connectProxyDialFunc{
		config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
			return nil, &connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: http.StatusNotImplemented}
		},
		config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
			connection, other := net.Pipe()
			peer = other
			return connection, nil
		},
	}
	connection, err := manager.dialForRule(context.Background(), ruleName, target, "destination.example:443")
	if err != nil {
		t.Fatalf("dialForRule() error = %v", err)
	}
	_ = connection.Close()
	if peer != nil {
		_ = peer.Close()
	}
	metricConnectProxyHandshake(ruleName, targetAddress, connectProxyAttemptTimeout)

	snapshot := processMetrics.snapshot()
	h3Attempt := connectProxyAttemptMetricKey{rule: ruleName, target: targetAddress, protocol: config.ConnectProxyH3, outcome: string(connectProxyFailureProtocolUnsupported)}
	h2Attempt := connectProxyAttemptMetricKey{rule: ruleName, target: targetAddress, protocol: config.ConnectProxyH2, outcome: connectProxyAttemptSuccess}
	h3Handshake := connectProxyAttemptMetricKey{rule: ruleName, target: targetAddress, protocol: config.ConnectProxyH3, outcome: connectProxyAttemptTimeout}
	h3Setup := connectProxyMetricKey{rule: ruleName, target: targetAddress, protocol: config.ConnectProxyH3}
	h2Setup := connectProxyMetricKey{rule: ruleName, target: targetAddress, protocol: config.ConnectProxyH2}
	fallback := connectProxyFallbackMetricKey{
		rule: ruleName, target: targetAddress,
		from: config.ConnectProxyH3, to: config.ConnectProxyH2,
		reason: connectProxyFallbackStatus501,
	}
	if snapshot.connectProxyAttempts[h3Attempt] != 1 || snapshot.connectProxyAttempts[h2Attempt] != 1 {
		t.Fatalf("CONNECT attempts = %#v, want one H3 status error and one H2 success", snapshot.connectProxyAttempts)
	}
	if snapshot.connectProxyHandshakes[h3Handshake] != 1 {
		t.Fatalf("CONNECT handshakes = %#v, want one physical H3 timeout", snapshot.connectProxyHandshakes)
	}
	if snapshot.connectProxySetupCount[h3Setup] != 1 || snapshot.connectProxySetupCount[h2Setup] != 1 {
		t.Fatalf("CONNECT setup counts = %#v, want one per protocol", snapshot.connectProxySetupCount)
	}
	if snapshot.connectProxyFallbacks[fallback] != 1 {
		t.Fatalf("CONNECT fallbacks = %#v, want one H3-to-H2 status_501 fallback", snapshot.connectProxyFallbacks)
	}

	beforeAttempts := len(snapshot.connectProxyAttempts)
	beforeHandshakes := len(snapshot.connectProxyHandshakes)
	beforeFallbacks := len(snapshot.connectProxyFallbacks)
	metricConnectProxyAttempt(ruleName, targetAddress, "h4", connectProxyAttemptSuccess, time.Second, true)
	metricConnectProxyAttempt(ruleName, targetAddress, config.ConnectProxyH2, "destination-controlled", time.Second, true)
	metricConnectProxyFallback(ruleName, targetAddress, "status_418")
	metricConnectProxyHandshake(ruleName, targetAddress, "destination-controlled")
	snapshot = processMetrics.snapshot()
	if len(snapshot.connectProxyAttempts) != beforeAttempts || len(snapshot.connectProxyHandshakes) != beforeHandshakes ||
		len(snapshot.connectProxyFallbacks) != beforeFallbacks {
		t.Fatal("unbounded CONNECT protocol, outcome, or fallback reason created a metric series")
	}

	body := renderPrometheusMetrics()
	wants := []string{
		`moto_connect_proxy_attempts_total{rule="native-connect",target="proxy.example:443",protocol="h3",outcome="protocol_unsupported"} 1` + "\n",
		`moto_connect_proxy_handshakes_total{rule="native-connect",target="proxy.example:443",protocol="h3",outcome="timeout"} 1` + "\n",
		`moto_connect_proxy_setup_duration_seconds_count{rule="native-connect",target="proxy.example:443",protocol="h2"} 1` + "\n",
		`moto_connect_proxy_fallbacks_total{rule="native-connect",target="proxy.example:443",from="h3",to="h2",reason="status_501"} 1` + "\n",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}
}

func TestMetricRegistryReclaimsRetiredGenerationLabels(t *testing.T) {
	resetProcessMetricsForTest()
	oldRules := []*config.Rule{{
		Name: "reload-rule", Mode: config.ModeNormal,
		Targets: []*config.Target{{
			Address: "old.example:443",
			ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
				config.ConnectProxyH3,
				config.ConnectProxyH2,
			}},
		}},
	}}
	newRules := []*config.Rule{{
		Name: "reload-rule", Mode: config.ModeBoost,
		Targets: []*config.Target{{
			Address:      "new.example:443",
			ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH2}},
		}},
	}}
	processMetrics.registerRules(oldRules)
	processMetrics.registerRules(newRules)
	metricConnectionAccepted("reload-rule", config.ModeNormal)
	metricConnectionAccepted("reload-rule", config.ModeBoost)
	metricDial("reload-rule", "old.example:443", time.Millisecond, nil)
	metricDial("reload-rule", "new.example:443", time.Millisecond, nil)
	metricDialBulkhead("reload-rule", "old.example:443", time.Millisecond, &dialBulkheadError{target: "old.example:443", saturated: true})
	metricDialBulkhead("reload-rule", "new.example:443", time.Millisecond, nil)
	metricRelay("reload-rule", "client_to_target", 1, nil)
	metricBoostHedgeEvent("reload-rule", boostHedgeWon)
	metricBoostHedgeDelay("reload-rule", time.Millisecond)
	metricBoostDecisionDuration("reload-rule", 2*time.Millisecond)
	metricConnectProxyAttempt("reload-rule", "old.example:443", config.ConnectProxyH3, connectProxyAttemptTimeout, 3*time.Millisecond, true)
	metricConnectProxyHandshake("reload-rule", "old.example:443", connectProxyAttemptTimeout)
	metricConnectProxyAttempt("reload-rule", "old.example:443", config.ConnectProxyH2, connectProxyAttemptSuccess, 2*time.Millisecond, true)
	metricConnectProxyFallback("reload-rule", "old.example:443", connectProxyFallbackTimeout)
	metricConnectProxyAttempt("reload-rule", "new.example:443", config.ConnectProxyH2, connectProxyAttemptSuccess, time.Millisecond, true)

	processMetrics.unregisterRules(oldRules)
	snapshot := processMetrics.snapshot()
	if _, exists := snapshot.connectionsAccepted[connectionMetricKey{rule: "reload-rule", mode: config.ModeNormal}]; exists {
		t.Fatal("retired mode label was retained")
	}
	if _, exists := snapshot.dialAttempts[dialMetricKey{rule: "reload-rule", target: "old.example:443"}]; exists {
		t.Fatal("retired target label was retained")
	}
	if _, exists := snapshot.dialBulkheadWaitCount[dialMetricKey{rule: "reload-rule", target: "old.example:443"}]; exists {
		t.Fatal("retired bulkhead target label was retained")
	}
	for key := range snapshot.connectProxyAttempts {
		if key.rule == "reload-rule" && key.target == "old.example:443" {
			t.Fatal("retired CONNECT attempt labels were retained")
		}
	}
	for key := range snapshot.connectProxyHandshakes {
		if key.rule == "reload-rule" && key.target == "old.example:443" {
			t.Fatal("retired CONNECT handshake labels were retained")
		}
	}
	for key := range snapshot.connectProxyFallbacks {
		if key.rule == "reload-rule" && key.target == "old.example:443" {
			t.Fatal("retired CONNECT fallback labels were retained")
		}
	}
	if _, exists := snapshot.connectProxySetupCount[connectProxyMetricKey{rule: "reload-rule", target: "old.example:443", protocol: config.ConnectProxyH3}]; exists {
		t.Fatal("retired CONNECT setup labels were retained")
	}
	if snapshot.connectionsAccepted[connectionMetricKey{rule: "reload-rule", mode: config.ModeBoost}] != 1 ||
		snapshot.dialAttempts[dialMetricKey{rule: "reload-rule", target: "new.example:443"}] != 1 ||
		snapshot.dialBulkheadWaitCount[dialMetricKey{rule: "reload-rule", target: "new.example:443"}] != 1 ||
		snapshot.connectProxyAttempts[connectProxyAttemptMetricKey{rule: "reload-rule", target: "new.example:443", protocol: config.ConnectProxyH2, outcome: connectProxyAttemptSuccess}] != 1 ||
		snapshot.connectProxySetupCount[connectProxyMetricKey{rule: "reload-rule", target: "new.example:443", protocol: config.ConnectProxyH2}] != 1 {
		t.Fatal("current generation metrics were removed")
	}
	if snapshot.relayBytes[relayMetricKey{rule: "reload-rule", direction: "client_to_target"}] != 1 {
		t.Fatal("shared rule metric was removed while still referenced")
	}
	if snapshot.boostHedgeEvents[boostHedgeMetricKey{rule: "reload-rule", outcome: boostHedgeWon}] != 1 ||
		snapshot.boostHedgeDelayCount["reload-rule"] != 1 || snapshot.boostDecisionCount["reload-rule"] != 1 {
		t.Fatal("shared Boost hedge metrics were removed while still referenced")
	}

	processMetrics.unregisterRules(newRules)
	snapshot = processMetrics.snapshot()
	if len(snapshot.connectionsAccepted) != 0 || len(snapshot.dialAttempts) != 0 ||
		len(snapshot.dialBulkheadWaitCount) != 0 || len(snapshot.relayBytes) != 0 ||
		len(snapshot.boostHedgeEvents) != 0 || len(snapshot.boostHedgeDelayCount) != 0 ||
		len(snapshot.boostDecisionCount) != 0 || len(snapshot.connectProxyAttempts) != 0 ||
		len(snapshot.connectProxyHandshakes) != 0 || len(snapshot.connectProxySetupCount) != 0 ||
		len(snapshot.connectProxyFallbacks) != 0 {
		t.Fatalf("retired labels remain: connections=%d dials=%d bulkhead=%d relay=%d hedge=%d",
			len(snapshot.connectionsAccepted), len(snapshot.dialAttempts),
			len(snapshot.dialBulkheadWaitCount), len(snapshot.relayBytes), len(snapshot.boostHedgeEvents))
	}
}

func TestMetricRegistryBulkConnectProxyLabelReclamation(t *testing.T) {
	resetProcessMetricsForTest()
	const (
		ruleName    = "bulk-connect-reload"
		targetCount = 512
	)
	outcomes := []string{
		connectProxyAttemptSuccess,
		connectProxyAttemptStatusError,
		connectProxyAttemptTransportError,
		connectProxyAttemptCanceled,
		connectProxyAttemptTimeout,
		connectProxyAttemptUnavailable,
		connectProxyAttemptCooldown,
		connectProxyAttemptCapacity,
		string(connectProxyFailurePolicyDenied),
		string(connectProxyFailureProxyAuth),
		string(connectProxyFailureRateLimited),
		string(connectProxyFailureDestinationConnect),
		string(connectProxyFailureServiceUnavailable),
		string(connectProxyFailureProtocolUnsupported),
	}
	reasons := []string{
		connectProxyFallbackUnavailable,
		connectProxyFallbackCooldown,
		connectProxyFallbackStatus405,
		connectProxyFallbackStatus501,
		connectProxyFallbackStatus505,
		connectProxyFallbackCanceled,
		connectProxyFallbackTimeout,
		connectProxyFallbackTransportError,
	}
	protocols := []string{config.ConnectProxyH3, config.ConnectProxyH2}
	oldTargets := make([]*config.Target, 0, targetCount)
	retainedTargets := make([]*config.Target, 0, targetCount/2)
	addresses := make([]string, 0, targetCount)
	for index := 0; index < targetCount; index++ {
		address := "proxy-" + strconv.Itoa(index) + ".example:443"
		addresses = append(addresses, address)
		oldTargets = append(oldTargets, &config.Target{
			Address:      address,
			ConnectProxy: &config.ConnectProxyConfig{Protocols: protocols},
		})
		if index%2 == 0 {
			retainedTargets = append(retainedTargets, &config.Target{
				Address:      address,
				ConnectProxy: &config.ConnectProxyConfig{Protocols: protocols},
			})
		}
	}
	oldRules := []*config.Rule{{Name: ruleName, Targets: oldTargets}}
	retainedRules := []*config.Rule{{Name: ruleName, Targets: retainedTargets}}
	processMetrics.registerRules(oldRules)
	processMetrics.registerRules(retainedRules)

	// Populate every bounded outcome and reason so cleanup exercises thousands
	// of series. Correctness is asserted by set membership, not wall-clock time.
	for _, address := range addresses {
		for _, protocol := range protocols {
			for _, outcome := range outcomes {
				metricConnectProxyAttempt(ruleName, address, protocol, outcome, time.Millisecond, outcome == connectProxyAttemptSuccess)
			}
		}
		for _, reason := range reasons {
			metricConnectProxyFallback(ruleName, address, reason)
		}
	}

	processMetrics.unregisterRules(oldRules)
	snapshot := processMetrics.snapshot()
	retainedCount := targetCount / 2
	if got, want := len(snapshot.connectProxyAttempts), retainedCount*len(protocols)*len(outcomes); got != want {
		t.Fatalf("CONNECT attempt series after bulk reload = %d, want %d", got, want)
	}
	if got, want := len(snapshot.connectProxySetupCount), retainedCount*len(protocols); got != want {
		t.Fatalf("CONNECT setup series after bulk reload = %d, want %d", got, want)
	}
	if got, want := len(snapshot.connectProxyFallbacks), retainedCount*len(reasons); got != want {
		t.Fatalf("CONNECT fallback series after bulk reload = %d, want %d", got, want)
	}
	for index, address := range addresses {
		attempt := connectProxyAttemptMetricKey{
			rule: ruleName, target: address,
			protocol: config.ConnectProxyH3, outcome: connectProxyAttemptTransportError,
		}
		fallback := connectProxyFallbackMetricKey{
			rule: ruleName, target: address,
			from: config.ConnectProxyH3, to: config.ConnectProxyH2,
			reason: connectProxyFallbackTimeout,
		}
		_, attemptExists := snapshot.connectProxyAttempts[attempt]
		_, fallbackExists := snapshot.connectProxyFallbacks[fallback]
		wantRetained := index%2 == 0
		if attemptExists != wantRetained || fallbackExists != wantRetained {
			t.Fatalf("target %q retained attempt=%t fallback=%t, want both %t", address, attemptExists, fallbackExists, wantRetained)
		}
	}
	processMetrics.mu.RLock()
	refCount := len(processMetrics.connectProxyRefs)
	processMetrics.mu.RUnlock()
	if want := retainedCount * len(protocols); refCount != want {
		t.Fatalf("CONNECT refs after bulk reload = %d, want %d", refCount, want)
	}

	processMetrics.unregisterRules(retainedRules)
	snapshot = processMetrics.snapshot()
	processMetrics.mu.RLock()
	refCount = len(processMetrics.connectProxyRefs)
	processMetrics.mu.RUnlock()
	if refCount != 0 || len(snapshot.connectProxyAttempts) != 0 ||
		len(snapshot.connectProxySetupCount) != 0 || len(snapshot.connectProxyFallbacks) != 0 {
		t.Fatalf("CONNECT labels remain after bulk retirement: refs=%d attempts=%d setup=%d fallbacks=%d",
			refCount, len(snapshot.connectProxyAttempts), len(snapshot.connectProxySetupCount), len(snapshot.connectProxyFallbacks))
	}
}

func TestMetricBoostHedgeRejectsUnboundedOutcome(t *testing.T) {
	resetProcessMetricsForTest()
	metricBoostHedgeEvent("boost-rule", "target-controlled-value")
	if got := len(processMetrics.snapshot().boostHedgeEvents); got != 0 {
		t.Fatalf("unknown hedge outcome created %d metric series", got)
	}
}

func TestMetricsLimitsConcurrentScrapes(t *testing.T) {
	resetProcessMetricsForTest()
	defer setMetricsGaugeRenderer(nil)
	started := make(chan struct{}, metricsMaxConcurrentScrapes)
	release := make(chan struct{})
	setMetricsGaugeRenderer(func(*strings.Builder) {
		started <- struct{}{}
		<-release
	})
	handler := newObservabilityHandler(func() bool { return true })

	var wait sync.WaitGroup
	wait.Add(metricsMaxConcurrentScrapes)
	for i := 0; i < metricsMaxConcurrentScrapes; i++ {
		go func() {
			defer wait.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if response.Code != http.StatusOK {
				t.Errorf("in-limit scrape status = %d, want 200", response.Code)
			}
		}()
	}
	for i := 0; i < metricsMaxConcurrentScrapes; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			wait.Wait()
			t.Fatalf("only %d scrapes reached renderer", i)
		}
	}

	overflow := httptest.NewRecorder()
	handler.ServeHTTP(overflow, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if overflow.Code != http.StatusServiceUnavailable {
		t.Fatalf("overflow scrape status = %d, want 503", overflow.Code)
	}
	close(release)
	wait.Wait()
}

func TestEscapePrometheusLabel(t *testing.T) {
	input := "quote\" slash\\ newline\n invalid:" + string([]byte{0xff})
	want := "quote\\\" slash\\\\ newline\\n invalid:\uFFFD"
	if got := escapePrometheusLabel(input); got != want {
		t.Fatalf("escapePrometheusLabel() = %q, want %q", got, want)
	}
}
