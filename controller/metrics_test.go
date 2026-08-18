package controller

import (
	"context"
	"errors"
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
	processMetrics.boostCacheHits = make(map[string]uint64)
	processMetrics.boostCacheMisses = make(map[string]uint64)
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
				metricBoostCache(rule, true)
				metricBoostCache(rule, false)
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

	labels := `{rule="` + escapePrometheusLabel(rule) + `",mode="` + escapePrometheusLabel(mode) + `"}`
	rejectionLabels := `{rule="` + escapePrometheusLabel(rule) + `",mode="` + escapePrometheusLabel(mode) + `",reason="` + escapePrometheusLabel(reason) + `"}`
	relayLabels := `{rule="` + escapePrometheusLabel(rule) + `",direction="` + escapePrometheusLabel(direction) + `"}`
	dialLabels := `{rule="` + escapePrometheusLabel(rule) + `",target="` + escapePrometheusLabel(target) + `"}`
	ruleLabel := `{rule="` + escapePrometheusLabel(rule) + `"}`

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
		"moto_boost_cache_hits_total" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
		"moto_boost_cache_misses_total" + ruleLabel + " " + strconv.FormatUint(total, 10) + "\n",
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
