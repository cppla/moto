package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"moto/config"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"go.uber.org/zap/zapcore"
)

func recoveryResultFixture(t *testing.T, established bool) (*http3RuleBreaker, *time.Time, http3ConnectTransportKey, uint64) {
	t.Helper()
	now := time.Date(2026, 9, 10, 1, 0, 0, 0, time.UTC)
	breaker := newHTTP3RuleBreaker(func() time.Time { return now })
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	breaker.register("mixed", key)
	breaker.rules["mixed"].phase = http3RuleBreakerCooldown
	breaker.rules["mixed"].failures = 1
	token, probation, allowed := breaker.begin("mixed", key)
	if !probation || !allowed || token == 0 {
		t.Fatal("probation admission failed")
	}
	if established && !breaker.establish("mixed", token, key, http3RuleProbationBinding{
		generationID: 3, payloadBytes: 1000, stats: quic.ConnectionStats{PacketsSent: 100},
	}) {
		t.Fatal("probation establishment failed")
	}
	return breaker, &now, key, token
}

func TestHTTP3RecoveryResultCompletionMatrix(t *testing.T) {
	for _, test := range []struct {
		name, reason, wantResult, wantReason string
		elapsed                              time.Duration
		payload, packets                     uint64
		healthy                              int
		rotate, connectionError              bool
		wantMet                              [3]bool
	}{
		{"short_probe", "probe_closed", "insufficient_evidence", "probe_closed", 8 * time.Second, 24000, 30, 1, false, false, [3]bool{}},
		{"observation_timeout", "sample", "insufficient_evidence", "observation_timeout", 90 * time.Second, 24000, 30, 3, false, false, [3]bool{true, false, true}},
		{"packet_alternative", "sample", "recovered", "recovered", 30 * time.Second, 1, 256, 3, false, false, [3]bool{true, true, true}},
		{"payload_alternative", "sample", "recovered", "recovered", 30 * time.Second, 512 << 10, 1, 3, false, false, [3]bool{true, true, true}},
		{"quality_degraded", "sample", "transport_degraded", "transport_degraded", 40 * time.Second, 1 << 20, 300, 3, true, false, [3]bool{true, true, false}},
		{"connection_closed", "sample", "transport_degraded", "transport_degraded", 10 * time.Second, 24000, 30, 3, false, true, [3]bool{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			breaker, now, key, token := recoveryResultFixture(t, true)
			state := breaker.rules["mixed"]
			state.probation.healthySamples = test.healthy
			// Keep this final sample from increasing the prepared consecutive count.
			state.probation.lastHealthyAt = now.Add(test.elapsed)
			*now = now.Add(test.elapsed)
			event := http3RuleSampleEvent{
				key: key, generationID: 3, at: *now,
				stats: quic.ConnectionStats{PacketsSent: 100 + test.packets}, payloadBytes: 1000 + test.payload,
				decision: http3DegradationDecision{Rotate: test.rotate, Signals: http3DegradationSignals{Sampled: true}},
			}
			if test.connectionError {
				event.connectionErr = errors.New("peer detail must not be exported https://private.invalid/token")
			}
			if test.reason == "sample" {
				breaker.noteSample(event)
			} else {
				breaker.failProbationWithEvidence("mixed", token, test.reason, &event)
			}
			last := breaker.snapshot()[0].lastRecovery
			if last.result != test.wantResult || last.reason != test.wantReason || last.elapsed != test.elapsed ||
				last.payloadBytes != test.payload || last.packetsSent != test.packets || last.requirementsMet() != test.wantMet {
				t.Fatalf("last result = %+v met=%v, want %+v", last, last.requirementsMet(), test)
			}
			if state.probation != (http3RuleProbationState{}) {
				t.Fatal("completed probation was not cleared")
			}
			var output strings.Builder
			writeHTTP3RecoveryGauges(&output, breaker.snapshot())
			if strings.Contains(output.String(), "private.invalid") {
				t.Fatal("peer error leaked into metrics")
			}
			encoder := zapcore.NewMapObjectEncoder()
			for _, field := range last.fields() {
				field.AddTo(encoder)
			}
			missing, ok := encoder.Fields["requirementsMissing"].([]interface{})
			if !ok {
				t.Fatalf("missing requirements not recorded: %+v", encoder.Fields)
			}
			wantMissing := 0
			for _, met := range test.wantMet {
				if !met {
					wantMissing++
				}
			}
			if len(missing) != wantMissing {
				t.Fatalf("missing=%v want count %d", missing, wantMissing)
			}
		})
	}
}

func TestHTTP3RecoveryResultNoNetworkAndUnknownEvidence(t *testing.T) {
	for _, reason := range []string{"canceled", "capacity", "protocol_unavailable", "target_cooldown", "unexpected peer secret"} {
		t.Run(reason, func(t *testing.T) {
			breaker, _, _, token := recoveryResultFixture(t, false)
			breaker.abortProbation("mixed", token, reason)
			state := breaker.rules["mixed"]
			if state.failures != 1 || state.lastRecovery.result != "aborted" || state.lastRecovery.evidence {
				t.Fatalf("abort changed policy or invented evidence: %+v", state)
			}
			assertHTTP3RecoveryHasNoDataMetrics(t, breaker.snapshot())
			if strings.Contains(state.lastRecovery.reason, "secret") {
				t.Fatal("reason was not normalized")
			}
		})
	}
	breaker, now, key, token := recoveryResultFixture(t, false)
	breaker.abortProbation("mixed", token, "capacity")
	*now = breaker.rules["mixed"].retryAt
	lease, claimed := breaker.claimRecoveryRouteProbe("mixed", key, *now)
	if !claimed {
		t.Fatal("route lease was not available")
	}
	breaker.releaseRecoveryRouteProbe("mixed", lease)
	last := breaker.snapshot()[0].lastRecovery
	if last.result != "aborted" || last.reason != "no_network" {
		t.Fatalf("released unsent route lease result=%+v", last)
	}
	*now = now.Add(time.Second)
	breaker.releaseRecoveryRouteProbe("mixed", lease)
	if got := breaker.snapshot()[0].lastRecovery; got != last {
		t.Fatal("duplicate route release overwrote terminal result")
	}
	assertHTTP3RecoveryHasNoDataMetrics(t, breaker.snapshot())
}

func assertHTTP3RecoveryHasNoDataMetrics(t *testing.T, gauges []http3RuleBreakerGauge) {
	t.Helper()
	var output strings.Builder
	writeHTTP3RecoveryGauges(&output, gauges)
	for _, metric := range []string{"elapsed_seconds", "payload_bytes", "packets_sent", "healthy_samples", "requirement_met"} {
		if strings.Contains(output.String(), "moto_connect_proxy_h3_rule_recovery_last_"+metric+"{") {
			t.Fatalf("unknown data exported as numeric evidence: %s", metric)
		}
	}
}

func TestHTTP3RecoveryResultPreservedAcrossNewAttemptAndStaleCompletions(t *testing.T) {
	breaker, now, key, token := recoveryResultFixture(t, true)
	*now = now.Add(8 * time.Second)
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			breaker.failProbation("mixed", token, "probe_closed")
		}()
	}
	workers.Wait()
	last := breaker.snapshot()[0].lastRecovery
	if breaker.rules["mixed"].events["probation_failed"] != 1 {
		t.Fatal("duplicate endings were counted")
	}
	*now = breaker.rules["mixed"].retryAt
	nextToken, _, allowed := breaker.begin("mixed", key)
	if !allowed || nextToken == token {
		t.Fatal("next probation not admitted")
	}
	if !breaker.establish("mixed", nextToken, key, http3RuleProbationBinding{generationID: 4}) {
		t.Fatal("next probation not established")
	}
	breaker.failProbation("mixed", token, "transport_degraded")
	breaker.abortProbation("mixed", token, "canceled")
	breaker.noteSample(http3RuleSampleEvent{key: key, generationID: 3, connectionErr: errors.New("old connection")})
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, generationID: 3})
	if got := breaker.snapshot()[0].lastRecovery; got != last {
		t.Fatalf("new probation/stale completion replaced previous result: %+v", got)
	}
	if breaker.rules["mixed"].phase != http3RuleBreakerProbation {
		t.Fatal("stale completion ended current probation")
	}
	breaker.failProbation("mixed", nextToken, "probe_closed")
	if got := breaker.snapshot()[0].lastRecovery; got.completedAt == last.completedAt {
		t.Fatal("new real completion did not replace previous result")
	}
}

func TestHTTP3RecoveryResultDegradationEventAndMissingBinding(t *testing.T) {
	breaker, now, key, _ := recoveryResultFixture(t, true)
	*now = now.Add(12 * time.Second)
	breaker.noteDegradation(http3RuleDegradationEvent{key: key, generationID: 3, at: *now})
	last := breaker.snapshot()[0].lastRecovery
	if last.result != "transport_degraded" || last.elapsed != 12*time.Second {
		t.Fatalf("degradation callback did not preserve final result: %+v", last)
	}
	breaker, _, _, token := recoveryResultFixture(t, false)
	breaker.failProbation("mixed", token, "missing_transport_evidence")
	last = breaker.snapshot()[0].lastRecovery
	if last.result != "setup_failed" || last.reason != "missing_transport_evidence" || last.evidence {
		t.Fatalf("missing binding result: %+v", last)
	}
	assertHTTP3RecoveryHasNoDataMetrics(t, breaker.snapshot())
}

func TestHTTP3RecoveryResultLateSnapshotCannotRollBackCounters(t *testing.T) {
	for _, kind := range []string{"empty_connection_close", "older_close_snapshot", "old_generation_snapshot"} {
		t.Run(kind, func(t *testing.T) {
			breaker, now, key, token := recoveryResultFixture(t, true)
			probe := &breaker.rules["mixed"].probation
			probe.initialPayload = 0
			probe.initialStats = quic.ConnectionStats{}
			breaker.noteSample(http3RuleSampleEvent{
				key: key, generationID: 3, at: now.Add(2 * time.Second),
				payloadBytes: 1024, stats: quic.ConnectionStats{PacketsSent: 16},
				decision: http3DegradationDecision{Signals: http3DegradationSignals{Sampled: true}},
			})
			*now = now.Add(3 * time.Second)
			switch kind {
			case "empty_connection_close":
				breaker.noteSample(http3RuleSampleEvent{key: key, generationID: 3, at: *now, connectionErr: errors.New("closed")})
			case "older_close_snapshot":
				breaker.failProbationWithEvidence("mixed", token, "probe_closed", &http3RuleSampleEvent{
					key: key, generationID: 3, payloadBytes: 512, stats: quic.ConnectionStats{PacketsSent: 8},
				})
			case "old_generation_snapshot":
				breaker.failProbationWithEvidence("mixed", token, "probe_closed", &http3RuleSampleEvent{
					key: key, generationID: 2, payloadBytes: 999999, stats: quic.ConnectionStats{PacketsSent: 999999},
				})
			}
			last := breaker.snapshot()[0].lastRecovery
			if last.payloadBytes != 1024 || last.packetsSent != 16 {
				t.Fatalf("terminal evidence was rolled back or contaminated by stale generation: %+v", last)
			}
		})
	}
}

func TestHTTP3RecoveryResultMetricsAbsentBeforeCompletion(t *testing.T) {
	breaker, _, _, _ := recoveryResultFixture(t, true)
	var output strings.Builder
	writeHTTP3RecoveryGauges(&output, breaker.snapshot())
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "moto_connect_proxy_h3_rule_recovery_last_") {
			t.Fatalf("an unfinished first probation fabricated a previous result: %s", line)
		}
	}
	for _, want := range []string{
		`moto_connect_proxy_h3_rule_recovery_min_duration_seconds{rule="mixed"} 30`,
		`moto_connect_proxy_h3_rule_recovery_max_duration_seconds{rule="mixed"} 90`,
		`moto_connect_proxy_h3_rule_recovery_min_payload_bytes{rule="mixed"} 524288`,
		`moto_connect_proxy_h3_rule_recovery_min_packets_sent{rule="mixed"} 256`,
		`moto_connect_proxy_h3_rule_recovery_min_healthy_samples{rule="mixed"} 3`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing threshold metric: %s", want)
		}
	}
}

func TestHTTP3RecoveryResultRealShortTunnelFinalCounters(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		buffer := make([]byte, 32768)
		for {
			n, err := request.Body.Read(buffer)
			if n > 0 {
				_, _ = writer.Write(buffer[:n])
				writer.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	endpoint, roots, stop, _ := startHTTP3ConnectTestServer(t, handler)
	defer stop()
	manager := newConnectProxyManager()
	defer manager.close()
	manager.h3.newTransport = func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	}
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
	}}
	manager.registerHTTP3RuleTarget("mixed", target)
	manager.h3RuleBreaker.mu.Lock()
	manager.h3RuleBreaker.rules["mixed"].phase = http3RuleBreakerCooldown
	manager.h3RuleBreaker.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tunnel, err := manager.dialForRule(ctx, "mixed", target, "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	payload := bytes.Repeat([]byte("recovery-evidence"), 4096)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("real H3 payload mismatch: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	last := manager.h3RuleBreaker.snapshot()[0].lastRecovery
	if last.result != "insufficient_evidence" || last.reason != "probe_closed" || !last.evidence || last.payloadBytes != uint64(len(payload)*2) || last.packetsSent == 0 {
		t.Fatalf("short real tunnel counters were not captured before teardown: %+v", last)
	}
	var output strings.Builder
	writeHTTP3RecoveryGauges(&output, manager.h3RuleBreaker.snapshot())
	if !strings.Contains(output.String(), `moto_connect_proxy_h3_rule_recovery_last_result{rule="mixed",result="insufficient_evidence",reason="probe_closed"} 1`) {
		t.Fatal("real tunnel result missing from metrics")
	}
	for range 3 {
		_ = tunnel.Close()
	}
	if got := manager.h3RuleBreaker.snapshot()[0].lastRecovery; !reflect.DeepEqual(got, last) {
		t.Fatal("repeated Close overwrote preserved evidence")
	}
}
