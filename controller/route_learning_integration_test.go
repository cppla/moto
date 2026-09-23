package controller

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"moto/config"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	xhttp2 "golang.org/x/net/http2"
)

// These tests exercise real HTTP CONNECT ingress and TLS/QUIC transports. Only
// the learning observation clock and policy hold/exploration ages are advanced;
// setup latencies and outcomes come from the production dial hook. This is a
// routing-logic integration test, not a link-throughput benchmark.
func newLearningIntegrationUpstream(t *testing.T, protocol string, handler http.HandlerFunc) (*config.Target, func(*routingRuntime)) {
	t.Helper()
	if protocol == config.ConnectProxyH2 {
		proxy := newHTTP2ConnectTestServer(t, handler)
		target := http2ConnectTestTarget(proxy, "moto", "fixture-secret")
		roots := x509.NewCertPool()
		roots.AddCert(proxy.Certificate())
		return target, func(runtime *routingRuntime) {
			// Retain production observers and pool ownership. Replacing the
			// entire manager with a TLS test manager would bypass those hooks.
			factory := runtime.connectProxy.h2.newTransport
			runtime.connectProxy.h2.newTransport = func(key http2ConnectTransportKey) *xhttp2.Transport {
				transport := factory(key)
				if key.address == target.Address {
					transport.TLSClientConfig.RootCAs = roots
				}
				return transport
			}
		}
	}
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	t.Cleanup(closeServer)
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{protocol}}}
	return target, func(runtime *routingRuntime) {
		factory := runtime.connectProxy.h3.newTransport
		runtime.connectProxy.h3.newTransport = func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
			transport := factory(key, owner)
			if key.address == target.Address {
				transport.TLSClientConfig.RootCAs = roots
			}
			return transport
		}
	}
}

func learningIntegrationServer(t *testing.T, rule *config.Rule, installs ...func(*routingRuntime)) (*Server, *atomic.Int64) {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(time.Now().Add(-20 * time.Second).Truncate(time.Second).UnixNano())
	server := startHTTPConnectIntegrationServer(t, rule, func(runtime *routingRuntime) {
		for _, install := range installs {
			install(runtime)
		}
		runtime.connectProxy.now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	return server, clock
}

func learningIntegrationRequest(t *testing.T, server *Server, clock *atomic.Int64, destination string, status int) string {
	t.Helper()
	clock.Add(int64(routeLearningWindow))
	client := dialHTTPConnectIntegrationClient(t, server)
	defer client.Close()
	writeHTTPConnectIntegrationRequest(t, client, destination)
	reader := bufio.NewReader(client)
	response := readHTTPConnectIntegrationResponse(t, reader)
	if response.StatusCode != status {
		t.Fatalf("CONNECT %s returned %s, want %d", destination, response.Status, status)
	}
	if status != http.StatusOK {
		_, err := io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatalf("read rejected CONNECT: %v", err)
		}
		return ""
	}
	const payload = "learning-integration-payload\n"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || !strings.HasSuffix(string(body), payload) {
		t.Fatalf("actual tunnel payload = %q, error = %v", body, err)
	}
	return strings.TrimSuffix(string(body), payload)
}

func learningIntegrationHandler(t *testing.T, protocol, label, onlyDestination string, delay time.Duration, calls *atomic.Int32) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		major := 2
		if protocol == config.ConnectProxyH3 {
			major = 3
		}
		if request.Method != http.MethodConnect || request.ProtoMajor != major {
			t.Errorf("fixture got %s %s, want CONNECT/%s", request.Method, request.Proto, protocol)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if onlyDestination != "" && request.Host != onlyDestination && request.Host != "common.example:443" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-request.Context().Done():
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, label)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(httpConnectIntegrationFlushWriter{writer}, request.Body)
	}
}

func TestRouteLearningIntegrationActualSetupAndForbiddenNeutral(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			var calls atomic.Int32
			target, install := newLearningIntegrationUpstream(t, protocol,
				learningIntegrationHandler(t, protocol, "accepted\n", "accepted.example:443", time.Millisecond, &calls))
			server, clock := learningIntegrationServer(t, httpConnectIntegrationRule(config.ModeBoost, target), install)
			generation := server.current.Load()
			runtime, rule := generation.runtime, generation.rules[0]
			key := routeLearningKey{boostRuleKey(rule), target.Address, protocol}
			for index := 0; index < 3; index++ {
				if label := learningIntegrationRequest(t, server, clock, "accepted.example:443", http.StatusOK); label != "accepted\n" {
					t.Fatalf("unexpected response label %q", label)
				}
			}
			estimate := runtime.learning.estimate(key, time.Now())
			if !estimate.Known || estimate.Latency <= 0 || estimate.FailureRatio != 0 || estimate.LastObservation.IsZero() {
				t.Fatalf("actual CONNECT hooks did not produce usable evidence: %+v", estimate)
			}
			runtime.learning.mu.Lock()
			before := *runtime.learning.states[key]
			runtime.learning.mu.Unlock()
			learningIntegrationRequest(t, server, clock, "denied.example:443", http.StatusForbidden)
			runtime.learning.mu.Lock()
			after := *runtime.learning.states[key]
			runtime.learning.mu.Unlock()
			if before != after {
				t.Fatalf("HTTP 403 polluted transport learning: before=%+v after=%+v", before, after)
			}
			if got := calls.Load(); got != 4 {
				t.Fatalf("upstream CONNECT requests = %d, want 4", got)
			}
		})
	}
}

func TestRouteLearningIntegrationQualityAlternativeReplacesCachedWinner(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			var callsA, callsB atomic.Int32
			a, installA := newLearningIntegrationUpstream(t, protocol,
				learningIntegrationHandler(t, protocol, "A\n", "a-only.example:443", 150*time.Millisecond, &callsA))
			b, installB := newLearningIntegrationUpstream(t, protocol,
				learningIntegrationHandler(t, protocol, "B\n", "b-only.example:443", time.Millisecond, &callsB))
			server, clock := learningIntegrationServer(t, httpConnectIntegrationRule(config.ModeBoost, a, b), installA, installB)
			generation := server.current.Load()
			runtime, rule := generation.runtime, generation.rules[0]
			key := boostRuleKey(rule)
			runtime.storeBoostWinner(key, a.Address)
			for _, destination := range []string{"a-only.example:443", "b-only.example:443"} {
				for index := 0; index < 3; index++ {
					learningIntegrationRequest(t, server, clock, destination, http.StatusOK)
				}
			}
			for _, target := range []*config.Target{a, b} {
				if estimate := runtime.learning.estimate(routeLearningKey{key, target.Address, protocol}, time.Now()); !estimate.Known {
					t.Fatalf("target %s did not learn from actual requests: %+v", target.Address, estimate)
				}
			}
			if cached, ok := runtime.loadBoostWinnerToken(key); !ok || cached.addr != a.Address {
				t.Fatalf("destination-specific 403 replaced original cache: %+v, %t", cached, ok)
			}
			runtime.learningPolicy.mu.Lock()
			runtime.learningPolicy.rules[key].preferredAt = time.Now().Add(-routeLearningPreferenceHold - time.Second)
			runtime.learningPolicy.rules[key].lastExplore = time.Now()
			runtime.learningPolicy.mu.Unlock()
			if label := learningIntegrationRequest(t, server, clock, "common.example:443", http.StatusOK); label != "B\n" {
				t.Fatalf("quality alternative did not carry actual tunnel: %q", label)
			}
			if cached, ok := runtime.loadBoostWinnerToken(key); !ok || cached.addr != b.Address {
				t.Fatalf("quality preference did not update winner cache: %+v, %t", cached, ok)
			}
			runtime.learningPolicy.mu.Lock()
			preferred := runtime.learningPolicy.rules[key].preferred
			qualityDecisions := runtime.learningPolicy.rules[key].decisions["quality"]
			runtime.learningPolicy.mu.Unlock()
			if preferred != b.Address || qualityDecisions == 0 {
				t.Fatalf("quality policy/decision not reflected: preference=%s decisions=%d", preferred, qualityDecisions)
			}
		})
	}
}

func TestRouteLearningIntegrationCachedWinnerStillExploresWithoutReplacingCache(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			var callsA, callsB atomic.Int32
			a, installA := newLearningIntegrationUpstream(t, protocol,
				learningIntegrationHandler(t, protocol, "A\n", "", time.Millisecond, &callsA))
			b, installB := newLearningIntegrationUpstream(t, protocol,
				learningIntegrationHandler(t, protocol, "B\n", "", 75*time.Millisecond, &callsB))
			server, clock := learningIntegrationServer(t, httpConnectIntegrationRule(config.ModeBoost, a, b), installA, installB)
			generation := server.current.Load()
			runtime, rule := generation.runtime, generation.rules[0]
			key := boostRuleKey(rule)
			original := runtime.storeBoostWinner(key, a.Address)
			for index := 0; index < 3; index++ {
				if label := learningIntegrationRequest(t, server, clock, "common.example:443", http.StatusOK); label != "A\n" {
					t.Fatalf("cached primary carried %q", label)
				}
			}
			if got := callsB.Load(); got != 0 {
				t.Fatalf("unused alternative received %d requests before exploration", got)
			}
			runtime.learningPolicy.mu.Lock()
			runtime.learningPolicy.rules[key].lastExplore = time.Now().Add(-routeLearningExploreInterval - time.Second)
			runtime.learningPolicy.mu.Unlock()
			if label := learningIntegrationRequest(t, server, clock, "common.example:443", http.StatusOK); label != "B\n" {
				t.Fatalf("cached winner suppressed exploratory tunnel: %q", label)
			}
			if estimate := runtime.learning.estimate(routeLearningKey{key, b.Address, protocol}, time.Now()); estimate.Samples <= 0 || estimate.Latency <= 0 {
				t.Fatalf("successful real exploration did not reach learning hook: %+v", estimate)
			}
			if cached, ok := runtime.loadBoostWinnerToken(key); !ok || cached.addr != original.addr || cached.generation != original.generation {
				t.Fatalf("exploration overwrote ordinary winner: %+v, %t", cached, ok)
			}
			if label := learningIntegrationRequest(t, server, clock, "common.example:443", http.StatusOK); label != "A\n" {
				t.Fatalf("request following explorer did not use ordinary primary: %q", label)
			}
			runtime.learningPolicy.mu.Lock()
			explorations := runtime.learningPolicy.rules[key].decisions["explore"]
			lease := runtime.learningPolicy.rules[key].exploreToken
			runtime.learningPolicy.mu.Unlock()
			if explorations != 1 || lease != 0 || callsB.Load() != 1 {
				t.Fatalf("explorer budget/release mismatch: decisions=%d lease=%d requests=%d", explorations, lease, callsB.Load())
			}
		})
	}
}
