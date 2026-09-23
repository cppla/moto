package controller

import (
	"context"
	"moto/config"
	"net"
	"sync"
	"testing"
	"time"
)

func learningObserverSeed(runtime *routingRuntime, rule, address, protocol string, start time.Time) routeLearningKey {
	return learningObserverSeedEndpoint(runtime, rule, address, protocol, routeLearningEndpoint{}, start)
}

func learningObserverSeedEndpoint(runtime *routingRuntime, rule, address, protocol string, endpoint routeLearningEndpoint, start time.Time) routeLearningKey {
	key := routeLearningKey{rule: rule, target: address, protocol: protocol}
	for offset := range 3 {
		runtime.learning.observeEndpointSetup(key, endpoint, 60*time.Millisecond, nil, start.Add(time.Duration(offset)*time.Second))
	}
	return key
}

func learningObserverState(learner *routeLearner, key routeLearningKey) routeLearningState {
	learner.mu.Lock()
	defer learner.mu.Unlock()
	state := learner.states[key]
	if state == nil {
		return routeLearningState{}
	}
	return *state
}

func TestRouteLearningObserverH2FactoryPreservesMetricAndDeduplicatesPhysicalFailure(t *testing.T) {
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	const address = "observer-h2-loss.example:443"
	rules := connectProxyMetricTestRules(t.Name(), address)
	processMetrics.registerRules(rules)
	t.Cleanup(func() { processMetrics.unregisterRules(rules) })
	start := time.Now().Add(-3 * time.Second)
	h2 := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH2, start)
	h3 := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH3, start)
	other := learningObserverSeed(runtime, t.Name(), "other-observer.example:443", config.ConnectProxyH2, start)
	beforeH2 := learningObserverState(runtime.learning, h2)
	beforeH3 := learningObserverState(runtime.learning, h3)
	beforeOther := learningObserverState(runtime.learning, other)

	// Use the factory installed by newRoutingRuntime, then the same physical
	// callback wrapper used by http2ConnectConnPool.newClientConn. No network
	// handshake or synthetic direct learner degradation call is involved.
	transport := runtime.connectProxy.h2.newTransport(http2ConnectTransportKey{address: address})
	if transport.CountError == nil {
		t.Fatal("H2 factory lost its error observer")
	}
	raw, peer := net.Pipe()
	connection, callback := wrapHTTP2PingMetricConnection(raw, transport.CountError)
	t.Cleanup(func() { connection.Close(); peer.Close() })
	for _, kind := range []string{"read_frame_eof", "read_frame_other", "conn_close_goaway", "stream_closed"} {
		callback(kind)
	}
	if after := learningObserverState(runtime.learning, h2); after != beforeH2 {
		t.Fatalf("unrelated H2 errors changed learning: before=%+v after=%+v", beforeH2, after)
	}
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 0 {
		t.Fatalf("unrelated H2 errors increased PING counter: %d", got)
	}

	callback("conn_close_lost_ping")
	first := learningObserverState(runtime.learning, h2)
	if first.degradedAt.IsZero() || !first.lastObservation.Equal(first.degradedAt) {
		t.Fatalf("physical failure did not reach learning observer: %+v", first)
	}
	if first.samples != beforeH2.samples || first.windows != beforeH2.windows || first.failureRatio != beforeH2.failureRatio {
		t.Fatal("physical degradation fabricated independent setup samples or failures")
	}
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			callback("conn_close_lost_ping")
		}()
	}
	workers.Wait()
	if after := learningObserverState(runtime.learning, h2); after != first {
		t.Fatalf("duplicate physical notifications refreshed degradation: first=%+v after=%+v", first, after)
	}
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 1 {
		t.Fatalf("original CountError metric not preserved/deduplicated: %d, want 1", got)
	}
	if after := learningObserverState(runtime.learning, h3); after != beforeH3 {
		t.Fatal("H2 failure polluted H3 evidence")
	}
	if after := learningObserverState(runtime.learning, other); after != beforeOther {
		t.Fatal("H2 failure polluted another target")
	}

	// A replacement physical connection owns a fresh callback, even though it
	// uses the same transport template. Its independent loss counts once too.
	replacement, replacementPeer := net.Pipe()
	next, nextCallback := wrapHTTP2PingMetricConnection(replacement, transport.CountError)
	t.Cleanup(func() { next.Close(); replacementPeer.Close() })
	nextCallback("conn_close_lost_ping")
	nextCallback("conn_close_lost_ping")
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 2 {
		t.Fatalf("replacement connection did not own an independent PING event: %d", got)
	}
}

func TestRouteLearningObserverH2LatePingAfterPhysicalCloseIsIgnored(t *testing.T) {
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	const address = "observer-h2-closed.example:443"
	key := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH2, time.Now().Add(-3*time.Second))
	before := learningObserverState(runtime.learning, key)
	transport := runtime.connectProxy.h2.newTransport(http2ConnectTransportKey{address: address})
	raw, peer := net.Pipe()
	connection, callback := wrapHTTP2PingMetricConnection(raw, transport.CountError)
	t.Cleanup(func() { connection.Close(); peer.Close() })
	connection.Close()
	callback("conn_close_lost_ping")
	if after := learningObserverState(runtime.learning, key); after != before {
		t.Fatalf("already closed physical connection created learning penalty: before=%+v after=%+v", before, after)
	}
}

func TestRouteLearningObserverH3PreservesPriorCallbackAndScopesEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := newConnectProxyManager()
	t.Cleanup(func() { cancel(); manager.close() })
	runtime := &routingRuntime{ctx: ctx, cancel: cancel, connectProxy: manager, learning: newRouteLearner()}
	var received []http3RuleDegradationEvent
	previous := manager.h3.onConnectionDegraded
	manager.h3.onConnectionDegraded = func(event http3RuleDegradationEvent) {
		received = append(received, event)
		if previous != nil {
			previous(event)
		}
	}
	runtime.installRouteLearningObservers()
	const address = "observer-h3-loss.example:443"
	start := time.Unix(1700000000, 0)
	h3 := learningObserverSeedEndpoint(runtime, t.Name(), address, config.ConnectProxyH3,
		routeLearningEndpoint{serverName: "observer.example"}, start)
	h2 := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH2, start)
	other := learningObserverSeed(runtime, t.Name(), "other-observer.example:443", config.ConnectProxyH3, start)
	beforeH3 := learningObserverState(runtime.learning, h3)
	beforeH2 := learningObserverState(runtime.learning, h2)
	beforeOther := learningObserverState(runtime.learning, other)
	event := http3RuleDegradationEvent{
		key:          http3ConnectTransportKey{address: address, serverName: "observer.example"},
		remoteIP:     "192.0.2.10",
		generationID: 42,
		at:           start.Add(4 * time.Second),
		reason:       http3DegradationReasonSustainedSignals,
	}
	manager.h3.onConnectionDegraded(event)
	if len(received) != 1 || received[0] != event {
		t.Fatalf("original callback lost or event changed: %+v", received)
	}
	after := learningObserverState(runtime.learning, h3)
	if !after.degradedAt.Equal(event.at) || !after.lastObservation.Equal(event.at) {
		t.Fatalf("H3 event did not preserve its event timestamp: %+v", after)
	}
	if after.samples != beforeH3.samples || after.windows != beforeH3.windows || after.failureRatio != beforeH3.failureRatio {
		t.Fatal("H3 event fabricated setup sample confidence")
	}
	if got := learningObserverState(runtime.learning, h2); got != beforeH2 {
		t.Fatal("H3 callback penalized H2")
	}
	if got := learningObserverState(runtime.learning, other); got != beforeOther {
		t.Fatal("H3 callback penalized another target")
	}
}

func TestRouteLearningObserverRuntimeCancellationStopsLearningButPreservesCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := newConnectProxyManager()
	t.Cleanup(func() { cancel(); manager.close() })
	runtime := &routingRuntime{ctx: ctx, cancel: cancel, connectProxy: manager, learning: newRouteLearner()}
	const address = "observer-canceled.example:443"
	rules := connectProxyMetricTestRules(t.Name(), address)
	processMetrics.registerRules(rules)
	t.Cleanup(func() { processMetrics.unregisterRules(rules) })
	priorCalls := 0
	manager.h3.onConnectionDegraded = func(http3RuleDegradationEvent) { priorCalls++ }
	runtime.installRouteLearningObservers()
	start := time.Now().Add(-3 * time.Second)
	h2 := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH2, start)
	h3 := learningObserverSeed(runtime, t.Name(), address, config.ConnectProxyH3, start)
	beforeH2 := learningObserverState(runtime.learning, h2)
	beforeH3 := learningObserverState(runtime.learning, h3)
	transport := manager.h2.newTransport(http2ConnectTransportKey{address: address})
	raw, peer := net.Pipe()
	connection, callback := wrapHTTP2PingMetricConnection(raw, transport.CountError)
	t.Cleanup(func() { connection.Close(); peer.Close() })
	cancel()
	callback("conn_close_lost_ping")
	manager.h3.onConnectionDegraded(http3RuleDegradationEvent{
		key: http3ConnectTransportKey{address: address}, at: time.Now(), generationID: 99,
		reason: http3DegradationReasonUDPBlackhole,
	})
	if after := learningObserverState(runtime.learning, h2); after != beforeH2 {
		t.Fatal("canceled runtime accepted H2 learning event")
	}
	if after := learningObserverState(runtime.learning, h3); after != beforeH3 {
		t.Fatal("canceled runtime accepted H3 learning event")
	}
	if priorCalls != 1 {
		t.Fatalf("canceled learner suppressed the existing H3 callback: %d", priorCalls)
	}
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 1 {
		t.Fatalf("canceled learner suppressed the original H2 metric sink: %d", got)
	}
}
