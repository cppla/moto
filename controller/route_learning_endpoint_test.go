package controller

import (
	"context"
	"moto/config"
	"net"
	"testing"
	"time"
)

// Feed through the production CONNECT setup hook so this catches an identity
// dropped either on the way into the learner or on the degradation callback.
func learningEndpointSeed(t *testing.T, runtime *routingRuntime, name, address, serverName, protocol, userAgent string, start time.Time) (*config.Rule, routeLearningKey) {
	t.Helper()
	rule := &config.Rule{Name: name, Listen: "127.0.0.1:19006", Protocol: config.ProtocolHTTP, Mode: config.ModeBoost}
	for _, candidate := range []string{address, name + "-backup.example:443"} {
		rule.Targets = append(rule.Targets, &config.Target{Address: candidate,
			ConnectProxy: &config.ConnectProxyConfig{ServerName: serverName, Protocols: []string{protocol}}})
	}
	ctx := withConnectProxyUserAgent(withRouteLearningScope(context.Background(), runtime.learning, rule), userAgent)
	runtime.connectProxy.dialers[protocol] = func(context.Context, *config.Target, string) (net.Conn, error) {
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	}
	for offset := range 3 {
		at := start.Add(time.Duration(offset) * time.Second)
		runtime.connectProxy.now = func() time.Time { return at }
		for _, target := range rule.Targets {
			connection, err := runtime.connectProxy.dialForRule(ctx, rule.Name, target, "destination.example:443")
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
		}
	}
	runtime.connectProxy.now = time.Now
	// Give each rule an established preferred route with a clear advantage.
	// The endpoint identity must continue to come from the production hook.
	runtime.learning.mu.Lock()
	for index, target := range rule.Targets {
		state := runtime.learning.states[routeLearningKey{boostRuleKey(rule), target.Address, protocol}]
		state.latency = time.Duration(50+index*100) * time.Millisecond
	}
	runtime.learning.mu.Unlock()
	choice := runtime.chooseLearningRoute(rule, start.Add(2*time.Second))
	if choice.address != address || choice.reason != "quality" {
		t.Fatalf("fixture did not establish its preferred endpoint: %+v", choice)
	}
	return rule, routeLearningKey{boostRuleKey(rule), address, protocol}
}

func TestRouteLearningObserversIsolateCompleteEndpointIdentity(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			runtime := newRoutingRuntime()
			t.Cleanup(runtime.stopBackground)
			const address = "192.0.2.20:443"
			const userAgent = "Mozilla/5.0 Firefox/120.0"
			start := time.Now().Add(-25 * time.Second)
			_, affected := learningEndpointSeed(t, runtime, "affected", address, "a.example", protocol, userAgent, start)
			_, shared := learningEndpointSeed(t, runtime, "shared", address, "a.example", protocol, userAgent, start)
			otherRule, otherSNI := learningEndpointSeed(t, runtime, "different-sni", address, "b.example", protocol, userAgent, start)
			beforeSNI := learningObserverState(runtime.learning, otherSNI)
			_, otherUA := learningEndpointSeed(t, runtime, "different-ua", address, "a.example", protocol, "Mozilla/5.0 Chrome/133.0.0.0", start)
			beforeUA := learningObserverState(runtime.learning, otherUA)

			if protocol == config.ConnectProxyH2 {
				transport := runtime.connectProxy.h2.newTransport(http2ConnectTransportKey{
					address: address, serverName: "a.example", userAgent: userAgent,
					tlsProfile: http2TLSProfileForUserAgent(userAgent),
				})
				raw, peer := net.Pipe()
				connection, callback := wrapHTTP2PingMetricConnection(raw, transport.CountError)
				t.Cleanup(func() { connection.Close(); peer.Close() })
				callback("conn_close_lost_ping")
			} else {
				runtime.connectProxy.h3.onConnectionDegraded(http3RuleDegradationEvent{
					key: http3ConnectTransportKey{address: address, serverName: "a.example"},
					at:  time.Now(), generationID: 42, reason: http3DegradationReasonSustainedSignals,
				})
			}
			for _, key := range []routeLearningKey{affected, shared} {
				if got := runtime.learning.estimate(key, time.Now()); !got.Degraded {
					t.Errorf("shared physical endpoint did not propagate to rule %q: %+v", key.rule, got)
				}
			}
			if got := learningObserverState(runtime.learning, otherSNI); got != beforeSNI {
				t.Errorf("different SNI on the same address was penalized: before=%+v after=%+v", beforeSNI, got)
			}
			if protocol == config.ConnectProxyH2 {
				if got := learningObserverState(runtime.learning, otherUA); got != beforeUA {
					t.Errorf("different H2 pool identity was penalized: before=%+v after=%+v", beforeUA, got)
				}
			} else if got := runtime.learning.estimate(otherUA, time.Now()); !got.Degraded {
				t.Errorf("H3 shares its physical pool across user agents: %+v", got)
			}
			if choice := learningPolicyOrdinaryChoice(runtime, otherRule, time.Now()); choice.address != address {
				t.Errorf("unrelated physical endpoint changed healthy preferred route: %+v", choice)
			}
		})
	}
}

func TestRouteLearningEndpointIdentitySurvivesInheritanceAndResetsOnChange(t *testing.T) {
	previous, next := newRouteLearner(), newRouteLearner()
	key := learningTestKey("192.0.2.20:443", config.ConnectProxyH2)
	endpoint := routeLearningEndpoint{serverName: "a.example", userAgent: "Firefox/120.0", tlsProfile: http2TLSProfileFirefox120}
	at := time.Unix(1700000000, 0)
	for offset := range 3 {
		previous.observeEndpointSetup(key, endpoint, 50*time.Millisecond, nil, at.Add(time.Duration(offset)*time.Second))
	}
	next.inherit(previous, map[string]struct{}{key.rule: {}})
	before := learningObserverState(next, key)
	for _, other := range []routeLearningEndpoint{
		{serverName: "b.example", userAgent: endpoint.userAgent, tlsProfile: endpoint.tlsProfile},
		{serverName: endpoint.serverName, userAgent: "Chrome/133.0.0.0", tlsProfile: endpoint.tlsProfile},
		{serverName: endpoint.serverName, userAgent: endpoint.userAgent, tlsProfile: http2TLSProfileChrome133},
	} {
		next.observeEndpointDegradation(key.target, key.protocol, other, at.Add(3*time.Second))
		if got := learningObserverState(next, key); got != before {
			t.Fatalf("inherited identity accepted another physical pool: %+v", other)
		}
	}
	next.observeEndpointDegradation(key.target, key.protocol, endpoint, at.Add(3*time.Second))
	if got := next.estimate(key, at.Add(3*time.Second)); !got.Degraded {
		t.Fatal("inherited identity lost matching physical degradation")
	}
	if got := learningObserverState(previous, key); got != before {
		t.Fatal("new runtime degradation modified its predecessor")
	}
	changed := endpoint
	changed.serverName = "b.example"
	next.observeEndpointSetup(key, changed, 150*time.Millisecond, nil, at.Add(4*time.Second))
	if got := next.estimate(key, at.Add(4*time.Second)); got.Degraded || got.Known || got.Samples != 1 || got.Latency != 150*time.Millisecond {
		t.Fatalf("changed physical identity retained old evidence: %+v", got)
	}
	next.observeEndpointDegradation(key.target, key.protocol, endpoint, at.Add(5*time.Second))
	if got := next.estimate(key, at.Add(5*time.Second)); got.Degraded {
		t.Fatal("old physical identity penalized a replacement endpoint")
	}
}
