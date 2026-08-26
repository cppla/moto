package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"testing"
	"time"
)

func newHTTP3CooldownTestConnection(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client
}

func TestHTTP3RepeatedDegradationUsesH2CooldownAndHalfOpenRecovery(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			ServerName: "proxy.example",
			Protocols:  []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	h3Calls := 0
	h2Calls := 0
	managedProbeSeen := false
	manager := &connectProxyManager{
		now:                  func() time.Time { return now },
		degradedCooldownBase: 30 * time.Second,
		degradedCooldownMax:  2 * time.Minute,
		degradationWindow:    5 * time.Minute,
		h3Fallback:           make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
				h3Calls++
				managedProbeSeen = http3ManagedProbeFromContext(ctx)
				return newHTTP3CooldownTestConnection(t), nil
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				h2Calls++
				return newHTTP3CooldownTestConnection(t), nil
			},
		},
	}

	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	if penalty := manager.http3RoutePenalty(nil, target, now); penalty <= 0 {
		t.Fatal("first active H3 degradation did not publish a Boost penalty")
	}
	manager.h3FallbackMu.Lock()
	first := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if first.degradationStrikes != 1 || first.pending {
		t.Fatalf("duplicate samples counted as independent degradation: %+v", first)
	}

	// A normal CONNECT success on the old physical connection is not recovery;
	// only promotion/redial clears the active generation while retaining strike 1.
	firstToken, firstManaged, firstAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !firstAllowed || firstManaged {
		t.Fatalf("first-generation permit = token:%d managed:%t allowed:%t", firstToken, firstManaged, firstAllowed)
	}
	manager.observeHTTP3Attempt(target, firstToken, firstManaged, nil, nil, false)
	manager.noteHTTP3Recovery(key)
	manager.noteHTTP3Degradation(key, http3DegradationReasonSevereLossAndWrite)

	manager.h3FallbackMu.Lock()
	second := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if second.degradationStrikes != 2 || !second.pending || second.pendingCause != http3FallbackCauseDegradation {
		t.Fatalf("second physical degradation did not open H2 validation: %+v", second)
	}
	if penalty := manager.http3RoutePenalty(nil, target, now); penalty != 0 {
		t.Fatalf("mixed target already falling back to H2 retained penalty %s", penalty)
	}

	connection, err := manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("H2 validation after repeated degradation: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 0 || h2Calls != 1 {
		t.Fatalf("validation calls = h3:%d h2:%d, want 0/1", h3Calls, h2Calls)
	}
	manager.h3FallbackMu.Lock()
	cooled := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if cooled.failures != 1 || cooled.cooldownCause != http3FallbackCauseDegradation ||
		!cooled.retryAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("degradation cooldown = %+v", cooled)
	}

	connection, err = manager.dial(context.Background(), target, "during-cooldown.example:443")
	if err != nil {
		t.Fatalf("H2 during degradation cooldown: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 0 || h2Calls != 2 {
		t.Fatalf("cooldown calls = h3:%d h2:%d, want 0/2", h3Calls, h2Calls)
	}

	now = now.Add(30 * time.Second)
	connection, err = manager.dial(context.Background(), target, "half-open.example:443")
	if err != nil {
		t.Fatalf("H3 half-open recovery: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 2 || !managedProbeSeen {
		t.Fatalf("half-open calls = h3:%d h2:%d managed:%t", h3Calls, h2Calls, managedProbeSeen)
	}
	manager.h3FallbackMu.Lock()
	recovered := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if recovered.failures != 0 || recovered.degradationStrikes != 0 || recovered.degradationActive ||
		!recovered.retryAt.IsZero() {
		t.Fatalf("successful half-open did not reset H3 policy: %+v", recovered)
	}
}

func TestHTTP3DegradationCooldownRequiresReachableHTTP2(t *testing.T) {
	now := time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC)
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address}
	h3Calls := 0
	h2Calls := 0
	h2Reachable := false
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: 5 * time.Second,
		h3Fallback:   make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
				h3Calls++
				return newHTTP3CooldownTestConnection(t), nil
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				h2Calls++
				if !h2Reachable {
					return nil, errors.New("H2 unavailable")
				}
				return newHTTP3CooldownTestConnection(t), nil
			},
		},
	}
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	manager.noteHTTP3Recovery(key)
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)

	if connection, err := manager.dial(context.Background(), target, "first.example:443"); err == nil {
		_ = connection.Close()
		t.Fatal("unreachable H2 validation unexpectedly succeeded")
	}
	manager.h3FallbackMu.Lock()
	failedValidation := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if failedValidation.failures != 0 || failedValidation.pending ||
		!failedValidation.degradationRetryAt.Equal(now.Add(5*time.Second)) {
		t.Fatalf("failed H2 validation suppressed H3: %+v", failedValidation)
	}

	connection, err := manager.dial(context.Background(), target, "old-h3.example:443")
	if err != nil {
		t.Fatalf("old H3 should remain fail-open while H2 is unavailable: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 1 {
		t.Fatalf("pre-retry calls = h3:%d h2:%d, want 1/1", h3Calls, h2Calls)
	}

	now = now.Add(5 * time.Second)
	h2Reachable = true
	if penalty := manager.http3RoutePenalty(nil, target, now); penalty != 0 {
		t.Fatalf("due H2 validation remained hidden behind Boost penalty %s", penalty)
	}
	connection, err = manager.dial(context.Background(), target, "retry.example:443")
	if err != nil {
		t.Fatalf("retried H2 validation: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 2 {
		t.Fatalf("validation retry calls = h3:%d h2:%d, want 1/2", h3Calls, h2Calls)
	}
}

func TestHTTP3OnlyRepeatedDegradationRemainsFailOpen(t *testing.T) {
	now := time.Date(2026, 8, 26, 14, 0, 0, 0, time.UTC)
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}},
	}
	key := http3ConnectTransportKey{address: target.Address}
	h3Calls := 0
	manager := &connectProxyManager{
		now:        func() time.Time { return now },
		h3Fallback: make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
				h3Calls++
				return newHTTP3CooldownTestConnection(t), nil
			},
		},
	}
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	manager.noteHTTP3Recovery(key)
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	if penalty := manager.http3RoutePenalty(nil, target, now); penalty <= 0 {
		t.Fatal("H3-only degraded target did not expose a Boost penalty")
	}
	connection, err := manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("H3-only target was blocked by fallback cooldown: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 {
		t.Fatalf("H3-only calls = %d, want 1", h3Calls)
	}
}

func TestHTTP3BoostCanaryClaimIsSingleflightAndPeriodic(t *testing.T) {
	now := time.Date(2026, 8, 26, 14, 30, 0, 0, time.UTC)
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			ServerName: "proxy.example",
			Protocols:  []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager := &connectProxyManager{
		now:               func() time.Time { return now },
		h3Fallback:        make(map[http3ConnectTransportKey]*http3FallbackState),
		degradationWindow: 5 * time.Minute,
	}
	manager.noteHTTP3Degradation(key, http3DegradationReasonSustainedSignals)
	if penalty := manager.http3RoutePenalty(nil, target, now); penalty <= 0 {
		t.Fatal("degraded H3 target did not publish a routing penalty")
	}
	token, claimed := manager.claimHTTP3BoostProbe(nil, target, now)
	if !claimed || token == 0 {
		t.Fatal("first post-degradation Boost canary was not admitted")
	}
	if _, claimed = manager.claimHTTP3BoostProbe(nil, target, now); claimed {
		t.Fatal("concurrent Boost canary was admitted")
	}
	now = now.Add(http3BoostCanaryInterval)
	if _, claimed = manager.claimHTTP3BoostProbe(nil, target, now); claimed {
		t.Fatal("second Boost canary overlapped a long-running owner")
	}
	manager.releaseHTTP3BoostProbe(nil, target, token)
	secondToken, claimed := manager.claimHTTP3BoostProbe(nil, target, now)
	if !claimed || secondToken == 0 || secondToken == token {
		t.Fatal("Boost canary was not retried after its bounded interval")
	}
	manager.releaseHTTP3BoostProbe(nil, target, secondToken)
	manager.noteHTTP3Recovery(key)
	if _, claimed = manager.claimHTTP3BoostProbe(nil, target, now); claimed {
		t.Fatal("healthy H3 target retained a recovery canary")
	}
}

func TestHTTP3DegradationCallbackUsesAggregateServingHealth(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	degradedEvents := 0
	recoveredEvents := 0
	manager.onDegraded = func(got http3ConnectTransportKey, _ http3DegradationReason) {
		if got != key {
			t.Errorf("degraded key = %+v, want %+v", got, key)
		}
		degradedEvents++
	}
	manager.onRecovered = func(got http3ConnectTransportKey) {
		if got != key {
			t.Errorf("recovered key = %+v, want %+v", got, key)
		}
		recoveredEvents++
	}

	_, first, releaseFirst, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire first serving slot: %v", err)
	}
	manager.mu.Lock()
	first.limit = 1
	manager.mu.Unlock()
	_, second, releaseSecond, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire second serving slot: %v", err)
	}
	started := time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC)
	firstConnection := attachHTTP3TestConnection(t, manager, key, first, started)
	secondConnection := attachHTTP3TestConnection(t, manager, key, second, started)

	degradeHTTP3TestSlot(t, manager, key, first, firstConnection, started.Add(time.Minute))
	if degradedEvents != 0 {
		t.Fatalf("one bad slot penalized target while another serving slot was healthy: %d events", degradedEvents)
	}
	degradeHTTP3TestSlot(t, manager, key, second, secondConnection, started.Add(time.Minute))
	degradeHTTP3TestSlot(t, manager, key, second, secondConnection, started.Add(2*time.Minute))
	if degradedEvents != 1 {
		t.Fatalf("aggregate degradation events = %d, want exactly 1", degradedEvents)
	}

	manager.mu.Lock()
	candidate := first.replacement
	manager.mu.Unlock()
	if candidate == nil {
		t.Fatal("aggregate degradation did not retain a warming replacement")
	}
	manager.promoteHTTP3Candidate(key, candidate)
	if recoveredEvents != 1 {
		t.Fatalf("promotion recovery events = %d, want 1", recoveredEvents)
	}
	releaseSecond()
	releaseFirst()
}

func TestHTTP3AcquirePrefersHealthyServingSlot(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	_, degraded, releaseDegraded, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire first slot: %v", err)
	}
	manager.mu.Lock()
	degraded.limit = 1
	manager.mu.Unlock()
	_, healthy, releaseHealthy, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire second slot: %v", err)
	}
	manager.mu.Lock()
	degraded.limit = 2
	healthy.limit = 2
	degraded.health = http3TransportDegraded
	healthy.health = http3TransportHealthy
	manager.mu.Unlock()

	_, selected, releaseSelected, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire preferred slot: %v", err)
	}
	defer releaseSelected()
	if selected != healthy {
		t.Fatalf("selected health = %s, want healthy serving slot", selected.health)
	}
	releaseHealthy()
	releaseDegraded()
}
