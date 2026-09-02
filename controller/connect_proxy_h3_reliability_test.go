package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3SetupDeadlinePropagatesToTransportDial(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()

	observedDeadline := make(chan time.Time, 1)
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		originalDial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			deadline, ok := http3SetupDeadlineFromContext(ctx)
			if !ok {
				return nil, errors.New("missing HTTP/3 setup deadline")
			}
			observedDeadline <- deadline
			return originalDial(ctx, address, tlsConfig, quicConfig)
		}
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	wantDeadline, _ := ctx.Deadline()
	connection, err := manager.dial(ctx, target, "destination.example:443")
	cancel()
	if err != nil {
		t.Fatalf("dial HTTP/3 CONNECT: %v", err)
	}
	_ = connection.Close()

	select {
	case gotDeadline := <-observedDeadline:
		if !gotDeadline.Equal(wantDeadline) {
			t.Fatalf("setup deadline = %s, want %s", gotDeadline, wantDeadline)
		}
	case <-time.After(time.Second):
		t.Fatal("transport Dial did not observe the setup deadline")
	}
}

func TestHTTP3SetupDeadlineBudgetAndQUICClone(t *testing.T) {
	now := time.Now()
	attempt, cancelAttempt := context.WithDeadline(context.Background(), now.Add(10*time.Second))
	defer cancelAttempt()
	requestCtx := withHTTP3SetupDeadline(context.Background(), attempt)
	wantDeadline, _ := attempt.Deadline()
	if got := http3SetupDeadline(requestCtx, now); !got.Equal(wantDeadline) {
		t.Fatalf("setup deadline = %s, want attempt deadline %s", got, wantDeadline)
	}

	longAttempt, cancelLong := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancelLong()
	longRequestCtx := withHTTP3SetupDeadline(context.Background(), longAttempt)
	if got, want := http3SetupDeadline(longRequestCtx, now), now.Add(http3ConnectMaxHandshakeTimeout); !got.Equal(want) {
		t.Fatalf("capped setup deadline = %s, want %s", got, want)
	}

	original := &quic.Config{HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 2 * time.Minute}
	cloned := cloneHTTP3QUICConfigForSetup(original, 9*time.Second)
	if cloned == original {
		t.Fatal("QUIC config was not cloned")
	}
	if original.HandshakeIdleTimeout != time.Second {
		t.Fatalf("original handshake timeout mutated to %s", original.HandshakeIdleTimeout)
	}
	if cloned.HandshakeIdleTimeout != 9*time.Second || cloned.MaxIdleTimeout != original.MaxIdleTimeout {
		t.Fatalf("cloned QUIC config = %+v, want handshake 9s and preserved idle timeout", cloned)
	}
}

func TestHTTP3TransportUsesFastKeepAliveWithConservativeIdleFallback(t *testing.T) {
	transport := newHTTP3ConnectTransportWithOwner(
		http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"},
		context.Background(),
	)
	defer transport.Close()
	if transport.QUICConfig == nil {
		t.Fatal("HTTP/3 transport has no QUIC config")
	}
	if got := transport.QUICConfig.KeepAlivePeriod; got != 10*time.Second {
		t.Fatalf("QUIC keepalive = %s, want 10s", got)
	}
	if got := transport.QUICConfig.MaxIdleTimeout; got != 90*time.Second {
		t.Fatalf("QUIC max idle timeout = %s, want 90s", got)
	}
}

func TestHTTP3EstablishedTunnelSurvivesSetupDeadline(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	connection, err := manager.dial(ctx, target, "destination.example:443")
	if err != nil {
		t.Fatalf("dial HTTP/3 CONNECT: %v", err)
	}
	defer connection.Close()
	<-ctx.Done()
	assertConnectTunnelEcho(t, connection, "after-setup-deadline")
}

func TestHTTP3RetireCancelsDetachedSetupWithoutWaitingForHandshakeBudget(t *testing.T) {
	dialStarted := make(chan struct{})
	dialStopped := make(chan struct{})
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.Dial = func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			close(dialStarted)
			<-owner.Done()
			close(dialStopped)
			return nil, owner.Err()
		}
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH3},
			ServerName: "proxy.example",
		},
	}

	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		connection, err := manager.dial(ctx, target, "destination.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		result <- err
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("detached physical H3 setup did not start")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("logical setup error = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("logical waiter did not return at its own deadline")
	}

	retired := make(chan struct{})
	go func() {
		manager.retire()
		close(retired)
	}()
	select {
	case <-retired:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retire waited for the detached H3 handshake budget")
	}
	select {
	case <-dialStopped:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retire did not cancel the idle slot's physical setup")
	}
	manager.mu.Lock()
	remaining := len(manager.transports)
	manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("retired H3 transport keys = %d, want 0", remaining)
	}
}

func TestHTTP3PhysicalSetupCanFinishWhileManagerRetires(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		originalDial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			close(dialStarted)
			select {
			case <-releaseDial:
				return originalDial(ctx, address, tlsConfig, quicConfig)
			case <-owner.Done():
				return nil, owner.Err()
			}
		}
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3},
		},
	}
	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connection, err := manager.dial(ctx, target, "destination.example:443")
		result <- dialResult{connection: connection, err: err}
	}()
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("physical H3 setup did not start")
	}
	retireStarted := time.Now()
	manager.retire()
	if elapsed := time.Since(retireStarted); elapsed > 500*time.Millisecond {
		t.Fatalf("retire blocked active physical setup for %s", elapsed)
	}
	close(releaseDial)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("physical H3 setup failed across retire: %v", got.err)
		}
		defer got.connection.Close()
		assertConnectTunnelEcho(t, got.connection, "physical-setup-after-retire")
	case <-time.After(3 * time.Second):
		t.Fatal("physical H3 setup did not finish after retire")
	}
}

func TestHTTP3SharedPhysicalFailureCountsOnceForRouteHealth(t *testing.T) {
	const waiterCount = 20
	var physicalDials atomic.Int64
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var startOnce sync.Once
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.Dial = func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			physicalDials.Add(1)
			startOnce.Do(func() { close(dialStarted) })
			<-releaseDial
			return nil, context.DeadlineExceeded
		}
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH3},
			ServerName: "proxy.example",
		},
	}
	rule := &config.Rule{
		Name:   "shared-h3-failure",
		Listen: "127.0.0.1:1080",
		Mode:   config.ModeBoost,
		Targets: []*config.Target{
			target,
		},
	}
	registry := newRouteHealthRegistry()
	metricRules := []*config.Rule{rule}
	processMetrics.registerRules(metricRules)
	defer processMetrics.unregisterRules(metricRules)
	handshakeKey := connectProxyAttemptMetricKey{
		rule: rule.Name, target: target.Address, protocol: config.ConnectProxyH3, outcome: connectProxyAttemptTimeout,
	}
	beforeHandshakes := processMetrics.snapshot().connectProxyHandshakes[handshakeKey]
	type result struct {
		err error
	}
	results := make(chan result, waiterCount)
	start := make(chan struct{})
	for index := 0; index < waiterCount; index++ {
		go func() {
			<-start
			attempt, err := registry.begin(rule, target.Address, time.Now())
			if err != nil {
				results <- result{err: err}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			ctx = withConnectProxyRuleName(ctx, rule.Name)
			connection, dialErr := manager.dial(ctx, target, "destination.example:443")
			cancel()
			if connection != nil {
				_ = connection.Close()
			}
			routeObserve(attempt, time.Millisecond, connectProxyRouteObservationError(dialErr), time.Now())
			results <- result{err: dialErr}
		}()
	}
	close(start)
	<-dialStarted
	waitForHTTP3ActiveSlots(t, manager, http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}, waiterCount)

	for index := 0; index < waiterCount; index++ {
		outcome := <-results
		if !errors.Is(outcome.err, context.DeadlineExceeded) {
			t.Fatalf("waiter %d error = %v, want deadline exceeded", index, outcome.err)
		}
	}
	close(releaseDial)
	if got := physicalDials.Load(); got != 1 {
		t.Fatalf("physical H3 dials = %d, want 1", got)
	}
	metricDeadline := time.Now().Add(time.Second)
	for time.Now().Before(metricDeadline) && processMetrics.snapshot().connectProxyHandshakes[handshakeKey]-beforeHandshakes != 1 {
		time.Sleep(time.Millisecond)
	}
	if got := processMetrics.snapshot().connectProxyHandshakes[handshakeKey] - beforeHandshakes; got != 1 {
		t.Fatalf("physical H3 handshake metric delta = %d, want 1", got)
	}
	snapshot := registry.snapshot(rule, target.Address, time.Now())
	if snapshot.ConsecutiveFailures != 1 || snapshot.CircuitOpen {
		t.Fatalf("route snapshot after shared failure = %+v, want one failure and closed circuit", snapshot)
	}
}

func TestRouteFailureGroupRequiresThreeIndependentPhysicalFailures(t *testing.T) {
	rule := &config.Rule{Name: "grouped-route", Listen: "127.0.0.1:1080", Mode: config.ModeBoost}
	registry := newRouteHealthRegistry()
	now := time.Now()
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := registry.begin(rule, "proxy.example:443", now.Add(time.Duration(index)*time.Second))
		if err != nil {
			t.Fatalf("begin physical failure %d: %v", index+1, err)
		}
		setupErr := &http3SetupError{cause: context.DeadlineExceeded, group: newRouteFailureGroup()}
		routeObserve(attempt, time.Second, connectProxyRouteObservationError(setupErr), now.Add(time.Duration(index)*time.Second))
		snapshot := registry.snapshot(rule, "proxy.example:443", now.Add(time.Duration(index)*time.Second))
		if got := snapshot.ConsecutiveFailures; got != index+1 {
			t.Fatalf("failures after physical setup %d = %d, want %d", index+1, got, index+1)
		}
		if snapshot.CircuitOpen != (index+1 == routeFailureThreshold) {
			t.Fatalf("circuit after physical setup %d = %t", index+1, snapshot.CircuitOpen)
		}
	}
}

func TestConnectProxyCompositeFailureGroupsConservatively(t *testing.T) {
	group := newRouteFailureGroup()
	shared := &http3SetupError{cause: context.DeadlineExceeded, group: group}
	grouped := connectProxyRouteObservationError(errors.Join(
		shared,
		errConnectProxyProtocolUnavailable,
	))
	if got := routeObservationFailureGroup(grouped); got != group {
		t.Fatalf("shared H3 plus neutral unavailable group = %p, want %p", got, group)
	}

	independent := connectProxyRouteObservationError(errors.Join(
		shared,
		errors.New("independent H2 transport failure"),
	))
	if got := routeObservationFailureGroup(independent); got != nil {
		t.Fatalf("shared H3 plus independent H2 failure unexpectedly grouped: %p", got)
	}

	reachable := connectProxyRouteObservationError(errors.Join(
		shared,
		&connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: http.StatusServiceUnavailable},
	))
	if !errors.Is(reachable, errRouteReachable) {
		t.Fatalf("shared H3 plus final 503 = %v, want route reachable", reachable)
	}
}

func TestRouteFailureGroupClaimIsScopedByRegistryAndRoute(t *testing.T) {
	group := newRouteFailureGroup()
	observation := &routeFailureObservation{cause: context.DeadlineExceeded, group: group}
	now := time.Now()
	for index := 0; index < 2; index++ {
		registry := newRouteHealthRegistry()
		rule := &config.Rule{Name: "same-rule", Listen: "127.0.0.1:1080", Mode: config.ModeBoost}
		attempt, err := registry.begin(rule, "proxy.example:443", now)
		if err != nil {
			t.Fatalf("registry %d begin: %v", index, err)
		}
		routeObserve(attempt, time.Second, observation, now)
		if got := registry.snapshot(rule, "proxy.example:443", now).ConsecutiveFailures; got != 1 {
			t.Fatalf("registry %d failures = %d, want 1", index, got)
		}
	}
}

func TestRouteFailureGroupCanceledWaiterDoesNotClaim(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := &config.Rule{Name: "canceled-group", Listen: "127.0.0.1:1080", Mode: config.ModeBoost}
	group := newRouteFailureGroup()
	now := time.Now()

	canceled, err := registry.begin(rule, "proxy.example:443", now)
	if err != nil {
		t.Fatalf("begin canceled waiter: %v", err)
	}
	routeObserve(canceled, time.Millisecond, &routeFailureObservation{cause: context.Canceled, group: group}, now)

	reporter, err := registry.begin(rule, "proxy.example:443", now.Add(time.Millisecond))
	if err != nil {
		t.Fatalf("begin reporting waiter: %v", err)
	}
	routeObserve(reporter, time.Millisecond, &routeFailureObservation{cause: context.DeadlineExceeded, group: group}, now.Add(time.Millisecond))
	if got := registry.snapshot(rule, "proxy.example:443", now).ConsecutiveFailures; got != 1 {
		t.Fatalf("failures after canceled and reporting waiters = %d, want 1", got)
	}
}

func TestRouteFailureGroupDuplicateHalfOpenReleasesProbe(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := &config.Rule{Name: "half-open-group", Listen: "127.0.0.1:1080", Mode: config.ModeBoost}
	address := "proxy.example:443"
	group := newRouteFailureGroup()
	now := time.Now()

	first, err := registry.begin(rule, address, now)
	if err != nil {
		t.Fatalf("begin grouped failure: %v", err)
	}
	routeObserve(first, time.Millisecond, &routeFailureObservation{cause: context.DeadlineExceeded, group: group}, now)
	for index := 1; index < routeFailureThreshold; index++ {
		attempt, beginErr := registry.begin(rule, address, now.Add(time.Duration(index)*time.Millisecond))
		if beginErr != nil {
			t.Fatalf("begin independent failure %d: %v", index, beginErr)
		}
		routeObserve(attempt, time.Millisecond, errors.New("independent setup failure"), now.Add(time.Duration(index)*time.Millisecond))
	}
	opened := registry.snapshot(rule, address, now)
	if !opened.CircuitOpen {
		t.Fatal("route did not open before half-open duplicate test")
	}

	probeTime := opened.OpenUntil
	probe, err := registry.begin(rule, address, probeTime)
	if err != nil {
		t.Fatalf("begin half-open duplicate: %v", err)
	}
	routeObserve(probe, time.Millisecond, &routeFailureObservation{cause: context.DeadlineExceeded, group: group}, probeTime)
	afterDuplicate := registry.snapshot(rule, address, probeTime)
	if !afterDuplicate.CircuitOpen || afterDuplicate.HalfOpen || afterDuplicate.ConsecutiveFailures != routeFailureThreshold {
		t.Fatalf("route after duplicate half-open = %+v", afterDuplicate)
	}

	replacement, err := registry.begin(rule, address, probeTime)
	if err != nil {
		t.Fatalf("duplicate half-open did not release probe ownership: %v", err)
	}
	routeObserve(replacement, 0, context.Canceled, probeTime)
}

func waitForHTTP3ActiveSlots(
	t *testing.T,
	manager *http3ConnectManager,
	key http3ConnectTransportKey,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		active := 0
		for _, slot := range manager.transports[key] {
			if slot != nil {
				active += slot.active
			}
		}
		manager.mu.Unlock()
		if active == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("HTTP/3 active slots did not reach %d", want)
}
