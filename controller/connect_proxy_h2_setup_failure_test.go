package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
)

// GetConn is invoked while the underlying pool lock is held, immediately
// before joining/starting the physical dial. This barrier makes a concurrent
// failure deterministic without sleeps or changes to production pool state.
type http2SetupFailureTestPool struct {
	pool   *http2ConnectConnPool
	joined chan struct{}
}

func (pool *http2SetupFailureTestPool) GetClientConn(request *http.Request, address string) (*xhttp2.ClientConn, error) {
	ctx := httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GetConn: func(string) {
			select {
			case pool.joined <- struct{}{}:
			default:
			}
		},
	})
	return pool.pool.GetClientConn(request.WithContext(ctx), address)
}

func (pool *http2SetupFailureTestPool) MarkDead(connection *xhttp2.ClientConn) {
	pool.pool.MarkDead(connection)
}

func newHTTP2SetupFailureTestRuntime(t *testing.T, factory func(http2ConnectTransportKey) *xhttp2.Transport, joined chan struct{}) *routingRuntime {
	t.Helper()
	runtime := newRoutingRuntime()
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := factory(key)
		pool := newHTTP2ConnectConnPool(transport)
		transport.ConnPool = &http2SetupFailureTestPool{pool: pool, joined: joined}
		return transport
	})
	runtime.connectProxy.h2 = manager
	runtime.connectProxy.dialers[config.ConnectProxyH2] = manager.dial
	t.Cleanup(func() {
		runtime.stopBackground()
		runtime.connectProxy.close()
	})
	return runtime
}

func http2SetupFailureTestRule(name, address string, mixed bool) *config.Rule {
	protocols := []string{config.ConnectProxyH2}
	if mixed {
		protocols = []string{config.ConnectProxyH3, config.ConnectProxyH2}
	}
	return &config.Rule{
		Name: name, Listen: "127.0.0.1:1099", Protocol: config.ProtocolHTTP,
		Mode: config.ModeBoost, Timeout: 3000,
		Targets: []*config.Target{{Address: address, ConnectProxy: &config.ConnectProxyConfig{
			Protocols: protocols, ServerName: "setup-failure.example",
		}}},
	}
}

func dialHTTP2SetupFailureTestRoute(ctx context.Context, runtime *routingRuntime, rule *config.Rule) error {
	connection, _, err := runtime.outboundDialRoute(
		withConnectDestination(ctx, "destination.example:443"), rule, rule.Targets[0].Address,
	)
	if connection != nil {
		_ = connection.Close()
	}
	return err
}

func awaitHTTP2SetupFailureTestWaiters(t *testing.T, joined <-chan struct{}, count int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for index := 0; index < count; index++ {
		select {
		case <-joined:
		case <-deadline.C:
			t.Fatalf("only %d/%d waiters joined the physical setup", index, count)
		}
	}
}

func awaitHTTP2SetupFailureTestResults(t *testing.T, results <-chan error, count int, canceled bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for index := 0; index < count; index++ {
		select {
		case err := <-results:
			if err == nil || (canceled && !errors.Is(err, context.Canceled)) {
				t.Fatalf("waiter %d error = %v, canceled=%v", index, err, canceled)
			}
		case <-deadline.C:
			t.Fatalf("only %d/%d waiters completed", index, count)
		}
	}
}

func TestHTTP2SharedTLSSetupFailureCountsOncePerRoute(t *testing.T) {
	for _, test := range []struct {
		name      string
		mixed     bool
		ruleCount int
	}{
		{name: "h2_only", ruleCount: 1},
		{name: "mixed_h3_cooldown", mixed: true, ruleCount: 1},
		{name: "shared_endpoint_two_rules", ruleCount: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			const waiterCount = 6
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			type acceptedResult struct {
				connection net.Conn
				err        error
			}
			accepted := make(chan acceptedResult, 1)
			go func() {
				connection, err := listener.Accept()
				accepted <- acceptedResult{connection: connection, err: err}
			}()
			joined := make(chan struct{}, waiterCount*4)
			var physicalDials atomic.Int32
			runtime := newHTTP2SetupFailureTestRuntime(t, func(key http2ConnectTransportKey) *xhttp2.Transport {
				transport := newHTTP2ConnectTransport(key)
				dial := transport.DialTLSContext
				transport.DialTLSContext = func(ctx context.Context, network, address string, configuration *tls.Config) (net.Conn, error) {
					physicalDials.Add(1)
					return dial(ctx, network, address, configuration)
				}
				return transport
			}, joined)
			address := listener.Addr().String()
			rules := make([]*config.Rule, test.ruleCount)
			for index := range rules {
				rules[index] = http2SetupFailureTestRule(fmt.Sprintf("shared-h2-%d", index), address, test.mixed)
			}
			if test.mixed {
				key := http3ConnectTransportKey{address: address, serverName: rules[0].Targets[0].ConnectProxy.ServerName}
				runtime.connectProxy.h3Fallback[key] = &http3FallbackState{
					epoch: 1, failures: 1, retryAt: time.Now().Add(time.Minute),
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancel)
			results := make(chan error, waiterCount)
			for index := 0; index < waiterCount; index++ {
				go func(rule *config.Rule) {
					results <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule)
				}(rules[index%len(rules)])
			}
			// Keep the real TCP/TLS session open until all route attempts share it.
			awaitHTTP2SetupFailureTestWaiters(t, joined, waiterCount)
			var peer net.Conn
			select {
			case result := <-accepted:
				if result.err != nil {
					t.Fatal(result.err)
				}
				peer = result.connection
			case <-ctx.Done():
				t.Fatal("physical TCP connection was not accepted")
			}
			t.Cleanup(func() { _ = peer.Close() })
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			var first [1]byte
			if _, err := io.ReadFull(peer, first[:]); err != nil {
				t.Fatalf("read ClientHello: %v", err)
			}
			_ = peer.Close() // One real TLS setup failure, before ServerHello.
			awaitHTTP2SetupFailureTestResults(t, results, waiterCount, false)
			if got := physicalDials.Load(); got != 1 {
				t.Fatalf("physical dials = %d, want 1", got)
			}
			for _, rule := range rules {
				snapshot := runtime.routes.snapshot(rule, address, time.Now())
				if snapshot.ConsecutiveFailures != 1 || snapshot.CircuitOpen {
					t.Fatalf("rule %s after one shared TLS failure = %+v", rule.Name, snapshot)
				}
			}
		})
	}
}

func TestHTTP2IndependentSetupFailuresTripCircuit(t *testing.T) {
	joined := make(chan struct{}, 16)
	var physicalDials atomic.Int32
	runtime := newHTTP2SetupFailureTestRuntime(t, func(http2ConnectTransportKey) *xhttp2.Transport {
		return &xhttp2.Transport{DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			physicalDials.Add(1)
			return nil, io.ErrUnexpectedEOF
		}}
	}, joined)
	rule := http2SetupFailureTestRule("independent-h2", "setup-failure.example:443", false)
	for index := 1; index <= routeFailureThreshold; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := dialHTTP2SetupFailureTestRoute(ctx, runtime, rule)
		cancel()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("setup error = %v, want original cause", err)
		}
		snapshot := runtime.routes.snapshot(rule, rule.Targets[0].Address, time.Now())
		if snapshot.ConsecutiveFailures != index || snapshot.CircuitOpen != (index == routeFailureThreshold) {
			t.Fatalf("independent failure %d = %+v", index, snapshot)
		}
	}
	if got := physicalDials.Load(); got != routeFailureThreshold {
		t.Fatalf("physical dials = %d, want %d", got, routeFailureThreshold)
	}
}

func TestHTTP2SharedSetupParentCancellationIsNeutral(t *testing.T) {
	const waiterCount = 6
	joined := make(chan struct{}, waiterCount*4)
	runtime := newHTTP2SetupFailureTestRuntime(t, func(http2ConnectTransportKey) *xhttp2.Transport {
		return &xhttp2.Transport{DialTLSContext: func(ctx context.Context, _ string, _ string, _ *tls.Config) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
	}, joined)
	rule := http2SetupFailureTestRule("canceled-h2", "setup-failure.example:443", false)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	results := make(chan error, waiterCount)
	for index := 0; index < waiterCount; index++ {
		go func() { results <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }()
	}
	awaitHTTP2SetupFailureTestWaiters(t, joined, waiterCount)
	cancel()
	awaitHTTP2SetupFailureTestResults(t, results, waiterCount, true)
	snapshot := runtime.routes.snapshot(rule, rule.Targets[0].Address, time.Now())
	if snapshot.ConsecutiveFailures != 0 || snapshot.CircuitOpen {
		t.Fatalf("parent cancellation = %+v, want neutral", snapshot)
	}
}

func TestHTTP2ConnectStatusFailuresAreNotSharedSetupFailures(t *testing.T) {
	var physicalConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusProxyAuthRequired)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			physicalConnections.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	runtime := newRoutingRuntime()
	installHTTP2ConnectTestManager(runtime, server)
	t.Cleanup(func() {
		runtime.stopBackground()
		runtime.connectProxy.close()
	})
	target := http2ConnectTestTarget(server, "user", "password")
	rule := http2SetupFailureTestRule("auth-h2", target.Address, false)
	rule.Targets = []*config.Target{target}
	for index := 1; index <= routeFailureThreshold; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := dialHTTP2SetupFailureTestRoute(ctx, runtime, rule)
		cancel()
		var status *connectProxyStatusError
		if !errors.As(err, &status) || status.statusCode != http.StatusProxyAuthRequired {
			t.Fatalf("CONNECT error = %v, want HTTP 407", err)
		}
		if group, grouped := connectProxyExclusiveSetupFailureGroup(err); grouped || group != nil {
			t.Fatal("a stream-level HTTP response was grouped as a physical setup failure")
		}
		snapshot := runtime.routes.snapshot(rule, target.Address, time.Now())
		if snapshot.ConsecutiveFailures != index || snapshot.CircuitOpen != (index == routeFailureThreshold) {
			t.Fatalf("HTTP 407 failure %d = %+v", index, snapshot)
		}
	}
	if got := physicalConnections.Load(); got != 1 {
		t.Fatalf("physical H2 connections = %d, want one reused connection", got)
	}
}

func TestConnectProxySharedSetupCompositePreservesIndependentFailures(t *testing.T) {
	group := newRouteFailureGroup()
	h2 := &http2SetupError{cause: io.ErrUnexpectedEOF, group: group}
	h3 := &http3SetupError{cause: context.DeadlineExceeded, group: newRouteFailureGroup()}
	for _, test := range []struct {
		name string
		err  error
		want *routeFailureGroup
	}{
		{name: "plain_h2", err: h2, want: group},
		{name: "wrapped_h2", err: fmt.Errorf("CONNECT: %w", h2), want: group},
		{name: "same_physical_failure", err: errors.Join(h2, h2), want: group},
		{name: "unavailable_then_h2", err: errors.Join(errConnectProxyProtocolUnavailable, h2), want: group},
		{name: "cooldown_then_h2", err: errors.Join(errConnectProxyProtocolCoolingDown, h2), want: group},
		{name: "independent_h2", err: errors.Join(h2, &http2SetupError{cause: io.EOF, group: newRouteFailureGroup()})},
		{name: "independent_h3", err: errors.Join(h3, h2)},
		{name: "independent_transport", err: errors.Join(h2, io.EOF)},
		{name: "independent_stream", err: errors.Join(h2, errors.New("HTTP/2 CONNECT stream reset"))},
		{name: "independent_auth", err: errors.Join(h2, &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: http.StatusProxyAuthRequired})},
	} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped_%v", test.name, wrapped), func(t *testing.T) {
				err := test.err
				if wrapped {
					err = fmt.Errorf("target attempt: %w", err)
				}
				got, grouped := connectProxyExclusiveSetupFailureGroup(err)
				if got != test.want || grouped != (test.want != nil) {
					t.Fatalf("failure group = %p/%v, want %p", got, grouped, test.want)
				}
				if got := routeObservationFailureGroup(connectProxyRouteObservationError(err)); got != test.want {
					t.Fatalf("route observation group = %p, want %p", got, test.want)
				}
			})
		}
	}
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		err := errors.Join(h2, &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: status})
		if !errors.Is(connectProxyRouteObservationError(err), errRouteReachable) {
			t.Fatalf("final HTTP %d no longer proves route reachability", status)
		}
	}
}
