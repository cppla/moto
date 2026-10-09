package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "moto/internal/browserhttp2"
)

// The peer consumes a complete, real ClientHello but never sends ServerHello.
// Receiving that hello and GetConn events are barriers, not timing assumptions.
func newHTTP2SetupDeadlineTestBlackhole(t *testing.T) (string, func() net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 16)
	acceptStopped := make(chan error, 1)
	go func() {
		for {
			peer, err := listener.Accept()
			if err != nil {
				acceptStopped <- err
				return
			}
			accepted <- peer
		}
	}()
	return listener.Addr().String(), func() net.Conn {
		t.Helper()
		var peer net.Conn
		select {
		case peer = <-accepted:
		case err := <-acceptStopped:
			t.Fatalf("accept physical TLS setup: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("physical TLS setup never reached the loopback peer")
		}
		t.Cleanup(func() { _ = peer.Close() })
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := readTLSClientHello(peer, 64<<10); err != nil {
			t.Fatalf("read complete physical ClientHello: %v", err)
		}
		_ = peer.SetReadDeadline(time.Time{})
		return peer
	}
}

func TestHTTP2SharedSetupWaiterDeadlineCountsOncePerRoute(t *testing.T) {
	for _, test := range []struct {
		name      string
		mixed     bool
		ruleCount int
		canceled  bool
	}{
		{name: "h2_only", ruleCount: 1},
		{name: "mixed_h3_cooldown", mixed: true, ruleCount: 1},
		{name: "shared_endpoint_two_rules", ruleCount: 2},
		{name: "parent_cancellation", ruleCount: 1, canceled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const waiterCount = 6
			address, awaitHello := newHTTP2SetupDeadlineTestBlackhole(t)
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
			rules := make([]*config.Rule, test.ruleCount)
			for index := range rules {
				rules[index] = http2SetupFailureTestRule(fmt.Sprintf("deadline-h2-%d", index), address, test.mixed)
			}
			if test.mixed {
				key := http3ConnectTransportKey{address: address, serverName: rules[0].Targets[0].ConnectProxy.ServerName}
				runtime.connectProxy.h3Fallback[key] = &http3FallbackState{
					epoch: 1, failures: 1, retryAt: time.Now().Add(time.Minute),
				}
			}

			// The long-lived keeper owns the socket, so a short request deadline
			// cannot close it or be mistaken for a separate physical setup.
			keeperCtx, cancelKeeper := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancelKeeper)
			keeperDone := make(chan error, 1)
			go func() {
				connection, err := runtime.connectProxy.h2.dial(keeperCtx, rules[0].Targets[0], "keeper.example:443")
				if connection != nil {
					_ = connection.Close()
				}
				keeperDone <- err
			}()
			awaitHTTP2SetupFailureTestWaiters(t, joined, 1)
			awaitHello()

			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			if test.canceled {
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
			}
			t.Cleanup(cancel)
			results := make(chan error, waiterCount)
			for index := 0; index < waiterCount; index++ {
				go func(rule *config.Rule) { results <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }(rules[index%len(rules)])
			}
			awaitHTTP2SetupFailureTestWaiters(t, joined, waiterCount)
			if test.canceled {
				cancel()
			}
			var shared *routeFailureGroup
			for index := 0; index < waiterCount; index++ {
				select {
				case err := <-results:
					cause := context.DeadlineExceeded
					if test.canceled {
						cause = context.Canceled
					}
					if !errors.Is(err, cause) {
						t.Fatalf("waiter %d error = %v, want %v", index, err, cause)
					}
					if !test.canceled {
						group, grouped := connectProxyExclusiveSetupFailureGroup(err)
						if !grouped || group == nil {
							t.Errorf("waiter %d lost its shared physical setup identity: %v", index, err)
						} else if shared != nil && shared != group {
							t.Errorf("waiter %d group = %p, want the same physical group %p", index, group, shared)
						} else {
							shared = group
						}
					}
				case <-time.After(3 * time.Second):
					t.Fatal("short-deadline waiter did not return promptly")
				}
			}
			if got := physicalDials.Load(); got != 1 {
				t.Fatalf("physical dials = %d, want one shared setup", got)
			}
			select {
			case err := <-keeperDone:
				t.Fatalf("short waiters interrupted the keeper's physical setup: %v", err)
			default:
			}
			for _, rule := range rules {
				wantFailures := 1
				if test.canceled {
					wantFailures = 0
				}
				snapshot := runtime.routes.snapshot(rule, address, time.Now())
				if snapshot.ConsecutiveFailures != wantFailures || snapshot.CircuitOpen {
					t.Errorf("rule %s after one shared setup = %+v, want %d failures and closed circuit", rule.Name, snapshot, wantFailures)
				}
			}
			cancelKeeper()
			select {
			case <-keeperDone:
			case <-time.After(3 * time.Second):
				t.Fatal("physical keeper did not settle after its own cancellation")
			}
		})
	}
}

func TestHTTP2IndependentPhysicalSetupDeadlinesTripCircuit(t *testing.T) {
	address, awaitHello := newHTTP2SetupDeadlineTestBlackhole(t)
	joined := make(chan struct{}, 16)
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
	rule := http2SetupFailureTestRule("independent-physical-deadlines", address, false)
	var previous *routeFailureGroup
	for index := 1; index <= routeFailureThreshold; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		result := make(chan error, 1)
		go func() { result <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }()
		awaitHTTP2SetupFailureTestWaiters(t, joined, 1)
		awaitHello()
		runtime.connectProxy.h2.mu.Lock()
		key := http2ConnectTransportKey{address: address, serverName: rule.Targets[0].ConnectProxy.ServerName}
		pool := runtime.connectProxy.h2.transports[key].ConnPool.(*http2SetupFailureTestPool).pool
		runtime.connectProxy.h2.mu.Unlock()
		pool.mu.Lock()
		call := pool.dialing[address]
		pool.mu.Unlock()
		if call == nil {
			t.Fatal("physical setup completed before the controlled blackhole deadline")
		}
		var err error
		select {
		case err = <-result:
		case <-time.After(3 * time.Second):
			t.Fatal("independent physical deadline did not finish")
		}
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("physical setup %d error = %v, want deadline exceeded", index, err)
		}
		group, grouped := connectProxyExclusiveSetupFailureGroup(err)
		if !grouped || group == nil || group == previous {
			t.Errorf("physical setup %d group = %p/%t, previous = %p; want a distinct group", index, group, grouped, previous)
		}
		previous = group
		// Wait for deletion of this physical call before starting a new one.
		select {
		case <-call.done:
		case <-time.After(3 * time.Second):
			t.Fatal("expired physical setup did not release the pool slot")
		}
		snapshot := runtime.routes.snapshot(rule, address, time.Now())
		if snapshot.ConsecutiveFailures != index || snapshot.CircuitOpen != (index == routeFailureThreshold) {
			t.Fatalf("independent physical deadline %d = %+v", index, snapshot)
		}
	}
	if got := physicalDials.Load(); got != routeFailureThreshold {
		t.Fatalf("physical dials = %d, want %d independent setups", got, routeFailureThreshold)
	}
}

func TestHTTP2SharedSetupCommonDeadlineRetainsPhysicalIdentity(t *testing.T) {
	const waiterCount = 6
	address, awaitHello := newHTTP2SetupDeadlineTestBlackhole(t)
	joined := make(chan struct{}, waiterCount*4)
	settleDial := make(chan struct{})
	var settleOnce sync.Once
	settle := func() { settleOnce.Do(func() { close(settleDial) }) }
	t.Cleanup(settle)
	var physicalDials atomic.Int32
	runtime := newHTTP2SetupFailureTestRuntime(t, func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		dial := transport.DialTLSContext
		transport.DialTLSContext = func(ctx context.Context, network, address string, configuration *tls.Config) (net.Conn, error) {
			physicalDials.Add(1)
			connection, err := dial(ctx, network, address, configuration)
			// Publish the initiating request's cancellation only after all
			// callers have observed their common deadline. This fixes the
			// cohort to one physical attempt without any keeper request.
			<-settleDial
			return connection, err
		}
		return transport
	}, joined)
	rule := http2SetupFailureTestRule("common-physical-deadline", address, false)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	t.Cleanup(cancel)
	results := make(chan error, waiterCount)
	for index := 0; index < waiterCount; index++ {
		go func() { results <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }()
	}
	awaitHTTP2SetupFailureTestWaiters(t, joined, waiterCount)
	awaitHello()
	var shared *routeFailureGroup
	for index := 0; index < waiterCount; index++ {
		select {
		case err := <-results:
			group, grouped := connectProxyExclusiveSetupFailureGroup(err)
			if !errors.Is(err, context.DeadlineExceeded) || !grouped || group == nil {
				t.Fatalf("common deadline waiter %d = %v, group=%p/%t", index, err, group, grouped)
			}
			if shared != nil && group != shared {
				t.Fatalf("one physical setup produced distinct groups %p and %p", shared, group)
			}
			shared = group
		case <-time.After(3 * time.Second):
			t.Fatal("common deadline did not release every caller")
		}
	}
	settle()
	if got := physicalDials.Load(); got != 1 {
		t.Fatalf("physical dials = %d, want one synchronized setup", got)
	}
	snapshot := runtime.routes.snapshot(rule, address, time.Now())
	if snapshot.ConsecutiveFailures != 1 || snapshot.CircuitOpen {
		t.Fatalf("common deadline duplicated a shared setup failure: %+v", snapshot)
	}
}

func TestHTTP2SharedSetupCanceledRetryRetainsDeadlineIdentity(t *testing.T) {
	joined := make(chan struct{}, 2)
	settleDial := make(chan struct{})
	var settleOnce sync.Once
	settle := func() { settleOnce.Do(func() { close(settleDial) }) }
	t.Cleanup(settle)
	transport := &xhttp2.Transport{DialTLSContext: func(ctx context.Context, _ string, _ string, _ *tls.Config) (net.Conn, error) {
		<-settleDial
		return nil, ctx.Err()
	}}
	pool := newHTTP2ConnectConnPool(transport)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	t.Cleanup(cancelFirst)
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	t.Cleanup(cancelSecond)
	secondWaiter := &http2SetupWaiter{}
	secondCtx = withHTTP2SetupWaiter(secondCtx, secondWaiter)
	trace := func(ctx context.Context) context.Context {
		return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) { joined <- struct{}{} }})
	}
	first, _ := http.NewRequestWithContext(trace(firstCtx), http.MethodConnect, "https://retry.example:443", nil)
	second, _ := http.NewRequestWithContext(trace(secondCtx), http.MethodConnect, "https://retry.example:443", nil)
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := pool.GetClientConn(first, first.URL.Host); firstDone <- err }()
	awaitHTTP2SetupFailureTestWaiters(t, joined, 1)
	go func() { _, err := pool.GetClientConn(second, second.URL.Host); secondDone <- err }()
	awaitHTTP2SetupFailureTestWaiters(t, joined, 1)
	pool.mu.Lock()
	call := pool.dialing[first.URL.Host]
	pool.mu.Unlock()
	if call == nil {
		t.Fatal("shared canceled call was not registered")
	}
	cancelFirst()
	cancelSecond()
	settle()
	awaitHTTP2SetupFailureTestResults(t, firstDone, 1, true)
	awaitHTTP2SetupFailureTestResults(t, secondDone, 1, true)
	// The pool normalizes the detached stream to context.Canceled. The caller
	// may actually have expired; do not lose its last shared physical attempt
	// between deciding to retry and checking the now-canceled stream context.
	err := http2SetupCallerError(secondWaiter, nil, context.DeadlineExceeded)
	group, grouped := connectProxyExclusiveSetupFailureGroup(err)
	if !errors.Is(err, context.DeadlineExceeded) || !grouped || group != call.group {
		t.Fatalf("canceled shared retry lost deadline identity: %v, group=%p/%t, want %p", err, group, grouped, call.group)
	}
}

func TestHTTP2SetupCallerErrorPreservesOnlyPhysicalFailures(t *testing.T) {
	newCall := func(err error, settled bool) *http2ConnectDialCall {
		call := &http2ConnectDialCall{done: make(chan struct{}), group: newRouteFailureGroup(), err: err}
		if settled {
			close(call.done)
		}
		return call
	}
	pending := newCall(nil, false)
	failed := newCall(io.ErrUnexpectedEOF, true)
	success := newCall(nil, true)
	for _, test := range []struct {
		name     string
		call     *http2ConnectDialCall
		previous error
		caller   error
		want     *routeFailureGroup
	}{
		{name: "pending_setup", call: pending, caller: context.DeadlineExceeded, want: pending.group},
		{name: "failed_setup", call: failed, caller: context.DeadlineExceeded, want: failed.group},
		{name: "successful_setup", call: success, caller: context.DeadlineExceeded},
		{name: "no_setup", caller: context.DeadlineExceeded},
		{name: "ordinary_cancel", call: pending, caller: context.Canceled},
		{name: "previous_physical_error", previous: fmt.Errorf("CONNECT: %w", &http2SetupError{cause: context.Canceled, group: failed.group}), caller: context.DeadlineExceeded, want: failed.group},
	} {
		t.Run(test.name, func(t *testing.T) {
			waiter := &http2SetupWaiter{}
			waiter.waitingOn(test.call)
			err := http2SetupCallerError(waiter, test.previous, test.caller)
			group, grouped := connectProxyExclusiveSetupFailureGroup(err)
			if !errors.Is(err, test.caller) || group != test.want || grouped != (test.want != nil) {
				t.Fatalf("caller error = %v, group=%p/%t; want cause=%v group=%p", err, group, grouped, test.caller, test.want)
			}
		})
	}
	// Finishing an old call cannot erase the newer replacement's identity.
	waiter := &http2SetupWaiter{}
	waiter.waitingOn(failed)
	waiter.waitingOn(pending)
	waiter.finished(failed)
	if got := waiter.failureGroup(); got != pending.group {
		t.Fatalf("old completion erased a replacement setup: group=%p, want %p", got, pending.group)
	}
	waiter.finished(pending)
	if got := waiter.failureGroup(); got != nil {
		t.Fatalf("completed reservation retained physical setup group %p", got)
	}
}

func TestHTTP2ConnectResponseDeadlinesRemainIndependentFailures(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse_%t", reuse), func(t *testing.T) {
			const waiterCount = 6
			started := make(chan struct{}, waiterCount)
			var physicalConnections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Host == "warm.example:443" {
					writer.WriteHeader(http.StatusOK)
					writer.(http.Flusher).Flush()
					_, _ = io.Copy(io.Discard, request.Body)
					return
				}
				started <- struct{}{}
				<-request.Context().Done()
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
			t.Cleanup(func() { runtime.stopBackground(); runtime.connectProxy.close() })
			target := http2ConnectTestTarget(server, "", "")
			rule := http2SetupFailureTestRule("independent-connect-deadlines", target.Address, false)
			rule.Targets = []*config.Target{target}
			if reuse {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				connection, err := runtime.connectProxy.h2.dial(ctx, target, "warm.example:443")
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = connection.Close() })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			t.Cleanup(cancel)
			results := make(chan error, waiterCount)
			for index := 0; index < waiterCount; index++ {
				go func() { results <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }()
			}
			awaitHTTP2SetupFailureTestWaiters(t, started, waiterCount)
			for index := 0; index < waiterCount; index++ {
				select {
				case err := <-results:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("CONNECT response %d error = %v, want deadline exceeded", index, err)
					}
					if group, grouped := connectProxyExclusiveSetupFailureGroup(err); grouped || group != nil {
						t.Fatalf("independent CONNECT response deadline was merged into setup group %p", group)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("CONNECT response deadline did not return")
				}
			}
			if got := physicalConnections.Load(); got != 1 {
				t.Fatalf("physical TLS connections = %d, want a single shared healthy transport", got)
			}
			snapshot := runtime.routes.snapshot(rule, target.Address, time.Now())
			if snapshot.ConsecutiveFailures != routeFailureThreshold || !snapshot.CircuitOpen {
				t.Fatalf("independent CONNECT response failures were incorrectly deduplicated: %+v", snapshot)
			}
		})
	}
}

func TestHTTP2ConnectResponseDeadlineDoesNotJoinAnotherPhysicalSetup(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
	}))
	server.EnableHTTP2 = true
	if err := xhttp2.ConfigureServer(server.Config, &xhttp2.Server{MaxConcurrentStreams: 1}); err != nil {
		t.Fatal(err)
	}
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	blackhole, awaitHello := newHTTP2SetupDeadlineTestBlackhole(t)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var physicalDials atomic.Int32
	runtime := newRoutingRuntime()
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = roots
		dial := transport.DialTLSContext
		transport.DialTLSContext = func(ctx context.Context, network, address string, configuration *tls.Config) (net.Conn, error) {
			if physicalDials.Add(1) > 1 {
				address = blackhole
			}
			return dial(ctx, network, address, configuration)
		}
		return transport
	})
	runtime.connectProxy.h2 = manager
	runtime.connectProxy.dialers[config.ConnectProxyH2] = manager.dial
	t.Cleanup(func() { runtime.stopBackground(); runtime.connectProxy.close() })
	target := http2ConnectTestTarget(server, "", "")
	rule := http2SetupFailureTestRule("stream-not-new-setup", target.Address, false)
	rule.Targets = []*config.Target{target}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- dialHTTP2SetupFailureTestRoute(ctx, runtime, rule) }()
	awaitHTTP2SetupFailureTestWaiters(t, requestStarted, 1)
	key := http2ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.mu.Lock()
	pool := manager.transports[key].ConnPool.(*http2ConnectConnPool)
	manager.mu.Unlock()
	awaitHTTP2PoolTestCondition(t, func() bool {
		pool.mu.Lock()
		connections := append([]*xhttp2.ClientConn(nil), pool.conns[target.Address]...)
		pool.mu.Unlock()
		return len(connections) == 1 && connections[0].State().MaxConcurrentStreams == 1
	}, "the peer's stream limit before starting another physical setup")

	// The first connection has one admitted CONNECT with no response. The
	// peer's stream limit forces another request to start a second real dial.
	keeperCtx, cancelKeeper := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancelKeeper)
	keeperDone := make(chan error, 1)
	go func() {
		connection, err := manager.dial(keeperCtx, target, "capacity-keeper.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		keeperDone <- err
	}()
	awaitHello()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first CONNECT error = %v, want deadline exceeded", err)
		}
		if group, grouped := connectProxyExclusiveSetupFailureGroup(err); grouped || group != nil {
			t.Fatalf("stream response timeout incorrectly inherited the unrelated in-flight setup group %p", group)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first CONNECT response deadline did not return")
	}
	if got := physicalDials.Load(); got != 2 {
		t.Fatalf("physical dials = %d, want serving connection plus a blackholed setup", got)
	}
	cancelKeeper()
	select {
	case <-keeperDone:
	case <-time.After(3 * time.Second):
		t.Fatal("unrelated physical setup did not clean up after cancellation")
	}
	snapshot := runtime.routes.snapshot(rule, target.Address, time.Now())
	if snapshot.ConsecutiveFailures != 1 || snapshot.CircuitOpen {
		t.Fatalf("one independent stream deadline = %+v", snapshot)
	}
}
