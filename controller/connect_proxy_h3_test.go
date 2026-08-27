package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type blockingHTTP3Resolver struct {
	started chan struct{}
}

func (resolver blockingHTTP3Resolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	close(resolver.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHTTP3ConnectTunnelFullDuplexAndReuse(t *testing.T) {
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("moto:secret"))
	requests := make(chan *http.Request, 2)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(context.Background())
		if request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") != wantAuthorization {
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("banner"))
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		buffer := make([]byte, 32<<10)
		for {
			read, readErr := request.Body.Read(buffer)
			if read > 0 {
				_, _ = writer.Write(buffer[:read])
				if flusher, ok := writer.(http.Flusher); ok {
					flusher.Flush()
				}
			}
			if readErr != nil {
				return
			}
		}
	})

	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServer(t, handler)
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
			BasicAuth: &config.BasicAuthConfig{Username: "moto", Password: "secret"},
		},
	}

	for index := 0; index < 2; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		tunnel, err := manager.dial(ctx, target, "destination.example:443")
		cancel()
		if err != nil {
			t.Fatalf("dial HTTP/3 CONNECT tunnel %d: %v", index, err)
		}

		banner := make([]byte, len("banner"))
		if _, err := io.ReadFull(tunnel, banner); err != nil {
			_ = tunnel.Close()
			t.Fatalf("read server-first data %d: %v", index, err)
		}
		if string(banner) != "banner" {
			_ = tunnel.Close()
			t.Fatalf("server-first data %d = %q", index, banner)
		}

		payload := []byte("full-duplex-over-h3")
		if _, err := tunnel.Write(payload); err != nil {
			_ = tunnel.Close()
			t.Fatalf("write tunnel %d: %v", index, err)
		}
		echo := make([]byte, len(payload))
		if _, err := io.ReadFull(tunnel, echo); err != nil {
			_ = tunnel.Close()
			t.Fatalf("read tunnel %d: %v", index, err)
		}
		if string(echo) != string(payload) {
			_ = tunnel.Close()
			t.Fatalf("echo %d = %q, want %q", index, echo, payload)
		}
		if err := closeWrite(tunnel); err != nil {
			_ = tunnel.Close()
			t.Fatalf("close tunnel write side %d: %v", index, err)
		}
		if _, err := tunnel.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			_ = tunnel.Close()
			t.Fatalf("tunnel %d final read error = %v, want EOF", index, err)
		}
		if err := tunnel.Close(); err != nil {
			t.Fatalf("close tunnel %d: %v", index, err)
		}

		select {
		case request := <-requests:
			if request.ProtoMajor != 3 {
				t.Fatalf("request %d protocol = %s, want HTTP/3", index, request.Proto)
			}
			if request.Host != "destination.example:443" {
				t.Fatalf("request %d authority = %q", index, request.Host)
			}
			if request.URL.Path != "" {
				t.Fatalf("request %d CONNECT path = %q, want empty", index, request.URL.Path)
			}
		case <-time.After(time.Second):
			t.Fatalf("HTTP/3 request %d was not observed", index)
		}
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("HTTP/3 QUIC connection count = %d, want one reused connection", got)
	}
}

func TestHTTP3ConnectPoolSpreadsLongTunnelsBeforePeerStreamLimit(t *testing.T) {
	const tunnelCount = 129
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServer(t, handler)
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

	type dialResult struct {
		connection net.Conn
		err        error
	}
	results := make(chan dialResult, tunnelCount)
	for index := 0; index < tunnelCount; index++ {
		go func(index int) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			connection, err := manager.dial(ctx, target, fmt.Sprintf("destination-%d.example:443", index))
			results <- dialResult{connection: connection, err: err}
		}(index)
	}
	connections := make([]net.Conn, 0, tunnelCount)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for index := 0; index < tunnelCount; index++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("long HTTP/3 tunnel %d: %v", index, result.err)
		}
		connections = append(connections, result.connection)
	}
	if got, want := connectionCount.Load(), int64(3); got != want {
		t.Fatalf("QUIC pool connections = %d, want %d for %d active tunnels", got, want, tunnelCount)
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	connections = nil
	manager.mu.Lock()
	remainingSlots := len(manager.transports[http3ConnectTransportKey{address: endpoint}])
	manager.mu.Unlock()
	if remainingSlots != 1 {
		t.Fatalf("idle QUIC pool slots = %d, want one warm transport", remainingSlots)
	}
}

func TestHTTP3ConnectManagerRetireClosesSlotsAfterActiveTunnelsDrain(t *testing.T) {
	manager := newHTTP3ConnectManager(func(http3ConnectTransportKey, context.Context) *http3.Transport {
		return &http3.Transport{}
	})
	defer manager.close()
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}

	_, _, release, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire H3 transport: %v", err)
	}
	manager.retire()
	manager.mu.Lock()
	retainedWhileActive := len(manager.transports[key])
	manager.mu.Unlock()
	if retainedWhileActive != 1 {
		t.Fatalf("retired active H3 slots = %d, want 1", retainedWhileActive)
	}

	release()
	manager.mu.Lock()
	_, keyRetainedAfterRelease := manager.transports[key]
	manager.mu.Unlock()
	if keyRetainedAfterRelease {
		t.Fatal("drained retired H3 transport left an empty map entry")
	}
}

func TestHTTP3ActiveAndLateTunnelsSurviveManagerRetire(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		buffer := make([]byte, 32)
		for {
			read, readErr := request.Body.Read(buffer)
			if read > 0 {
				_, _ = writer.Write(buffer[:read])
				writer.(http.Flusher).Flush()
			}
			if readErr != nil {
				return
			}
		}
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
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}

	connection, err := manager.dial(context.Background(), target, "active.example:443")
	if err != nil {
		t.Fatalf("dial active H3 tunnel: %v", err)
	}
	assertConnectTunnelEcho(t, connection, "before-retire")
	manager.retire()
	assertConnectTunnelEcho(t, connection, "after-retire")
	if err := closeWrite(connection); err != nil {
		t.Fatalf("H3 CloseWrite after retire: %v", err)
	}
	manager.mu.Lock()
	activeAfterCloseWrite := manager.transports[key][0].active
	manager.mu.Unlock()
	if activeAfterCloseWrite != 1 {
		t.Fatalf("H3 active after CloseWrite = %d, want 1 until full Close", activeAfterCloseWrite)
	}
	if _, err := io.ReadAll(connection); err != nil {
		t.Fatalf("read H3 response EOF after retire: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close active H3 tunnel: %v", err)
	}
	manager.mu.Lock()
	_, retainedAfterClose := manager.transports[key]
	manager.mu.Unlock()
	if retainedAfterClose {
		t.Fatal("retired H3 transport remained after active tunnel full Close")
	}

	late, err := manager.dial(context.Background(), target, "late.example:443")
	if err != nil {
		t.Fatalf("dial H3 tunnel after manager retire: %v", err)
	}
	assertConnectTunnelEcho(t, late, "late-after-retire")
	if err := late.Close(); err != nil {
		t.Fatalf("close late H3 tunnel: %v", err)
	}
	manager.mu.Lock()
	_, retainedLate := manager.transports[key]
	manager.mu.Unlock()
	if retainedLate {
		t.Fatal("late H3 transport remained idle in retired manager")
	}
}

func TestHTTP3SetupCanFinishWhileManagerRetires(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		<-releaseResponse
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
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
	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connection, err := manager.dial(ctx, target, "setup.example:443")
		result <- dialResult{connection: connection, err: err}
	}()
	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		close(releaseResponse)
		t.Fatal("H3 CONNECT setup did not reach proxy")
	}
	manager.retire()
	close(releaseResponse)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("H3 setup failed across retire: %v", got.err)
		}
		if err := got.connection.Close(); err != nil {
			t.Fatalf("close H3 setup tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("H3 setup did not finish after retire")
	}
}

func TestHTTP3ConnectPoolAdaptsToLowerPeerStreamCredit(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServerWithQUICConfig(
		t,
		handler,
		&quic.Config{MaxIncomingStreams: 1},
	)
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

	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 3*time.Second)
	first, err := manager.dial(firstCtx, target, "first.example:443")
	cancelFirst()
	if err != nil {
		t.Fatalf("first low-credit H3 tunnel: %v", err)
	}
	defer first.Close()

	blockedCtx, cancelBlocked := context.WithTimeout(context.Background(), 150*time.Millisecond)
	blocked, err := manager.dial(blockedCtx, target, "blocked.example:443")
	cancelBlocked()
	if blocked != nil {
		_ = blocked.Close()
		t.Fatal("stream-credit blocked request returned a tunnel")
	}
	if !errors.Is(err, errConnectProxyProtocolCapacity) {
		t.Fatalf("stream-credit error = %v, want local capacity classification", err)
	}
	if got := connectProxyAttemptOutcome(err); got != connectProxyAttemptCapacity {
		t.Fatalf("real stream-credit metric outcome = %q, want %q", got, connectProxyAttemptCapacity)
	}
	if !connectProxyErrorIsRouteNeutral(err) {
		t.Fatalf("real stream-credit error poisoned proxy route: %v", err)
	}
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := &config.Rule{Name: "low-credit", Mode: config.ModeNormal, Protocol: config.ProtocolSOCKS5}
	routeAttempt, beginErr := runtime.routes.begin(rule, target.Address, time.Now())
	if beginErr != nil {
		t.Fatalf("begin low-credit route observation: %v", beginErr)
	}
	routeObserve(routeAttempt, 150*time.Millisecond, connectProxyRouteObservationError(err), time.Now())
	if snapshot := runtime.routes.snapshot(rule, target.Address, time.Now()); snapshot.ConsecutiveFailures != 0 || snapshot.CircuitOpen {
		t.Fatalf("stream-credit capacity changed route health: %+v", snapshot)
	}

	thirdCtx, cancelThird := context.WithTimeout(context.Background(), 10*time.Second)
	third, err := manager.dial(thirdCtx, target, "third.example:443")
	cancelThird()
	if err != nil {
		t.Fatalf("new pooled QUIC connection after learned credit: %v", err)
	}
	defer third.Close()
	fourthCtx, cancelFourth := context.WithTimeout(context.Background(), 10*time.Second)
	fourth, err := manager.dial(fourthCtx, target, "fourth.example:443")
	cancelFourth()
	if err != nil {
		t.Fatalf("fourth tunnel did not inherit learned stream credit: %v", err)
	}
	defer fourth.Close()
	if got := connectionCount.Load(); got != 3 {
		t.Fatalf("low-credit QUIC connection count = %d, want 3", got)
	}

	_ = first.Close()
	_ = third.Close()
	_ = fourth.Close()
	key := http3ConnectTransportKey{address: endpoint}
	manager.mu.Lock()
	remainingSlots := len(manager.transports[key])
	learnedLimit := manager.learnedStreamLimits[key]
	manager.mu.Unlock()
	if remainingSlots != 1 || learnedLimit != 1 {
		t.Fatalf("post-peak low-credit pool = slots:%d learned:%d, want 1/1", remainingSlots, learnedLimit)
	}

	fifthCtx, cancelFifth := context.WithTimeout(context.Background(), 10*time.Second)
	fifth, err := manager.dial(fifthCtx, target, "fifth.example:443")
	cancelFifth()
	if err != nil {
		t.Fatalf("retained low-credit warm tunnel: %v", err)
	}
	defer fifth.Close()
	sixthCtx, cancelSixth := context.WithTimeout(context.Background(), 10*time.Second)
	sixth, err := manager.dial(sixthCtx, target, "sixth.example:443")
	cancelSixth()
	if err != nil {
		t.Fatalf("new post-shrink slot did not inherit learned credit: %v", err)
	}
	defer sixth.Close()
	manager.mu.Lock()
	for index, slot := range manager.transports[key] {
		if slot.limit != 1 {
			manager.mu.Unlock()
			t.Fatalf("post-shrink slot %d limit = %d, want 1", index, slot.limit)
		}
	}
	manager.mu.Unlock()
}

func TestHTTP3HeadersWrittenTimeoutActivatesCooldownInsteadOfCapacity(t *testing.T) {
	requestStarted := make(chan struct{}, 2)
	handler := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()
	h3 := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer h3.close()
	var h3Calls atomic.Int64
	var h2Calls atomic.Int64
	h3Errors := make(chan error, 2)
	manager := &connectProxyManager{
		h3Fallback: make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(ctx context.Context, target *config.Target, destination string) (net.Conn, error) {
				h3Calls.Add(1)
				connection, err := h3.dial(ctx, target, destination)
				if err != nil {
					h3Errors <- err
				}
				return connection, err
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				h2Calls.Add(1)
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			},
		},
	}
	target := &config.Target{
		Address:      endpoint,
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result, 2)
	for index := 0; index < 2; index++ {
		go func(index int) {
			ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			defer cancel()
			connection, err := manager.dial(ctx, target, fmt.Sprintf("stalled-%d.example:443", index))
			results <- result{connection: connection, err: err}
		}(index)
	}
	for index := 0; index < 2; index++ {
		select {
		case <-requestStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("HTTP/3 proxy did not receive both CONNECT headers")
		}
	}
	for index := 0; index < 2; index++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("H2 fallback after stalled H3 response %d: %v", index, result.err)
		}
		_ = result.connection.Close()
	}
	for index := 0; index < 2; index++ {
		err := <-h3Errors
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errConnectProxyProtocolCapacity) {
			t.Fatalf("written-header timeout %d = %v, want transport deadline", index, err)
		}
	}

	thirdCtx, cancelThird := context.WithTimeout(context.Background(), 250*time.Millisecond)
	third, err := manager.dial(thirdCtx, target, "third.example:443")
	cancelThird()
	if err != nil {
		t.Fatalf("cooldown H2 fallback: %v", err)
	}
	_ = third.Close()
	if got := h3Calls.Load(); got != 2 {
		t.Fatalf("H3 calls after confirmed timeout = %d, want 2 with third request cooled down", got)
	}
	if got := h2Calls.Load(); got != 3 {
		t.Fatalf("H2 fallback calls = %d, want 3", got)
	}
}

func TestHTTP3LocalPoolCapacityFallsBackWithoutCooldown(t *testing.T) {
	h3Calls := 0
	h2Calls := 0
	manager := &connectProxyManager{
		h3Fallback: make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
				h3Calls++
				return nil, errConnectProxyProtocolCapacity
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				h2Calls++
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			},
		},
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := manager.dial(context.Background(), target, "destination.example:443")
		if err != nil {
			t.Fatalf("capacity fallback %d: %v", attempt, err)
		}
		_ = connection.Close()
	}
	if h3Calls != 2 || h2Calls != 2 {
		t.Fatalf("capacity protocol calls = h3:%d h2:%d, want 2/2", h3Calls, h2Calls)
	}
	if got := connectProxyAttemptOutcome(errors.Join(errConnectProxyProtocolCapacity, context.DeadlineExceeded)); got != connectProxyAttemptCapacity {
		t.Fatalf("capacity timeout metric outcome = %q, want %q", got, connectProxyAttemptCapacity)
	}
}

func TestHTTP3ConnectRejectsBadBasicAuth(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
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
			BasicAuth: &config.BasicAuthConfig{Username: "wrong", Password: "credential"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "destination.example:443")
	if connection != nil {
		_ = connection.Close()
		t.Fatal("authentication failure returned a tunnel")
	}
	var statusErr *connectProxyStatusError
	if !errors.As(err, &statusErr) || statusErr.protocol != config.ConnectProxyH3 || statusErr.statusCode != http.StatusForbidden {
		t.Fatalf("authentication error = %v, want H3 status 403", err)
	}
	if statusErr.class != connectProxyFailurePolicyDenied {
		t.Fatalf("classified error = %+v, want policy_denied", statusErr)
	}
}

func TestHTTP3ConnectCloseWriteDeliversEndStreamAndKeepsResponseReadable(t *testing.T) {
	const payload = "request-before-half-close"
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body through END_STREAM: %v", err)
			return
		}
		_, _ = io.WriteString(writer, "after-eof:"+string(body))
		writer.(http.Flusher).Flush()
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "service.example:443")
	if err != nil {
		t.Fatalf("dial HTTP/3 CONNECT: %v", err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, payload); err != nil {
		t.Fatalf("write request body: %v", err)
	}
	if err := closeWrite(connection); err != nil {
		t.Fatalf("deliver HTTP/3 END_STREAM: %v", err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read response after CloseWrite: %v", err)
	}
	if want := "after-eof:" + payload; string(response) != want {
		t.Fatalf("response after CloseWrite = %q, want %q", response, want)
	}
}

func TestHTTP3SharedConnectionDialSurvivesFirstRequestCancellation(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()

	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		ownerDial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			close(dialStarted)
			<-releaseDial
			return ownerDial(ctx, address, tlsConfig, quicConfig)
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

	firstBase, cancelFirstBase := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFirstBase()
	firstCtx, cancelFirst := context.WithCancel(firstBase)
	firstResult := make(chan error, 1)
	go func() {
		connection, err := manager.dial(firstCtx, target, "first.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		firstResult <- err
	}()
	<-dialStarted

	type dialResult struct {
		connection net.Conn
		err        error
	}
	secondStarted := make(chan struct{})
	secondResult := make(chan dialResult, 1)
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSecond()
	go func() {
		close(secondStarted)
		connection, err := manager.dial(secondCtx, target, "second.example:443")
		secondResult <- dialResult{connection: connection, err: err}
	}()
	<-secondStarted
	time.Sleep(10 * time.Millisecond) // let the second RoundTrip join the shared setup
	cancelFirst()
	close(releaseDial)

	select {
	case err := <-firstResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first canceled request error = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first canceled request did not return")
	}
	select {
	case result := <-secondResult:
		if result.err != nil {
			t.Fatalf("second request lost the shared QUIC dial: %v", result.err)
		}
		_ = result.connection.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("second request did not complete")
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("QUIC connection count = %d, want one shared connection", got)
	}
}

func TestHTTP3GenerationCancellationInterruptsDNSResolution(t *testing.T) {
	owner, cancelOwner := context.WithCancel(context.Background())
	started := make(chan struct{})
	transport := newHTTP3ConnectTransportWithResolver(
		http3ConnectTransportKey{serverName: "blocked.example"},
		owner,
		blockingHTTP3Resolver{started: started},
	)
	result := make(chan error, 1)
	go func() {
		_, err := transport.Dial(
			context.Background(),
			"blocked.example:443",
			&tls.Config{ServerName: "blocked.example", NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{},
		)
		result <- err
	}()
	<-started
	cancelOwner()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DNS cancellation error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("generation cancellation did not interrupt HTTP/3 DNS resolution")
	}
}

func TestSOCKS5NormalUsesHTTP3Connect(t *testing.T) {
	const (
		banner    = "H3-READY\n"
		userAgent = "Moto-H3-UA/1.0"
	)
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("moto:secret"))
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 3 || request.Method != http.MethodConnect ||
			request.Host != "service.example:443" || request.Header.Get("Proxy-Authorization") != expectedAuth ||
			request.Header.Get("User-Agent") != userAgent {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, banner)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()

	runtime := newRoutingRuntime()
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	runtime.connectProxy.h3 = manager
	runtime.connectProxy.dialers[config.ConnectProxyH3] = manager.dial
	t.Cleanup(func() {
		runtime.stopBackground()
		runtime.connectProxy.close()
	})
	rule := &config.Rule{
		Name:                "huojian-h3",
		Listen:              "127.0.0.1:1080",
		Mode:                config.ModeNormal,
		Protocol:            config.ProtocolSOCKS5,
		Timeout:             1_000,
		MaxConnections:      16,
		MaxConnectionsPerIP: 16,
		UserAgent:           []string{userAgent},
		Targets: []*config.Target{{
			Address: endpoint,
			ConnectProxy: &config.ConnectProxyConfig{
				Protocols: []string{config.ConnectProxyH3},
				BasicAuth: &config.BasicAuthConfig{Username: "moto", Password: "secret"},
			},
		}},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule.Validate(): %v", err)
	}

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		runtime.dispatch(context.Background(), serverSide, rule, userAgent)
		close(done)
	}()
	performSOCKS5DomainRequest(t, clientSide, "service.example", 443)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatalf("read SOCKS5 CONNECT reply: %v", err)
	}
	if reply[1] != socks5ReplySuccess {
		t.Fatalf("SOCKS5 CONNECT reply = %v", reply)
	}
	gotBanner := make([]byte, len(banner))
	if _, err := io.ReadFull(clientSide, gotBanner); err != nil {
		t.Fatalf("read HTTP/3 server-first data: %v", err)
	}
	if string(gotBanner) != banner {
		t.Fatalf("HTTP/3 server-first data = %q", gotBanner)
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 over HTTP/3 dispatch did not stop")
	}
}

func TestConnectProxyProtocolBudgetLeavesTimeForFallback(t *testing.T) {
	firstFinished := make(chan struct{})
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
		config.ConnectProxyH3: func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
			<-ctx.Done()
			close(firstFinished)
			return nil, ctx.Err()
		},
		config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
			return clientSide, nil
		},
	}}
	target := &config.Target{ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
		config.ConnectProxyH3,
		config.ConnectProxyH2,
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	started := time.Now()
	connection, err := manager.dial(ctx, target, "destination.example:443")
	if err != nil {
		t.Fatalf("fallback dial: %v", err)
	}
	defer connection.Close()
	select {
	case <-firstFinished:
	default:
		t.Fatal("H2 fallback ran before the H3 attempt ended")
	}
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond || elapsed >= 350*time.Millisecond {
		t.Fatalf("fallback elapsed = %s, want approximately half the overall timeout", elapsed)
	}
}

func TestConnectProxyHTTP3CooldownOnlyAfterSuccessfulHTTP2Fallback(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h3Calls := 0
	h2Calls := 0
	h3Succeeds := false
	h2Succeeds := true
	newConnection := func() net.Conn {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client
	}
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: 10 * time.Second,
		cooldownMax:  time.Minute,
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
				h3Calls++
				if h3Succeeds {
					return newConnection(), nil
				}
				return nil, errors.New("UDP path unavailable")
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				h2Calls++
				if h2Succeeds {
					return newConnection(), nil
				}
				return nil, errors.New("TCP path unavailable")
			},
		},
	}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
			config.ConnectProxyH3,
			config.ConnectProxyH2,
		}},
	}

	connection, err := manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("initial fallback dial: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 1 {
		t.Fatalf("initial calls = h3:%d h2:%d, want 1/1", h3Calls, h2Calls)
	}

	connection, err = manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("cooldown fallback dial: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 || h2Calls != 2 {
		t.Fatalf("cooldown calls = h3:%d h2:%d, want 1/2", h3Calls, h2Calls)
	}

	now = now.Add(10 * time.Second)
	h3Succeeds = true
	connection, err = manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("half-open H3 probe: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 2 || h2Calls != 2 {
		t.Fatalf("recovery calls = h3:%d h2:%d, want 2/2", h3Calls, h2Calls)
	}

	// If both protocols fail, H3 must remain eligible on the next request.
	h3Succeeds = false
	h2Succeeds = false
	if connection, err = manager.dial(context.Background(), target, "destination.example:443"); err == nil {
		_ = connection.Close()
		t.Fatal("all-protocol failure unexpectedly succeeded")
	}
	previousH3Calls := h3Calls
	if connection, err = manager.dial(context.Background(), target, "destination.example:443"); err == nil {
		_ = connection.Close()
		t.Fatal("second all-protocol failure unexpectedly succeeded")
	}
	if h3Calls != previousH3Calls+1 {
		t.Fatalf("H3 was suppressed without a successful fallback: calls %d -> %d", previousH3Calls, h3Calls)
	}
}

func TestConnectProxyHTTP3CooldownAfterReachableHTTP2Status(t *testing.T) {
	for _, statusCode := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			h3Calls := 0
			h2Calls := 0
			manager := &connectProxyManager{
				now:          func() time.Time { return now },
				cooldownBase: 10 * time.Second,
				cooldownMax:  time.Minute,
				dialers: map[string]connectProxyDialFunc{
					config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
						h3Calls++
						return nil, errors.New("UDP path unavailable")
					},
					config.ConnectProxyH2: func(_ context.Context, target *config.Target, _ string) (net.Conn, error) {
						h2Calls++
						return nil, &connectProxyStatusError{
							protocol:   config.ConnectProxyH2,
							target:     target.Address,
							statusCode: statusCode,
						}
					},
				},
			}
			target := &config.Target{
				Address: "proxy.example:443",
				ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
					config.ConnectProxyH3,
					config.ConnectProxyH2,
				}},
			}

			for attempt := 0; attempt < 2; attempt++ {
				connection, err := manager.dial(context.Background(), target, "destination.example:443")
				if connection != nil {
					_ = connection.Close()
					t.Fatal("non-2xx H2 fallback returned a tunnel")
				}
				var statusErr *connectProxyStatusError
				if !errors.As(err, &statusErr) || statusErr.statusCode != statusCode {
					t.Fatalf("dial error = %v, want final HTTP status %d", err, statusCode)
				}
			}
			if h3Calls != 1 || h2Calls != 2 {
				t.Fatalf("protocol calls = h3:%d h2:%d, want 1/2 after reachable H2 status", h3Calls, h2Calls)
			}
		})
	}
}

func TestConnectProxyHTTPStatusDoesNotFallbackAcrossProtocols(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusForbidden,
		http.StatusProxyAuthRequired,
		http.StatusTooManyRequests,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			h3Calls := 0
			h2Calls := 0
			manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
				config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
					h3Calls++
					return nil, &connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: statusCode}
				},
				config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
					h2Calls++
					return nil, errors.New("must not be called")
				},
			}}
			target := &config.Target{
				Address: "proxy.example:443",
				ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
					config.ConnectProxyH3,
					config.ConnectProxyH2,
				}},
			}

			for attempt := 0; attempt < 2; attempt++ {
				connection, err := manager.dial(context.Background(), target, "destination.example:443")
				if connection != nil {
					_ = connection.Close()
					t.Fatal("non-2xx H3 response returned a connection")
				}
				var statusErr *connectProxyStatusError
				if !errors.As(err, &statusErr) || statusErr.statusCode != statusCode {
					t.Fatalf("dial error = %v, want HTTP %d", err, statusCode)
				}
			}
			if h3Calls != 2 {
				t.Fatalf("direct H3 status calls = %d, want 2 without cooldown", h3Calls)
			}
			if h2Calls != 0 {
				t.Fatalf("HTTP status triggered %d H2 fallback attempts", h2Calls)
			}
		})
	}
}

func TestConnectProxyHTTP3CapabilityStatusFallsBackToHTTP2(t *testing.T) {
	h3Calls := 0
	h2Calls := 0
	manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
		config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
			h3Calls++
			return nil, &connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: http.StatusNotImplemented}
		},
		config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
			h2Calls++
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			return client, nil
		},
	}}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
			config.ConnectProxyH3,
			config.ConnectProxyH2,
		}},
	}
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := manager.dial(context.Background(), target, "destination.example:443")
		if err != nil {
			t.Fatalf("capability fallback %d: %v", attempt, err)
		}
		_ = connection.Close()
	}
	if h3Calls != 1 || h2Calls != 2 {
		t.Fatalf("capability fallback calls = h3:%d h2:%d, want 1/2", h3Calls, h2Calls)
	}
}

func TestConnectProxyHTTP2CapabilityStatusFallsBackToHTTP3(t *testing.T) {
	h3Calls := 0
	manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
		config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
			return nil, &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: http.StatusHTTPVersionNotSupported}
		},
		config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
			h3Calls++
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			return client, nil
		},
	}}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
			config.ConnectProxyH2,
			config.ConnectProxyH3,
		}},
	}
	connection, err := manager.dial(context.Background(), target, "destination.example:443")
	if err != nil {
		t.Fatalf("H2 capability fallback: %v", err)
	}
	_ = connection.Close()
	if h3Calls != 1 {
		t.Fatalf("H3 fallback calls = %d, want 1", h3Calls)
	}
}

func TestConnectProxyHTTP3OnlyNeverUsesFallbackCooldown(t *testing.T) {
	h3Calls := 0
	manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
		config.ConnectProxyH3: func(context.Context, *config.Target, string) (net.Conn, error) {
			h3Calls++
			return nil, errors.New("temporary H3 failure")
		},
	}}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}},
	}
	for attempt := 0; attempt < 2; attempt++ {
		if connection, err := manager.dial(context.Background(), target, "destination.example:443"); err == nil {
			_ = connection.Close()
			t.Fatalf("H3-only attempt %d unexpectedly succeeded", attempt)
		}
	}
	if h3Calls != 2 {
		t.Fatalf("H3-only calls = %d, want 2", h3Calls)
	}
}

func TestHTTP3CooldownIgnoresStaleAttemptsWithoutColdStartHeadOfLineBlocking(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: time.Second,
		cooldownMax:  time.Minute,
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	firstToken, managed, allowed := manager.beginHTTP3Attempt(context.Background(), target)
	if firstToken == 0 || managed || !allowed {
		t.Fatalf("initial permit = token:%d managed:%t allowed:%t", firstToken, managed, allowed)
	}
	siblingToken, siblingManaged, siblingAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if siblingToken != firstToken || siblingManaged || !siblingAllowed {
		t.Fatalf("concurrent cold-start permit = token:%d managed:%t allowed:%t", siblingToken, siblingManaged, siblingAllowed)
	}
	manager.markHTTP3FailurePending(target, firstToken)
	pendingToken, _, pendingAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if pendingAllowed || pendingToken != firstToken {
		t.Fatal("new H3 attempt was admitted after a transport failure became pending")
	}
	manager.observeHTTP3Attempt(target, firstToken, false, errors.New("UDP unavailable"), nil, true)
	manager.observeHTTP3PendingFallback(target, pendingToken, nil, false)
	manager.markHTTP3FailurePending(target, siblingToken)

	now = now.Add(time.Second)
	probeToken, managed, allowed := manager.beginHTTP3Attempt(context.Background(), target)
	if probeToken == 0 || probeToken == firstToken || !managed || !allowed {
		t.Fatalf("half-open permit = token:%d managed:%t allowed:%t", probeToken, managed, allowed)
	}
	manager.markHTTP3FailurePending(target, firstToken)
	manager.observeHTTP3Attempt(target, firstToken, false, errors.New("stale failure"), nil, true)

	key := http3ConnectTransportKey{address: target.Address}
	manager.h3FallbackMu.Lock()
	state := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if state.epoch != probeToken || !state.probing || state.pending || state.failures != 1 {
		t.Fatalf("stale attempt corrupted half-open state: %+v", state)
	}
	manager.observeHTTP3Attempt(target, probeToken, true, nil, nil, false)
}

func TestHTTP3CooldownSameEpochH3SuccessOverridesEarlierFallbackSuccess(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: time.Second,
		cooldownMax:  time.Minute,
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	failedToken, _, failedAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	successToken, _, successAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !failedAllowed || !successAllowed || failedToken != successToken {
		t.Fatalf("same-epoch permits = (%d,%t) (%d,%t)", failedToken, failedAllowed, successToken, successAllowed)
	}
	manager.markHTTP3FailurePending(target, failedToken)
	manager.observeHTTP3Attempt(target, failedToken, false, errors.New("one H3 stream failed"), nil, true)

	key := http3ConnectTransportKey{address: target.Address}
	manager.h3FallbackMu.Lock()
	beforeSuccess := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if !beforeSuccess.pending || !beforeSuccess.fallbackReady || beforeSuccess.h3InFlight != 1 || beforeSuccess.failures != 0 {
		t.Fatalf("fallback committed before sibling H3 resolved: %+v", beforeSuccess)
	}

	manager.observeHTTP3Attempt(target, successToken, false, nil, nil, false)
	thirdToken, managed, allowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !allowed || managed || thirdToken == 0 {
		t.Fatalf("H3 success did not reset same-epoch failure: token:%d managed:%t allowed:%t", thirdToken, managed, allowed)
	}
}

func TestHTTP3CooldownHalfOpenSkipSuccessCommitsIfProbeFails(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: time.Second,
		cooldownMax:  time.Minute,
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	initialToken, _, allowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !allowed {
		t.Fatal("initial H3 attempt was not admitted")
	}
	manager.markHTTP3FailurePending(target, initialToken)
	manager.observeHTTP3Attempt(target, initialToken, false, errors.New("initial H3 failure"), nil, true)
	now = now.Add(time.Second)

	probeToken, managed, allowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !allowed || !managed || probeToken == 0 {
		t.Fatalf("half-open permit = token:%d managed:%t allowed:%t", probeToken, managed, allowed)
	}
	skipToken, _, skipAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if skipAllowed || skipToken != probeToken {
		t.Fatalf("concurrent half-open request = token:%d allowed:%t", skipToken, skipAllowed)
	}
	manager.observeHTTP3PendingFallback(target, skipToken, nil, true)
	manager.markHTTP3FailurePending(target, probeToken)
	manager.observeHTTP3Attempt(target, probeToken, managed, errors.New("probe H3 failure"), nil, false)

	if token, _, allowed := manager.beginHTTP3Attempt(context.Background(), target); allowed || token != 0 {
		t.Fatalf("successful probe-window fallback did not commit cooldown: token:%d allowed:%t", token, allowed)
	}
}

func TestHTTP3CooldownSuccessfulSiblingFallbackWinsFailureWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: time.Second,
		cooldownMax:  time.Minute,
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	firstToken, firstManaged, firstAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	secondToken, secondManaged, secondAllowed := manager.beginHTTP3Attempt(context.Background(), target)
	if !firstAllowed || !secondAllowed || firstManaged || secondManaged || firstToken != secondToken {
		t.Fatalf("sibling permits = (%d,%t,%t) (%d,%t,%t)",
			firstToken, firstManaged, firstAllowed, secondToken, secondManaged, secondAllowed)
	}
	manager.markHTTP3FailurePending(target, firstToken)
	manager.markHTTP3FailurePending(target, secondToken)
	manager.observeHTTP3Attempt(target, firstToken, firstManaged, errors.New("first H3 failure"), nil, false)

	key := http3ConnectTransportKey{address: target.Address}
	manager.h3FallbackMu.Lock()
	afterFirst := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if afterFirst.epoch != firstToken || !afterFirst.pending || afterFirst.fallbackPending != 1 {
		t.Fatalf("first failed fallback cleared sibling window: %+v", afterFirst)
	}

	manager.observeHTTP3Attempt(target, secondToken, secondManaged, errors.New("second H3 failure"), nil, true)
	if _, _, allowed := manager.beginHTTP3Attempt(context.Background(), target); allowed {
		t.Fatal("successful sibling H2 fallback did not activate H3 cooldown")
	}
}

func TestHTTP3CooldownSkippedSiblingSuccessSurvivesOriginalFallbackFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	firstH2Started := make(chan struct{})
	releaseFirstH2 := make(chan struct{})
	var callsMu sync.Mutex
	h3Calls := 0
	h2Calls := 0
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: time.Second,
		cooldownMax:  time.Minute,
		h3Fallback:   make(map[http3ConnectTransportKey]*http3FallbackState),
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(_ context.Context, _ *config.Target, destination string) (net.Conn, error) {
				callsMu.Lock()
				h3Calls++
				callsMu.Unlock()
				return nil, fmt.Errorf("H3 unavailable for %s", destination)
			},
			config.ConnectProxyH2: func(_ context.Context, _ *config.Target, destination string) (net.Conn, error) {
				callsMu.Lock()
				h2Calls++
				callsMu.Unlock()
				if destination == "first.example:443" {
					close(firstH2Started)
					<-releaseFirstH2
					return nil, errors.New("first H2 fallback failed")
				}
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			},
		},
	}
	target := &config.Target{
		Address:      "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}},
	}

	firstResult := make(chan error, 1)
	go func() {
		connection, err := manager.dial(context.Background(), target, "first.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		firstResult <- err
	}()
	<-firstH2Started

	second, err := manager.dial(context.Background(), target, "second.example:443")
	if err != nil {
		t.Fatalf("pending-window H2 fallback: %v", err)
	}
	_ = second.Close()
	close(releaseFirstH2)
	if err := <-firstResult; err == nil {
		t.Fatal("original failed fallback unexpectedly succeeded")
	}

	third, err := manager.dial(context.Background(), target, "third.example:443")
	if err != nil {
		t.Fatalf("cooldown H2 fallback after sibling success: %v", err)
	}
	_ = third.Close()
	callsMu.Lock()
	gotH3Calls, gotH2Calls := h3Calls, h2Calls
	callsMu.Unlock()
	if gotH3Calls != 1 || gotH2Calls != 3 {
		t.Fatalf("protocol calls = h3:%d h2:%d, want 1/3", gotH3Calls, gotH2Calls)
	}
}

func TestConnectProxyRouteNeutralErrors(t *testing.T) {
	statusH3 := &connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: http.StatusBadGateway}
	statusH2 := &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: http.StatusForbidden}
	if !connectProxyErrorIsRouteNeutral(errors.Join(
		fmt.Errorf("h3 CONNECT: %w", statusH3),
		fmt.Errorf("h2 CONNECT: %w", statusH2),
	)) {
		t.Fatal("HTTP CONNECT status failures should not poison shared route health")
	}
	if connectProxyErrorIsRouteNeutral(errors.Join(statusH3, errors.New("QUIC handshake failed"))) {
		t.Fatal("a mixed HTTP status and transport failure was treated as route-neutral")
	}
	for _, finalStatus := range []int{http.StatusProxyAuthRequired, http.StatusTooManyRequests} {
		capacityThenStatus := errors.Join(
			errConnectProxyProtocolCapacity,
			&connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: finalStatus},
		)
		if connectProxyErrorIsRouteNeutral(capacityThenStatus) {
			t.Fatalf("local H3 capacity masked final HTTP status %d", finalStatus)
		}
	}
	if !connectProxyErrorIsRouteNeutral(errors.Join(errConnectProxyProtocolCapacity, context.DeadlineExceeded)) {
		t.Fatal("stream capacity joined with its observation deadline should stay route-neutral")
	}
	for _, finalStatus := range []int{http.StatusForbidden, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		fallbackErr := errors.Join(
			fmt.Errorf("h3 CONNECT: %w", errors.New("UDP path unavailable")),
			fmt.Errorf("h2 CONNECT: %w", &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: finalStatus}),
		)
		if !connectProxyErrorIsRouteNeutral(fallbackErr) {
			t.Fatalf("H3 failure followed by destination status %d poisoned route health", finalStatus)
		}
	}
	for _, finalStatus := range []int{
		http.StatusMethodNotAllowed,
		http.StatusProxyAuthRequired,
		http.StatusTooManyRequests,
		http.StatusNotImplemented,
	} {
		fallbackErr := errors.Join(
			fmt.Errorf("h3 CONNECT: %w", errors.New("UDP path unavailable")),
			fmt.Errorf("h2 CONNECT: %w", &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: finalStatus}),
		)
		if connectProxyErrorIsRouteNeutral(fallbackErr) {
			t.Fatalf("H3 failure followed by proxy status %d was treated as route-neutral", finalStatus)
		}
	}
	if connectProxyErrorIsRouteNeutral(context.DeadlineExceeded) {
		t.Fatal("a transport deadline was treated as route-neutral")
	}
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusProxyAuthRequired,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusNetworkAuthenticationRequired,
	} {
		if connectProxyErrorIsRouteNeutral(&connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: status}) {
			t.Fatalf("proxy health status %d was treated as route-neutral", status)
		}
	}
	for _, status := range []int{http.StatusForbidden, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		if !connectProxyErrorIsRouteNeutral(&connectProxyStatusError{protocol: config.ConnectProxyH3, statusCode: status}) {
			t.Fatalf("destination/policy status %d poisoned shared route health", status)
		}
	}

	runtime := newRoutingRuntime()
	rule := &config.Rule{Name: "proxy", Mode: config.ModeBoost}
	now := time.Now()
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := runtime.routes.begin(rule, "proxy.example:443", now.Add(time.Duration(index)*time.Millisecond))
		if err != nil {
			t.Fatalf("begin route attempt %d: %v", index, err)
		}
		routeObserve(attempt, time.Millisecond, connectProxyRouteObservationError(statusH3), now)
	}
	snapshot := runtime.routes.snapshot(rule, "proxy.example:443", now)
	if snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("destination status poisoned route health: %+v", snapshot)
	}
	compositeNeutral := errors.Join(
		fmt.Errorf("h3 CONNECT: %w", errors.New("UDP path unavailable")),
		fmt.Errorf("h2 CONNECT: %w", &connectProxyStatusError{protocol: config.ConnectProxyH2, statusCode: http.StatusBadGateway}),
	)
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := runtime.routes.begin(rule, "proxy.example:443", now.Add(time.Duration(index+10)*time.Millisecond))
		if err != nil {
			t.Fatalf("begin composite route attempt %d: %v", index, err)
		}
		routeObserve(attempt, time.Millisecond, connectProxyRouteObservationError(compositeNeutral), now)
	}
	snapshot = runtime.routes.snapshot(rule, "proxy.example:443", now)
	if snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("H3 failure plus H2 destination status poisoned route health: %+v", snapshot)
	}
}

func startHTTP3ConnectTestServer(
	t *testing.T,
	handler http.Handler,
) (string, *x509.CertPool, func(), *atomic.Int64) {
	return startHTTP3ConnectTestServerWithQUICConfig(t, handler, nil)
}

func startHTTP3ConnectTestServerWithQUICConfig(
	t *testing.T,
	handler http.Handler,
	quicConfig *quic.Config,
) (string, *x509.CertPool, func(), *atomic.Int64) {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP for HTTP/3: %v", err)
	}
	var connectionCount atomic.Int64
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
		QUICConfig: quicConfig,
		Handler:    handler,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			connectionCount.Add(1)
			return ctx
		},
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packetConn) }()
	closeServer := func() {
		_ = server.Close()
		_ = packetConn.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP/3 server close: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	}
	return packetConn.LocalAddr().String(), roots, closeServer, &connectionCount
}
