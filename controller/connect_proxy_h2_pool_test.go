package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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

// GetConn runs under the pool lock before the shared dial is selected. Once
// signaled, cancellation cannot remove that dial before the waiter joins it.
func http2PoolTestWaitContext(ctx context.Context) (context.Context, <-chan struct{}) {
	waiting := make(chan struct{})
	var once sync.Once
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {
		once.Do(func() { close(waiting) })
	}}), waiting
}

func TestHTTP2ConnectPoolRetriesCanceledSharedDial(t *testing.T) {
	server, transport, pool := newHTTP2ConnectPoolTestTransport(t)
	var dials atomic.Int32
	firstStarted := make(chan struct{})
	transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
		if dials.Add(1) == 1 {
			close(firstStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	t.Cleanup(cancelFirst)
	firstRequest, err := http.NewRequestWithContext(firstCtx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		response, err := transport.RoundTrip(firstRequest)
		if response != nil {
			_ = response.Body.Close()
		}
		firstDone <- err
	}()
	awaitHTTP2PoolTestEvent(t, firstStarted, "initiating dial")

	secondBase, cancelSecond := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancelSecond)
	secondCtx, secondWaiting := http2PoolTestWaitContext(secondBase)
	secondRequest, err := http.NewRequestWithContext(secondCtx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- roundTripHTTP2PoolTestRequest(transport, secondRequest) }()
	awaitHTTP2PoolTestEvent(t, secondWaiting, "shared dial waiter")
	cancelFirst()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("initiating request error = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initiating request did not return after cancellation")
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("independent waiter failed to retry canceled shared dial: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("independent waiter did not finish its replacement dial")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("physical dial attempts = %d, want canceled attempt and one replacement", got)
	}
	pool.closeIdleConnections()
}

func TestHTTP2ConnectPoolCanceledWaiterLeavesSharedDialRunning(t *testing.T) {
	server, transport, _ := newHTTP2ConnectPoolTestTransport(t)
	var dials atomic.Int32
	started := make(chan struct{})
	proceed := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(proceed) }) }
	t.Cleanup(release)
	transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
		if dials.Add(1) == 1 {
			close(started)
		}
		select {
		case <-proceed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
	}
	initiatorCtx, cancelInitiator := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancelInitiator)
	initiatorRequest, err := http.NewRequestWithContext(initiatorCtx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	initiatorDone := make(chan error, 1)
	go func() { initiatorDone <- roundTripHTTP2PoolTestRequest(transport, initiatorRequest) }()
	awaitHTTP2PoolTestEvent(t, started, "shared physical dial")

	waiterBase, cancelWaiter := context.WithCancel(context.Background())
	t.Cleanup(cancelWaiter)
	waiterCtx, waiterWaiting := http2PoolTestWaitContext(waiterBase)
	waiterRequest, err := http.NewRequestWithContext(waiterCtx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	waiterDone := make(chan error, 1)
	go func() { waiterDone <- roundTripHTTP2PoolTestRequest(transport, waiterRequest) }()
	awaitHTTP2PoolTestEvent(t, waiterWaiting, "cancelable shared waiter")
	cancelWaiter()
	select {
	case err := <-waiterDone:
		t.Fatalf("shared waiter released cleanup before physical dial settled: %v", err)
	default:
	}
	release()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter error after shared dial settled = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled shared waiter did not clean up after dial settled")
	}
	select {
	case err := <-initiatorDone:
		if err != nil {
			t.Fatalf("waiter cancellation interrupted shared initiator: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initiating request did not finish")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("physical dial attempts = %d, want one shared dial", got)
	}
}

func TestHTTP2ConnectPoolIdleClosePreservesReservedRequest(t *testing.T) {
	server, _, pool := newHTTP2ConnectPoolTestTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := pool.GetClientConn(request, request.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	pool.closeIdleConnections()
	if state := connection.State(); state.Closed || state.StreamsReserved != 1 {
		t.Fatalf("idle close invalidated a reserved request: %+v", state)
	}
	response, err := connection.RoundTrip(request)
	if err != nil {
		t.Fatalf("reserved request failed after idle close: %v", err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	pool.closeIdleConnections()
	awaitHTTP2PoolTestCondition(t, func() bool { return connection.State().Closed }, "completed idle connection to close")
	pool.mu.Lock()
	remaining := len(pool.keys)
	pool.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("idle close retained %d physical connections in pool", remaining)
	}
}

func TestHTTP2ConnectPoolIdleCloseDoesNotWaitForBlockedWrite(t *testing.T) {
	server, transport, pool := newHTTP2ConnectPoolTestTransport(t)
	other := newHTTP2ConnectTestServer(t, func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "pool-ok")
	})
	blockedReady := make(chan *http2PoolBlockedWriteConn, 1)
	transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
		connection, err := (&tls.Dialer{Config: config}).DialContext(ctx, network, address)
		if err != nil || address != server.Listener.Addr().String() {
			return connection, err
		}
		blocked := &http2PoolBlockedWriteConn{
			Conn: connection, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
		}
		blockedReady <- blocked
		return blocked, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := pool.GetClientConn(request, request.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	blocked := <-blockedReady
	t.Cleanup(blocked.unblock)
	t.Cleanup(func() { _ = connection.Close() })
	response, err := connection.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Ping takes the real ClientConn writer lock and calls this connection's
	// blocking Write. State cannot return until the write is released.
	blocked.block.Store(true)
	pingDone := make(chan error, 1)
	go func() { pingDone <- connection.Ping(ctx) }()
	awaitHTTP2PoolTestEvent(t, blocked.entered, "blocked HTTP/2 write")
	closeReturned := make(chan struct{})
	go func() {
		for range 100 {
			pool.closeIdleConnections()
		}
		close(closeReturned)
	}()
	select {
	case <-closeReturned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("idle closing waited for the physical connection's blocked writer")
	}
	pool.mu.Lock()
	checks := len(pool.idleChecks)
	pool.mu.Unlock()
	if checks != 1 {
		t.Fatalf("repeated idle close spawned %d checks, want one per physical connection", checks)
	}

	// Another authority in the same pool must still be dialed and usable.
	otherRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, other.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherDone := make(chan error, 1)
	go func() { otherDone <- roundTripHTTP2PoolTestRequest(transport, otherRequest) }()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("other connection failed while idle cleanup was blocked: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked idle check prevented another connection from making progress")
	}
	blocked.unblock()
	awaitHTTP2PoolTestEvent(t, blocked.closed, "deferred idle connection close")
	select {
	case <-pingDone:
	case <-time.After(time.Second):
		t.Fatal("PING did not finish after its blocked write was released")
	}
	awaitHTTP2PoolTestCondition(t, func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return len(pool.idleChecks) == 0
	}, "idle check worker cleanup")
}

type http2PoolBlockedWriteConn struct {
	net.Conn
	block       atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	closed      chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
	closedOnce  sync.Once
}

func (connection *http2PoolBlockedWriteConn) Write(buffer []byte) (int, error) {
	if connection.block.Load() {
		connection.enteredOnce.Do(func() { close(connection.entered) })
		<-connection.release
	}
	return connection.Conn.Write(buffer)
}

func (connection *http2PoolBlockedWriteConn) unblock() {
	connection.releaseOnce.Do(func() { close(connection.release) })
}

func (connection *http2PoolBlockedWriteConn) Close() error {
	connection.unblock()
	connection.closedOnce.Do(func() { close(connection.closed) })
	return connection.Conn.Close()
}

func newHTTP2ConnectPoolTestTransport(t *testing.T) (*httptest.Server, *xhttp2.Transport, *http2ConnectConnPool) {
	t.Helper()
	server := newHTTP2ConnectTestServer(t, func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "pool-ok")
	})
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &xhttp2.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	pool := newHTTP2ConnectConnPool(transport)
	transport.ConnPool = pool
	t.Cleanup(pool.closeIdleConnections)
	return server, transport, pool
}

func roundTripHTTP2PoolTestRequest(transport *xhttp2.Transport, request *http.Request) error {
	response, err := transport.RoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if string(body) != "pool-ok" {
		return errors.New("HTTP/2 pool returned unexpected response body")
	}
	return nil
}

func awaitHTTP2PoolTestEvent(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func awaitHTTP2PoolTestCondition(t *testing.T, condition func() bool, label string) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", label)
		case <-poll.C:
		}
	}
}
