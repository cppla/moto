package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"testing"
	"time"
)

func TestRelayBidirectionalPreservesResponseAfterRequestEOF(t *testing.T) {
	client, proxyClient := newTCPPair(t)
	proxyTarget, backend := newTCPPair(t)
	defer client.Close()
	defer proxyClient.Close()
	defer proxyTarget.Close()
	defer backend.Close()

	deadline := time.Now().Add(3 * time.Second)
	for _, conn := range []net.Conn{client, proxyClient, proxyTarget, backend} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	resultCh := make(chan relayResult, 1)
	go func() {
		resultCh <- relayBidirectional(context.Background(), proxyClient, proxyTarget)
	}()

	request := []byte("short request")
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	gotRequest, err := io.ReadAll(backend)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRequest) != string(request) {
		t.Fatalf("backend request = %q, want %q", gotRequest, request)
	}

	response := []byte("response after request EOF")
	if _, err := backend.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := backend.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	gotResponse, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotResponse) != string(response) {
		t.Fatalf("client response = %q, want %q", gotResponse, response)
	}

	select {
	case result := <-resultCh:
		if result.ClientToTarget.Err != nil || result.TargetToClient.Err != nil {
			t.Fatalf("relay errors: client->target=%v target->client=%v",
				result.ClientToTarget.Err, result.TargetToClient.Err)
		}
		if result.ClientToTarget.Bytes != int64(len(request)) {
			t.Fatalf("client->target bytes = %d, want %d", result.ClientToTarget.Bytes, len(request))
		}
		if result.TargetToClient.Bytes != int64(len(response)) {
			t.Fatalf("target->client bytes = %d, want %d", result.TargetToClient.Bytes, len(response))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after both TCP half-closes")
	}
}

func TestCopyConnFallsBackForNonTCPConnections(t *testing.T) {
	sender, relaySource := net.Pipe()
	relayDestination, receiver := net.Pipe()
	defer sender.Close()
	defer relaySource.Close()
	defer relayDestination.Close()
	defer receiver.Close()

	payload := []byte("portable buffered relay")
	resultCh := make(chan relayDirectionResult, 1)
	go func() {
		copied, err := copyConn(relayDestination, relaySource)
		resultCh <- relayDirectionResult{Bytes: copied, Err: err}
	}()

	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(payload)
		_ = sender.Close()
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("receiver payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultCh:
		if result.Err != nil {
			t.Fatalf("copyConn() error = %v", result.Err)
		}
		if result.Bytes != int64(len(payload)) {
			t.Fatalf("copyConn() bytes = %d, want %d", result.Bytes, len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("copyConn did not finish after source close")
	}
}

func TestRelayBidirectionalStopsOnUpstreamReset(t *testing.T) {
	client, proxyClient := newTCPPair(t)
	proxyTarget, backend := newTCPPair(t)
	defer client.Close()
	defer proxyClient.Close()
	defer proxyTarget.Close()

	deadline := time.Now().Add(3 * time.Second)
	for _, conn := range []net.Conn{client, proxyClient, proxyTarget, backend} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	resultCh := make(chan relayResult, 1)
	go func() {
		resultCh <- relayBidirectional(context.Background(), proxyClient, proxyTarget)
	}()

	if err := backend.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultCh:
		if result.TargetToClient.Err == nil {
			t.Fatal("upstream reset did not produce a target read error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after upstream reset")
	}
}

func TestRelayBidirectionalStopsOnClientReset(t *testing.T) {
	client, proxyClient := newTCPPair(t)
	proxyTarget, backend := newTCPPair(t)
	defer proxyClient.Close()
	defer proxyTarget.Close()
	defer backend.Close()

	deadline := time.Now().Add(3 * time.Second)
	for _, conn := range []net.Conn{client, proxyClient, proxyTarget, backend} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	resultCh := make(chan relayResult, 1)
	go func() {
		resultCh <- relayBidirectional(context.Background(), proxyClient, proxyTarget)
	}()

	if err := client.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-resultCh:
		if result.ClientToTarget.Err == nil {
			t.Fatal("client reset did not produce a client read error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after client reset")
	}
}

func TestReportRouteRelayIgnoresAmbiguousCopyErrors(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := &config.Rule{Name: "copy-errors", Mode: config.ModeBoost}
	now := time.Now()
	attempt, err := registry.begin(rule, "127.0.0.1:443", now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(attempt, time.Millisecond, nil, now)

	result := relayResult{
		ClientToTarget: relayDirectionResult{Err: errors.New("ambiguous io.Copy error")},
	}
	for range routeFailureThreshold {
		reportRouteRelay(attempt, result)
	}

	snapshot := registry.snapshot(rule, "127.0.0.1:443", now)
	if snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("ambiguous copy errors changed route health: %+v", snapshot)
	}
}

func TestReportRouteRelayDoesNotTreatErroredBytesAsRecovery(t *testing.T) {
	registry := newRouteHealthRegistry()
	rule := &config.Rule{Name: "copy-error-recovery", Mode: config.ModeBoost}
	now := time.Now()
	attempt, err := registry.begin(rule, "127.0.0.1:443", now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(attempt, time.Millisecond, errors.New("dial failed"), now)

	reportRouteRelay(attempt, relayResult{
		ClientToTarget: relayDirectionResult{
			Bytes: 1,
			Err:   errors.New("ambiguous io.Copy error"),
		},
	})

	snapshot := registry.snapshot(rule, "127.0.0.1:443", now)
	if snapshot.ConsecutiveFailures != 1 {
		t.Fatalf("errored relay reset route failures: %+v", snapshot)
	}
}

func TestRelayBidirectionalContextCancellationStopsIdleCopies(t *testing.T) {
	client, proxyClient := newTCPPair(t)
	proxyTarget, backend := newTCPPair(t)
	defer client.Close()
	defer proxyClient.Close()
	defer proxyTarget.Close()
	defer backend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan relayResult, 1)
	go func() {
		resultCh <- relayBidirectional(ctx, proxyClient, proxyTarget)
	}()
	cancel()

	select {
	case <-resultCh:
	case <-time.After(3 * time.Second):
		t.Fatal("idle io.Copy calls did not stop after context cancellation")
	}
}

func newTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		return dialed, conn
	case err := <-acceptErr:
		dialed.Close()
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		dialed.Close()
		t.Fatal("timed out accepting TCP pair")
	}
	return nil, nil
}
