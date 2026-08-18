package controller

import (
	"context"
	"errors"
	"io"
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

func TestUpstreamRelayErrorOnlyClassifiesUpstreamOperations(t *testing.T) {
	upstreamWrite := errors.New("upstream write reset")
	upstreamRead := errors.New("upstream read reset")
	clientWrite := errors.New("client write reset")
	clientRead := errors.New("client read reset")

	tests := []struct {
		name   string
		result relayResult
		want   bool
	}{
		{name: "target write", result: relayResult{ClientToTarget: relayDirectionResult{Err: upstreamWrite, upstreamFailure: true}}, want: true},
		{name: "target read", result: relayResult{TargetToClient: relayDirectionResult{Err: upstreamRead, upstreamFailure: true}}, want: true},
		{name: "client read", result: relayResult{ClientToTarget: relayDirectionResult{Err: clientRead}}, want: false},
		{name: "client write", result: relayResult{TargetToClient: relayDirectionResult{Err: clientWrite}}, want: false},
		{name: "ambiguous", result: relayResult{TargetToClient: relayDirectionResult{Err: errors.New("closed")}}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := upstreamRelayError(test.result) != nil; got != test.want {
				t.Fatalf("upstreamRelayError() classified=%v, want %v", got, test.want)
			}
		})
	}
}

func TestRelayBidirectionalClassifiesRealUpstreamReset(t *testing.T) {
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
		if !result.TargetToClient.upstreamFailure {
			t.Fatalf("target read error not attributed upstream: %v", result.TargetToClient.Err)
		}
		if upstreamRelayError(result) == nil {
			t.Fatal("real upstream reset was not reported to route health")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after upstream reset")
	}
}

func TestRelayBidirectionalDoesNotClassifyRealClientResetAsUpstream(t *testing.T) {
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
		if result.ClientToTarget.upstreamFailure {
			t.Fatalf("client reset attributed upstream: %v", result.ClientToTarget.Err)
		}
		if upstreamRelayError(result) != nil {
			t.Fatalf("client reset poisoned route health: %v", upstreamRelayError(result))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after client reset")
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
