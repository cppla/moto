package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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
		if result.TargetToClient.Origin != relayErrorOriginPrimary {
			t.Fatalf("target-to-client origin = %v, want primary", result.TargetToClient.Origin)
		}
		if result.StopCause.Kind != relayStopCopyError ||
			result.StopCause.Direction != relayDirectionTargetToClient {
			t.Fatalf("stop cause = %+v, want target-to-client copy error", result.StopCause)
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
		if result.ClientToTarget.Origin != relayErrorOriginPrimary {
			t.Fatalf("client-to-target origin = %v, want primary", result.ClientToTarget.Origin)
		}
		if result.StopCause.Kind != relayStopCopyError ||
			result.StopCause.Direction != relayDirectionClientToTarget {
			t.Fatalf("stop cause = %+v, want client-to-target copy error", result.StopCause)
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

func TestRelayInvalidatesBoostWinnerOnlyForActionableFailures(t *testing.T) {
	clientReadReset := &net.OpError{Op: "writeto", Net: "tcp", Err: &net.OpError{
		Op: "read", Net: "tcp", Err: syscall.ECONNRESET,
	}}
	upstreamWriteReset := &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}
	upstreamReadReset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	clientWriteBrokenPipe := &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}

	tests := []struct {
		name   string
		result relayResult
		want   bool
	}{
		{name: "clean relay", result: relayResult{}, want: false},
		{
			name: "client read reset",
			result: relayResult{
				ClientToTarget: relayDirectionResult{
					Err: clientReadReset, Origin: relayErrorOriginPrimary,
				},
				TargetToClient: relayDirectionResult{
					Err: net.ErrClosed, Origin: relayErrorOriginSecondary,
				},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			want: false,
		},
		{
			name: "upstream write reset",
			result: relayResult{
				ClientToTarget: relayDirectionResult{
					Err: upstreamWriteReset, Origin: relayErrorOriginPrimary,
				},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			want: true,
		},
		{
			name: "upstream read reset",
			result: relayResult{
				TargetToClient: relayDirectionResult{
					Err: upstreamReadReset, Origin: relayErrorOriginPrimary,
				},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
				},
			},
			want: true,
		},
		{
			name: "write to closed client",
			result: relayResult{
				TargetToClient: relayDirectionResult{
					Err: clientWriteBrokenPipe, Origin: relayErrorOriginPrimary,
				},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
				},
			},
			want: false,
		},
		{
			name: "context shutdown",
			result: relayResult{
				ClientToTarget: relayDirectionResult{
					Err: errors.New("relay context closed"), Origin: relayErrorOriginUnknown,
				},
				StopCause: relayStopCause{Kind: relayStopContext},
			},
			want: false,
		},
		{
			name: "ambiguous primary error",
			result: relayResult{
				ClientToTarget: relayDirectionResult{
					Err: errors.New("ambiguous relay failure"), Origin: relayErrorOriginPrimary,
				},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := relayInvalidatesBoostWinner(test.result); got != test.want {
				t.Fatalf("invalidates winner = %t, want %t", got, test.want)
			}
		})
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
	case result := <-resultCh:
		if result.StopCause.Kind != relayStopContext {
			t.Fatalf("stop cause = %+v, want context cancellation", result.StopCause)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle io.Copy calls did not stop after context cancellation")
	}
}

func TestRelayStopArbiterKeepsCauseAndInterruptTogether(t *testing.T) {
	interrupts := 0
	arbiter := relayStopArbiter{interrupt: func() { interrupts++ }}
	primaryCause := relayStopCause{
		Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
	}
	if origin := arbiter.observeError(primaryCause); origin != relayErrorOriginPrimary {
		t.Fatalf("first origin = %v, want primary", origin)
	}
	if interrupts != 1 || arbiter.cause != primaryCause {
		t.Fatalf("interrupts=%d cause=%+v, want one interrupt and %+v",
			interrupts, arbiter.cause, primaryCause)
	}
	if arbiter.claim(relayStopCause{Kind: relayStopContext}) {
		t.Fatal("second stop cause replaced the first")
	}
	if interrupts != 1 || arbiter.cause != primaryCause {
		t.Fatalf("second claim changed stop: interrupts=%d cause=%+v", interrupts, arbiter.cause)
	}
}

func TestRelayStopArbiterDistinguishesConcurrentAndSecondaryErrors(t *testing.T) {
	claimed := relayStopArbiter{}
	claimed.phase.Store(uint32(relayStopPhaseClaimed))
	if origin := claimed.observeError(relayStopCause{
		Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
	}); origin != relayErrorOriginConcurrent {
		t.Fatalf("error observed before close origin = %v, want concurrent", origin)
	}

	closing := relayStopArbiter{}
	closing.phase.Store(uint32(relayStopPhaseClosing))
	if origin := closing.observeError(relayStopCause{
		Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
	}); origin != relayErrorOriginSecondary {
		t.Fatalf("error observed after close began origin = %v, want secondary", origin)
	}
}

func TestClassifyRelayError(t *testing.T) {
	unexpected := errors.New("unexpected relay failure")
	http2BodyClosed := errors.New("http2: response body closed")
	expectedClose := &net.OpError{Op: "close", Net: "tcp", Err: syscall.ENOTCONN}
	brokenPipe := &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}
	clientReset := &net.OpError{Op: "writeto", Net: "tcp", Err: &net.OpError{
		Op: "read", Net: "tcp", Err: syscall.ECONNRESET,
	}}
	upstreamWriteReset := &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET}

	tests := []struct {
		name      string
		result    relayResult
		direction relayDirection
		err       error
		want      relayLogDecision
	}{
		{
			name: "client read reset is expected close",
			result: relayResult{
				ClientToTarget: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionClientToTarget,
			err:       clientReset,
			want: relayLogDecision{
				Level: zapcore.DebugLevel, Class: relayLogClassExpectedClose, Primary: true,
			},
		},
		{
			name: "upstream write reset remains warning",
			result: relayResult{
				ClientToTarget: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionClientToTarget,
			err:       upstreamWriteReset,
			want:      relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassPrimary, Primary: true},
		},
		{
			name: "primary copy error stays warning",
			result: relayResult{
				ClientToTarget: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionClientToTarget,
			err:       unexpected,
			want:      relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassPrimary, Primary: true},
		},
		{
			name: "other direction is secondary debug detail",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginSecondary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionTargetToClient,
			err:       http2BodyClosed,
			want:      relayLogDecision{Level: zapcore.DebugLevel, Class: relayLogClassSecondary},
		},
		{
			name: "context shutdown is debug detail",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginSecondary},
				StopCause:      relayStopCause{Kind: relayStopContext},
			},
			direction: relayDirectionTargetToClient,
			err:       http2BodyClosed,
			want:      relayLogDecision{Level: zapcore.DebugLevel, Class: relayLogClassContextClose},
		},
		{
			name: "expected half-close failure is debug detail",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
				},
			},
			direction: relayDirectionTargetToClient,
			err:       expectedClose,
			want: relayLogDecision{
				Level: zapcore.DebugLevel, Class: relayLogClassExpectedClose, Primary: true,
			},
		},
		{
			name: "standalone h2 body close remains warning",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
				},
			},
			direction: relayDirectionTargetToClient,
			err:       http2BodyClosed,
			want:      relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassPrimary, Primary: true},
		},
		{
			name: "concurrent independent error remains warning",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginConcurrent},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionTargetToClient,
			err:       unexpected,
			want:      relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassConcurrent},
		},
		{
			name: "client-bound broken pipe is expected close",
			result: relayResult{
				TargetToClient: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionTargetToClient,
				},
			},
			direction: relayDirectionTargetToClient,
			err:       brokenPipe,
			want: relayLogDecision{
				Level: zapcore.DebugLevel, Class: relayLogClassExpectedClose, Primary: true,
			},
		},
		{
			name: "upstream-bound broken pipe remains warning",
			result: relayResult{
				ClientToTarget: relayDirectionResult{Origin: relayErrorOriginPrimary},
				StopCause: relayStopCause{
					Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
				},
			},
			direction: relayDirectionClientToTarget,
			err:       brokenPipe,
			want:      relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassPrimary, Primary: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyRelayError(test.result, test.direction, test.err); got != test.want {
				t.Fatalf("classification = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestExpectedRelayCloseErrorWindowsErrnos(t *testing.T) {
	tests := []struct {
		name      string
		direction relayDirection
		err       error
		want      bool
	}{
		{
			name:      "winsock not connected",
			direction: relayDirectionClientToTarget,
			err:       &net.OpError{Op: "close", Net: "tcp", Err: windowsWSAENOTCONN},
			want:      true,
		},
		{
			name:      "winsock shutdown",
			direction: relayDirectionClientToTarget,
			err:       &net.OpError{Op: "write", Net: "tcp", Err: windowsWSAESHUTDOWN},
			want:      true,
		},
		{
			name:      "client-bound broken pipe",
			direction: relayDirectionTargetToClient,
			err:       &net.OpError{Op: "write", Net: "tcp", Err: windowsErrorBrokenPipe},
			want:      true,
		},
		{
			name:      "upstream-bound broken pipe",
			direction: relayDirectionClientToTarget,
			err:       &net.OpError{Op: "write", Net: "tcp", Err: windowsErrorBrokenPipe},
			want:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isExpectedRelayCloseErrorForOS("windows", test.direction, test.err); got != test.want {
				t.Fatalf("expected close = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLogRelayDirectionEmitsBoundedClassification(t *testing.T) {
	core, observed := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	result := relayResult{
		ClientToTarget: relayDirectionResult{Origin: relayErrorOriginPrimary},
		TargetToClient: relayDirectionResult{Origin: relayErrorOriginSecondary},
		StopCause: relayStopCause{
			Kind: relayStopCopyError, Direction: relayDirectionClientToTarget,
		},
	}
	baseFields := []zap.Field{zap.String("ruleName", "relay-log-test")}

	logRelayDirection(logger, "primary", baseFields, result,
		relayDirectionClientToTarget, errors.New("client reset"))
	logRelayDirection(logger, "secondary", baseFields, result,
		relayDirectionTargetToClient, errors.New("http2: response body closed"))

	entries := observed.AllUntimed()
	if len(entries) != 2 {
		t.Fatalf("log entries = %d, want 2", len(entries))
	}
	if entries[0].Level != zapcore.WarnLevel {
		t.Fatalf("primary level = %s, want warn", entries[0].Level)
	}
	if entries[1].Level != zapcore.DebugLevel {
		t.Fatalf("secondary level = %s, want debug", entries[1].Level)
	}
	primaryFields := entries[0].ContextMap()
	if primaryFields["class"] != relayLogClassPrimary || primaryFields["primary"] != true ||
		primaryFields["direction"] != string(relayDirectionClientToTarget) ||
		primaryFields["origin"] != "primary" || primaryFields["event"] != "relay_termination" {
		t.Fatalf("primary fields = %#v", primaryFields)
	}
	secondaryFields := entries[1].ContextMap()
	if secondaryFields["class"] != relayLogClassSecondary || secondaryFields["primary"] != false ||
		secondaryFields["direction"] != string(relayDirectionTargetToClient) ||
		secondaryFields["origin"] != "secondary" || secondaryFields["event"] != "relay_termination" {
		t.Fatalf("secondary fields = %#v", secondaryFields)
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
