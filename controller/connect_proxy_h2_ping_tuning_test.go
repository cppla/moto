package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"moto/config"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	xhttp2 "moto/internal/browserhttp2"
)

// TestHTTP2ConnectPingTuning measures real seconds using the same certificate-
// verified uTLS transport and frame-level peer as the ordinary PING tests. It
// deliberately injects ACK behavior, not network delay/loss; tc netem tests
// exercise those separately. No production timeout is scaled down.
//
// Run all independent cases together (the longest takes about 75 seconds):
//
//	MOTO_H2_PING_TUNING_TEST=1 go test ./controller -run '^TestHTTP2ConnectPingTuning$' -count=1 -parallel=24 -timeout=3m -v
func TestHTTP2ConnectPingTuning(t *testing.T) {
	if os.Getenv("MOTO_H2_PING_TUNING_TEST") != "1" {
		t.Skip("set MOTO_H2_PING_TUNING_TEST=1 for the real-clock H2 PING parameter experiment")
	}
	for _, readIdle := range []time.Duration{10 * time.Second, 15 * time.Second, 30 * time.Second} {
		for _, pingTimeout := range []time.Duration{3 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second} {
			t.Run(fmt.Sprintf("blackhole_idle%s_timeout%s", readIdle, pingTimeout), func(t *testing.T) {
				t.Parallel()
				runHTTP2PingTuningBlackhole(t, readIdle, pingTimeout)
			})
		}
	}
	for _, test := range []struct {
		ackDelay    time.Duration
		pingTimeout time.Duration
		wantLoss    bool
	}{
		{4 * time.Second, 3 * time.Second, true},
		{4 * time.Second, 5 * time.Second, false},
		{6 * time.Second, 5 * time.Second, true},
		{6 * time.Second, 10 * time.Second, false},
	} {
		t.Run(fmt.Sprintf("delayed_ack%s_timeout%s", test.ackDelay, test.pingTimeout), func(t *testing.T) {
			t.Parallel()
			runHTTP2PingTuningDelayedACK(t, 10*time.Second, test.pingTimeout, test.ackDelay, test.wantLoss)
		})
	}
}

type http2PingTuningResult struct {
	Scenario                        string    `json:"scenario"`
	ReadIdleSeconds                 float64   `json:"read_idle_seconds"`
	PingTimeoutSeconds              float64   `json:"ping_timeout_seconds"`
	ACKDelaySeconds                 float64   `json:"ack_delay_seconds"`
	Outcome                         string    `json:"outcome"`
	HealthyPINGAfterPayloadSeconds  float64   `json:"healthy_ping_after_payload_seconds,omitempty"`
	PINGAfterPayloadSeconds         float64   `json:"ping_after_payload_seconds"`
	StreamsReleasedAfterPayloadSecs []float64 `json:"streams_released_after_payload_seconds,omitempty"`
	StreamsReleasedAfterPINGSecs    []float64 `json:"streams_released_after_ping_seconds,omitempty"`
	RecoverySeconds                 float64   `json:"recovery_seconds,omitempty"`
	TLSConnections                  uint64    `json:"tls_connections"`
}

func runHTTP2PingTuningBlackhole(t *testing.T, readIdle, pingTimeout time.Duration) {
	t.Helper()
	proxy := newHTTP2PingTestProxy(t, 0)
	manager, target := newHTTP2PingTuningManager(t, proxy, readIdle, pingTimeout)
	first := dialHTTP2PingTuningTunnel(t, manager, target)
	second := dialHTTP2PingTuningTunnel(t, manager, target)
	echoHTTP2PingTuningPayload(t, first, "first-before-healthy-idle")
	lastHealthyPayload := echoHTTP2PingTuningPayload(t, second, "second-before-healthy-idle")

	// Leave both streams completely silent until the physical connection's
	// first PING. Echoes then prove ACK processing and reuse of the same TLS
	// connection, before starting a separate blackhole observation window.
	healthyPING := receiveHTTP2PingTuningEvent(t, proxy.pings, "healthy PING", readIdle+10*time.Second)
	assertHTTP2PingTuningDuration(t, "healthy idle to PING", healthyPING.Sub(lastHealthyPayload), readIdle)
	echoHTTP2PingTuningPayload(t, first, "first-after-healthy-idle")
	lastPayload := echoHTTP2PingTuningPayload(t, second, "second-before-blackhole")
	if got := proxy.accepted.Load(); got != 1 {
		t.Fatalf("healthy idle accepted %d TLS connections, want one shared connection", got)
	}

	proxy.dropFirstPingACK.Store(true)
	reads := startHTTP2PingTuningReads(first, second)
	ping := receiveHTTP2PingTuningEvent(t, proxy.droppedPings, "blackholed PING", readIdle+10*time.Second)
	assertHTTP2PingTuningDuration(t, "blackhole idle to PING", ping.Sub(lastPayload), readIdle)
	releases := awaitHTTP2PingTuningLoss(t, reads, pingTimeout+10*time.Second)
	result := http2PingTuningResult{
		Scenario: "idle_then_ack_blackhole", ReadIdleSeconds: readIdle.Seconds(), PingTimeoutSeconds: pingTimeout.Seconds(),
		Outcome: "expected_connection_loss_and_recovery", HealthyPINGAfterPayloadSeconds: healthyPING.Sub(lastHealthyPayload).Seconds(),
		PINGAfterPayloadSeconds: ping.Sub(lastPayload).Seconds(),
	}
	setHTTP2PingTuningReleaseTimes(t, &result, releases, lastPayload, ping, readIdle, pingTimeout)
	receiveHTTP2PingTuningEvent(t, proxy.closed, "failed TLS connection close", 10*time.Second)
	recoveryStart := time.Now()
	recovered := dialHTTP2PingTuningTunnel(t, manager, target)
	echoHTTP2PingTuningPayload(t, recovered, "recovered-after-ack-blackhole")
	result.RecoverySeconds = time.Since(recoveryStart).Seconds()
	result.TLSConnections = proxy.accepted.Load()
	if result.TLSConnections != 2 {
		t.Fatalf("recovery accepted %d TLS connections, want exactly two", result.TLSConnections)
	}
	logHTTP2PingTuningResult(t, result)
}

func runHTTP2PingTuningDelayedACK(t *testing.T, readIdle, pingTimeout, ackDelay time.Duration, wantLoss bool) {
	t.Helper()
	proxy := newHTTP2PingTestProxy(t, ackDelay)
	manager, target := newHTTP2PingTuningManager(t, proxy, readIdle, pingTimeout)
	first := dialHTTP2PingTuningTunnel(t, manager, target)
	second := dialHTTP2PingTuningTunnel(t, manager, target)
	echoHTTP2PingTuningPayload(t, first, "first-before-delayed-ack")
	lastPayload := echoHTTP2PingTuningPayload(t, second, "second-before-delayed-ack")
	if got := proxy.accepted.Load(); got != 1 {
		t.Fatalf("initial TLS connections = %d, want one shared connection", got)
	}
	var reads <-chan http2PingTuningRead
	if wantLoss {
		reads = startHTTP2PingTuningReads(first, second)
	}
	ping := receiveHTTP2PingTuningEvent(t, proxy.pings, "PING with delayed ACK", readIdle+10*time.Second)
	assertHTTP2PingTuningDuration(t, "delayed ACK idle to PING", ping.Sub(lastPayload), readIdle)
	result := http2PingTuningResult{
		Scenario: "delayed_ack", ReadIdleSeconds: readIdle.Seconds(), PingTimeoutSeconds: pingTimeout.Seconds(),
		ACKDelaySeconds: ackDelay.Seconds(), PINGAfterPayloadSeconds: ping.Sub(lastPayload).Seconds(),
	}
	if wantLoss {
		releases := awaitHTTP2PingTuningLoss(t, reads, pingTimeout+10*time.Second)
		setHTTP2PingTuningReleaseTimes(t, &result, releases, lastPayload, ping, readIdle, pingTimeout)
		// This fixture's frame loop waits before writing its ACK. It sees the
		// client's close after that delay, whereas the blocked stream reads
		// above measure the actual client-side timeout independently.
		receiveHTTP2PingTuningEvent(t, proxy.closed, "delayed ACK connection close", ackDelay+10*time.Second)
		recoveryStart := time.Now()
		recovered := dialHTTP2PingTuningTunnel(t, manager, target)
		echoHTTP2PingTuningPayload(t, recovered, "recovered-after-late-ack")
		result.RecoverySeconds = time.Since(recoveryStart).Seconds()
		result.Outcome = "expected_connection_loss_and_recovery"
		result.TLSConnections = proxy.accepted.Load()
		if result.TLSConnections != 2 {
			t.Fatalf("late ACK recovery accepted %d TLS connections, want exactly two", result.TLSConnections)
		}
	} else {
		// Stay silent beyond the original PING deadline. The delayed ACK must
		// cancel that deadline and preserve both original CONNECT streams.
		timer := time.NewTimer(time.Until(ping.Add(pingTimeout + 250*time.Millisecond)))
		defer timer.Stop()
		select {
		case id := <-proxy.closed:
			t.Fatalf("ACK delayed %v unexpectedly lost TLS connection %d with PingTimeout %v", ackDelay, id, pingTimeout)
		case <-timer.C:
		}
		echoHTTP2PingTuningPayload(t, first, "first-after-delayed-ack")
		echoHTTP2PingTuningPayload(t, second, "second-after-delayed-ack")
		result.Outcome = "original_tls_and_both_streams_preserved"
		result.TLSConnections = proxy.accepted.Load()
		if result.TLSConnections != 1 {
			t.Fatalf("timely ACK accepted %d TLS connections, want original connection", result.TLSConnections)
		}
	}
	logHTTP2PingTuningResult(t, result)
}

func newHTTP2PingTuningManager(t *testing.T, proxy *http2PingTestProxy, readIdle, pingTimeout time.Duration) (*http2ConnectManager, *config.Target) {
	t.Helper()
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = proxy.roots
		transport.ReadIdleTimeout = readIdle
		transport.PingTimeout = pingTimeout
		return transport
	})
	t.Cleanup(manager.closeIdle)
	return manager, &config.Target{
		Address: proxy.listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH2}, ServerName: "127.0.0.1",
		},
	}
}

func dialHTTP2PingTuningTunnel(t *testing.T, manager *http2ConnectManager, target *config.Target) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunnel, err := manager.dial(ctx, target, "service.example:443")
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = tunnel.Close() })
	return tunnel
}

func echoHTTP2PingTuningPayload(t *testing.T, tunnel net.Conn, payload string) time.Time {
	t.Helper()
	completed := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(tunnel, payload); err != nil {
			completed <- err
			return
		}
		response := make([]byte, len(payload))
		_, err := io.ReadFull(tunnel, response)
		if err == nil && string(response) != payload {
			err = fmt.Errorf("echo = %q, want %q", response, payload)
		}
		completed <- err
	}()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("tunnel payload: %v", err)
		}
		return time.Now()
	case <-timer.C:
		t.Fatal("tunnel payload did not complete within 20s")
		return time.Time{}
	}
}

// Existing fixture channels carry connection IDs. Record receipt immediately;
// the bounded timing tolerance includes local scheduling/channel observation.
func receiveHTTP2PingTuningEvent(t *testing.T, events <-chan uint64, name string, timeout time.Duration) time.Time {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case id := <-events:
		observed := time.Now()
		if id != 1 {
			t.Fatalf("%s on TLS connection %d, want original connection 1", name, id)
		}
		return observed
	case <-timer.C:
		t.Fatalf("timed out after %v waiting for %s", timeout, name)
		return time.Time{}
	}
}

type http2PingTuningRead struct {
	stream int
	at     time.Time
	err    error
}

func startHTTP2PingTuningReads(tunnels ...net.Conn) <-chan http2PingTuningRead {
	reads := make(chan http2PingTuningRead, len(tunnels))
	for stream, tunnel := range tunnels {
		go func() {
			_, err := tunnel.Read(make([]byte, 1))
			reads <- http2PingTuningRead{stream: stream, at: time.Now(), err: err}
		}()
	}
	return reads
}

func awaitHTTP2PingTuningLoss(t *testing.T, reads <-chan http2PingTuningRead, timeout time.Duration) [2]time.Time {
	t.Helper()
	var releases [2]time.Time
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for range releases {
		select {
		case read := <-reads:
			if read.err == nil || !strings.Contains(read.err.Error(), "client connection lost") {
				t.Fatalf("stream %d read = %v, want expected HTTP/2 health-check connection loss", read.stream, read.err)
			}
			releases[read.stream] = read.at
		case <-timer.C:
			t.Fatalf("PING timeout did not release both streams within %v", timeout)
		}
	}
	return releases
}

func setHTTP2PingTuningReleaseTimes(t *testing.T, result *http2PingTuningResult, releases [2]time.Time, payload, ping time.Time, readIdle, pingTimeout time.Duration) {
	t.Helper()
	for stream, released := range releases {
		fromPayload, fromPING := released.Sub(payload), released.Sub(ping)
		assertHTTP2PingTuningDuration(t, fmt.Sprintf("stream %d payload to release", stream), fromPayload, readIdle+pingTimeout)
		assertHTTP2PingTuningDuration(t, fmt.Sprintf("stream %d PING to release", stream), fromPING, pingTimeout)
		result.StreamsReleasedAfterPayloadSecs = append(result.StreamsReleasedAfterPayloadSecs, fromPayload.Seconds())
		result.StreamsReleasedAfterPINGSecs = append(result.StreamsReleasedAfterPINGSecs, fromPING.Seconds())
	}
}

func assertHTTP2PingTuningDuration(t *testing.T, name string, observed, expected time.Duration) {
	t.Helper()
	if observed < expected-500*time.Millisecond || observed > expected+3*time.Second {
		t.Fatalf("%s = %v, want %v (-500ms/+3s scheduling tolerance)", name, observed, expected)
	}
}

func logHTTP2PingTuningResult(t *testing.T, result http2PingTuningResult) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT %s", encoded)
}
