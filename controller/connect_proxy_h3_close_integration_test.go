package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// These tests exercise actual loopback QUIC connections and multiplexed CONNECT
// streams. Error classification is not supplied as a synthetic Go error.
func TestHTTP3PhysicalCloseIntegration(t *testing.T) {
	const secret = "private-peer-close-reason-do-not-log"
	const password = "private-test-auth-do-not-log"
	const destination = "private-destination.example:443"
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture:"+password))

	previousLogger := utils.Logger
	core, observed := observer.New(zapcore.DebugLevel)
	utils.Logger = zap.New(core)
	t.Cleanup(func() { utils.Logger = previousLogger })

	for _, test := range []struct {
		name          string
		streams       int
		closeStreams  bool
		idle          bool
		managerClose  bool
		code          quic.ApplicationErrorCode
		wantClass     string
		wantOrigin    string
		wantLevel     zapcore.Level
		wantCloseCode bool
	}{
		{
			name: "remote application error affects four streams but counts once", streams: 4,
			code: 0x1234, wantClass: "remote_application_close", wantOrigin: "remote",
			wantLevel: zapcore.WarnLevel, wantCloseCode: true,
		},
		{
			name: "graceful remote closure without active streams", streams: 1, closeStreams: true,
			code: quic.ApplicationErrorCode(http3.ErrCodeNoError), wantClass: "remote_application_close",
			wantOrigin: "remote", wantLevel: zapcore.DebugLevel, wantCloseCode: true,
		},
		{
			name: "idle timeout after successful traffic", streams: 1, closeStreams: true, idle: true,
			wantClass: "idle_timeout", wantOrigin: "unknown", wantLevel: zapcore.DebugLevel,
		},
		{
			name: "manager close is local not a remote failure", streams: 3, managerClose: true,
			wantClass: "local_close", wantOrigin: "local", wantLevel: zapcore.DebugLevel, wantCloseCode: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed.TakeAll()
			endpoint, roots, peers, connectionCount := startHTTP3CloseObservationServer(t, wantAuthorization)
			manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
				transport := newHTTP3ConnectTransportWithOwner(key, owner)
				transport.TLSClientConfig.RootCAs = roots
				if test.idle {
					// Production keepalive and timeout settings remain unchanged.
					transport.QUICConfig.KeepAlivePeriod = 0
					transport.QUICConfig.MaxIdleTimeout = 200 * time.Millisecond
				}
				return transport
			})
			t.Cleanup(manager.close)
			target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
				Protocols: []string{config.ConnectProxyH3},
				BasicAuth: &config.BasicAuthConfig{Username: "fixture", Password: password},
			}}
			var tunnels []net.Conn
			for index := 0; index < test.streams; index++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				tunnel, err := manager.dial(ctx, target, destination)
				cancel()
				if err != nil {
					t.Fatalf("open real H3 stream %d: %v", index, err)
				}
				tunnels = append(tunnels, tunnel)
				t.Cleanup(func() { _ = tunnel.Close() })
				// CONNECT pipe connections intentionally do not support deadlines.
				// Bound this real payload exchange by closing only this test stream.
				payloadTimer := time.AfterFunc(3*time.Second, func() { _ = tunnel.Close() })
				t.Cleanup(func() { payloadTimer.Stop() })
				payload := []byte("successful-data-before-physical-close")
				if _, err := tunnel.Write(payload); err != nil {
					t.Fatalf("write real H3 payload: %v", err)
				}
				echo := make([]byte, len(payload))
				if _, err := io.ReadFull(tunnel, echo); err != nil || string(echo) != string(payload) {
					t.Fatalf("read real H3 payload: got %q, err %v", echo, err)
				}
				payloadTimer.Stop()
			}
			var peer *quic.Conn
			select {
			case peer = <-peers:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not expose its real QUIC connection")
			}
			if got := connectionCount.Load(); got != 1 {
				t.Fatalf("physical QUIC connections = %d for %d streams, want 1", got, test.streams)
			}
			if test.closeStreams {
				for _, tunnel := range tunnels {
					_ = tunnel.Close()
				}
			}
			if test.managerClose {
				manager.close()
			} else if !test.idle {
				if err := peer.CloseWithError(test.code, secret); err != nil {
					t.Fatalf("server application close: %v", err)
				}
			}

			entry := waitHTTP3PhysicalCloseEntry(t, observed, endpoint)
			fields := entry.ContextMap()
			if fields["closeClass"] != test.wantClass || fields["closeOrigin"] != test.wantOrigin || entry.Level != test.wantLevel {
				t.Fatalf("close classification: level=%s fields=%v", entry.Level, fields)
			}
			if generation, ok := fields["generation"].(uint64); !ok || generation == 0 {
				t.Fatalf("missing physical connection generation: %v", fields)
			}
			if age, ok := fields["connectionAgeMs"].(int64); !ok || age < 0 {
				t.Fatalf("invalid connection age: %v", fields)
			}
			wantActive := test.streams
			if test.closeStreams {
				wantActive = 0
			}
			if got := fields["activeTunnelsAtObservation"]; got != int64(wantActive) {
				t.Fatalf("active tunnels = %v, want %d", got, wantActive)
			}
			code, hasCode := fields["closeCode"]
			if hasCode != test.wantCloseCode || hasCode && code != uint64(test.code) {
				t.Fatalf("close code = %v (present=%t), want %d (present=%t)", code, hasCode, test.code, test.wantCloseCode)
			}

			// Retiring before assertions also shuts down the sampler and any unused
			// replacement slot. An idempotent manager close must not count again.
			manager.close()
			manager.close()
			snapshot := manager.snapshotGauges()
			if len(snapshot.closures) != 1 || snapshot.closures[0].target != endpoint ||
				snapshot.closures[0].reason != test.wantClass || snapshot.closures[0].count != 1 {
				t.Fatalf("one physical closure must count once despite %d streams: %+v", test.streams, snapshot.closures)
			}
			entries := observed.FilterField(zap.String("event", "h3_connection_closed")).All()
			if len(entries) != 1 {
				t.Fatalf("close log count = %d, want exactly 1", len(entries))
			}
			serialized, err := json.Marshal(observed.AllUntimed())
			if err != nil {
				t.Fatal(err)
			}
			var metrics strings.Builder
			renderHTTP3CloseMetrics(&metrics, snapshot.closures)
			for _, sensitive := range []string{secret, password, wantAuthorization, destination} {
				if strings.Contains(string(serialized), sensitive) || strings.Contains(metrics.String(), sensitive) {
					t.Error("connection diagnostics leaked peer reason, credentials, or CONNECT destination")
				}
			}
			for _, forbiddenLabel := range []string{"generation=", "closeCode=", "connectionAgeMs=", "activeTunnelsAtObservation="} {
				if strings.Contains(metrics.String(), forbiddenLabel) {
					t.Errorf("unbounded or per-connection metric label %q", forbiddenLabel)
				}
			}
		})
	}
}

func waitHTTP3PhysicalCloseEntry(t *testing.T, observed *observer.ObservedLogs, endpoint string) observer.LoggedEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries := observed.FilterField(zap.String("event", "h3_connection_closed")).
			FilterField(zap.String("targetAddr", endpoint)).All()
		if len(entries) > 0 {
			return entries[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("real QUIC close watcher did not publish its diagnostic")
	return observer.LoggedEntry{}
}

func startHTTP3CloseObservationServer(t *testing.T, authorization string) (string, *x509.CertPool, <-chan *quic.Conn, *atomic.Int64) {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for real H3 fixture: %v", err)
	}
	connections := make(chan *quic.Conn, 8)
	count := new(atomic.Int64)
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			count.Add(1)
			connections <- connection
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodConnect || request.Header.Get("Proxy-Authorization") != authorization {
				writer.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			buffer := make([]byte, 1024)
			for {
				n, err := request.Body.Read(buffer)
				if n > 0 {
					if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
						return
					}
					writer.(http.Flusher).Flush()
				}
				if err != nil {
					return
				}
			}
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packetConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packetConn.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("close real H3 server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("real H3 server failed to exit")
		}
	})
	return packetConn.LocalAddr().String(), roots, connections, count
}
