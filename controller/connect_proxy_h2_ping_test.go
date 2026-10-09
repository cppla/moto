package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
	xhttp2 "moto/internal/browserhttp2"
)

func TestHTTP2ConnectPingProductionDefaults(t *testing.T) {
	transport := newHTTP2ConnectTransport(http2ConnectTransportKey{
		address: "proxy.example:443", serverName: "proxy.example",
	})
	if got := transport.ReadIdleTimeout; got != 15*time.Second {
		t.Fatalf("ReadIdleTimeout = %v, want 15s", got)
	}
	if got := transport.PingTimeout; got != 10*time.Second {
		t.Fatalf("PingTimeout = %v, want 10s", got)
	}
	if got := transport.IdleConnTimeout; got != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want existing 90s idle-pool lifetime", got)
	}
}

func TestHTTP2ConnectPingKeepsIdleTunnelsReusable(t *testing.T) {
	for _, ackDelay := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(ackDelay.String(), func(t *testing.T) {
			proxy := newHTTP2PingTestProxy(t, ackDelay)
			manager, target := proxy.newManager(t)
			first := dialHTTP2PingTestTunnel(t, manager, target)

			// Several idle checks prove that an active but silent tunnel is not
			// treated as an idle pooled connection or a failed upstream.
			for range 3 {
				if connectionID := receiveHTTP2PingTestEvent(t, proxy.pings, "idle PING"); connectionID != 1 {
					t.Fatalf("PING used connection %d, want original connection 1", connectionID)
				}
			}
			assertHTTP2PingTestEcho(t, first, "first-after-idle")
			second := dialHTTP2PingTestTunnel(t, manager, target)
			assertHTTP2PingTestEcho(t, second, "second-after-idle")
			if got := proxy.accepted.Load(); got != 1 {
				t.Fatalf("accepted TLS connections = %d, want 1 after healthy idle PINGs", got)
			}
		})
	}
}

func TestHTTP2ConnectPingTimeoutClosesSharedConnectionAndReconnects(t *testing.T) {
	proxy := newHTTP2PingTestProxy(t, 0)
	manager, target := proxy.newManager(t)
	first := dialHTTP2PingTestTunnel(t, manager, target)
	second := dialHTTP2PingTestTunnel(t, manager, target)
	assertHTTP2PingTestEcho(t, first, "first-before-blackhole")
	assertHTTP2PingTestEcho(t, second, "second-before-blackhole")
	if got := proxy.accepted.Load(); got != 1 {
		t.Fatalf("initial TLS connections = %d, want one shared connection", got)
	}

	// The TCP/TLS socket stays open; only the peer's PING acknowledgements
	// disappear. Neither a setup deadline nor a server close can rescue it.
	proxy.dropFirstPingACK.Store(true)
	readErrors := make(chan error, 2)
	for _, tunnel := range []net.Conn{first, second} {
		go func() {
			_, err := tunnel.Read(make([]byte, 1))
			readErrors <- err
		}()
	}
	if connectionID := receiveHTTP2PingTestEvent(t, proxy.droppedPings, "dropped PING ACK"); connectionID != 1 {
		t.Fatalf("dropped PING used connection %d, want 1", connectionID)
	}
	for range 2 {
		select {
		case err := <-readErrors:
			if err == nil || !strings.Contains(err.Error(), "client connection lost") {
				t.Fatalf("blocked tunnel Read error = %v, want HTTP/2 health-check connection loss", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("PING timeout did not release all blocked tunnels")
		}
	}
	if connectionID := receiveHTTP2PingTestEvent(t, proxy.closed, "failed connection close"); connectionID != 1 {
		t.Fatalf("closed TLS connection = %d, want 1", connectionID)
	}

	recovered := dialHTTP2PingTestTunnel(t, manager, target)
	assertHTTP2PingTestEcho(t, recovered, "new-connection-after-blackhole")
	if got := proxy.accepted.Load(); got != 2 {
		t.Fatalf("TLS connections after recovery = %d, want exactly 2", got)
	}
}

// A frame-level TLS peer lets the test selectively withhold PING ACKs while
// retaining real certificate verification, uTLS, pooling, and CONNECT streams.
type http2PingTestProxy struct {
	listener net.Listener
	roots    *x509.CertPool
	ackDelay time.Duration

	accepted           atomic.Uint64
	dropFirstPingACK   atomic.Bool
	dropPingACKThrough atomic.Uint64
	pings              chan uint64
	droppedPings       chan uint64
	closed             chan uint64
	stop               chan struct{}
	acceptDone         chan struct{}
	workers            sync.WaitGroup
	mu                 sync.Mutex
	connections        map[net.Conn]struct{}
}

func newHTTP2PingTestProxy(t *testing.T, ackDelay time.Duration) *http2PingTestProxy {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certificateSource.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: certificates,
		NextProtos:   []string{xhttp2.NextProtoTLS},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http2PingTestProxy{
		listener: listener, roots: roots, ackDelay: ackDelay,
		pings: make(chan uint64, 32), droppedPings: make(chan uint64, 32),
		closed: make(chan uint64, 32), stop: make(chan struct{}), acceptDone: make(chan struct{}),
		connections: make(map[net.Conn]struct{}),
	}
	go func() {
		defer close(proxy.acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			id := proxy.accepted.Add(1)
			proxy.mu.Lock()
			proxy.connections[connection] = struct{}{}
			proxy.mu.Unlock()
			proxy.workers.Add(1)
			go proxy.serve(t, connection, id)
		}
	}()
	t.Cleanup(func() {
		close(proxy.stop)
		_ = listener.Close()
		<-proxy.acceptDone
		proxy.mu.Lock()
		for connection := range proxy.connections {
			_ = connection.Close()
		}
		proxy.mu.Unlock()
		proxy.workers.Wait()
	})
	return proxy
}

func (proxy *http2PingTestProxy) newManager(t *testing.T) (*http2ConnectManager, *config.Target) {
	t.Helper()
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = proxy.roots
		// Keep production defaults intact, shortening only test observation.
		transport.ReadIdleTimeout = 150 * time.Millisecond
		transport.PingTimeout = time.Second
		return transport
	})
	t.Cleanup(manager.closeIdle)
	return manager, &config.Target{
		Address: proxy.listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH2},
			ServerName: "127.0.0.1",
		},
	}
}

func (proxy *http2PingTestProxy) serve(t *testing.T, connection net.Conn, id uint64) {
	defer proxy.workers.Done()
	defer func() {
		_ = connection.Close()
		proxy.mu.Lock()
		delete(proxy.connections, connection)
		proxy.mu.Unlock()
		select {
		case proxy.closed <- id:
		case <-proxy.stop:
		}
	}()
	preface := make([]byte, len(xhttp2.ClientPreface))
	if _, err := io.ReadFull(connection, preface); err != nil {
		return
	}
	if string(preface) != xhttp2.ClientPreface {
		t.Error("TLS peer did not receive HTTP/2 client preface")
		return
	}
	framer := xhttp2.NewFramer(connection, connection)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := framer.WriteSettings(xhttp2.Setting{ID: xhttp2.SettingMaxConcurrentStreams, Val: 100}); err != nil {
		return
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch frame := frame.(type) {
		case *xhttp2.SettingsFrame:
			if !frame.IsAck() {
				err = framer.WriteSettingsAck()
			}
		case *xhttp2.MetaHeadersFrame:
			if frame.PseudoValue("method") != http.MethodConnect || frame.PseudoValue("authority") != "service.example:443" {
				t.Errorf("unexpected H2 request: method=%q authority=%q", frame.PseudoValue("method"), frame.PseudoValue("authority"))
				return
			}
			var headers bytes.Buffer
			encoder := hpack.NewEncoder(&headers)
			if err = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err == nil {
				err = framer.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: headers.Bytes(), EndHeaders: true})
			}
		case *xhttp2.DataFrame:
			err = framer.WriteData(frame.StreamID, frame.StreamEnded(), frame.Data())
		case *xhttp2.PingFrame:
			if frame.IsAck() {
				continue
			}
			select {
			case proxy.pings <- id:
			case <-proxy.stop:
				return
			}
			if id == 1 && proxy.dropFirstPingACK.Load() || id <= proxy.dropPingACKThrough.Load() {
				select {
				case proxy.droppedPings <- id:
				case <-proxy.stop:
					return
				}
				continue
			}
			if proxy.ackDelay > 0 {
				timer := time.NewTimer(proxy.ackDelay)
				select {
				case <-timer.C:
				case <-proxy.stop:
					timer.Stop()
					return
				}
			}
			err = framer.WritePing(true, frame.Data)
		}
		if err != nil {
			return
		}
	}
}

func dialHTTP2PingTestTunnel(t *testing.T, manager *http2ConnectManager, target *config.Target) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := manager.dial(ctx, target, "service.example:443")
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = tunnel.Close() })
	return tunnel
}

func assertHTTP2PingTestEcho(t *testing.T, tunnel net.Conn, payload string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(tunnel, payload); err != nil {
			done <- err
			return
		}
		response := make([]byte, len(payload))
		_, err := io.ReadFull(tunnel, response)
		if err == nil && string(response) != payload {
			err = fmt.Errorf("echo = %q, want %q", response, payload)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tunnel payload: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel payload did not make progress")
	}
}

func receiveHTTP2PingTestEvent(t *testing.T, events <-chan uint64, name string) uint64 {
	t.Helper()
	select {
	case id := <-events:
		return id
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return 0
	}
}
