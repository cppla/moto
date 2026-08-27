package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
)

func TestHTTP2ConnectTunnelBasicAuthAndServerFirstData(t *testing.T) {
	const (
		destination = "service.example:443"
		username    = "moto"
		password    = "secret"
		banner      = "SERVER-FIRST\n"
	)
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", request.Proto)
		}
		if request.Method != http.MethodConnect || request.Host != destination || request.RequestURI != destination {
			t.Errorf("CONNECT method/authority/URI = %q/%q/%q", request.Method, request.Host, request.RequestURI)
		}
		if got := request.Header.Get("Proxy-Authorization"); got != expectedAuth {
			t.Errorf("Proxy-Authorization = %q", got)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, banner)
		w.(http.Flusher).Flush()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(request.Body, payload); err != nil {
			return
		}
		_, _ = w.Write(bytes.ToUpper(payload))
		w.(http.Flusher).Flush()
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()

	target := http2ConnectTestTarget(proxy, username, password)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, destination)
	if err != nil {
		t.Fatalf("dial() error = %v", err)
	}
	defer connection.Close()

	gotBanner := make([]byte, len(banner))
	if _, err := io.ReadFull(connection, gotBanner); err != nil {
		t.Fatalf("read server-first data: %v", err)
	}
	if string(gotBanner) != banner {
		t.Fatalf("server-first data = %q", gotBanner)
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(response) != "PING" {
		t.Fatalf("tunnel response = %q", response)
	}
	if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
}

func TestHTTP2ConnectTunnelSurvivesSetupContextCancellation(t *testing.T) {
	const (
		destination = "service.example:443"
		banner      = "READY\n"
	)
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, banner)
		w.(http.Flusher).Flush()
		payload := make([]byte, 4)
		if _, err := io.ReadFull(request.Body, payload); err != nil {
			return
		}
		_, _ = w.Write(bytes.ToUpper(payload))
		w.(http.Flusher).Flush()
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()

	setupCtx, cancelSetup := context.WithCancel(context.Background())
	connection, err := manager.dial(setupCtx, http2ConnectTestTarget(proxy, "", ""), destination)
	if err != nil {
		cancelSetup()
		t.Fatalf("dial() error = %v", err)
	}
	cancelSetup()
	defer connection.Close()

	gotBanner := make([]byte, len(banner))
	if _, err := io.ReadFull(connection, gotBanner); err != nil {
		t.Fatalf("read after canceling setup context: %v", err)
	}
	if string(gotBanner) != banner {
		t.Fatalf("server-first data = %q", gotBanner)
	}
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatalf("write after canceling setup context: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("read response after canceling setup context: %v", err)
	}
	if string(response) != "PING" {
		t.Fatalf("tunnel response = %q", response)
	}
}

func TestHTTP2ConnectSetupPreservesDeadlineCause(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	proxy := newHTTP2ConnectTestServer(t, func(_ http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	connection, err := manager.dial(ctx, http2ConnectTestTarget(proxy, "", ""), "stalled.example:443")
	if connection != nil {
		_ = connection.Close()
		t.Fatal("stalled HTTP/2 setup returned a tunnel")
	}
	select {
	case <-requestStarted:
	default:
		t.Fatal("HTTP/2 proxy did not receive CONNECT headers")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("HTTP/2 setup error = %v, want context deadline exceeded", err)
	}
}

func TestHTTP2ConnectCloseWriteDeliversEndStreamAndKeepsResponseReadable(t *testing.T) {
	const payload = "request-before-half-close"
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body through END_STREAM: %v", err)
			return
		}
		_, _ = io.WriteString(w, "after-eof:"+string(body))
		w.(http.Flusher).Flush()
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, http2ConnectTestTarget(proxy, "", ""), "service.example:443")
	if err != nil {
		t.Fatalf("dial HTTP/2 CONNECT: %v", err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, payload); err != nil {
		t.Fatalf("write request body: %v", err)
	}
	if err := closeWrite(connection); err != nil {
		t.Fatalf("deliver HTTP/2 END_STREAM: %v", err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("read response after CloseWrite: %v", err)
	}
	if want := "after-eof:" + payload; string(response) != want {
		t.Fatalf("response after CloseWrite = %q, want %q", response, want)
	}
}

func TestHTTP2ConnectReusesOneTLSConnectionForConcurrentTunnels(t *testing.T) {
	var tlsConnections atomic.Int64
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 32)
		for {
			read, readErr := request.Body.Read(buffer)
			if read > 0 {
				_, _ = w.Write(buffer[:read])
				w.(http.Flusher).Flush()
			}
			if readErr != nil {
				return
			}
		}
	}))
	proxy.EnableHTTP2 = true
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			tlsConnections.Add(1)
		}
	}
	proxy.StartTLS()
	defer proxy.Close()
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")

	first, err := manager.dial(context.Background(), target, "first.example:443")
	if err != nil {
		t.Fatalf("dial first H2 tunnel: %v", err)
	}
	defer first.Close()
	second, err := manager.dial(context.Background(), target, "second.example:443")
	if err != nil {
		t.Fatalf("dial second H2 tunnel: %v", err)
	}
	defer second.Close()
	if got := tlsConnections.Load(); got != 1 {
		t.Fatalf("HTTP/2 TLS connection count = %d, want one multiplexed connection", got)
	}
	for index, connection := range []net.Conn{first, second} {
		payload := []byte{byte('a' + index)}
		if _, err := connection.Write(payload); err != nil {
			t.Fatalf("write tunnel %d: %v", index, err)
		}
		echo := make([]byte, 1)
		if _, err := io.ReadFull(connection, echo); err != nil || echo[0] != payload[0] {
			t.Fatalf("read tunnel %d = %q, %v", index, echo, err)
		}
	}
}

func TestHTTP2ConnectOpensBeyondEightConnectionsForLowPeerStreamLimit(t *testing.T) {
	const tunnelCount = 9
	var tlsConnections atomic.Int64
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	}))
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			tlsConnections.Add(1)
		}
	}
	proxy.EnableHTTP2 = true
	if err := xhttp2.ConfigureServer(proxy.Config, &xhttp2.Server{MaxConcurrentStreams: 1}); err != nil {
		t.Fatalf("configure low-credit HTTP/2 server: %v", err)
	}
	proxy.TLS = proxy.Config.TLSConfig
	proxy.StartTLS()
	defer proxy.Close()
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")

	connections := make([]net.Conn, 0, tunnelCount)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for index := 0; index < tunnelCount; index++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		connection, err := manager.dial(ctx, target, fmt.Sprintf("destination-%d.example:443", index))
		cancel()
		if err != nil {
			t.Fatalf("low-credit H2 tunnel %d: %v", index, err)
		}
		connections = append(connections, connection)
	}
	if got := tlsConnections.Load(); got != tunnelCount {
		t.Fatalf("low-credit HTTP/2 TLS connections = %d, want %d", got, tunnelCount)
	}
}

func TestHTTP2ConnectManagerRetireClosesTransportsAfterActiveTunnelsDrain(t *testing.T) {
	manager := newHTTP2ConnectManager(func(http2ConnectTransportKey) *xhttp2.Transport {
		return &xhttp2.Transport{}
	})
	key := http2ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}

	_, release := manager.acquireTransport(key)
	manager.retire()
	manager.mu.Lock()
	activeBeforeRelease := manager.active[key]
	_, retainedWhileActive := manager.transports[key]
	manager.mu.Unlock()
	if activeBeforeRelease != 1 || !retainedWhileActive {
		t.Fatalf("retired active H2 transport = active:%d retained:%v, want 1/true", activeBeforeRelease, retainedWhileActive)
	}

	release()
	manager.mu.Lock()
	activeAfterRelease := manager.active[key]
	_, retainedAfterRelease := manager.transports[key]
	manager.mu.Unlock()
	if activeAfterRelease != 0 || retainedAfterRelease {
		t.Fatalf("drained retired H2 transport = active:%d retained:%v, want 0/false", activeAfterRelease, retainedAfterRelease)
	}
}

func TestHTTP2ActiveAndLateTunnelsSurviveManagerRetire(t *testing.T) {
	proxy := newHTTP2ConnectTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
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
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")
	key := http2ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}

	connection, err := manager.dial(context.Background(), target, "active.example:443")
	if err != nil {
		t.Fatalf("dial active H2 tunnel: %v", err)
	}
	assertConnectTunnelEcho(t, connection, "before-retire")
	manager.retire()
	assertConnectTunnelEcho(t, connection, "after-retire")
	if err := closeWrite(connection); err != nil {
		t.Fatalf("H2 CloseWrite after retire: %v", err)
	}
	manager.mu.Lock()
	activeAfterCloseWrite := manager.active[key]
	manager.mu.Unlock()
	if activeAfterCloseWrite != 1 {
		t.Fatalf("H2 active after CloseWrite = %d, want 1 until full Close", activeAfterCloseWrite)
	}
	if _, err := io.ReadAll(connection); err != nil {
		t.Fatalf("read H2 response EOF after retire: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close active H2 tunnel: %v", err)
	}
	manager.mu.Lock()
	_, retainedAfterClose := manager.transports[key]
	manager.mu.Unlock()
	if retainedAfterClose {
		t.Fatal("retired H2 transport remained after active tunnel full Close")
	}

	late, err := manager.dial(context.Background(), target, "late.example:443")
	if err != nil {
		t.Fatalf("dial H2 tunnel after manager retire: %v", err)
	}
	assertConnectTunnelEcho(t, late, "late-after-retire")
	if err := late.Close(); err != nil {
		t.Fatalf("close late H2 tunnel: %v", err)
	}
	manager.mu.Lock()
	_, retainedLate := manager.transports[key]
	manager.mu.Unlock()
	if retainedLate {
		t.Fatal("late H2 transport remained idle in retired manager")
	}
}

func TestHTTP2SetupCanFinishWhileManagerRetires(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	proxy := newHTTP2ConnectTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		<-releaseResponse
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")
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
		t.Fatal("H2 CONNECT setup did not reach proxy")
	}
	manager.retire()
	close(releaseResponse)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("H2 setup failed across retire: %v", got.err)
		}
		if err := got.connection.Close(); err != nil {
			t.Fatalf("close H2 setup tunnel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("H2 setup did not finish after retire")
	}
}

func assertConnectTunnelEcho(t *testing.T, connection net.Conn, payload string) {
	t.Helper()
	if _, err := io.WriteString(connection, payload); err != nil {
		t.Fatalf("write CONNECT tunnel payload: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("read CONNECT tunnel echo: %v", err)
	}
	if string(response) != payload {
		t.Fatalf("CONNECT tunnel echo = %q, want %q", response, payload)
	}
}

func TestHTTP2ConnectRejectsBadBasicAuthWithoutCredentialLeak(t *testing.T) {
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusProxyAuthRequired)
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "moto", "do-not-leak")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "service.example:443")
	if connection != nil {
		_ = connection.Close()
		t.Fatal("dial() returned a connection for HTTP 407")
	}
	var statusErr *connectProxyStatusError
	if !errors.As(err, &statusErr) || statusErr.statusCode != http.StatusProxyAuthRequired {
		t.Fatalf("dial() error = %v, want status 407", err)
	}
	if statusErr.class != connectProxyFailureProxyAuth {
		t.Fatalf("classified error = %+v, want proxy_auth", statusErr)
	}
	if !statusErr.hasRetryAfter || statusErr.retryAfter != 15*time.Second {
		t.Fatalf("Retry-After = %s/%t, want 15s/true", statusErr.retryAfter, statusErr.hasRetryAfter)
	}
	if strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("dial() error leaked password: %v", err)
	}
}

func TestSOCKS5NormalUsesHTTP2ConnectAndRepliesAfterProxyAcceptance(t *testing.T) {
	const (
		banner    = "H2-READY\n"
		userAgent = "Moto-H2-UA/1.0"
	)
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") == "" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if got := request.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, banner)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(w, request.Body)
	})
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	installHTTP2ConnectTestManager(runtime, proxy)
	rule := http2ConnectSOCKS5Rule(t, config.ModeNormal, proxy, "moto", "secret")
	rule.UserAgent = []string{userAgent}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule.Validate() with User-Agent: %v", err)
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
		t.Fatalf("read server-first data: %v", err)
	}
	if string(gotBanner) != banner {
		t.Fatalf("server-first data = %q", gotBanner)
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 dispatch did not stop")
	}
}

func TestSOCKS5DoesNotAcknowledgeRejectedHTTP2Connect(t *testing.T) {
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	})
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	installHTTP2ConnectTestManager(runtime, proxy)
	rule := http2ConnectSOCKS5Rule(t, config.ModeNormal, proxy, "moto", "wrong")

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		runtime.dispatch(context.Background(), serverSide, rule, "")
		close(done)
	}()
	performSOCKS5DomainRequest(t, clientSide, "service.example", 443)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatalf("read SOCKS5 failure reply: %v", err)
	}
	if reply[1] == socks5ReplySuccess {
		t.Fatalf("SOCKS5 acknowledged rejected HTTP CONNECT: %v", reply)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 dispatch did not stop after HTTP 407")
	}
}

func newHTTP2ConnectTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newHTTP2ConnectTestManager(server *httptest.Server) *http2ConnectManager {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
}

func installHTTP2ConnectTestManager(runtime *routingRuntime, server *httptest.Server) {
	manager := newHTTP2ConnectTestManager(server)
	runtime.connectProxy.h2 = manager
	runtime.connectProxy.dialers[config.ConnectProxyH2] = manager.dial
}

func http2ConnectTestTarget(server *httptest.Server, username, password string) *config.Target {
	address := strings.TrimPrefix(server.URL, "https://")
	return &config.Target{
		Address: address,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH2},
			ServerName: "127.0.0.1",
			BasicAuth:  &config.BasicAuthConfig{Username: username, Password: password},
		},
	}
}

func http2ConnectSOCKS5Rule(t *testing.T, mode string, server *httptest.Server, username, password string) *config.Rule {
	t.Helper()
	rule := &config.Rule{
		Name:                "huojian",
		Listen:              "127.0.0.1:1080",
		Mode:                mode,
		Protocol:            config.ProtocolSOCKS5,
		Timeout:             1_000,
		MaxConnections:      16,
		MaxConnectionsPerIP: 16,
		Targets:             []*config.Target{http2ConnectTestTarget(server, username, password)},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule.Validate() error = %v", err)
	}
	return rule
}

func performSOCKS5DomainRequest(t *testing.T, connection net.Conn, host string, port uint16) {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte{socks5Version, 1, socks5MethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(connection, method); err != nil {
		t.Fatal(err)
	}
	if method[1] != socks5MethodNoAuth {
		t.Fatalf("SOCKS5 method = %v", method)
	}
	request := []byte{socks5Version, socks5CommandConnect, 0, socks5AddressDomain, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
}
