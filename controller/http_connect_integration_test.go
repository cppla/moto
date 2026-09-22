package controller

import (
	"bufio"
	"bytes"
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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTPConnectIntegrationTunnelModes(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		for _, mode := range []string{config.ModeNormal, config.ModeBoost, config.ModeRoundRobin} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				const destination = "destination.example:443"
				const banner = "upstream-ready\n"
				const trailer = "response-after-client-eof\n"
				requests := make(chan *http.Request, 1)
				target, install := newHTTPConnectIntegrationUpstream(t, protocol, func(writer http.ResponseWriter, request *http.Request) {
					requests <- request.Clone(context.Background())
					writer.Header().Set("X-Upstream-Secret", "must-not-be-forwarded")
					writer.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(writer, banner)
					writer.(http.Flusher).Flush()
					if _, err := io.Copy(httpConnectIntegrationFlushWriter{writer}, request.Body); err != nil {
						return
					}
					_, _ = io.WriteString(writer, trailer)
					writer.(http.Flusher).Flush()
				})
				rule := httpConnectIntegrationRule(mode, target)
				rule.UserAgent = []string{"Configured-Moto-UA/1.0"}
				server := startHTTPConnectIntegrationServer(t, rule, install)
				client := dialHTTPConnectIntegrationClient(t, server)
				reader := bufio.NewReader(client)
				payload := bytes.Repeat([]byte{0, 1, 2, 127, 128, 254, 255, '\r', '\n'}, 32<<10)
				request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic Y2xpZW50OnNlY3JldA==\r\nAuthorization: Bearer client-secret\r\nUser-Agent: Client-UA/1.0\r\nCookie: client-cookie=private\r\nX-Client-Secret: private\r\n\r\n", destination, destination)
				// One write deliberately puts tunnel bytes immediately after the
				// headers, exercising replay of bytes buffered by HTTP parsing.
				firstPacket := append([]byte(request), payload[:512]...)
				if _, err := client.Write(firstPacket); err != nil {
					t.Fatal(err)
				}
				response := readHTTPConnectIntegrationResponse(t, reader)
				if response.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status = %s", response.Status)
				}
				for _, header := range []string{"Content-Length", "Transfer-Encoding", "X-Upstream-Secret"} {
					if value := response.Header.Get(header); value != "" {
						t.Errorf("successful CONNECT leaked %s: %q", header, value)
					}
				}
				gotBanner := make([]byte, len(banner))
				if _, err := io.ReadFull(reader, gotBanner); err != nil || string(gotBanner) != banner {
					t.Fatalf("server-first bytes = %q, error = %v", gotBanner, err)
				}
				writeDone := make(chan error, 1)
				go func() {
					_, err := client.Write(payload[512:])
					if err == nil {
						err = client.CloseWrite()
					}
					writeDone <- err
				}()
				received, err := io.ReadAll(reader)
				if err != nil {
					t.Fatalf("read tunnel through half-close: %v", err)
				}
				if err := <-writeDone; err != nil {
					t.Fatalf("write and half-close client: %v", err)
				}
				want := append(append([]byte(nil), payload...), []byte(trailer)...)
				if !bytes.Equal(received, want) {
					t.Fatalf("tunnel payload mismatch: received %d bytes, want %d", len(received), len(want))
				}
				select {
				case upstream := <-requests:
					wantMajor := 2
					if protocol == config.ConnectProxyH3 {
						wantMajor = 3
					}
					if upstream.ProtoMajor != wantMajor || upstream.Method != http.MethodConnect || upstream.Host != destination || upstream.URL.Path != "" {
						t.Fatalf("upstream request = %s %s %q %q", upstream.Proto, upstream.Method, upstream.Host, upstream.URL.Path)
					}
					wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("moto:upstream-secret"))
					if got := upstream.Header.Get("Proxy-Authorization"); got != wantAuth {
						t.Fatalf("upstream did not receive configured Basic auth")
					}
					if got := upstream.Header.Get("User-Agent"); got != rule.UserAgent[0] {
						t.Errorf("upstream User-Agent = %q, want %q", got, rule.UserAgent[0])
					}
					for _, header := range []string{"Authorization", "Cookie", "X-Client-Secret"} {
						if upstream.Header.Get(header) != "" {
							t.Errorf("client %s was forwarded to upstream", header)
						}
					}
				case <-time.After(time.Second):
					t.Fatal("upstream did not observe CONNECT")
				}
			})
		}
	}
}

func TestHTTPConnectIntegrationHTTPSClient(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			payload := bytes.Repeat([]byte("encrypted HTTPS response\x00\xff\n"), 8192)
			origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.RequestURI() != "/through-connect?check=integrity" {
					t.Errorf("origin request URI = %q", request.URL.RequestURI())
				}
				writer.Header().Set("Content-Type", "application/octet-stream")
				_, _ = writer.Write(payload)
			}))
			t.Cleanup(origin.Close)
			target, install := newHTTPConnectIntegrationUpstream(t, protocol, func(writer http.ResponseWriter, request *http.Request) {
				if request.Host != origin.Listener.Addr().String() {
					writer.WriteHeader(http.StatusForbidden)
					return
				}
				upstream, err := net.DialTimeout("tcp", request.Host, time.Second)
				if err != nil {
					t.Errorf("dial HTTPS origin: %v", err)
					writer.WriteHeader(http.StatusBadGateway)
					return
				}
				defer upstream.Close()
				writer.WriteHeader(http.StatusOK)
				writer.(http.Flusher).Flush()
				uploadDone := make(chan struct{})
				go func() {
					defer close(uploadDone)
					_, _ = io.Copy(upstream, request.Body)
					_ = upstream.(*net.TCPConn).CloseWrite()
				}()
				_, _ = io.Copy(httpConnectIntegrationFlushWriter{writer}, upstream)
				_ = upstream.Close()
				_ = request.Body.Close()
				<-uploadDone
			})
			server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeNormal, target), install)
			proxyURL := &url.URL{Scheme: "http", Host: server.listeners[0].listener.Addr().String()}
			roots := x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			transport := &http.Transport{
				Proxy:             http.ProxyURL(proxyURL),
				TLSClientConfig:   &tls.Config{RootCAs: roots},
				DisableKeepAlives: true,
			}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(origin.URL + "/through-connect?check=integrity")
			if err != nil {
				t.Fatalf("HTTPS request through local HTTP proxy: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
				t.Fatalf("HTTPS response: status = %s, body bytes = %d, error = %v", response.Status, len(body), err)
			}
		})
	}
}

func TestHTTPConnectIntegrationUpstreamFailureStatus(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		for _, mode := range []string{config.ModeNormal, config.ModeBoost, config.ModeRoundRobin} {
			for _, status := range []int{403, 407, 429, 502, 503, 504} {
				t.Run(fmt.Sprintf("%s/%s/%d", protocol, mode, status), func(t *testing.T) {
					target, install := newHTTPConnectIntegrationUpstream(t, protocol, func(writer http.ResponseWriter, _ *http.Request) {
						writer.Header().Set("Proxy-Authenticate", `Basic realm="upstream-private"`)
						writer.Header().Set("X-Upstream-Secret", "upstream-private")
						writer.Header().Set("Set-Cookie", "upstream-private=secret")
						writer.Header().Set("Retry-After", "11")
						writer.WriteHeader(status)
						_, _ = io.WriteString(writer, "upstream-private response body")
					})
					server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(mode, target), install)
					client := dialHTTPConnectIntegrationClient(t, server)
					writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
					response := readHTTPConnectIntegrationResponse(t, bufio.NewReader(client))
					want := status
					if status == http.StatusProxyAuthRequired {
						want = http.StatusBadGateway
					}
					if response.StatusCode != want {
						t.Fatalf("local CONNECT status = %d, want %d for upstream %d", response.StatusCode, want, status)
					}
					for _, header := range []string{"Proxy-Authenticate", "X-Upstream-Secret", "Set-Cookie"} {
						if response.Header.Get(header) != "" {
							t.Errorf("upstream %s leaked to local client", header)
						}
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil {
						t.Fatalf("read rejection body: %v", err)
					}
					if strings.Contains(string(body), "upstream-private") || strings.Contains(string(body), target.Address) {
						t.Error("upstream rejection details leaked to local client")
					}
				})
			}
		}
	}
}

func TestHTTPConnectIntegrationWaitsForUpstreamAcceptance(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			target, install := newHTTPConnectIntegrationUpstream(t, protocol, func(writer http.ResponseWriter, request *http.Request) {
				started <- struct{}{}
				select {
				case <-release:
					writer.WriteHeader(http.StatusForbidden)
				case <-request.Context().Done():
				}
			})
			server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeNormal, target), install)
			client := dialHTTPConnectIntegrationClient(t, server)
			writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream CONNECT did not start")
			}
			_ = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			var firstByte [1]byte
			count, err := client.Read(firstByte[:])
			var timeout net.Error
			if count != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("local proxy replied before upstream decision: bytes = %q, error = %v", firstByte[:count], err)
			}
			close(release)
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			response := readHTTPConnectIntegrationResponse(t, bufio.NewReader(client))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("delayed upstream denial became %s", response.Status)
			}
		})
	}
}

func TestHTTPConnectIntegrationSetupTimeout(t *testing.T) {
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		t.Run(protocol, func(t *testing.T) {
			started := make(chan struct{}, 1)
			target, install := newHTTPConnectIntegrationUpstream(t, protocol, func(_ http.ResponseWriter, request *http.Request) {
				started <- struct{}{}
				<-request.Context().Done()
			})
			rule := httpConnectIntegrationRule(config.ModeNormal, target)
			rule.Timeout = 200
			server := startHTTPConnectIntegrationServer(t, rule, install)
			client := dialHTTPConnectIntegrationClient(t, server)
			writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
			response := readHTTPConnectIntegrationResponse(t, bufio.NewReader(client))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusGatewayTimeout {
				t.Fatalf("stalled upstream CONNECT status = %s, want 504", response.Status)
			}
			select {
			case <-started:
			default:
				t.Fatal("timeout did not exercise an established upstream CONNECT request")
			}
		})
	}
}

func TestHTTPConnectIntegrationOpenCircuitReturns503BeforeDial(t *testing.T) {
	for _, mode := range []string{config.ModeNormal, config.ModeBoost, config.ModeRoundRobin} {
		t.Run(mode, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			target, install := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH2, func(writer http.ResponseWriter, _ *http.Request) {
				upstreamRequests.Add(1)
				writer.WriteHeader(http.StatusForbidden)
			})
			server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(mode, target), install)
			generation := server.current.Load()
			rule := generation.rules[0]
			now := time.Now()
			for index := 0; index < routeFailureThreshold; index++ {
				attempt, err := generation.runtime.routes.begin(rule, target.Address, now)
				if err != nil {
					t.Fatal(err)
				}
				routeObserve(attempt, time.Millisecond, errors.New("synthetic prior route failure"), now)
			}
			client := dialHTTPConnectIntegrationClient(t, server)
			writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
			response := readHTTPConnectIntegrationResponse(t, bufio.NewReader(client))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("open-circuit CONNECT status = %s, want 503", response.Status)
			}
			if got := upstreamRequests.Load(); got != 0 {
				t.Fatalf("open circuit admitted %d upstream requests", got)
			}
		})
	}
}

func TestHTTPConnectIntegrationH3FailureFallsBackToH2(t *testing.T) {
	target, installH2 := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH2, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(httpConnectIntegrationFlushWriter{writer}, request.Body)
	})
	target.ConnectProxy.Protocols = []string{config.ConnectProxyH3, config.ConnectProxyH2}
	var h3Attempts atomic.Int32
	server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeNormal, target), func(runtime *routingRuntime) {
		installH2(runtime)
		runtime.connectProxy.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
			h3Attempts.Add(1)
			return nil, &net.OpError{Op: "dial", Net: "udp", Err: errors.New("synthetic UDP transport failure")}
		}
	})
	client := dialHTTPConnectIntegrationClient(t, server)
	writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
	reader := bufio.NewReader(client)
	response := readHTTPConnectIntegrationResponse(t, reader)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("H3 to H2 fallback status = %s", response.Status)
	}
	const payload = "h3-failed-h2-carries-the-tunnel"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	echo, err := io.ReadAll(reader)
	if err != nil || string(echo) != payload {
		t.Fatalf("H2 fallback echo = %q, error = %v", echo, err)
	}
	if got := h3Attempts.Load(); got != 1 {
		t.Fatalf("H3 dial attempts = %d, want 1", got)
	}
	generation := server.current.Load()
	snapshot := generation.runtime.routes.snapshot(generation.rules[0], target.Address, time.Now())
	if snapshot.CircuitOpen || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("successful H2 fallback poisoned route health: %+v", snapshot)
	}
}

func TestHTTPConnectIntegrationRoundRobinAlternatesH2AndH3Targets(t *testing.T) {
	newHandler := func(name string) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, name)
			writer.(http.Flusher).Flush()
			_, _ = io.Copy(io.Discard, request.Body)
		}
	}
	h2Target, installH2 := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH2, newHandler("h2"))
	h3Target, installH3 := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH3, newHandler("h3"))
	server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeRoundRobin, h2Target, h3Target), func(runtime *routingRuntime) {
		installH2(runtime)
		installH3(runtime)
	})
	for index, want := range []string{"h2", "h3", "h2", "h3"} {
		client := dialHTTPConnectIntegrationClient(t, server)
		writeHTTPConnectIntegrationRequest(t, client, "destination.example:443")
		reader := bufio.NewReader(client)
		response := readHTTPConnectIntegrationResponse(t, reader)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("round-robin request %d status = %s", index, response.Status)
		}
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		_ = client.Close()
		if err != nil || string(body) != want {
			t.Fatalf("round-robin request %d selected %q, want %q; error = %v", index, body, want, err)
		}
	}
}

func TestHTTPConnectIntegrationBoostCachesAcceptedTarget(t *testing.T) {
	var rejectedAttempts atomic.Int32
	rejected := make(chan struct{})
	h2Target, installH2 := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH2, func(writer http.ResponseWriter, _ *http.Request) {
		if rejectedAttempts.Add(1) == 1 {
			close(rejected)
		}
		writer.WriteHeader(http.StatusBadGateway)
	})
	destinations := make(chan string, 2)
	h3Target, installH3 := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH3, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-rejected:
		case <-request.Context().Done():
			return
		}
		destinations <- request.Host
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "accepted-h3-winner")
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeBoost, h2Target, h3Target), func(runtime *routingRuntime) {
		installH2(runtime)
		installH3(runtime)
	})
	for _, destination := range []string{"first.example:443", "second.example:8443"} {
		client := dialHTTPConnectIntegrationClient(t, server)
		writeHTTPConnectIntegrationRequest(t, client, destination)
		reader := bufio.NewReader(client)
		response := readHTTPConnectIntegrationResponse(t, reader)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Boost CONNECT status = %s", response.Status)
		}
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		_ = client.Close()
		if err != nil || string(body) != "accepted-h3-winner" {
			t.Fatalf("Boost selected response = %q, error = %v", body, err)
		}
		select {
		case got := <-destinations:
			if got != destination {
				t.Fatalf("cached target retained old CONNECT authority %q, want %q", got, destination)
			}
		case <-time.After(time.Second):
			t.Fatal("accepted target did not observe CONNECT")
		}
	}
	if got := rejectedAttempts.Load(); got != 1 {
		t.Fatalf("rejected target dialed %d times, want one initial race then accepted cached target", got)
	}
	generation := server.current.Load()
	if winner, ok := generation.runtime.loadBoostWinnerToken(boostRuleKey(generation.rules[0])); !ok || winner.addr != h3Target.Address {
		t.Fatalf("cached Boost winner = %q, present = %t, want accepted H3 target", winner.addr, ok)
	}
}

func TestHTTPConnectIntegrationRejectsInvalidRequestsBeforeDial(t *testing.T) {
	var upstreamRequests atomic.Int32
	target, install := newHTTPConnectIntegrationUpstream(t, config.ConnectProxyH2, func(writer http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		writer.WriteHeader(http.StatusForbidden)
	})
	server := startHTTPConnectIntegrationServer(t, httpConnectIntegrationRule(config.ModeNormal, target), install)
	for _, test := range []struct {
		name    string
		request string
		status  int
	}{
		{"missing_port", "CONNECT destination.example HTTP/1.1\r\nHost: destination.example\r\n\r\n", http.StatusBadRequest},
		{"absolute_uri", "CONNECT https://destination.example:443/ HTTP/1.1\r\nHost: destination.example:443\r\n\r\n", http.StatusBadRequest},
		{"non_connect", "GET http://destination.example/ HTTP/1.1\r\nHost: destination.example\r\n\r\n", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := dialHTTPConnectIntegrationClient(t, server)
			if _, err := io.WriteString(client, test.request); err != nil {
				t.Fatal(err)
			}
			response := readHTTPConnectIntegrationResponse(t, bufio.NewReader(client))
			_ = response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("invalid request status = %s, want %d", response.Status, test.status)
			}
		})
	}
	if got := upstreamRequests.Load(); got != 0 {
		t.Fatalf("invalid inbound requests reached upstream %d times", got)
	}
}

type httpConnectIntegrationFlushWriter struct{ http.ResponseWriter }

func (writer httpConnectIntegrationFlushWriter) Write(data []byte) (int, error) {
	count, err := writer.ResponseWriter.Write(data)
	writer.ResponseWriter.(http.Flusher).Flush()
	return count, err
}

func newHTTPConnectIntegrationUpstream(t *testing.T, protocol string, handler http.HandlerFunc) (*config.Target, func(*routingRuntime)) {
	t.Helper()
	if protocol == config.ConnectProxyH2 {
		proxy := newHTTP2ConnectTestServer(t, handler)
		return http2ConnectTestTarget(proxy, "moto", "upstream-secret"), func(runtime *routingRuntime) {
			installHTTP2ConnectTestManager(runtime, proxy)
		}
	}
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	t.Cleanup(closeServer)
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3},
			BasicAuth: &config.BasicAuthConfig{Username: "moto", Password: "upstream-secret"},
		},
	}
	return target, func(runtime *routingRuntime) {
		manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
			transport := newHTTP3ConnectTransportWithOwner(key, owner)
			transport.TLSClientConfig.RootCAs = roots
			return transport
		})
		runtime.connectProxy.h3 = manager
		runtime.connectProxy.dialers[config.ConnectProxyH3] = manager.dial
	}
}

func httpConnectIntegrationRule(mode string, targets ...*config.Target) *config.Rule {
	return &config.Rule{
		Name:                "http-connect-integration",
		Listen:              "127.0.0.1:0",
		Mode:                mode,
		Protocol:            config.ProtocolHTTP,
		Timeout:             2_000,
		MaxConnections:      16,
		MaxConnectionsPerIP: 16,
		Targets:             targets,
	}
}

func startHTTPConnectIntegrationServer(t *testing.T, rule *config.Rule, install func(*routingRuntime)) *Server {
	t.Helper()
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatalf("start local HTTP CONNECT proxy: %v", err)
	}
	if install != nil {
		install(server.current.Load().runtime)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		server.forceCancel()
		server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stop local HTTP CONNECT proxy: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("local HTTP CONNECT proxy did not stop")
		}
	})
	waitReloadServerReady(t, server)
	return server
}

func dialHTTPConnectIntegrationClient(t *testing.T, server *Server) *net.TCPConn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", server.listeners[0].listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial local HTTP CONNECT listener: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return connection.(*net.TCPConn)
}

func writeHTTPConnectIntegrationRequest(t *testing.T, connection net.Conn, destination string) {
	t.Helper()
	if _, err := fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", destination, destination); err != nil {
		t.Fatalf("write local HTTP CONNECT request: %v", err)
	}
}

func readHTTPConnectIntegrationResponse(t *testing.T, reader *bufio.Reader) *http.Response {
	t.Helper()
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read local HTTP CONNECT response: %v", err)
	}
	return response
}
