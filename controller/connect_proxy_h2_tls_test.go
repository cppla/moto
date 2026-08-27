package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	xhttp2 "golang.org/x/net/http2"
)

func TestHTTP2TLSClientHelloUsesChromeProfile(t *testing.T) {
	const (
		destination = "clienthello-destination-marker.example:443"
		username    = "clienthello-user-marker"
		password    = "clienthello-password-marker"
	)
	proxy, captures := newHTTP2TLSCaptureServer(t, []string{"h2"}, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	manager := newHTTP2ConnectTestManager(proxy)
	t.Cleanup(manager.closeIdle)
	target := http2ConnectTestTarget(proxy, username, password)
	// The httptest certificate contains example.com, and a DNS name makes the
	// configured proxy identity visible as SNI in the captured ClientHello.
	target.ConnectProxy.ServerName = "example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, destination)
	if err != nil {
		t.Fatalf("dial fingerprinted HTTP/2 CONNECT: %v", err)
	}
	defer connection.Close()

	captured := waitForHTTP2TLSCapture(t, captures)
	probe := capturedHTTP2ClientHello(t, captured)
	if probe.ServerName != target.ConnectProxy.ServerName {
		t.Fatalf("ClientHello SNI = %q, want %q", probe.ServerName, target.ConnectProxy.ServerName)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(probe.ALPNProtocols, want) {
		t.Fatalf("ClientHello ALPN = %q, want %q", probe.ALPNProtocols, want)
	}
	assertChromeHTTP2ClientHello(t, probe.Raw)

	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	for label, secret := range map[string]string{
		"destination":   destination,
		"username":      username,
		"password":      password,
		"authorization": authorization,
	} {
		if bytes.Contains(probe.Raw, []byte(secret)) {
			t.Fatalf("plaintext ClientHello contains %s marker %q", label, secret)
		}
	}
}

func TestHTTP2TLSProfileForUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      http2TLSClientHelloProfile
	}{
		{name: "empty", want: http2TLSProfileChrome133},
		{name: "unknown", userAgent: "Moto-Test/1.0", want: http2TLSProfileChrome133},
		{
			name:      "desktop Chrome",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36",
			want:      http2TLSProfileChrome133,
		},
		{
			name:      "Android Chrome",
			userAgent: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/133.0.0.0 Mobile Safari/537.36",
			want:      http2TLSProfileChrome133,
		},
		{
			name:      "modern Edge before embedded Chrome",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
			want:      http2TLSProfileChrome133,
		},
		{
			name:      "Firefox",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			want:      http2TLSProfileFirefox120,
		},
		{
			name:      "pure macOS Safari",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
			want:      http2TLSProfileSafari160,
		},
		{
			name:      "iPhone Safari before Safari",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 Version/14.0 Mobile/15E148 Safari/604.1",
			want:      http2TLSProfileIOS14,
		},
		{
			name:      "iPad Chrome",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/133.0.0.0 Mobile/15E148 Safari/604.1",
			want:      http2TLSProfileIOS14,
		},
		{
			name:      "iOS Edge",
			userAgent: "Mozilla/5.0 AppleWebKit/605.1.15 EdgiOS/133.0 Mobile/15E148 Safari/605.1.15",
			want:      http2TLSProfileIOS14,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := http2TLSProfileForUserAgent(test.userAgent); got != test.want {
				t.Fatalf("profile for %q = %d, want %d", test.userAgent, got, test.want)
			}
		})
	}
}

func TestHTTP2TLSProfileClientHelloIDs(t *testing.T) {
	for _, test := range []struct {
		profile http2TLSClientHelloProfile
		want    utls.ClientHelloID
	}{
		{profile: http2TLSProfileChrome133, want: utls.HelloChrome_133},
		{profile: http2TLSProfileFirefox120, want: utls.HelloFirefox_120},
		{profile: http2TLSProfileSafari160, want: utls.HelloSafari_16_0},
		{profile: http2TLSProfileIOS14, want: utls.HelloIOS_14},
	} {
		if got := test.profile.clientHelloID(); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("profile %d ClientHello ID = %#v, want %#v", test.profile, got, test.want)
		}
	}
}

func TestHTTP2TLSClientHelloProfilesOnWire(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		profile   http2TLSClientHelloProfile
	}{
		{
			name:      "Chrome 133",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36",
			profile:   http2TLSProfileChrome133,
		},
		{
			name:      "Firefox 120",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			profile:   http2TLSProfileFirefox120,
		},
		{
			name:      "Safari 16",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
			profile:   http2TLSProfileSafari160,
		},
		{
			name:      "iOS 14",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 Version/14.0 Mobile/15E148 Safari/604.1",
			profile:   http2TLSProfileIOS14,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxy, captures := newHTTP2TLSCaptureServer(t, []string{"h2"}, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
				writer.(http.Flusher).Flush()
				_, _ = io.Copy(io.Discard, request.Body)
			})
			manager := newHTTP2ConnectTestManager(proxy)
			t.Cleanup(manager.closeIdle)
			target := http2ConnectTestTarget(proxy, "", "")
			target.ConnectProxy.ServerName = "example.com"

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = withConnectProxyUserAgent(ctx, test.userAgent)
			connection, err := manager.dial(ctx, target, "profile-destination.example:443")
			if err != nil {
				t.Fatalf("dial HTTP/2 CONNECT with %s profile: %v", test.name, err)
			}
			defer connection.Close()

			captured := waitForHTTP2TLSCapture(t, captures)
			probe := capturedHTTP2ClientHello(t, captured)
			fingerprint, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(probe.Raw)
			if err != nil {
				t.Fatalf("fingerprint %s ClientHello: %v", test.name, err)
			}
			want, err := utls.UTLSIdToSpec(test.profile.clientHelloID())
			if err != nil {
				t.Fatalf("load %s uTLS profile: %v", test.name, err)
			}
			if !reflect.DeepEqual(fingerprint.CipherSuites, want.CipherSuites) {
				t.Fatalf("%s ClientHello cipher suites = %#v, want %#v", test.name, fingerprint.CipherSuites, want.CipherSuites)
			}
			if wantALPN := []string{"h2", "http/1.1"}; !reflect.DeepEqual(probe.ALPNProtocols, wantALPN) {
				t.Fatalf("%s ClientHello ALPN = %q, want %q", test.name, probe.ALPNProtocols, wantALPN)
			}
		})
	}
}

func TestHTTP2TLSTransportPoolIsolatedBySelectedIdentity(t *testing.T) {
	proxy := newHTTP2ConnectTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	})
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())

	var (
		createdMu sync.Mutex
		created   []http2ConnectTransportKey
	)
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		createdMu.Lock()
		created = append(created, key)
		createdMu.Unlock()
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	t.Cleanup(manager.closeIdle)
	target := http2ConnectTestTarget(proxy, "", "")

	desktopChrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36"
	identities := []string{
		desktopChrome,
		desktopChrome,
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/133.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	}
	for _, userAgent := range identities {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ctx = withConnectProxyUserAgent(ctx, userAgent)
		connection, err := manager.dial(ctx, target, "pool-destination.example:443")
		cancel()
		if err != nil {
			t.Fatalf("dial HTTP/2 CONNECT for identity %q: %v", userAgent, err)
		}
		if err := connection.Close(); err != nil {
			t.Fatalf("close HTTP/2 CONNECT for identity %q: %v", userAgent, err)
		}
	}

	createdMu.Lock()
	gotCreated := append([]http2ConnectTransportKey(nil), created...)
	createdMu.Unlock()
	if len(gotCreated) != 4 {
		t.Fatalf("created H2 identity pools = %d, want 4 for four distinct UA/profile identities: %#v", len(gotCreated), gotCreated)
	}
	for _, key := range gotCreated {
		if key.userAgent == "" {
			t.Fatalf("created H2 pool without selected User-Agent: %#v", key)
		}
		if got := http2TLSProfileForUserAgent(key.userAgent); got != key.tlsProfile {
			t.Fatalf("pool profile for %q = %d, want mapped %d", key.userAgent, key.tlsProfile, got)
		}
	}
	if gotCreated[0].tlsProfile != http2TLSProfileChrome133 ||
		gotCreated[1].tlsProfile != http2TLSProfileChrome133 ||
		gotCreated[2].tlsProfile != http2TLSProfileChrome133 {
		t.Fatalf("Chrome, Android Chrome, and Edge profiles = %d/%d/%d, want Chrome 133",
			gotCreated[0].tlsProfile, gotCreated[1].tlsProfile, gotCreated[2].tlsProfile)
	}
	if gotCreated[3].tlsProfile != http2TLSProfileFirefox120 {
		t.Fatalf("Firefox profile = %d, want Firefox 120", gotCreated[3].tlsProfile)
	}
}

func TestHTTP2TLSRejectsUnknownAuthorityAndClosesConnection(t *testing.T) {
	var requests atomic.Int64
	proxy, captures := newHTTP2TLSCaptureServer(t, []string{"h2"}, func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
	})
	manager := newHTTP2ConnectManager(nil)
	t.Cleanup(manager.closeIdle)
	target := http2ConnectTestTarget(proxy, "", "")
	target.ConnectProxy.ServerName = "example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "unknown-ca-destination.example:443")
	if connection != nil {
		_ = connection.Close()
		t.Fatal("untrusted proxy certificate returned an HTTP/2 tunnel")
	}
	if err == nil {
		t.Fatal("untrusted proxy certificate was accepted")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("untrusted proxy error = %T: %v, want x509.UnknownAuthorityError", err, err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("HTTP/2 CONNECT requests after certificate rejection = %d, want 0", got)
	}
	waitForHTTP2TLSCaptureClosed(t, waitForHTTP2TLSCapture(t, captures))
}

func TestHTTP2TLSRejectsWrongServerNameAndClosesConnection(t *testing.T) {
	var requests atomic.Int64
	proxy, captures := newHTTP2TLSCaptureServer(t, []string{"h2"}, func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
	})
	manager := newHTTP2ConnectTestManager(proxy)
	t.Cleanup(manager.closeIdle)
	target := http2ConnectTestTarget(proxy, "", "")
	target.ConnectProxy.ServerName = "wrong-hostname.invalid"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "wrong-host-destination.example:443")
	if connection != nil {
		_ = connection.Close()
		t.Fatal("wrong proxy server name returned an HTTP/2 tunnel")
	}
	if err == nil {
		t.Fatal("wrong proxy server name was accepted")
	}
	var hostnameError x509.HostnameError
	if !errors.As(err, &hostnameError) {
		t.Fatalf("wrong server name error = %T: %v, want x509.HostnameError", err, err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("HTTP/2 CONNECT requests after hostname rejection = %d, want 0", got)
	}
	waitForHTTP2TLSCaptureClosed(t, waitForHTTP2TLSCapture(t, captures))
}

func TestHTTP2TLSRequiresH2ALPNAndClosesConnection(t *testing.T) {
	for _, test := range []struct {
		name       string
		nextProtos []string
	}{
		{name: "http1", nextProtos: []string{"http/1.1"}},
		{name: "none", nextProtos: []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int64
			proxy, captures := newHTTP2TLSCaptureServer(t, test.nextProtos, func(writer http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				writer.WriteHeader(http.StatusOK)
			})
			manager := newHTTP2ConnectTestManager(proxy)
			t.Cleanup(manager.closeIdle)
			target := http2ConnectTestTarget(proxy, "", "")
			target.ConnectProxy.ServerName = "example.com"

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			connection, err := manager.dial(ctx, target, "alpn-destination.example:443")
			if connection != nil {
				_ = connection.Close()
				t.Fatal("non-h2 ALPN returned an HTTP/2 tunnel")
			}
			if err == nil {
				t.Fatal("non-h2 ALPN was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "alpn") {
				t.Fatalf("non-h2 protocol error = %v, want an ALPN error", err)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("HTTP/2 CONNECT requests after ALPN rejection = %d, want 0", got)
			}
			captured := waitForHTTP2TLSCapture(t, captures)
			probe := capturedHTTP2ClientHello(t, captured)
			if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(probe.ALPNProtocols, want) {
				t.Fatalf("ClientHello ALPN = %q, want %q", probe.ALPNProtocols, want)
			}
			waitForHTTP2TLSCaptureClosed(t, captured)
		})
	}
}

func TestHTTP2TLSHandshakeHonorsCallerDeadlineAndClosesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stalled TLS server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type readResult struct {
		bytes int
		err   error
	}
	accepted := make(chan net.Conn, 1)
	closed := make(chan readResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			closed <- readResult{err: acceptErr}
			return
		}
		accepted <- connection
		buffer := make([]byte, 4096)
		total := 0
		for {
			read, readErr := connection.Read(buffer)
			total += read
			if readErr != nil {
				closed <- readResult{bytes: total, err: readErr}
				return
			}
		}
	}()

	manager := newHTTP2ConnectManager(nil)
	t.Cleanup(manager.closeIdle)
	target := &config.Target{
		Address: listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH2},
			ServerName: "stalled-tls.example",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	started := time.Now()
	connection, dialErr := manager.dial(ctx, target, "stalled-tls-destination.example:443")
	elapsed := time.Since(started)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("stalled TLS handshake returned an HTTP/2 tunnel")
	}
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("stalled TLS handshake error = %v, want context deadline exceeded", dialErr)
	}
	if elapsed >= time.Second {
		t.Fatalf("stalled TLS handshake returned after %s, want caller deadline well before one second", elapsed)
	}

	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.Close()
	case <-time.After(time.Second):
		t.Fatal("stalled TLS server did not accept the client connection")
	}
	select {
	case result := <-closed:
		if result.bytes == 0 {
			t.Fatal("stalled TLS server received no ClientHello bytes")
		}
		if result.err == nil {
			t.Fatal("stalled TLS server did not observe the client closing TCP")
		}
	case <-time.After(time.Second):
		t.Fatal("caller deadline did not close the stalled TLS connection")
	}
}

func TestHTTP2TLSSharedDialWaiterUsesOwnDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for shared TLS dial: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 4)
	acceptStopped := make(chan error, 1)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				acceptStopped <- acceptErr
				return
			}
			accepted <- connection
		}
	}()

	var physicalDials atomic.Int64
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		productionDial := transport.DialTLSContext
		transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
			physicalDials.Add(1)
			return productionDial(ctx, network, address, config)
		}
		return transport
	})
	t.Cleanup(manager.closeIdle)
	target := &config.Target{
		Address: listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH2},
			ServerName: "shared-tls-dial.example",
		},
	}
	key := http2ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}

	type dialResult struct {
		connection net.Conn
		err        error
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan dialResult, 1)
	go func() {
		connection, dialErr := manager.dial(firstCtx, target, "first-shared-dial.example:443")
		firstDone <- dialResult{connection: connection, err: dialErr}
	}()

	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.Close()
	case err := <-acceptStopped:
		t.Fatalf("shared TLS listener stopped before first accept: %v", err)
	case <-time.After(time.Second):
		t.Fatal("first HTTP/2 TLS dial did not reach the server")
	}
	clientHelloRead := make(chan error, 1)
	physicalClosed := make(chan error, 1)
	go func() {
		_, helloErr := readTLSClientHello(serverConnection, 64<<10)
		clientHelloRead <- helloErr
		if helloErr != nil {
			physicalClosed <- helloErr
			return
		}
		buffer := make([]byte, 256)
		for {
			if _, readErr := serverConnection.Read(buffer); readErr != nil {
				physicalClosed <- readErr
				return
			}
		}
	}()
	select {
	case helloErr := <-clientHelloRead:
		if helloErr != nil {
			t.Fatalf("read first shared ClientHello: %v", helloErr)
		}
	case <-time.After(time.Second):
		t.Fatal("first shared TLS dial did not send a ClientHello")
	}
	if !waitForHTTP2TLSManagerActive(manager, key, 1, time.Second) {
		t.Fatal("first shared TLS dial did not remain active")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelSecond()
	secondStarted := time.Now()
	secondDone := make(chan dialResult, 1)
	go func() {
		connection, dialErr := manager.dial(secondCtx, target, "second-shared-dial.example:443")
		secondDone <- dialResult{connection: connection, err: dialErr}
	}()
	if !waitForHTTP2TLSManagerActive(manager, key, 2, 100*time.Millisecond) {
		cancelSecond()
		t.Fatal("second HTTP/2 request did not join the shared in-flight dial")
	}

	var second dialResult
	select {
	case second = <-secondDone:
	case <-time.After(time.Second):
		cancelSecond()
		t.Fatal("second shared-dial waiter did not honor its deadline")
	}
	if second.connection != nil {
		_ = second.connection.Close()
		t.Fatal("timed-out shared-dial waiter returned an HTTP/2 tunnel")
	}
	if !errors.Is(second.err, context.DeadlineExceeded) {
		t.Fatalf("second shared-dial error = %v, want context deadline exceeded", second.err)
	}
	if elapsed := time.Since(secondStarted); elapsed >= time.Second {
		t.Fatalf("second shared-dial waiter returned after %s, want its short deadline", elapsed)
	}
	if !errors.Is(secondCtx.Err(), context.DeadlineExceeded) {
		t.Fatalf("second request context = %v, want context deadline exceeded", secondCtx.Err())
	}
	if got := physicalDials.Load(); got != 1 {
		t.Fatalf("physical TLS dials while sharing an in-flight dial = %d, want 1", got)
	}
	select {
	case extra := <-accepted:
		_ = extra.Close()
		t.Fatal("second waiter opened a second physical TCP connection")
	default:
	}
	select {
	case first := <-firstDone:
		if first.connection != nil {
			_ = first.connection.Close()
		}
		t.Fatalf("second waiter canceled the first shared dial: %v", first.err)
	default:
	}
	select {
	case closeErr := <-physicalClosed:
		t.Fatalf("second waiter closed the shared physical TCP connection: %v", closeErr)
	default:
	}
	// The timed-out request returns to its caller immediately, but its shared
	// RoundTrip cleanup keeps the second manager lease until the common dial
	// resolves. Releasing it early would let retire discard a transport that
	// still has a goroutine waiting on that dial.
	if !waitForHTTP2TLSManagerActive(manager, key, 2, 100*time.Millisecond) {
		manager.mu.Lock()
		active := manager.active[key]
		manager.mu.Unlock()
		t.Fatalf("shared-dial cleanup lease count = %d, want 2 until the physical dial resolves", active)
	}

	manager.retire()
	manager.mu.Lock()
	activeBeforeCancel := manager.active[key]
	_, retainedBeforeCancel := manager.transports[key]
	retiredBeforeCancel := manager.retired
	manager.mu.Unlock()
	if !retiredBeforeCancel || activeBeforeCancel != 2 || !retainedBeforeCancel {
		t.Fatalf("retired manager before first cancel = retired:%t active:%d retained:%t, want true/2/true",
			retiredBeforeCancel, activeBeforeCancel, retainedBeforeCancel)
	}

	cancelFirst()
	var first dialResult
	select {
	case first = <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first shared TLS dial did not stop after cancellation")
	}
	if first.connection != nil {
		_ = first.connection.Close()
		t.Fatal("canceled first shared dial returned an HTTP/2 tunnel")
	}
	if !errors.Is(first.err, context.Canceled) {
		t.Fatalf("first shared-dial error = %v, want context canceled", first.err)
	}
	select {
	case closeErr := <-physicalClosed:
		if closeErr == nil {
			t.Fatal("canceled first shared dial did not close physical TCP")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled first shared dial left physical TCP open")
	}
	if !waitForHTTP2TLSManagerActive(manager, key, 0, time.Second) {
		manager.mu.Lock()
		active := manager.active[key]
		manager.mu.Unlock()
		t.Fatalf("shared-dial manager leases were not cleaned after cancellation: active=%d", active)
	}
	manager.mu.Lock()
	activeAfterCancel := manager.active[key]
	_, retainedAfterCancel := manager.transports[key]
	manager.mu.Unlock()
	if activeAfterCancel != 0 || retainedAfterCancel {
		t.Fatalf("retired manager after first cancel = active:%d retained:%t, want 0/false",
			activeAfterCancel, retainedAfterCancel)
	}

	_ = listener.Close()
	select {
	case <-acceptStopped:
	case <-time.After(time.Second):
		t.Fatal("shared TLS accept loop did not stop")
	}
}

func waitForHTTP2TLSManagerActive(
	manager *http2ConnectManager,
	key http2ConnectTransportKey,
	want int,
	timeout time.Duration,
) bool {
	deadline := time.Now().Add(timeout)
	for {
		manager.mu.Lock()
		active := manager.active[key]
		manager.mu.Unlock()
		if active == want {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHTTP2TLSRejectsInsecureSkipVerifyBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for insecure TLS dial detection: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpListener := listener.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set insecure TLS accept deadline: %v", err)
	}

	manager := newHTTP2ConnectManager(nil)
	t.Cleanup(manager.closeIdle)
	target := &config.Target{
		Address: listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols:  []string{config.ConnectProxyH2},
			ServerName: "insecure-tls.example",
		},
	}
	key := http2ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	transport, release := manager.acquireTransport(key)
	transport.TLSClientConfig.InsecureSkipVerify = true
	release()

	type dialResult struct {
		connection net.Conn
		err        error
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialed := make(chan dialResult, 1)
	go func() {
		connection, dialErr := manager.dial(ctx, target, "insecure-tls-destination.example:443")
		dialed <- dialResult{connection: connection, err: dialErr}
	}()

	accepted, acceptErr := listener.Accept()
	if accepted != nil {
		_ = accepted.Close()
		cancel()
	}
	var result dialResult
	select {
	case result = <-dialed:
	case <-time.After(time.Second):
		t.Fatal("insecure TLS configuration did not return promptly")
	}
	if accepted != nil {
		if result.connection != nil {
			_ = result.connection.Close()
		}
		t.Fatal("InsecureSkipVerify reached the TCP dial instead of being rejected first")
	}
	var netError net.Error
	if acceptErr == nil || !errors.As(acceptErr, &netError) || !netError.Timeout() {
		t.Fatalf("accept without an insecure TLS dial = %v, want deadline timeout", acceptErr)
	}
	if result.connection != nil {
		_ = result.connection.Close()
		t.Fatal("InsecureSkipVerify returned an HTTP/2 tunnel")
	}
	if result.err == nil || !strings.Contains(result.err.Error(), "certificate verification cannot be disabled") {
		t.Fatalf("InsecureSkipVerify error = %v, want explicit certificate-verification rejection", result.err)
	}
}

func assertChromeHTTP2ClientHello(t *testing.T, raw []byte) {
	t.Helper()
	fingerprint, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(raw)
	if err != nil {
		t.Fatalf("fingerprint captured ClientHello: %v", err)
	}
	wantCipherSuites := []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	if !reflect.DeepEqual(fingerprint.CipherSuites, wantCipherSuites) {
		t.Fatalf("ClientHello cipher suites = %#v, want pinned Chrome suites %#v", fingerprint.CipherSuites, wantCipherSuites)
	}
	if want := []uint8{0}; !reflect.DeepEqual(fingerprint.CompressionMethods, want) {
		t.Fatalf("ClientHello compression methods = %#v, want %#v", fingerprint.CompressionMethods, want)
	}

	var (
		greaseExtensions int
		compressCert     *utls.UtlsCompressCertExtension
		application      *utls.ApplicationSettingsExtensionNew
		ech              *utls.GREASEEncryptedClientHelloExtension
		curves           *utls.SupportedCurvesExtension
		versions         *utls.SupportedVersionsExtension
		signatures       *utls.SignatureAlgorithmsExtension
		alpn             *utls.ALPNExtension
	)
	for _, extension := range fingerprint.Extensions {
		switch typed := extension.(type) {
		case *utls.UtlsGREASEExtension:
			greaseExtensions++
		case *utls.UtlsCompressCertExtension:
			compressCert = typed
		case *utls.ApplicationSettingsExtensionNew:
			application = typed
		case *utls.GREASEEncryptedClientHelloExtension:
			ech = typed
		case *utls.SupportedCurvesExtension:
			curves = typed
		case *utls.SupportedVersionsExtension:
			versions = typed
		case *utls.SignatureAlgorithmsExtension:
			signatures = typed
		case *utls.ALPNExtension:
			alpn = typed
		}
	}
	if greaseExtensions != 2 {
		t.Fatalf("ClientHello GREASE extension count = %d, want 2", greaseExtensions)
	}
	if compressCert == nil || !reflect.DeepEqual(compressCert.Algorithms, []utls.CertCompressionAlgo{utls.CertCompressionBrotli}) {
		t.Fatalf("ClientHello compress_certificate = %#v, want Brotli", compressCert)
	}
	if application == nil || !reflect.DeepEqual(application.SupportedProtocols, []string{"h2"}) {
		t.Fatalf("ClientHello ALPS = %#v, want h2 on Chrome codepoint", application)
	}
	if ech == nil {
		t.Fatal("ClientHello is missing Chrome GREASE ECH")
	}
	if alpn == nil || !reflect.DeepEqual(alpn.AlpnProtocols, []string{"h2", "http/1.1"}) {
		t.Fatalf("ClientHello ALPN extension = %#v, want h2 and http/1.1", alpn)
	}
	if curves == nil {
		t.Fatal("ClientHello is missing supported_groups")
	}
	wantCurves := []utls.CurveID{
		utls.GREASE_PLACEHOLDER,
		utls.X25519MLKEM768,
		utls.X25519,
		utls.CurveP256,
		utls.CurveP384,
	}
	if !reflect.DeepEqual(curves.Curves, wantCurves) {
		t.Fatalf("ClientHello supported groups = %#v, want pinned Chrome groups %#v", curves.Curves, wantCurves)
	}
	if versions == nil || !reflect.DeepEqual(versions.Versions, []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.VersionTLS13,
		utls.VersionTLS12,
	}) {
		t.Fatalf("ClientHello supported versions = %#v, want Chrome TLS 1.3/1.2", versions)
	}
	wantSignatures := []utls.SignatureScheme{
		utls.ECDSAWithP256AndSHA256,
		utls.PSSWithSHA256,
		utls.PKCS1WithSHA256,
		utls.ECDSAWithP384AndSHA384,
		utls.PSSWithSHA384,
		utls.PKCS1WithSHA384,
		utls.PSSWithSHA512,
		utls.PKCS1WithSHA512,
	}
	if signatures == nil || !reflect.DeepEqual(signatures.SupportedSignatureAlgorithms, wantSignatures) {
		t.Fatalf("ClientHello signature algorithms = %#v, want pinned Chrome algorithms %#v", signatures, wantSignatures)
	}
}

type http2TLSCaptureListener struct {
	net.Listener
	captures chan *http2TLSCaptureConn
}

func (listener *http2TLSCaptureListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	captured := &http2TLSCaptureConn{
		Conn:   connection,
		closed: make(chan struct{}),
	}
	listener.captures <- captured
	return captured, nil
}

type http2TLSCaptureConn struct {
	net.Conn
	mu        sync.Mutex
	clientRaw bytes.Buffer
	closed    chan struct{}
	closeOnce sync.Once
}

func (connection *http2TLSCaptureConn) Read(buffer []byte) (int, error) {
	read, err := connection.Conn.Read(buffer)
	if read > 0 {
		connection.mu.Lock()
		_, _ = connection.clientRaw.Write(buffer[:read])
		connection.mu.Unlock()
	}
	return read, err
}

func (connection *http2TLSCaptureConn) Close() error {
	err := connection.Conn.Close()
	connection.closeOnce.Do(func() { close(connection.closed) })
	return err
}

func (connection *http2TLSCaptureConn) snapshot() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return bytes.Clone(connection.clientRaw.Bytes())
}

func newHTTP2TLSCaptureServer(
	t *testing.T,
	nextProtos []string,
	handler http.HandlerFunc,
) (*httptest.Server, <-chan *http2TLSCaptureConn) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.EnableHTTP2 = true
	server.TLS = server.Config.TLSConfig
	if server.TLS == nil {
		server.TLS = new(tls.Config)
	}
	server.TLS.NextProtos = make([]string, len(nextProtos))
	copy(server.TLS.NextProtos, nextProtos)
	captures := make(chan *http2TLSCaptureConn, 16)
	server.Listener = &http2TLSCaptureListener{
		Listener: server.Listener,
		captures: captures,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, captures
}

func waitForHTTP2TLSCapture(t *testing.T, captures <-chan *http2TLSCaptureConn) *http2TLSCaptureConn {
	t.Helper()
	select {
	case captured := <-captures:
		return captured
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/2 TLS server did not accept a connection")
		return nil
	}
}

func capturedHTTP2ClientHello(t *testing.T, captured *http2TLSCaptureConn) tlsClientHelloProbe {
	t.Helper()
	raw := captured.snapshot()
	probe, err := readTLSClientHello(bytes.NewReader(raw), 64<<10)
	if err != nil {
		t.Fatalf("parse captured HTTP/2 ClientHello from %d bytes: %v", len(raw), err)
	}
	return probe
}

func waitForHTTP2TLSCaptureClosed(t *testing.T, captured *http2TLSCaptureConn) {
	t.Helper()
	select {
	case <-captured.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("failed HTTP/2 TLS connection was not closed")
	}
}

var _ net.Listener = (*http2TLSCaptureListener)(nil)
var _ net.Conn = (*http2TLSCaptureConn)(nil)
