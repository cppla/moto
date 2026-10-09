package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"moto/config"
	xhttp2 "moto/internal/browserhttp2"
)

const (
	browserH2SuccessProxyHost = "proxy.baseline.invalid"
	browserH2SuccessUser      = "baseline-user"
	browserH2SuccessPassword  = "baseline-pass"
)

var browserH2SuccessURLs = []string{"https://one.baseline.invalid/one", "https://two.baseline.invalid/two"}

var errBrowserH2SuccessDuplicateAuth = errors.New("duplicate Proxy-Authorization headers; raw bytes not persisted")

func browserH2SuccessBody(index int) string {
	return fmt.Sprintf("<!doctype html><html><head><link rel=\"icon\" href=\"data:,\"></head><body>moto-browser-baseline-payload-%d</body></html>\n", index+1)
}

// TestBrowserBaselineH2Success is an opt-in, closed-loop wire fixture. The only
// permitted CONNECT targets terminate in an in-memory TLS origin. Neither the
// proxy nor its origins resolve or dial a client-supplied network address.
func TestBrowserBaselineH2Success(t *testing.T) {
	dir := os.Getenv("MOTO_BROWSER_CAPTURE_DIR")
	if dir == "" {
		t.Skip("set MOTO_BROWSER_CAPTURE_DIR for the opt-in successful browser capture")
	}
	actor := os.Getenv("MOTO_BROWSER_ACTOR")
	if actor == "" {
		actor = "moto"
	}
	scenario := os.Getenv("MOTO_BROWSER_SCENARIO")
	if scenario == "" {
		scenario = "h2_sni_reuse"
	}
	if actor != "moto" && actor != "chrome" {
		t.Fatalf("unknown capture actor %q", actor)
	}
	if scenario != "h2_sni_reuse" && scenario != "h2_auth_reuse" {
		t.Fatalf("unknown successful H2 scenario %q", scenario)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if actor == "chrome" {
		if err := browserH2SuccessFreshDirectory(dir); err != nil {
			t.Fatal(err)
		}
	}
	certificate, parsed := browserH2SuccessCertificate(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	server := browserH2StartSuccessServer(listener, certificate, scenario == "h2_auth_reuse", ctx)
	defer server.close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	bodies := []string{browserH2SuccessBody(0), browserH2SuccessBody(1)}
	bodyHashes := make([]string, len(bodies))
	for index, body := range bodies {
		bodyHashes[index] = fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	}
	spki := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	browserH2WriteJSON(t, filepath.Join(dir, "ready.json"), map[string]any{
		"endpoint": listener.Addr().String(), "proxy_url": "https://" + net.JoinHostPort(browserH2SuccessProxyHost, port),
		"proxy_host": browserH2SuccessProxyHost, "protocol": "h2", "scenario": scenario,
		"spki": base64.StdEncoding.EncodeToString(spki[:]), "urls": browserH2SuccessURLs, "expected_bodies": bodies,
		"test_credentials": map[string]string{"username": browserH2SuccessUser, "password": browserH2SuccessPassword},
	})
	if actor == "moto" {
		browserH2SuccessRunMoto(t, ctx, listener.Addr().String(), parsed, server.authRequired)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		server.mu.Lock()
		completed := 0
		for _, request := range server.requests {
			if request.PayloadCompleted {
				completed++
			}
		}
		server.mu.Unlock()
		if completed >= 2 {
			if actor == "moto" || browserH2SuccessClientProof(t, dir, bodyHashes) {
				break
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			server.mu.Lock()
			requests, _ := json.Marshal(server.requests)
			server.mu.Unlock()
			t.Fatalf("successful H2 capture timed out; completed=%d requests=%s", completed, requests)
		}
	}
	server.close()
	browserH2SuccessWriteCapture(t, dir, actor, scenario, server)
}

func browserH2SuccessFreshDirectory(dir string) error {
	for _, name := range []string{"client-proof.json", "capture.json"} {
		_, err := os.Lstat(filepath.Join(dir, name))
		if err == nil {
			return fmt.Errorf("Chrome capture directory already contains %s; use a fresh directory", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check fresh Chrome capture directory: %w", err)
		}
	}
	return nil
}

func TestBrowserBaselineH2SuccessFreshDirectory(t *testing.T) {
	for _, name := range []string{"", "client-proof.json", "capture.json"} {
		t.Run("existing_"+name, func(t *testing.T) {
			dir := t.TempDir()
			if name != "" {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := browserH2SuccessFreshDirectory(dir); (err == nil) != (name == "") {
				t.Fatalf("fresh directory validation error=%v existing=%q", err, name)
			}
		})
	}
}

func browserH2SuccessClientProof(t *testing.T, dir string, hashes []string) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "client-proof.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		Verified   bool     `json:"verified"`
		URLs       []string `json:"urls"`
		BodySHA256 []string `json:"body_sha256"`
	}
	if err := json.Unmarshal(data, &proof); err != nil {
		return false // The runner may still be publishing its proof.
	}
	if !proof.Verified || !reflect.DeepEqual(proof.URLs, browserH2SuccessURLs) || !reflect.DeepEqual(proof.BodySHA256, hashes) {
		t.Fatalf("Chrome client proof does not verify both fixture responses")
	}
	return true
}

func browserH2SuccessCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: browserH2SuccessProxyHost},
		DNSNames:  []string{browserH2SuccessProxyHost, "one.baseline.invalid", "two.baseline.invalid"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, parsed
}

func browserH2SuccessRunMoto(t *testing.T, ctx context.Context, endpoint string, certificate *x509.Certificate, auth bool) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer manager.closeIdle()
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH2}, ServerName: browserH2SuccessProxyHost,
	}}
	if auth {
		target.ConnectProxy.BasicAuth = &config.BasicAuthConfig{Username: browserH2SuccessUser, Password: browserH2SuccessPassword}
	}
	for index, rawURL := range browserH2SuccessURLs {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		tunnel, err := manager.dial(ctx, target, request.URL.Host+":443")
		if err != nil {
			t.Fatalf("Moto successful CONNECT %d: %v", index+1, err)
		}
		// H2 tunnels do not implement deadlines. Keep the whole fixture exchange,
		// including the origin shutdown read, bounded by the capture context.
		stopOnCancel := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
		origin := tls.Client(tunnel, &tls.Config{RootCAs: roots, ServerName: request.URL.Host, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := origin.HandshakeContext(ctx); err != nil {
			_ = origin.Close()
			stopOnCancel()
			t.Fatal(err)
		}
		if err := request.Write(origin); err != nil {
			_ = origin.Close()
			stopOnCancel()
			t.Fatal(err)
		}
		readErr := browserH2SuccessReadOriginResponse(origin, tunnel, request, index)
		_ = origin.Close()
		stopOnCancel()
		if readErr != nil {
			t.Fatalf("Moto payload %d: %v", index+1, readErr)
		}
	}
}

func browserH2SuccessReadOriginResponse(origin, tunnel io.Reader, request *http.Request, index int) error {
	reader := bufio.NewReader(origin)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return fmt.Errorf("read origin response body: %w", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != browserH2SuccessBody(index) {
		return fmt.Errorf("unexpected origin response: status=%d body=%q", response.StatusCode, body)
	}
	// This controlled origin promises Connection: close. Let its TLS shutdown
	// finish before closing the CONNECT upload: an early client close makes the
	// proxy's upload goroutine close net.Pipe while its download still relays
	// close_notify, misreporting a fully delivered response as a closed pipe.
	// Reuse the buffered reader so any bytes after the declared body fail closed.
	if err := browserH2SuccessWaitEOF(reader, "origin"); err != nil {
		return err
	}
	// close_notify ends the inner TLS stream before the proxy necessarily
	// finishes its relay. Also await the outer H2 END_STREAM before canceling
	// the tunnel, so the upload cannot close the pipe underneath that relay.
	return browserH2SuccessWaitEOF(tunnel, "CONNECT")
}

func browserH2SuccessWaitEOF(reader io.Reader, stage string) error {
	var extra [1]byte
	if _, err := io.ReadFull(reader, extra[:]); err != io.EOF {
		if err != nil {
			return fmt.Errorf("read %s shutdown: %w", stage, err)
		}
		return fmt.Errorf("unexpected bytes after %s response", stage)
	}
	return nil
}

type browserH2SuccessShutdownReader struct {
	started chan struct{}
	release chan struct{}
}

func (reader browserH2SuccessShutdownReader) Read([]byte) (int, error) {
	close(reader.started)
	<-reader.release
	return 0, io.EOF
}

func TestBrowserBaselineH2SuccessWaitsForOriginShutdown(t *testing.T) {
	for _, stage := range []string{"origin", "CONNECT"} {
		t.Run(stage, func(t *testing.T) {
			body := browserH2SuccessBody(0)
			response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			shutdown := browserH2SuccessShutdownReader{started: make(chan struct{}), release: make(chan struct{})}
			releaseShutdown := sync.OnceFunc(func() { close(shutdown.release) })
			defer releaseShutdown()
			var reader io.Reader = strings.NewReader(response)
			var tunnel io.Reader = strings.NewReader("")
			if stage == "origin" {
				reader = io.MultiReader(reader, shutdown)
			} else {
				tunnel = shutdown
			}
			request, err := http.NewRequest(http.MethodGet, browserH2SuccessURLs[0], nil)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- browserH2SuccessReadOriginResponse(reader, tunnel, request, 0) }()
			select {
			case err := <-done:
				t.Fatalf("response verification returned before %s shutdown: %v", stage, err)
			case <-shutdown.started:
			case <-time.After(time.Second):
				t.Fatalf("response verification did not wait for %s shutdown", stage)
			}
			releaseShutdown()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("response verification after %s shutdown: %v", stage, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("response verification did not finish after %s shutdown", stage)
			}
		})
	}
}

func TestBrowserBaselineH2SuccessOriginResponseFailures(t *testing.T) {
	wantBody := browserH2SuccessBody(0)
	for _, test := range []struct {
		name        string
		body        string
		extra       string
		finalErr    error
		tunnelExtra string
		tunnelErr   error
		wantErr     error
		valid       bool
	}{
		{name: "complete", body: wantBody, finalErr: io.EOF, valid: true},
		{name: "truncated", body: wantBody[:len(wantBody)-1], finalErr: io.EOF, wantErr: io.ErrUnexpectedEOF},
		{name: "corrupt", body: strings.Repeat("x", len(wantBody)), finalErr: io.EOF},
		{name: "trailing_bytes", body: wantBody, extra: "unexpected", finalErr: io.EOF},
		{name: "shutdown_timeout", body: wantBody, finalErr: os.ErrDeadlineExceeded, wantErr: os.ErrDeadlineExceeded},
		{name: "shutdown_closed_pipe", body: wantBody, finalErr: io.ErrClosedPipe, wantErr: io.ErrClosedPipe},
		{name: "tunnel_trailing_bytes", body: wantBody, finalErr: io.EOF, tunnelExtra: "unexpected"},
		{name: "tunnel_shutdown_timeout", body: wantBody, finalErr: io.EOF, tunnelErr: os.ErrDeadlineExceeded, wantErr: os.ErrDeadlineExceeded},
		{name: "tunnel_shutdown_closed_pipe", body: wantBody, finalErr: io.EOF, tunnelErr: io.ErrClosedPipe, wantErr: io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s%s", len(wantBody), test.body, test.extra)
			reader := io.MultiReader(strings.NewReader(response), iotest.ErrReader(test.finalErr))
			request, err := http.NewRequest(http.MethodGet, browserH2SuccessURLs[0], nil)
			if err != nil {
				t.Fatal(err)
			}
			tunnelErr := test.tunnelErr
			if tunnelErr == nil {
				tunnelErr = io.EOF
			}
			tunnel := io.MultiReader(strings.NewReader(test.tunnelExtra), iotest.ErrReader(tunnelErr))
			err = browserH2SuccessReadOriginResponse(reader, tunnel, request, 0)
			if (err == nil) != test.valid {
				t.Fatalf("origin response error = %v, valid = %t", err, test.valid)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("origin response error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestBrowserBaselineH2SuccessOriginShutdownDeadline(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, err := http.NewRequest(http.MethodGet, browserH2SuccessURLs[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- browserH2SuccessReadOriginResponse(reader, strings.NewReader(""), request, 0) }()
	body := browserH2SuccessBody(0)
	if _, err := fmt.Fprintf(writer, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body); err != nil {
		t.Fatal(err)
	}
	// The entire response has been consumed, but the origin never shuts down.
	if err := reader.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("origin shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("origin shutdown read ignored its deadline")
	}
}

type browserH2SuccessRequest struct {
	ConnectionID     int    `json:"connection_id"`
	StreamID         uint32 `json:"stream_id,omitempty"`
	Method           string `json:"method"`
	Authority        string `json:"authority"`
	Auth             string `json:"auth"`
	Status           int    `json:"status"`
	PayloadCompleted bool   `json:"payload_completed"`
	OriginMethod     string `json:"origin_method,omitempty"`
	OriginPath       string `json:"origin_path,omitempty"`
	OriginHost       string `json:"origin_host,omitempty"`
	ResponseBytes    int    `json:"response_bytes,omitempty"`
	Error            string `json:"error,omitempty"`
}

type browserH2SuccessConnection struct {
	ID                 int                           `json:"id"`
	ServerName         string                        `json:"server_name"`
	NegotiatedProtocol string                        `json:"negotiated_protocol"`
	Error              string                        `json:"error,omitempty"`
	WireRequests       []browserH2SuccessWireRequest `json:"wire_requests,omitempty"`
	WireParseError     string                        `json:"wire_parse_error,omitempty"`
	hello              []byte
	plaintext          browserH2SuccessBuffer
}

// x/net/http2 reads frames in its own goroutine, which can still finish a Read
// while ServeConn returns. Snapshot under a lock instead of exposing Bytes().
type browserH2SuccessBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *browserH2SuccessBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *browserH2SuccessBuffer) snapshot() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

type browserH2SuccessServer struct {
	listener       net.Listener
	certificate    tls.Certificate
	authRequired   bool
	ctx            context.Context
	mu             sync.Mutex
	connections    map[net.Conn]*browserH2SuccessConnection
	allConnections []*browserH2SuccessConnection
	requests       []*browserH2SuccessRequest
	acceptDone     chan struct{}
	workers        sync.WaitGroup
	handlers       sync.WaitGroup
	closing        bool
	closeOnce      sync.Once
}

func browserH2StartSuccessServer(listener net.Listener, certificate tls.Certificate, auth bool, ctx context.Context) *browserH2SuccessServer {
	server := &browserH2SuccessServer{listener: listener, certificate: certificate, authRequired: auth, ctx: ctx,
		connections: make(map[net.Conn]*browserH2SuccessConnection), acceptDone: make(chan struct{})}
	go func() {
		defer close(server.acceptDone)
		for id := 1; id <= 16; id++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			record := &browserH2SuccessConnection{ID: id}
			server.mu.Lock()
			server.connections[connection] = record
			server.allConnections = append(server.allConnections, record)
			server.mu.Unlock()
			server.workers.Add(1)
			go func() {
				defer server.workers.Done()
				defer connection.Close()
				defer func() { server.mu.Lock(); delete(server.connections, connection); server.mu.Unlock() }()
				server.serveConnection(connection, record)
			}()
		}
	}()
	return server
}

func (server *browserH2SuccessServer) close() {
	server.closeOnce.Do(func() {
		_ = server.listener.Close()
		<-server.acceptDone
		server.mu.Lock()
		server.closing = true
		connections := make([]net.Conn, 0, len(server.connections))
		for connection := range server.connections {
			connections = append(connections, connection)
		}
		server.mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		server.workers.Wait()
		server.handlers.Wait()
	})
}

func (server *browserH2SuccessServer) serveConnection(connection net.Conn, record *browserH2SuccessConnection) {
	deadline, _ := server.ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	probe, err := readTLSClientHello(connection, 64<<10)
	if err != nil {
		record.Error = "capture ClientHello: " + err.Error()
		return
	}
	record.hello, record.ServerName = probe.Raw, probe.ServerName
	secured := tls.Server(&browserH2ReplayConn{Conn: connection, reader: io.MultiReader(bytes.NewReader(probe.Raw), connection)}, &tls.Config{
		Certificates: []tls.Certificate{server.certificate}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12,
	})
	if err := secured.HandshakeContext(server.ctx); err != nil {
		record.Error = "proxy TLS handshake: " + err.Error()
		return
	}
	record.NegotiatedProtocol = secured.ConnectionState().NegotiatedProtocol
	if record.NegotiatedProtocol != "h2" {
		record.Error = "client did not negotiate h2"
		return
	}
	tee := &browserH2ReplayConn{Conn: secured, reader: io.TeeReader(io.LimitReader(secured, 2<<20), &record.plaintext)}
	// Keep the pinned upstream server independent of Moto's H2 implementation.
	// This test needs to capture plaintext after its own TLS handshake and pass
	// that exact connection to the frame server, without another TLS accept path.
	//lint:ignore SA1019 Intentional low-level API for this loopback-only wire capture fixture.
	protocol := &http2.Server{MaxConcurrentStreams: 8, MaxReadFrameSize: 64 << 10, IdleTimeout: 30 * time.Second}
	//lint:ignore SA1019 Serve the already-negotiated, plaintext-captured connection in this test only.
	protocol.ServeConn(tee, &http2.ServeConnOpts{Context: server.ctx, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// Close the admission gate before waiting for handlers, including any
		// handler goroutines that ServeConn scheduled but has not entered yet.
		server.mu.Lock()
		if server.closing {
			server.mu.Unlock()
			return
		}
		server.handlers.Add(1)
		server.mu.Unlock()
		defer server.handlers.Done()
		server.serveConnect(record.ID, writer, request)
	})})
}

type browserH2SuccessFlushWriter struct{ writer http.ResponseWriter }

func (writer browserH2SuccessFlushWriter) Write(data []byte) (int, error) {
	count, err := writer.writer.Write(data)
	if err == nil {
		err = http.NewResponseController(writer.writer).Flush()
	}
	return count, err
}

func (server *browserH2SuccessServer) serveConnect(connectionID int, writer http.ResponseWriter, request *http.Request) {
	record := &browserH2SuccessRequest{ConnectionID: connectionID, Method: request.Method, Authority: request.Host, Auth: "none"}
	authorizations := request.Header.Values("Proxy-Authorization")
	if len(authorizations) != 0 {
		record.Auth = "invalid"
		if len(authorizations) == 1 && authorizations[0] == "Basic "+base64.StdEncoding.EncodeToString([]byte(browserH2SuccessUser+":"+browserH2SuccessPassword)) {
			record.Auth = "valid"
		}
	}
	index := -1
	switch request.Host {
	case "one.baseline.invalid:443":
		index = 0
	case "two.baseline.invalid:443":
		index = 1
	}
	if request.Method != http.MethodConnect || index < 0 {
		record.Status = http.StatusForbidden
	} else if server.authRequired && record.Auth != "valid" {
		record.Status = http.StatusProxyAuthRequired
		writer.Header().Set("Proxy-Authenticate", `Basic realm="browser-baseline"`)
	} else {
		record.Status = http.StatusOK
	}
	server.mu.Lock()
	if len(server.requests) >= 128 {
		server.mu.Unlock()
		writer.WriteHeader(http.StatusTooManyRequests)
		return
	}
	server.requests = append(server.requests, record)
	server.mu.Unlock()
	writer.WriteHeader(record.Status)
	if record.Status != http.StatusOK {
		return
	}
	if err := http.NewResponseController(writer).Flush(); err != nil {
		server.mu.Lock()
		record.Error = err.Error()
		server.mu.Unlock()
		return
	}
	proxySide, originSide := net.Pipe()
	deadline, _ := server.ctx.Deadline()
	_ = proxySide.SetDeadline(deadline)
	_ = originSide.SetDeadline(deadline)
	originDone := make(chan error, 1)
	go func() { originDone <- server.serveOrigin(originSide, index, record) }()
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, _ = io.Copy(proxySide, io.LimitReader(request.Body, 128<<10))
		_ = proxySide.Close()
	}()
	_, relayErr := io.Copy(browserH2SuccessFlushWriter{writer}, proxySide)
	_ = proxySide.Close()
	_ = request.Body.Close()
	<-uploadDone
	originErr := <-originDone
	server.mu.Lock()
	defer server.mu.Unlock()
	if originErr != nil {
		record.Error = originErr.Error()
	} else if relayErr != nil {
		record.Error = relayErr.Error()
	} else {
		record.PayloadCompleted = true
	}
}

func (server *browserH2SuccessServer) serveOrigin(connection net.Conn, index int, record *browserH2SuccessRequest) error {
	defer connection.Close()
	secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{server.certificate}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	defer secured.Close()
	if err := secured.HandshakeContext(server.ctx); err != nil {
		return fmt.Errorf("origin TLS handshake: %w", err)
	}
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(secured, 16<<10)))
	if err != nil {
		return fmt.Errorf("origin HTTP request: %w", err)
	}
	defer request.Body.Close()
	wantHost := []string{"one.baseline.invalid", "two.baseline.invalid"}[index]
	wantPath := []string{"/one", "/two"}[index]
	if request.Method != http.MethodGet || request.Host != wantHost || request.URL.RequestURI() != wantPath || secured.ConnectionState().ServerName != wantHost {
		return fmt.Errorf("origin request does not match the controlled target")
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return errors.New("controlled GET unexpectedly included a request body")
	}
	body := browserH2SuccessBody(index)
	_, err = fmt.Fprintf(secured, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n%s", len(body), body)
	if err != nil {
		return fmt.Errorf("origin response: %w", err)
	}
	server.mu.Lock()
	record.OriginMethod, record.OriginHost, record.OriginPath, record.ResponseBytes = request.Method, request.Host, request.URL.RequestURI(), len(body)
	server.mu.Unlock()
	return nil
}

type browserH2SuccessWireRequest struct {
	StreamID              uint32   `json:"stream_id"`
	Authority             string   `json:"authority"`
	HeaderNames           []string `json:"header_names"`
	HeaderRepresentations []string `json:"hpack_representations"`
	UserAgent             string   `json:"user_agent"`
	Auth                  string   `json:"auth"`
}

func browserH2SuccessWire(plaintext []byte) (map[string]any, []browserH2SuccessWireRequest, error) {
	if !bytes.HasPrefix(plaintext, []byte(http2.ClientPreface)) {
		return nil, nil, errors.New("missing HTTP/2 client preface")
	}
	blocks, err := browserH2SuccessHeaderBlocks(plaintext[len(http2.ClientPreface):])
	if err != nil {
		return nil, nil, err
	}
	framer := http2.NewFramer(io.Discard, bytes.NewReader(plaintext[len(http2.ClientPreface):]))
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	framer.MaxHeaderListSize = 64 << 10
	framer.SetMaxReadFrameSize(64 << 10)
	type setting struct {
		ID    uint16 `json:"id"`
		Value uint32 `json:"value"`
	}
	settings := []setting{}
	var haveSettings bool
	var increment uint64
	requests := []browserH2SuccessWireRequest{}
	for count := 0; count < 1024; count++ {
		frame, err := framer.ReadFrame()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break // Shutdown can truncate a trailing DATA frame, after verified payloads.
		}
		if err != nil {
			return nil, nil, err
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() && !haveSettings {
				if err := frame.ForeachSetting(func(value http2.Setting) error {
					settings = append(settings, setting{uint16(value.ID), value.Val})
					return nil
				}); err != nil {
					return nil, nil, err
				}
				haveSettings = true
			}
		case *http2.WindowUpdateFrame:
			if frame.StreamID == 0 && len(requests) == 0 {
				increment += uint64(frame.Increment)
			}
		case *http2.MetaHeadersFrame:
			if frame.Truncated || frame.PseudoValue("method") != http.MethodConnect {
				return nil, nil, errors.New("unexpected HTTP/2 request headers")
			}
			representations, err := browserH2SuccessHPACKRepresentations(blocks[frame.StreamID])
			if err != nil {
				return nil, nil, err
			}
			request := browserH2SuccessWireRequest{StreamID: frame.StreamID, Authority: frame.PseudoValue("authority"), HeaderRepresentations: representations, Auth: "none"}
			haveAuthorization := false
			for _, field := range frame.Fields {
				request.HeaderNames = append(request.HeaderNames, field.Name)
				if field.Name == "user-agent" {
					request.UserAgent = field.Value
				}
				if field.Name == "proxy-authorization" {
					if haveAuthorization {
						return nil, nil, errBrowserH2SuccessDuplicateAuth
					}
					haveAuthorization = true
					request.Auth = "invalid"
					if field.Value == "Basic "+base64.StdEncoding.EncodeToString([]byte(browserH2SuccessUser+":"+browserH2SuccessPassword)) {
						request.Auth = "valid"
					}
				}
			}
			requests = append(requests, request)
		}
	}
	if !haveSettings {
		return nil, nil, errors.New("no initial HTTP/2 SETTINGS")
	}
	return map[string]any{"h2.settings": settings, "h2.connection_window_increment": increment}, requests, nil
}

// A separate raw pass retains HPACK representation classes that a normal
// decoder discards. It neither rewrites traffic nor depends on header values.
func browserH2SuccessHeaderBlocks(plaintext []byte) (map[uint32][]byte, error) {
	blocks := make(map[uint32][]byte)
	framer := http2.NewFramer(io.Discard, bytes.NewReader(plaintext))
	framer.SetMaxReadFrameSize(64 << 10)
	var incompleteHeaders bool
	for count := 0; count < 1024; count++ {
		frame, err := framer.ReadFrame()
		if errors.Is(err, io.EOF) && !incompleteHeaders {
			return blocks, nil
		}
		if err != nil {
			return nil, err
		}
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			blocks[frame.StreamID] = append(blocks[frame.StreamID], frame.HeaderBlockFragment()...)
			incompleteHeaders = !frame.HeadersEnded()
		case *http2.ContinuationFrame:
			blocks[frame.StreamID] = append(blocks[frame.StreamID], frame.HeaderBlockFragment()...)
			incompleteHeaders = !frame.HeadersEnded()
		}
	}
	return nil, errors.New("capture exceeds 1024 HTTP/2 frames")
}

func browserH2SuccessHPACKRepresentations(block []byte) ([]string, error) {
	classes := []string{}
	readInteger := func(prefix byte) (uint64, error) {
		if len(block) == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		mask := byte((1 << prefix) - 1)
		value := uint64(block[0] & mask)
		block = block[1:]
		if value < uint64(mask) {
			return value, nil
		}
		for shift := uint(0); shift < 56; shift += 7 {
			if len(block) == 0 {
				return 0, io.ErrUnexpectedEOF
			}
			current := block[0]
			block = block[1:]
			value += uint64(current&127) << shift
			if current&128 == 0 {
				return value, nil
			}
		}
		return 0, errors.New("HPACK integer exceeds capture bound")
	}
	skipString := func() error {
		length, err := readInteger(7)
		if err != nil {
			return err
		}
		if length > uint64(len(block)) {
			return io.ErrUnexpectedEOF
		}
		block = block[length:]
		return nil
	}
	for len(block) > 0 {
		first := block[0]
		if first&128 != 0 {
			index, err := readInteger(7)
			if err != nil {
				return nil, err
			}
			if index == 0 {
				return nil, errors.New("HPACK indexed representation has index zero")
			}
			class := "indexed_static"
			if index > 61 {
				class = "indexed_dynamic"
			}
			classes = append(classes, class)
			continue
		}
		if first&224 == 32 {
			if _, err := readInteger(5); err != nil {
				return nil, err
			}
			classes = append(classes, "dynamic_table_size_update")
			continue
		}
		class, prefix := "literal_without_indexing", byte(4)
		if first&64 != 0 {
			class, prefix = "literal_incremental_indexing", 6
		} else if first&16 != 0 {
			class = "literal_never_indexed"
		}
		nameIndex, err := readInteger(prefix)
		if err != nil {
			return nil, err
		}
		switch {
		case nameIndex == 0:
			class += ":new_name"
			if err := skipString(); err != nil {
				return nil, err
			}
		case nameIndex <= 61:
			class += ":static_name"
		default:
			class += ":dynamic_name"
		}
		if err := skipString(); err != nil {
			return nil, err
		}
		classes = append(classes, class)
	}
	return classes, nil
}

func browserH2SuccessWriteCapture(t *testing.T, dir, actor, scenario string, server *browserH2SuccessServer) {
	t.Helper()
	server.mu.Lock()
	defer server.mu.Unlock()
	rawArtifacts := make(map[string]any)
	snapshots := make(map[int][]byte)
	unexpectedCredentials := false
	unsafeConnections := make(map[int]bool)
	// Include denied background requests: credential safety does not depend on
	// whether an authority is part of the controlled comparison scenario.
	for _, request := range server.requests {
		if request.Auth == "invalid" {
			unsafeConnections[request.ConnectionID] = true
			unexpectedCredentials = true
		}
	}
	for _, connection := range server.allConnections {
		plaintext := connection.plaintext.snapshot()
		snapshots[connection.ID] = plaintext
		_, wireRequests, err := browserH2SuccessWire(plaintext)
		if err != nil {
			connection.WireParseError = err.Error()
			if errors.Is(err, errBrowserH2SuccessDuplicateAuth) {
				unexpectedCredentials = true
			}
			continue
		}
		connection.WireRequests = wireRequests
		if unsafeConnections[connection.ID] {
			connection.WireParseError = "unexpected credentials; raw bytes not persisted"
		}
		for _, wireRequest := range wireRequests {
			if wireRequest.Auth == "invalid" {
				unexpectedCredentials = true
				connection.WireParseError = "unexpected credentials; raw bytes not persisted"
			}
			for _, request := range server.requests {
				if request.ConnectionID == connection.ID && request.StreamID == 0 && request.Authority == wireRequest.Authority && request.Auth == wireRequest.Auth {
					request.StreamID = wireRequest.StreamID
					break
				}
			}
		}
		if connection.WireParseError != "" {
			continue
		}
		for suffix, data := range map[string][]byte{"tls-clienthello.bin": connection.hello, "h2-client-plaintext.bin": plaintext} {
			if len(data) == 0 {
				continue
			}
			name := fmt.Sprintf("connection-%02d-%s", connection.ID, suffix)
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			rawArtifacts[name] = map[string]any{"sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "bytes": len(data)}
		}
	}
	// Keep bounded factual evidence even when an assertion below rejects a
	// browser behavior. Diagnostic output never converts a failed run to a pass.
	browserH2WriteJSON(t, filepath.Join(dir, "diagnostic.json"), map[string]any{
		"actor": actor, "scenario": scenario, "connections": server.allConnections, "requests": server.requests, "raw_artifacts": rawArtifacts,
	})
	if unexpectedCredentials {
		t.Fatal("unexpected credentials observed; associated raw bytes were not persisted")
	}
	var successful []*browserH2SuccessRequest
	var controlled []*browserH2SuccessRequest
	challenges, validated, completed := 0, 0, 0
	sequence := []map[string]any{}
	for _, request := range server.requests {
		if request.Method != http.MethodConnect || (request.Authority != "one.baseline.invalid:443" && request.Authority != "two.baseline.invalid:443") {
			if request.Status != http.StatusForbidden || request.PayloadCompleted {
				t.Fatal("out-of-scope request was not rejected without payload")
			}
			continue
		}
		controlled = append(controlled, request)
		sequence = append(sequence, map[string]any{"credentials": request.Auth, "status": request.Status})
		if request.Status == http.StatusProxyAuthRequired {
			challenges++
		}
		if request.Auth == "valid" {
			validated++
		}
		if request.Status == http.StatusOK {
			successful = append(successful, request)
		}
		if request.PayloadCompleted {
			completed++
		}
		if request.Error != "" {
			t.Fatalf("controlled CONNECT failed: %+v", request)
		}
	}
	if err := browserH2SuccessValidateTunnels(successful, completed); err != nil {
		t.Fatalf("invalid successful tunnel evidence: %v", err)
	}
	if server.authRequired {
		if validated != 2 || (actor == "chrome" && (challenges < 1 || challenges > 8)) || (actor == "moto" && challenges != 0) {
			t.Fatalf("unexpected authentication sequence: %+v", sequence)
		}
		if err := browserH2SuccessValidateAuthSequence(controlled); err != nil {
			t.Fatalf("authentication sequence is not initial challenge then cached credentials: %v", err)
		}
	}
	var features map[string]any
	for _, connection := range server.allConnections {
		if connection.ID != successful[0].ConnectionID {
			continue
		}
		if connection.ServerName != browserH2SuccessProxyHost {
			t.Fatalf("proxy SNI = %q", connection.ServerName)
		}
		features = browserH2TLSFeatures(t, connection.hello)
		features["tls.server_name"] = connection.ServerName
		h2Features, wireRequests, err := browserH2SuccessWire(snapshots[connection.ID])
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range h2Features {
			features[key] = value
		}
		var accepted []browserH2SuccessWireRequest
		for _, request := range wireRequests {
			if request.StreamID == successful[0].StreamID || request.StreamID == successful[1].StreamID {
				accepted = append(accepted, request)
			}
		}
		if len(accepted) != 2 {
			t.Fatalf("want two captured successful CONNECT blocks, got %d", len(accepted))
		}
		for index, request := range accepted {
			if request.Authority != successful[index].Authority || request.Auth != successful[index].Auth {
				t.Fatal("captured CONNECT does not match successful request evidence")
			}
		}
		features["connect.first.header_names"], features["connect.second.header_names"] = accepted[0].HeaderNames, accepted[1].HeaderNames
		features["connect.first.hpack_representations"], features["connect.second.hpack_representations"] = accepted[0].HeaderRepresentations, accepted[1].HeaderRepresentations
		features["connect.user_agent"] = accepted[0].UserAgent
		features["connect.reused_physical_connection"] = true
		features["auth.sequence"] = sequence
	}
	if features == nil {
		t.Fatal("missing successful physical connection capture")
	}
	browserH2WriteJSON(t, filepath.Join(dir, "capture.json"), map[string]any{
		"schema_version": 1, "actor": actor, "protocol": "h2", "scenario": scenario, "features": features,
		"evidence": map[string]any{
			"connect_received": true, "response_status": http.StatusOK, "successful_tunnels": len(successful),
			"completed_payloads": completed, "client_payloads_verified": true, "reused_physical_connection": true,
			"server_name": browserH2SuccessProxyHost, "auth_required": server.authRequired,
			"auth_challenges": challenges, "auth_validated": validated,
			"connections": server.allConnections, "requests": server.requests,
		},
		"normalization": []string{
			"TLS normalization matches the rejected-CONNECT baseline; actual proxy SNI is additionally retained",
			"HTTP/2 SETTINGS and successful CONNECT header names retain wire order",
			"HPACK classes retain literal/indexed encoding, name-table source and dynamic table size updates; values and exact indexes are excluded",
			"Authentication records preserve challenge attempts separately from successful CONNECT requests",
			"Only exact allowed CONNECT authorities enter auth.sequence; denied browser background requests remain in evidence and raw artifacts",
			"Multiple first-origin challenges are retained; second-origin CONNECT must use cached credentials without a challenge",
			"Raw bytes can include denied Chrome background hostnames and contain only public fixture credentials",
		}, "raw_artifacts": rawArtifacts,
	})
	t.Logf("captured %s %s with two verified payloads on physical H2 connection %d in %s", actor, scenario, successful[0].ConnectionID, dir)
}

func browserH2SuccessValidateTunnels(successful []*browserH2SuccessRequest, completed int) error {
	if len(successful) != 2 || completed != 2 {
		return errors.New("expected exactly two completed tunnels")
	}
	if successful[0].ConnectionID <= 0 || successful[0].ConnectionID != successful[1].ConnectionID {
		return errors.New("successful tunnels did not share one physical connection")
	}
	if successful[0].StreamID == 0 || successful[1].StreamID == 0 || successful[0].StreamID == successful[1].StreamID {
		return errors.New("successful tunnels did not have distinct observed stream IDs")
	}
	if successful[0].Authority != "one.baseline.invalid:443" || successful[1].Authority != "two.baseline.invalid:443" {
		return errors.New("successful destinations were not the expected sequential targets")
	}
	return nil
}

func TestBrowserBaselineH2SuccessTunnelEvidence(t *testing.T) {
	for _, test := range []struct {
		name             string
		secondConnection int
		secondStream     uint32
		secondAuthority  string
		valid            bool
	}{
		{"shared_physical_distinct_streams", 1, 3, "two.baseline.invalid:443", true},
		{"separate_physical_connections", 2, 3, "two.baseline.invalid:443", false},
		{"reused_stream_id", 1, 1, "two.baseline.invalid:443", false},
		{"missing_stream_id", 1, 0, "two.baseline.invalid:443", false},
		{"duplicate_first_authority", 1, 3, "one.baseline.invalid:443", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := []*browserH2SuccessRequest{
				{ConnectionID: 1, StreamID: 1, Authority: "one.baseline.invalid:443"},
				{ConnectionID: test.secondConnection, StreamID: test.secondStream, Authority: test.secondAuthority},
			}
			if err := browserH2SuccessValidateTunnels(requests, 2); (err == nil) != test.valid {
				t.Fatalf("tunnel evidence error=%v want valid=%t", err, test.valid)
			}
		})
	}
}

func browserH2SuccessValidateAuthSequence(requests []*browserH2SuccessRequest) error {
	firstSucceeded := false
	secondSucceeded := false
	for _, request := range requests {
		if secondSucceeded {
			return errors.New("additional controlled request after second origin succeeded")
		}
		if !firstSucceeded {
			if request.Authority != "one.baseline.invalid:443" {
				return errors.New("second origin was attempted before first origin succeeded")
			}
			if request.Auth == "none" && request.Status == http.StatusProxyAuthRequired {
				continue
			}
			if request.Auth != "valid" || request.Status != http.StatusOK {
				return errors.New("first origin did not pass BasicAuth")
			}
			firstSucceeded = true
			continue
		}
		if request.Authority != "two.baseline.invalid:443" || request.Auth != "valid" || request.Status != http.StatusOK {
			return errors.New("second origin did not send valid credentials on its first attempt")
		}
		secondSucceeded = true
	}
	if !firstSucceeded || !secondSucceeded {
		return errors.New("missing successful first or second origin")
	}
	return nil
}

func TestBrowserBaselineH2SuccessAuthSequence(t *testing.T) {
	firstChallenge := &browserH2SuccessRequest{Authority: "one.baseline.invalid:443", Auth: "none", Status: http.StatusProxyAuthRequired}
	firstSuccess := &browserH2SuccessRequest{Authority: "one.baseline.invalid:443", Auth: "valid", Status: http.StatusOK}
	secondChallenge := &browserH2SuccessRequest{Authority: "two.baseline.invalid:443", Auth: "none", Status: http.StatusProxyAuthRequired}
	secondSuccess := &browserH2SuccessRequest{Authority: "two.baseline.invalid:443", Auth: "valid", Status: http.StatusOK}
	for _, test := range []struct {
		name     string
		requests []*browserH2SuccessRequest
		valid    bool
	}{
		{"preemptive_moto", []*browserH2SuccessRequest{firstSuccess, secondSuccess}, true},
		{"chrome_initial_challenge", []*browserH2SuccessRequest{firstChallenge, firstSuccess, secondSuccess}, true},
		{"chrome_parallel_initial_challenges", []*browserH2SuccessRequest{firstChallenge, firstChallenge, firstSuccess, secondSuccess}, true},
		{"second_origin_challenged", []*browserH2SuccessRequest{firstSuccess, secondChallenge, secondSuccess}, false},
		{"challenge_after_first_success", []*browserH2SuccessRequest{firstChallenge, firstSuccess, firstChallenge, secondSuccess}, false},
		{"second_origin_attempted_early", []*browserH2SuccessRequest{secondChallenge, firstSuccess, secondSuccess}, false},
		{"duplicate_second_success", []*browserH2SuccessRequest{firstSuccess, secondSuccess, secondSuccess}, false},
		{"first_success_missing", []*browserH2SuccessRequest{firstChallenge, secondSuccess}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := browserH2SuccessValidateAuthSequence(test.requests)
			if (err == nil) != test.valid {
				t.Fatalf("sequence validation error=%v want valid=%t", err, test.valid)
			}
		})
	}
}

// The allowlist is tested independently of Chrome so the opt-in fixture cannot
// become a general forward proxy when a browser sends speculative requests.
func TestBrowserBaselineH2SuccessRejectsOtherAuthorities(t *testing.T) {
	server := &browserH2SuccessServer{}
	request, err := http.NewRequest(http.MethodConnect, "https://uncontrolled.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "uncontrolled.invalid:443"
	writer := &browserH2SuccessStatusWriter{header: make(http.Header)}
	server.serveConnect(1, writer, request)
	if writer.status != http.StatusForbidden || len(server.requests) != 1 {
		t.Fatalf("unexpected allowlist response: %d", writer.status)
	}
}

type browserH2SuccessStatusWriter struct {
	header http.Header
	status int
}

func (writer *browserH2SuccessStatusWriter) Header() http.Header            { return writer.header }
func (writer *browserH2SuccessStatusWriter) WriteHeader(status int)         { writer.status = status }
func (writer *browserH2SuccessStatusWriter) Write(data []byte) (int, error) { return len(data), nil }

func TestBrowserBaselineH2SuccessAuthChallenge(t *testing.T) {
	for _, auth := range []string{"none", "invalid"} {
		t.Run(auth, func(t *testing.T) {
			server := &browserH2SuccessServer{authRequired: true}
			request, err := http.NewRequest(http.MethodConnect, "https://one.baseline.invalid", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "one.baseline.invalid:443"
			if auth == "invalid" {
				request.Header.Set("Proxy-Authorization", "Basic invalid-fixture-credentials")
			}
			writer := &browserH2SuccessStatusWriter{header: make(http.Header)}
			server.serveConnect(1, writer, request)
			if writer.status != http.StatusProxyAuthRequired || !strings.HasPrefix(writer.header.Get("Proxy-Authenticate"), "Basic ") || server.requests[0].Auth != auth {
				t.Fatalf("unexpected challenge: status=%d headers=%v", writer.status, writer.header)
			}
		})
	}
}

func TestBrowserBaselineH2SuccessHPACKRepresentations(t *testing.T) {
	for _, test := range []struct {
		name  string
		block []byte
		want  []string
	}{
		{"indexed", []byte{0x82, 0xbe}, []string{"indexed_static", "indexed_dynamic"}},
		{"new_name", []byte{0x40, 1, 'n', 1, 'v'}, []string{"literal_incremental_indexing:new_name"}},
		{"static_name", []byte{0x41, 1, 'v'}, []string{"literal_incremental_indexing:static_name"}},
		{"dynamic_name", []byte{0x7e, 1, 'v'}, []string{"literal_incremental_indexing:dynamic_name"}},
		{"without_indexing", []byte{0, 1, 'n', 1, 'v'}, []string{"literal_without_indexing:new_name"}},
		{"never_indexed", []byte{0x11, 1, 'v'}, []string{"literal_never_indexed:static_name"}},
		{"table_update", []byte{0x20, 0x82}, []string{"dynamic_table_size_update", "indexed_static"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := browserH2SuccessHPACKRepresentations(test.block)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("classes=%v error=%v want=%v", got, err, test.want)
			}
		})
	}
	for _, block := range [][]byte{{0x80}, {0x40}, {0xff}, {0x41, 2, 'v'}, {0x3f}} {
		if _, err := browserH2SuccessHPACKRepresentations(block); err == nil {
			t.Errorf("malformed block %x accepted", block)
		}
	}
}

func TestBrowserBaselineH2SuccessRejectsDuplicateAuthHeaders(t *testing.T) {
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte(browserH2SuccessUser+":"+browserH2SuccessPassword))
	invalid := "Basic invalid-fixture-credentials"
	for _, test := range []struct {
		name   string
		values []string
	}{
		{"invalid_then_valid", []string{invalid, valid}},
		{"valid_then_invalid", []string{valid, invalid}},
		{"valid_then_valid", []string{valid, valid}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			fields := []hpack.HeaderField{{Name: ":method", Value: http.MethodConnect}, {Name: ":authority", Value: "background.invalid:443"}}
			for _, value := range test.values {
				fields = append(fields, hpack.HeaderField{Name: "proxy-authorization", Value: value})
			}
			for _, field := range fields {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			var wire bytes.Buffer
			wire.WriteString(http2.ClientPreface)
			framer := http2.NewFramer(&wire, nil)
			if err := framer.WriteSettings(); err != nil {
				t.Fatal(err)
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := browserH2SuccessWire(wire.Bytes()); !errors.Is(err, errBrowserH2SuccessDuplicateAuth) {
				t.Fatalf("duplicate authorization was not rejected: %v", err)
			}
			server := &browserH2SuccessServer{authRequired: true}
			request, err := http.NewRequest(http.MethodConnect, "https://background.invalid", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "background.invalid:443"
			for _, value := range test.values {
				request.Header.Add("Proxy-Authorization", value)
			}
			writer := &browserH2SuccessStatusWriter{header: make(http.Header)}
			server.serveConnect(1, writer, request)
			if writer.status != http.StatusForbidden || server.requests[0].Auth != "invalid" {
				t.Fatalf("denied background duplicate credentials not classified invalid: %+v", server.requests[0])
			}
		})
	}
}
