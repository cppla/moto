package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"moto/config"
	xhttp2 "moto/internal/browserhttp2"
)

// TestBrowserBaselineH2 captures actual client bytes. The external runner starts
// Chrome only after ready.json exists; ordinary go test runs never launch a
// browser or collect traffic. This fixture rejects CONNECT after its headers,
// without resolving or connecting to the requested authority.
func TestBrowserBaselineH2(t *testing.T) {
	dir := os.Getenv("MOTO_BROWSER_CAPTURE_DIR")
	if dir == "" {
		t.Skip("set MOTO_BROWSER_CAPTURE_DIR for the opt-in browser wire capture")
	}
	actor := os.Getenv("MOTO_BROWSER_ACTOR")
	if actor == "" {
		actor = "moto"
	}
	if actor != "chrome" && actor != "moto" {
		t.Fatalf("MOTO_BROWSER_ACTOR = %q, want chrome or moto", actor)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}

	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	parsedCertificate, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	server := browserH2StartServer(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, ctx)
	defer server.close()
	endpoint := listener.Addr().String()
	spki := sha256.Sum256(parsedCertificate.RawSubjectPublicKeyInfo)
	browserH2WriteJSON(t, filepath.Join(dir, "ready.json"), map[string]any{
		"endpoint": endpoint, "proxy_url": "https://" + endpoint,
		"protocol": "h2", "spki": base64.StdEncoding.EncodeToString(spki[:]),
	})

	if actor == "moto" {
		roots := x509.NewCertPool()
		roots.AddCert(parsedCertificate)
		manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
			transport := newHTTP2ConnectTransport(key)
			transport.TLSClientConfig.RootCAs = roots
			return transport
		})
		defer manager.closeIdle()
		target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH2}, ServerName: "127.0.0.1",
		}}
		connection, dialErr := manager.dial(ctx, target, "baseline.invalid:443")
		if connection != nil {
			_ = connection.Close()
			t.Fatal("capture proxy unexpectedly accepted CONNECT")
		}
		var statusError *connectProxyStatusError
		if !errors.As(dialErr, &statusError) || statusError.statusCode != http.StatusBadGateway {
			t.Fatalf("actual Moto CONNECT error = %v, want controlled HTTP 502", dialErr)
		}
	}

	var lastError error
	for {
		select {
		case result := <-server.results:
			if result.err != nil {
				lastError = result.err
				continue // Chrome can also open unused speculative connections.
			}
			features := browserH2TLSFeatures(t, result.hello)
			for key, value := range result.features {
				features[key] = value
			}
			rawArtifacts := make(map[string]any)
			for name, data := range map[string][]byte{
				"tls-clienthello.bin": result.hello, "h2-client-plaintext.bin": result.plaintext,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(data)
				rawArtifacts[name] = map[string]any{"sha256": fmt.Sprintf("%x", digest), "bytes": len(data)}
			}
			browserH2WriteJSON(t, filepath.Join(dir, "capture.json"), map[string]any{
				"schema_version": 1, "actor": actor, "protocol": "h2",
				"scenario": "connect_rejected_after_headers", "features": features,
				"evidence": map[string]any{"connect_received": true, "response_status": http.StatusBadGateway},
				"normalization": []string{
					"TLS GREASE values become 0x?a?a; vector positions and extension multiplicity are retained",
					"TLS extension IDs are sorted because Chrome permutes extension order",
					"TLS random, session ID, key share bytes, padding, and unlisted extension payloads are excluded",
					"HTTP/2 SETTINGS and CONNECT header names retain wire order",
				},
				"raw_artifacts": rawArtifacts,
			})
			t.Logf("captured %s HTTP/2 ClientHello and rejected CONNECT in %s", actor, dir)
			return
		case <-ctx.Done():
			t.Fatalf("timed out waiting for controlled HTTP/2 CONNECT (last connection error: %v)", lastError)
		}
	}
}

type browserH2CaptureResult struct {
	hello, plaintext []byte
	features         map[string]any
	err              error
}

type browserH2CaptureServer struct {
	listener    net.Listener
	results     chan browserH2CaptureResult
	acceptDone  chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	workers     sync.WaitGroup
}

func browserH2StartServer(listener net.Listener, tlsConfig *tls.Config, ctx context.Context) *browserH2CaptureServer {
	server := &browserH2CaptureServer{
		listener: listener, results: make(chan browserH2CaptureResult, 16),
		acceptDone: make(chan struct{}), connections: make(map[net.Conn]struct{}),
	}
	go func() {
		defer close(server.acceptDone)
		// Bound speculative sockets and memory even in opt-in runs.
		for accepted := 0; accepted < cap(server.results); accepted++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.connections[connection] = struct{}{}
			server.mu.Unlock()
			server.workers.Add(1)
			go func() {
				defer server.workers.Done()
				defer connection.Close()
				defer func() {
					server.mu.Lock()
					delete(server.connections, connection)
					server.mu.Unlock()
				}()
				server.results <- browserH2ReadConnection(connection, tlsConfig, ctx)
			}()
		}
	}()
	return server
}

func (server *browserH2CaptureServer) close() {
	_ = server.listener.Close()
	<-server.acceptDone
	server.mu.Lock()
	for connection := range server.connections {
		_ = connection.Close()
	}
	server.mu.Unlock()
	server.workers.Wait()
}

type browserH2ReplayConn struct {
	net.Conn
	reader io.Reader
}

func (connection *browserH2ReplayConn) Read(p []byte) (int, error) {
	return connection.reader.Read(p)
}

func browserH2ReadConnection(connection net.Conn, tlsConfig *tls.Config, ctx context.Context) (result browserH2CaptureResult) {
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		result.err = err
		return
	}
	probe, err := readTLSClientHello(connection, 64<<10)
	if err != nil {
		result.err = fmt.Errorf("capture ClientHello: %w", err)
		return
	}
	result.hello = probe.Raw
	secured := tls.Server(&browserH2ReplayConn{
		Conn: connection, reader: io.MultiReader(bytes.NewReader(probe.Raw), connection),
	}, tlsConfig)
	if err := secured.HandshakeContext(ctx); err != nil {
		result.err = fmt.Errorf("proxy TLS handshake: %w", err)
		return
	}
	if secured.ConnectionState().NegotiatedProtocol != "h2" {
		result.err = errors.New("client did not negotiate h2")
		return
	}
	var plaintext bytes.Buffer
	// A controlled first CONNECT needs only a few kilobytes. Bound all input,
	// including frames that are not retained as normalized features.
	reader := io.TeeReader(io.LimitReader(secured, 1<<20), &plaintext)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(reader, preface); err != nil || string(preface) != http2.ClientPreface {
		result.err = fmt.Errorf("invalid HTTP/2 client preface: %v", err)
		return
	}
	framer := http2.NewFramer(secured, reader)
	framer.SetMaxReadFrameSize(64 << 10)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	framer.MaxHeaderListSize = 64 << 10
	if err := framer.WriteSettings(); err != nil {
		result.err = err
		return
	}
	type setting struct {
		ID    uint16 `json:"id"`
		Value uint32 `json:"value"`
	}
	settings := []setting{}
	var haveSettings bool
	var connectionWindowIncrement uint64
	for count := 0; count < 256; count++ {
		frame, err := framer.ReadFrame()
		if err != nil {
			result.err = fmt.Errorf("read HTTP/2 frame: %w", err)
			return
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() {
				continue
			}
			if !haveSettings {
				if err := frame.ForeachSetting(func(value http2.Setting) error {
					settings = append(settings, setting{uint16(value.ID), value.Val})
					return nil
				}); err != nil {
					result.err = err
					return
				}
				haveSettings = true
			}
			if err := framer.WriteSettingsAck(); err != nil {
				result.err = err
				return
			}
		case *http2.WindowUpdateFrame:
			if frame.StreamID == 0 {
				connectionWindowIncrement += uint64(frame.Increment)
			}
		case *http2.PingFrame:
			if !frame.IsAck() {
				if err := framer.WritePing(true, frame.Data); err != nil {
					result.err = err
					return
				}
			}
		case *http2.MetaHeadersFrame:
			if !haveSettings || frame.Truncated || frame.PseudoValue("method") != "CONNECT" || frame.PseudoValue("authority") != "baseline.invalid:443" {
				result.err = errors.New("expected initial SETTINGS and controlled CONNECT baseline.invalid:443")
				return
			}
			headerNames := make([]string, 0, len(frame.Fields))
			var userAgent string
			for _, field := range frame.Fields {
				headerNames = append(headerNames, field.Name)
				if field.Name == "user-agent" {
					userAgent = field.Value
				}
			}
			var response bytes.Buffer
			encoder := hpack.NewEncoder(&response)
			if err := encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "502"}); err != nil {
				result.err = err
				return
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID: frame.StreamID, BlockFragment: response.Bytes(), EndHeaders: true, EndStream: true,
			}); err != nil {
				result.err = err
				return
			}
			result.plaintext = append([]byte(nil), plaintext.Bytes()...)
			result.features = map[string]any{
				"h2.settings": settings, "h2.connection_window_increment": connectionWindowIncrement,
				"connect.header_names": headerNames, "connect.user_agent": userAgent,
			}
			return
		}
	}
	result.err = errors.New("no CONNECT in first 256 HTTP/2 frames")
	return
}

func browserH2TLSFeatures(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	probe, err := readTLSClientHello(bytes.NewReader(raw), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	var handshake []byte
	for records := probe.Raw; len(records) > 0; {
		length := int(binary.BigEndian.Uint16(records[3:5]))
		handshake = append(handshake, records[5:5+length]...)
		records = records[5+length:]
	}
	ciphers, extensions := chromeWireExtensions(t, handshake)
	normalize := func(values []uint16) []string {
		result := make([]string, 0, len(values))
		for _, value := range values {
			if value&0x0f0f == 0x0a0a && byte(value) == byte(value>>8) {
				result = append(result, "0x?a?a")
			} else {
				result = append(result, fmt.Sprintf("0x%04x", value))
			}
		}
		return result
	}
	vector := func(extension uint16, lengthBytes int) []string {
		data, present := extensions[extension]
		if !present {
			t.Fatalf("ClientHello missing extension %d", extension)
		}
		if len(data) < lengthBytes {
			t.Fatalf("short ClientHello extension %d", extension)
		}
		length := int(data[0])
		if lengthBytes == 2 {
			length = int(binary.BigEndian.Uint16(data[:2]))
		}
		data = data[lengthBytes:]
		if length != len(data) || length%2 != 0 {
			t.Fatalf("invalid ClientHello extension %d vector length", extension)
		}
		values := make([]uint16, 0, length/2)
		for len(data) > 0 {
			values = append(values, binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		return normalize(values)
	}
	ids := make([]uint16, 0, len(extensions))
	for id := range extensions {
		ids = append(ids, id)
	}
	normalizedIDs := normalize(ids)
	sort.Strings(normalizedIDs)
	type keyShare struct {
		Group            string `json:"group"`
		KeyExchangeBytes int    `json:"key_exchange_bytes"`
	}
	keyShares := []keyShare{}
	keyShareData := extensions[51]
	if len(keyShareData) < 2 || int(binary.BigEndian.Uint16(keyShareData[:2])) != len(keyShareData)-2 {
		t.Fatal("invalid ClientHello key share vector length")
	}
	for data := keyShareData[2:]; len(data) > 0; {
		if len(data) < 4 {
			t.Fatal("truncated ClientHello key share")
		}
		group := binary.BigEndian.Uint16(data[:2])
		length := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if length > len(data) {
			t.Fatal("truncated ClientHello key exchange bytes")
		}
		keyShares = append(keyShares, keyShare{normalize([]uint16{group})[0], length})
		data = data[length:]
	}
	return map[string]any{
		"tls.cipher_suites": normalize(ciphers), "tls.extension_ids": normalizedIDs,
		"tls.supported_groups": vector(10, 2), "tls.signature_algorithms": vector(13, 2),
		"tls.alpn": probe.ALPNProtocols, "tls.supported_versions": vector(43, 1),
		"tls.key_share_groups": keyShares,
	}
}

func browserH2WriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// Renaming prevents the browser runner from observing partial readiness.
	temporary, err := os.CreateTemp(filepath.Dir(path), ".browser-capture-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		t.Fatal(err)
	}
}
