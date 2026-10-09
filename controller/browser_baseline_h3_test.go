package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// TestBrowserBaselineH3 is an opt-in capture fixture, not an assertion of
// browser equivalence. A separate process launches real Chrome after ready.json
// appears. The Moto actor uses the production CONNECT manager against the same
// loopback fixture. No request is forwarded outside this process.
func TestBrowserBaselineH3(t *testing.T) {
	directory := os.Getenv("MOTO_BROWSER_CAPTURE_DIR")
	if directory == "" {
		t.Skip("set MOTO_BROWSER_CAPTURE_DIR to record a browser baseline")
	}
	actor := os.Getenv("MOTO_BROWSER_ACTOR")
	if actor == "" {
		actor = "moto"
	}
	if actor != "chrome" && actor != "moto" {
		t.Fatal("MOTO_BROWSER_ACTOR must be chrome or moto")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	leaf := certificateSource.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	certificateSource.Close()
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packets := &browserH3Packets{PacketConn: socket}
	var mu sync.Mutex
	connections := make(map[string]*quic.Conn)
	connectAuthority, requestProtocol, connectRemote := "", "", ""
	responseStatus, responseError := 0, ""
	connectReceived := make(chan struct{}, 1)
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			mu.Lock()
			if len(connections) < 64 {
				connections[connection.RemoteAddr().String()] = connection
			}
			mu.Unlock()
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusBadGateway)
			flushErr := http.NewResponseController(writer).Flush()
			if request.Method == http.MethodConnect && request.Host == "baseline.invalid:443" && request.ProtoMajor == 3 {
				mu.Lock()
				if connectRemote != "" {
					mu.Unlock()
					return
				}
				connectAuthority, requestProtocol = request.Host, request.Proto
				connectRemote = request.RemoteAddr
				if flushErr == nil {
					responseStatus = http.StatusBadGateway
				} else {
					responseError = flushErr.Error()
				}
				mu.Unlock()
				select {
				case connectReceived <- struct{}{}:
				default:
				}
			}
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packets) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = socket.Close()
		select {
		case serveErr := <-done:
			if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("close browser H3 fixture: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Error("browser H3 fixture failed to stop")
		}
	})
	endpoint := socket.LocalAddr().String()
	browserH3WriteJSON(t, directory, "ready.json", map[string]any{
		"endpoint": endpoint, "proxy_url": "quic://" + endpoint, "protocol": "h3",
		"spki": base64.StdEncoding.EncodeToString(spki[:]),
	})
	var dialError string
	if actor == "moto" {
		manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
			transport := newHTTP3ConnectTransportWithOwner(key, owner)
			transport.TLSClientConfig.RootCAs = roots
			return transport
		})
		t.Cleanup(manager.close)
		target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3}, ServerName: "127.0.0.1",
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tunnel, dialErr := manager.dial(ctx, target, "baseline.invalid:443")
		cancel()
		if tunnel != nil {
			_ = tunnel.Close()
			t.Error("502 fixture unexpectedly produced an established tunnel")
		}
		if dialErr == nil {
			t.Error("502 fixture unexpectedly produced a successful dial")
		} else {
			dialError = dialErr.Error()
			var statusError *connectProxyStatusError
			if !errors.As(dialErr, &statusError) || statusError.statusCode != http.StatusBadGateway {
				t.Errorf("Moto dial returned %v, want CONNECT status 502", dialErr)
			}
		}
	}
	connected := false
	if actor == "chrome" {
		select {
		case <-connectReceived:
			connected = true
		case <-time.After(45 * time.Second):
		}
	} else {
		select {
		case <-connectReceived:
			connected = true
		default:
		}
	}

	mu.Lock()
	capturedRemote := connectRemote
	mu.Unlock()
	capturedRemote, datagrams := packets.snapshot(capturedRemote)
	sources := make([]map[string]any, 0, len(datagrams)+1)
	for index, datagram := range datagrams {
		name := fmt.Sprintf("client-datagram-%03d.bin", index)
		sources = append(sources, browserH3WriteSource(t, directory, name, datagram))
	}
	hello, initialPackets, parseErr := chromeWireClientHello(datagrams)
	mu.Lock()
	handshakeCompleted := false
	if connection := connections[capturedRemote]; connection != nil {
		handshakeCompleted = connection.ConnectionState().TLS.HandshakeComplete
	}
	observedResponseStatus := responseStatus
	evidence := map[string]any{
		"connect_received": connected, "handshake_completed": handshakeCompleted,
		"connect_authority": connectAuthority, "request_protocol": requestProtocol,
		"captured_remote": capturedRemote, "connect_remote": connectRemote,
		"initial_packets": initialPackets, "datagram_count": len(datagrams),
		"response_status": responseStatus,
	}
	if responseError != "" {
		evidence["response_error"] = responseError
	}
	mu.Unlock()
	status := "handshake_only"
	if connected {
		status = "connect_received"
	}
	features := map[string]any{}
	if parseErr != nil {
		status = "incomplete_client_hello"
		evidence["parse_error"] = parseErr.Error()
	} else {
		sources = append(sources, browserH3WriteSource(t, directory, "clienthello.bin", hello))
		features = browserH3Features(t, hello, datagrams[0])
	}
	evidence["status"] = status
	evidence["source_files"] = sources
	if dialError != "" {
		evidence["moto_dial_error"] = dialError
	}
	browserH3WriteJSON(t, directory, "capture.json", map[string]any{
		"schema_version": 1, "actor": actor, "protocol": "h3",
		"scenario": "connect_rejected_after_headers", "features": features, "evidence": evidence,
	})
	if parseErr != nil {
		t.Fatalf("capture saved without complete QUIC ClientHello: %v", parseErr)
	}
	if !connected {
		t.Error("captured QUIC ClientHello but no controlled CONNECT: handshake_only; no CONNECT comparison is valid")
	} else if observedResponseStatus != http.StatusBadGateway {
		t.Error("captured CONNECT but failed to send the controlled HTTP 502 response")
	}
}

type browserH3Datagram struct {
	remote string
	data   []byte
}

// Chrome may open more than one physical connection. Never combine CRYPTO
// fragments from different peers or attribute a speculative hello to CONNECT.
type browserH3Packets struct {
	net.PacketConn
	mu        sync.Mutex
	datagrams []browserH3Datagram
}

func (packets *browserH3Packets) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, remote, err := packets.PacketConn.ReadFrom(buffer)
	if n > 0 {
		packets.mu.Lock()
		if len(packets.datagrams) < 64 {
			packets.datagrams = append(packets.datagrams, browserH3Datagram{remote.String(), bytes.Clone(buffer[:n])})
		}
		packets.mu.Unlock()
	}
	return n, remote, err
}

func (packets *browserH3Packets) snapshot(remote string) (string, [][]byte) {
	packets.mu.Lock()
	defer packets.mu.Unlock()
	if remote == "" && len(packets.datagrams) > 0 {
		remote = packets.datagrams[0].remote
	}
	var result [][]byte
	for _, datagram := range packets.datagrams {
		if datagram.remote == remote {
			result = append(result, datagram.data)
		}
	}
	return remote, result
}

func browserH3Features(t *testing.T, hello, firstDatagram []byte) map[string]any {
	t.Helper()
	ciphers, extensions := chromeWireExtensions(t, hello)
	ids := make([]string, 0, len(extensions))
	for id := range extensions {
		ids = append(ids, browserH3TLSID(id))
	}
	slices.Sort(ids)
	_, alpn, err := parseTLSClientHelloBody(hello[4:])
	if err != nil {
		t.Fatal(err)
	}
	if len(firstDatagram) < 7 || 6+int(firstDatagram[5]) >= len(firstDatagram) {
		t.Fatal("invalid captured QUIC Initial header")
	}
	return map[string]any{
		"tls.cipher_suites": browserH3TLSIDs(ciphers), "tls.extension_ids": ids,
		"tls.supported_groups":     browserH3TLSVector(t, extensions[10], 2),
		"tls.signature_algorithms": browserH3TLSVector(t, extensions[13], 2),
		"tls.alpn":                 alpn, "tls.supported_versions": browserH3TLSVector(t, extensions[43], 1),
		"tls.key_share_groups":       browserH3KeyShares(t, extensions[51]),
		"quic.version":               binary.BigEndian.Uint32(firstDatagram[1:5]),
		"quic.dcid_length":           int(firstDatagram[5]),
		"quic.scid_length":           int(firstDatagram[6+int(firstDatagram[5])]),
		"quic.first_datagram_length": len(firstDatagram),
		"quic.transport_parameters":  browserH3TransportParameters(t, chromeWireTransportParameters(t, extensions[57])),
	}
}

func browserH3KeyShares(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		t.Fatal("invalid TLS key share vector")
	}
	result := []map[string]any{}
	for data = data[2:]; len(data) > 0; {
		if len(data) < 4 {
			t.Fatal("truncated TLS key share")
		}
		group, length := binary.BigEndian.Uint16(data[:2]), int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if length > len(data) {
			t.Fatal("truncated TLS key exchange bytes")
		}
		result = append(result, map[string]any{"group": browserH3TLSID(group), "key_exchange_bytes": length})
		data = data[length:]
	}
	return result
}

func browserH3TLSID(value uint16) string {
	if value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value) {
		return "0x?a?a"
	}
	return fmt.Sprintf("0x%04x", value)
}

func browserH3TLSIDs(values []uint16) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, browserH3TLSID(value))
	}
	return result
}

func browserH3TLSVector(t *testing.T, data []byte, prefix int) []string {
	t.Helper()
	if len(data) < prefix {
		t.Fatal("missing TLS vector")
	}
	length := int(data[0])
	if prefix == 2 {
		length = int(binary.BigEndian.Uint16(data[:2]))
	}
	data = data[prefix:]
	if length != len(data) || length%2 != 0 {
		t.Fatal("invalid TLS vector length")
	}
	values := make([]uint16, 0, length/2)
	for len(data) != 0 {
		values = append(values, binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	return browserH3TLSIDs(values)
}

// Preserve stable numeric values, flags, and opaque nonrandom options. Omit
// connection IDs, reset tokens, preferred addresses, cached RTT and reserved
// GREASE parameters. Version GREASE is normalized and its list is sorted.
func browserH3TransportParameters(t *testing.T, parameters map[uint64]chromeWireParameter) map[string]any {
	t.Helper()
	result := map[string]any{}
	for id, parameter := range parameters {
		if id%31 == 27 {
			continue
		}
		key, value := fmt.Sprintf("0x%x", id), parameter.value
		switch id {
		case 0, 2, 13, 15, 16, 0x3127:
			continue
		case 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 0x20:
			number, _, err := chromeWireVarint(&value)
			if err != nil || len(value) != 0 {
				t.Fatalf("transport parameter %s is not one QUIC varint", key)
			}
			result[key] = number
		case 0x11:
			if len(value) < 4 || len(value)%4 != 0 {
				t.Fatal("invalid QUIC version_information")
			}
			versions := make([]string, 0, len(value)/4-1)
			for offset := 4; offset < len(value); offset += 4 {
				version := binary.BigEndian.Uint32(value[offset : offset+4])
				if version&0x0f0f0f0f == 0x0a0a0a0a {
					versions = append(versions, "0x?a?a?a?a")
				} else {
					versions = append(versions, fmt.Sprintf("0x%08x", version))
				}
			}
			slices.Sort(versions)
			result[key] = map[string]any{"chosen": fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(value[:4])), "available": versions}
		default:
			if len(value) == 0 {
				result[key] = true
			} else {
				result[key] = "0x" + hex.EncodeToString(value)
			}
		}
	}
	return result
}

func browserH3WriteSource(t *testing.T, directory, name string, data []byte) map[string]any {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return map[string]any{"path": name, "sha256": hex.EncodeToString(digest[:]), "bytes": len(data)}
}

func browserH3WriteJSON(t *testing.T, directory, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	temporary, destination := filepath.Join(directory, name+".tmp"), filepath.Join(directory, name)
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		t.Fatal(err)
	}
}
