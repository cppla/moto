package controller

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// These tests decode the UDP datagrams received by a loopback proxy. Inspecting
// Config.ChromeParrot alone would miss a preset whose transport parameters were
// lost while copying the ClientHello, or settings overridden inside quic-go.
func TestHTTP3ChromeClientHelloAndTransportParametersOnWire(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		endpoint, roots, packets, requests := chromeWireServer(t)
		negotiated := make(chan tls.ConnectionState, 1)
		manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
			transport := newHTTP3ConnectTransportWithOwner(key, owner)
			transport.TLSClientConfig.RootCAs = roots
			originalDial := transport.Dial
			transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				connection, err := originalDial(ctx, address, tlsConfig, quicConfig)
				if err == nil {
					negotiated <- connection.ConnectionState().TLS
				}
				return connection, err
			}
			return transport
		})
		t.Cleanup(manager.close)
		target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3}, ServerName: "example.com",
			BasicAuth: &config.BasicAuthConfig{Username: "wire-user-marker", Password: "wire-password-marker"},
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tunnel, err := manager.dial(ctx, target, "wire-destination-marker.example:443")
		if err != nil {
			t.Fatalf("actual Moto HTTP/3 CONNECT: %v", err)
		}
		t.Cleanup(func() { _ = tunnel.Close() })
		assertConnectTunnelEcho(t, tunnel, "verified-real-h3-payload")
		if requests.Load() != 1 {
			t.Fatalf("CONNECT requests = %d, want 1", requests.Load())
		}
		select {
		case state := <-negotiated:
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || len(state.VerifiedChains) == 0 {
				t.Fatalf("successful TLS state lacks TLS 1.3, h3 or verified chains: %+v", state)
			}
		default:
			t.Fatal("CONNECT succeeded without a completed physical handshake")
		}

		datagrams := packets.snapshot()
		hello, initialPackets, err := chromeWireClientHello(datagrams)
		if err != nil {
			t.Fatalf("decode actual QUIC Initial: %v", err)
		}
		serverName, alpn, err := parseTLSClientHelloBody(hello[4:])
		if err != nil || serverName != "example.com" || !reflect.DeepEqual(alpn, []string{"h3"}) {
			t.Fatalf("wire ClientHello SNI/ALPN = %q/%v, error %v", serverName, alpn, err)
		}
		for _, marker := range []string{"wire-user-marker", "wire-password-marker", "wire-destination-marker"} {
			if bytes.Contains(hello, []byte(marker)) {
				t.Fatalf("ClientHello leaks CONNECT marker %q", marker)
			}
		}
		ciphers, extensions := chromeWireExtensions(t, hello)
		params := chromeWireTransportParameters(t, extensions[57])
		if len(datagrams) == 0 {
			t.Fatal("successful handshake emitted no captured datagrams")
		}
		if len(datagrams[0]) != 1250 {
			t.Fatalf("first UDP datagram size = %d, want pinned Chrome 1250", len(datagrams[0]))
		}
		first := datagrams[0]
		if binary.BigEndian.Uint32(first[1:5]) != 1 || first[5] != 8 || first[14] != 0 {
			t.Fatalf("Initial version/DCID/SCID header = %x, want v1 / 8 / 0", first[:15])
		}
		if initialPackets < 2 {
			t.Fatalf("ClientHello completed in %d Initial packets, want split ML-KEM hello", initialPackets)
		}
		if want := []uint16{0x1301, 0x1302, 0x1303}; !reflect.DeepEqual(ciphers, want) {
			t.Fatalf("QUIC ClientHello cipher suites = %x, want %x", ciphers, want)
		}
		var ids []int
		for id := range extensions {
			ids = append(ids, int(id))
		}
		slices.Sort(ids)
		wantIDs := []int{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 0xca34, 0xfe0d}
		slices.Sort(wantIDs)
		if !reflect.DeepEqual(ids, wantIDs) {
			t.Fatalf("wire extension IDs = %x, want pinned QUIC profile %x", ids, wantIDs)
		}
		for id, want := range map[uint16][]byte{
			10:    {0, 8, 0x11, 0xec, 0, 29, 0, 23, 0, 24},
			13:    {0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1},
			27:    {2, 0, 2}, // Brotli certificate compression.
			43:    {2, 3, 4}, // TLS 1.3 only, no TCP TLS 1.2 compatibility.
			45:    {1, 1},
			17613: {0, 3, 2, 'h', '3'},
		} {
			if !bytes.Equal(extensions[id], want) {
				t.Fatalf("extension %d = %x, want %x", id, extensions[id], want)
			}
		}
		if len(extensions[0xfe0d]) == 0 || len(extensions[0xca34]) < 3 {
			t.Fatal("missing GREASE ECH or trust anchor extension data")
		}
		for id, want := range map[uint64]uint64{
			1: 30000, 3: 1472, 4: 15728640, 5: 6291456, 6: 6291456, 7: 6291456,
			8: 100, 9: 103, 0x20: 65536,
		} {
			chromeWireAssertInteger(t, params, id, want)
		}
		if source, ok := params[15]; !ok || len(source.value) != 0 {
			t.Fatalf("initial_source_connection_id = %x, want present and empty", source.value)
		}
		if !bytes.Equal(params[0x3128].value, []byte("ORIG")) {
			t.Fatalf("google_connection_options = %q, want ORIG", params[0x3128].value)
		}
		version := params[0x11].value
		if len(version) != 12 || binary.BigEndian.Uint32(version[:4]) != 1 {
			t.Fatalf("version_information = %x, want chosen v1 and two available versions", version)
		}
		one, two := binary.BigEndian.Uint32(version[4:8]), binary.BigEndian.Uint32(version[8:12])
		if one != 1 {
			one, two = two, one
		}
		if one != 1 || two&0x0f0f0f0f != 0x0a0a0a0a {
			t.Fatalf("available QUIC versions = %x, want v1 and reserved GREASE", version[4:])
		}
		for _, id := range []uint64{10, 11, 12, 14} {
			if _, ok := params[id]; ok {
				t.Fatalf("Chrome wire parameters unexpectedly contain omitted parameter %d", id)
			}
		}
		grease := 0
		for id, parameter := range params {
			if id%31 == 27 {
				grease++
				if parameter.idBytes != 8 || len(parameter.value) > 15 {
					t.Fatalf("GREASE transport parameter id bytes/value size = %d/%d", parameter.idBytes, len(parameter.value))
				}
			}
		}
		if grease != 1 || len(params) != 13 {
			t.Fatalf("wire transport parameters = %d, GREASE = %d, want 13/1", len(params), grease)
		}
	})
}

func TestHTTP3ChromeCertificateVerificationOnWire(t *testing.T) {
	for _, test := range []struct {
		name, serverName string
		trust            bool
	}{
		{name: "untrusted authority", serverName: "example.com"},
		{name: "wrong server name", serverName: "wrong.example.invalid", trust: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint, roots, packets, requests := chromeWireServer(t)
			manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
				transport := newHTTP3ConnectTransportWithOwner(key, owner)
				if test.trust {
					transport.TLSClientConfig.RootCAs = roots
				} else {
					transport.TLSClientConfig.RootCAs = x509.NewCertPool()
				}
				return transport
			})
			t.Cleanup(manager.close)
			target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
				Protocols: []string{config.ConnectProxyH3}, ServerName: test.serverName,
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			tunnel, err := manager.dial(ctx, target, "must-not-reach-proxy.example:443")
			if tunnel != nil {
				_ = tunnel.Close()
				t.Fatal("invalid certificate produced a tunnel")
			}
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("certificate rejection = %v, want prompt certificate validation failure", err)
			}
			// The custom QUIC TLS adapter reports certificate failures through
			// a local transport error rather than preserving x509 error types.
			// Pin the actual validation failure and the absence of HTTP bytes.
			cause := "x509: certificate signed by unknown authority"
			if test.trust {
				cause = "not " + test.serverName
			}
			if !strings.Contains(err.Error(), "failed to verify certificate") || !strings.Contains(err.Error(), cause) {
				t.Fatalf("certificate rejection = %T: %v, want %q", err, err, cause)
			}
			if requests.Load() != 0 {
				t.Fatal("CONNECT was sent before certificate validation")
			}
			if _, _, err := chromeWireClientHello(packets.snapshot()); err != nil {
				t.Fatalf("negative test did not send a real ClientHello: %v", err)
			}
		})
	}
}

func TestHTTP3ChromeRejectsNonH3ALPN(t *testing.T) {
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"not-h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	transport := newHTTP3ConnectTransportWithOwner(http3ConnectTransportKey{
		address: listener.Addr().String(), serverName: "example.com",
	}, context.Background())
	t.Cleanup(func() { _ = transport.Close() })
	transport.TLSClientConfig.RootCAs = roots
	transport.TLSClientConfig.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := transport.Dial(ctx, listener.Addr().String(), transport.TLSClientConfig, transport.QUICConfig)
	if connection != nil {
		_ = connection.CloseWithError(0, "test cleanup")
		t.Fatal("non-h3 peer produced a QUIC connection")
	}
	var transportError *quic.TransportError
	if err == nil || !errors.As(err, &transportError) || uint64(transportError.ErrorCode) != 0x178 {
		t.Fatalf("ALPN rejection = %T: %v, want TLS no_application_protocol alert", err, err)
	}
}

type chromeWirePackets struct {
	net.PacketConn
	mu        sync.Mutex
	datagrams [][]byte
}

func (packets *chromeWirePackets) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, address, err := packets.PacketConn.ReadFrom(buffer)
	if n > 0 {
		packets.mu.Lock()
		// Only the handshake is needed. Bound capture storage even if a test
		// fails and the live fixture keeps receiving payload or retransmits.
		if len(packets.datagrams) < 64 {
			packets.datagrams = append(packets.datagrams, bytes.Clone(buffer[:n]))
		}
		packets.mu.Unlock()
	}
	return n, address, err
}

func (packets *chromeWirePackets) snapshot() [][]byte {
	packets.mu.Lock()
	defer packets.mu.Unlock()
	return slices.Clone(packets.datagrams)
}

func chromeWireServer(t *testing.T) (string, *x509.CertPool, *chromeWirePackets, *atomic.Int64) {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packets := &chromeWirePackets{PacketConn: socket}
	requests := &atomic.Int64{}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			echoHTTP3OwnershipTunnel(writer, request)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packets) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = socket.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("close wire fixture: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("wire fixture failed to stop")
		}
	})
	return socket.LocalAddr().String(), roots, packets, requests
}

// chromeWireClientHello independently implements the RFC 9001 v1 Initial
// decryption used by passive analyzers. It needs no endpoint TLS secrets and
// must tolerate shuffled CRYPTO fragments and retransmission overlaps.
func chromeWireClientHello(datagrams [][]byte) ([]byte, int, error) {
	var assembled [65536]byte
	var seen [65536]bool
	contiguous, initialPackets := 0, 0
	for _, datagram := range datagrams {
		for len(datagram) > 0 {
			if datagram[0]&0x80 == 0 {
				break // A short header consumes the remaining UDP datagram.
			}
			packet, remaining, initial, err := chromeWireDecryptInitial(datagram)
			if err != nil {
				return nil, initialPackets, err
			}
			datagram = remaining
			if !initial {
				continue
			}
			initialPackets++
			for len(packet) > 0 {
				frameType, _, err := chromeWireVarint(&packet)
				if err != nil {
					return nil, initialPackets, err
				}
				switch frameType {
				case 0, 1: // PADDING, PING.
				case 2, 3: // ACK with or without ECN.
					if err := chromeWireSkipACK(&packet, frameType == 3); err != nil {
						return nil, initialPackets, err
					}
				case 6: // CRYPTO.
					offset, _, err := chromeWireVarint(&packet)
					if err != nil {
						return nil, initialPackets, err
					}
					length, _, err := chromeWireVarint(&packet)
					if err != nil || length > uint64(len(packet)) || offset > uint64(len(assembled)) || length > uint64(len(assembled))-offset {
						return nil, initialPackets, errors.New("out-of-bounds Initial CRYPTO frame")
					}
					for i, value := range packet[:int(length)] {
						at := int(offset) + i
						if seen[at] && assembled[at] != value {
							return nil, initialPackets, errors.New("conflicting retransmitted CRYPTO bytes")
						}
						assembled[at], seen[at] = value, true
					}
					packet = packet[int(length):]
				default:
					return nil, initialPackets, fmt.Errorf("unexpected frame %d before ClientHello", frameType)
				}
			}
			for contiguous < len(seen) && seen[contiguous] {
				contiguous++
			}
			if contiguous >= 4 {
				if assembled[0] != 1 {
					return nil, initialPackets, errors.New("Initial CRYPTO does not start with ClientHello")
				}
				length := 4 + (int(assembled[1]) << 16) + (int(assembled[2]) << 8) + int(assembled[3])
				if contiguous >= length {
					return bytes.Clone(assembled[:length]), initialPackets, nil
				}
			}
		}
	}
	return nil, initialPackets, fmt.Errorf("incomplete ClientHello: %d contiguous bytes", contiguous)
}

func chromeWireDecryptInitial(datagram []byte) (plain, remaining []byte, initial bool, err error) {
	if len(datagram) < 7 || binary.BigEndian.Uint32(datagram[1:5]) != 1 {
		return nil, nil, false, errors.New("expected QUIC v1 long header")
	}
	position := 6 + int(datagram[5])
	if position >= len(datagram) {
		return nil, nil, false, io.ErrUnexpectedEOF
	}
	destinationCID := datagram[6:position]
	position += 1 + int(datagram[position])
	if position > len(datagram) {
		return nil, nil, false, io.ErrUnexpectedEOF
	}
	packetType := (datagram[0] >> 4) & 3
	if packetType == 3 {
		return nil, nil, false, errors.New("unexpected Retry from client")
	}
	rest := datagram[position:]
	if packetType == 0 {
		tokenLength, _, parseErr := chromeWireVarint(&rest)
		if parseErr != nil || tokenLength > uint64(len(rest)) {
			return nil, nil, false, io.ErrUnexpectedEOF
		}
		rest = rest[int(tokenLength):]
	}
	packetLength, _, parseErr := chromeWireVarint(&rest)
	if parseErr != nil || packetLength > uint64(len(rest)) {
		return nil, nil, false, io.ErrUnexpectedEOF
	}
	pnOffset := len(datagram) - len(rest)
	packetEnd := pnOffset + int(packetLength)
	if packetType != 0 {
		return nil, datagram[packetEnd:], false, nil
	}
	if pnOffset+4+aes.BlockSize > packetEnd {
		return nil, nil, false, errors.New("Initial too short for header protection sample")
	}
	// RFC 9001 section 5.2 v1 initial salt and TLS 1.3 HKDF labels.
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(destinationCID)
	secret := chromeWireExpandLabel(extract.Sum(nil), "client in", 32)
	key := chromeWireExpandLabel(secret, "quic key", 16)
	iv := chromeWireExpandLabel(secret, "quic iv", 12)
	hp := chromeWireExpandLabel(secret, "quic hp", 16)
	hpCipher, err := aes.NewCipher(hp)
	if err != nil {
		return nil, nil, false, err
	}
	var mask [aes.BlockSize]byte
	hpCipher.Encrypt(mask[:], datagram[pnOffset+4:pnOffset+4+aes.BlockSize])
	header := bytes.Clone(datagram[:pnOffset+4])
	header[0] ^= mask[0] & 0x0f
	pnLength := int(header[0]&3) + 1
	var packetNumber uint64
	for i := range pnLength {
		header[pnOffset+i] ^= mask[i+1]
		packetNumber = packetNumber<<8 | uint64(header[pnOffset+i])
	}
	// Only the first handshake flight is captured, before packet-number wrap.
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, false, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, false, err
	}
	plain, err = aead.Open(nil, iv, datagram[pnOffset+pnLength:packetEnd], header[:pnOffset+pnLength])
	return plain, datagram[packetEnd:], true, err
}

func chromeWireExpandLabel(secret []byte, label string, length int) []byte {
	label = "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(label))}
	info = append(info, label...)
	info = append(info, 0) // Empty context.
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(info)
	_, _ = mac.Write([]byte{1})
	return mac.Sum(nil)[:length] // All required secrets fit one SHA-256 block.
}

func chromeWireVarint(data *[]byte) (uint64, int, error) {
	if len(*data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << ((*data)[0] >> 6)
	if len(*data) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64((*data)[0] & 0x3f)
	for _, b := range (*data)[1:n] {
		v = v<<8 | uint64(b)
	}
	*data = (*data)[n:]
	return v, n, nil
}

func chromeWireSkipACK(data *[]byte, ecn bool) error {
	for range 2 { // Largest acknowledged, delay.
		if _, _, err := chromeWireVarint(data); err != nil {
			return err
		}
	}
	ranges, _, err := chromeWireVarint(data)
	if err != nil || ranges > 1024 {
		return errors.New("invalid ACK range count")
	}
	values := 1 + 2*ranges // First range, then gap/range pairs.
	if ecn {
		values += 3
	}
	for range values {
		if _, _, err := chromeWireVarint(data); err != nil {
			return err
		}
	}
	return nil
}

func chromeWireExtensions(t *testing.T, hello []byte) ([]uint16, map[uint16][]byte) {
	t.Helper()
	cursor := tlsClientHelloCursor{data: hello[4:]}
	if _, ok := cursor.take(34); !ok {
		t.Fatal("missing legacy version and ClientHello random")
	}
	sessionLength, ok := cursor.uint8()
	if !ok {
		t.Fatal("missing session ID length")
	}
	if _, ok := cursor.take(sessionLength); !ok {
		t.Fatal("truncated session ID")
	}
	cipherLength, ok := cursor.uint16()
	if !ok || cipherLength%2 != 0 {
		t.Fatal("invalid cipher suite length")
	}
	cipherBytes, ok := cursor.take(cipherLength)
	if !ok {
		t.Fatal("truncated cipher suites")
	}
	var ciphers []uint16
	for i := 0; i < len(cipherBytes); i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(cipherBytes[i:i+2]))
	}
	compressionLength, ok := cursor.uint8()
	if !ok {
		t.Fatal("missing compression length")
	}
	compression, ok := cursor.take(compressionLength)
	if !ok || !bytes.Equal(compression, []byte{0}) {
		t.Fatalf("unexpected compression methods %x", compression)
	}
	extensionsLength, ok := cursor.uint16()
	if !ok || extensionsLength != cursor.remaining() {
		t.Fatal("invalid extension block length")
	}
	extensions := make(map[uint16][]byte)
	for cursor.remaining() > 0 {
		id, idOK := cursor.uint16()
		length, lengthOK := cursor.uint16()
		value, valueOK := cursor.take(length)
		if !idOK || !lengthOK || !valueOK {
			t.Fatal("truncated extension")
		}
		if _, exists := extensions[uint16(id)]; exists {
			t.Fatalf("duplicate extension %d", id)
		}
		extensions[uint16(id)] = value
	}
	return ciphers, extensions
}

type chromeWireParameter struct {
	idBytes int
	value   []byte
}

func chromeWireTransportParameters(t *testing.T, data []byte) map[uint64]chromeWireParameter {
	t.Helper()
	if len(data) == 0 {
		t.Fatal("missing on-wire QUIC transport parameters")
	}
	params := make(map[uint64]chromeWireParameter)
	for len(data) > 0 {
		id, idBytes, err := chromeWireVarint(&data)
		if err != nil {
			t.Fatal(err)
		}
		length, _, err := chromeWireVarint(&data)
		if err != nil || length > uint64(len(data)) {
			t.Fatal("truncated transport parameter")
		}
		if _, duplicate := params[id]; duplicate {
			t.Fatalf("duplicate transport parameter %d", id)
		}
		params[id] = chromeWireParameter{idBytes: idBytes, value: data[:int(length)]}
		data = data[int(length):]
	}
	return params
}

func chromeWireAssertInteger(t *testing.T, params map[uint64]chromeWireParameter, id, want uint64) {
	t.Helper()
	parameter, ok := params[id]
	data := parameter.value
	got, _, err := chromeWireVarint(&data)
	if !ok || err != nil || len(data) != 0 || got != want {
		t.Fatalf("wire transport parameter %d = %x, want integer %d", id, parameter.value, want)
	}
}
