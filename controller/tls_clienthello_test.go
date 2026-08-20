package controller

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadTLSClientHelloAcrossRecordAndReaderFragments(t *testing.T) {
	handshake := testTLSClientHelloHandshake("edge.example.com", []string{"h2", "http/1.1"})
	wire := testTLSHandshakeRecords(handshake, 1, 2, 0, 1, 7, 13)
	source := bytes.NewReader(wire)
	reader := bufio.NewReaderSize(&testTLSShortReader{reader: source, maximum: 1}, 8)

	probe, err := readTLSClientHello(reader, len(wire))
	if err != nil {
		t.Fatalf("readTLSClientHello: %v", err)
	}
	if probe.ServerName != "edge.example.com" {
		t.Fatalf("ServerName = %q, want edge.example.com", probe.ServerName)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(probe.ALPNProtocols, want) {
		t.Fatalf("ALPNProtocols = %q, want %q", probe.ALPNProtocols, want)
	}
	if !bytes.Equal(probe.Raw, wire) {
		t.Fatalf("Raw differs from input:\n got %x\nwant %x", probe.Raw, wire)
	}
	if source.Len() != 0 || reader.Buffered() != 0 {
		t.Fatalf("successful probe left source=%d buffered=%d bytes", source.Len(), reader.Buffered())
	}
}

func TestReadTLSClientHelloAcceptsLegacyHelloWithoutExtensions(t *testing.T) {
	body := testTLSClientHelloBody(nil, false)
	wire := testTLSHandshakeRecords(testTLSHandshake(body))
	probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
	if err != nil {
		t.Fatalf("readTLSClientHello: %v", err)
	}
	if probe.ServerName != "" || probe.ALPNProtocols != nil {
		t.Fatalf("probe = %+v, want no SNI or ALPN", probe)
	}
	if !bytes.Equal(probe.Raw, wire) {
		t.Fatal("legacy ClientHello was not retained exactly")
	}
}

func TestReadTLSClientHelloRawAndReaderReplayOriginalStream(t *testing.T) {
	wire := testTLSHandshakeRecords(testTLSClientHelloHandshake("replay.example.com", []string{"h2"}))
	suffix := []byte("encrypted bytes after ClientHello")
	stream := append(append([]byte(nil), wire...), suffix...)
	reader := bufio.NewReaderSize(bytes.NewReader(stream), 4096)

	probe, err := readTLSClientHello(reader, len(wire))
	if err != nil {
		t.Fatalf("readTLSClientHello: %v", err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read buffered remainder: %v", err)
	}
	replayed := append(append([]byte(nil), probe.Raw...), remaining...)
	if !bytes.Equal(replayed, stream) {
		t.Fatalf("replayed stream differs:\n got %x\nwant %x", replayed, stream)
	}
}

func TestReadTLSClientHelloMalformedInputCanStillBeReplayed(t *testing.T) {
	stream := []byte{23, 3, 3, 0, 4, 'd', 'a', 't', 'a'}
	reader := bufio.NewReaderSize(bytes.NewReader(stream), 32)
	probe, err := readTLSClientHello(reader, len(stream))
	if !errors.Is(err, errTLSClientHelloMalformed) {
		t.Fatalf("error = %v, want errTLSClientHelloMalformed", err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read buffered remainder: %v", err)
	}
	replayed := append(append([]byte(nil), probe.Raw...), remaining...)
	if !bytes.Equal(replayed, stream) {
		t.Fatalf("replayed malformed stream differs: got %x want %x", replayed, stream)
	}
}

func TestReadTLSClientHelloParsesCryptoTLSOutput(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "real.example.com",
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	defer clientTLS.Close()
	defer serverConn.Close()

	if err := serverConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- clientTLS.Handshake()
	}()

	probe, err := readTLSClientHello(serverConn, 64<<10)
	if err != nil {
		t.Fatalf("readTLSClientHello on crypto/tls output: %v", err)
	}
	if probe.ServerName != "real.example.com" {
		t.Fatalf("ServerName = %q, want real.example.com", probe.ServerName)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(probe.ALPNProtocols, want) {
		t.Fatalf("ALPNProtocols = %q, want %q", probe.ALPNProtocols, want)
	}
	if len(probe.Raw) < tlsRecordHeaderLength || probe.Raw[0] != tlsRecordTypeHandshake {
		t.Fatalf("Raw does not contain a TLS handshake record: %x", probe.Raw)
	}

	_ = serverConn.Close()
	select {
	case <-handshakeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("crypto/tls client did not stop after probe connection closed")
	}
}

func TestReadTLSClientHelloRetainsEveryTruncatedPrefix(t *testing.T) {
	wire := testTLSHandshakeRecords(testTLSClientHelloHandshake("cut.example.com", []string{"h2"}))
	for length := 0; length < len(wire); length++ {
		t.Run(testTLSLengthName(length), func(t *testing.T) {
			prefix := wire[:length]
			probe, err := readTLSClientHello(bytes.NewReader(prefix), len(wire))
			if !errors.Is(err, errTLSClientHelloTruncated) {
				t.Fatalf("error = %v, want errTLSClientHelloTruncated", err)
			}
			if !bytes.Equal(probe.Raw, prefix) {
				t.Fatalf("Raw = %x, want full truncated prefix %x", probe.Raw, prefix)
			}
		})
	}
}

func TestReadTLSClientHelloNeverExceedsCallerLimit(t *testing.T) {
	wire := testTLSHandshakeRecords(testTLSClientHelloHandshake("limit.example.com", []string{"h2"}), 1, 2, 3, 5)
	for limit := 0; limit < len(wire); limit++ {
		t.Run(testTLSLengthName(limit), func(t *testing.T) {
			reader := bytes.NewReader(wire)
			probe, err := readTLSClientHello(reader, limit)
			if !errors.Is(err, errTLSClientHelloTooLarge) {
				t.Fatalf("error = %v, want errTLSClientHelloTooLarge", err)
			}
			if len(probe.Raw) > limit {
				t.Fatalf("read %d bytes with limit %d", len(probe.Raw), limit)
			}
			consumed := len(wire) - reader.Len()
			if consumed != len(probe.Raw) {
				t.Fatalf("reader consumed %d bytes but Raw has %d", consumed, len(probe.Raw))
			}
			if !bytes.Equal(probe.Raw, wire[:consumed]) {
				t.Fatal("Raw is not the exact consumed input prefix")
			}
		})
	}

	probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
	if err != nil {
		t.Fatalf("exact limit rejected: %v", err)
	}
	if len(probe.Raw) != len(wire) {
		t.Fatalf("exact limit retained %d bytes, want %d", len(probe.Raw), len(wire))
	}
}

func TestReadTLSClientHelloRejectsMalformedRecordEnvelope(t *testing.T) {
	valid := testTLSHandshakeRecords(testTLSClientHelloHandshake("record.example.com", nil))
	wrongType := append([]byte(nil), valid...)
	wrongType[0] = 23
	wrongVersion := append([]byte(nil), valid...)
	wrongVersion[1] = 2
	wrongHandshake := append([]byte(nil), valid...)
	wrongHandshake[tlsRecordHeaderLength] = 2
	oversizedRecord := []byte{tlsRecordTypeHandshake, 3, 1, 0x40, 0x01}

	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "application data", wire: wrongType},
		{name: "non-TLS version", wire: wrongVersion},
		{name: "non-ClientHello handshake", wire: wrongHandshake},
		{name: "oversized plaintext record", wire: oversizedRecord},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe, err := readTLSClientHello(bytes.NewReader(test.wire), len(test.wire)+64<<10)
			if !errors.Is(err, errTLSClientHelloMalformed) {
				t.Fatalf("error = %v, want errTLSClientHelloMalformed", err)
			}
			if len(probe.Raw) > len(test.wire) || !bytes.Equal(probe.Raw, test.wire[:len(probe.Raw)]) {
				t.Fatalf("Raw is not an input prefix: %x", probe.Raw)
			}
		})
	}
}

func TestReadTLSClientHelloRejectsDeclaredLengthBeyondLimit(t *testing.T) {
	wire := testTLSRecord([]byte{tlsHandshakeTypeClientHello, 0xff, 0xff, 0xff})
	reader := bytes.NewReader(wire)
	probe, err := readTLSClientHello(reader, 64<<10)
	if !errors.Is(err, errTLSClientHelloTooLarge) {
		t.Fatalf("error = %v, want errTLSClientHelloTooLarge", err)
	}
	if !bytes.Equal(probe.Raw, wire) || reader.Len() != 0 {
		t.Fatalf("declared-length failure lost consumed bytes: Raw=%x remaining=%d", probe.Raw, reader.Len())
	}
}

func TestReadTLSClientHelloZeroLengthRecordsRemainBounded(t *testing.T) {
	wire := bytes.Repeat([]byte{tlsRecordTypeHandshake, 3, 1, 0, 0}, 20)
	probe, err := readTLSClientHello(bytes.NewReader(wire), 25)
	if !errors.Is(err, errTLSClientHelloTooLarge) {
		t.Fatalf("error = %v, want errTLSClientHelloTooLarge", err)
	}
	if len(probe.Raw) != 25 {
		t.Fatalf("Raw length = %d, want 25", len(probe.Raw))
	}
}

func TestReadTLSClientHelloRejectsMalformedBodyVectors(t *testing.T) {
	validExtensions := testTLSExtensions(
		testTLSExtension(tlsExtensionServerName, testTLSServerNamePayload("body.example.com")),
	)
	validBody := testTLSClientHelloBody(validExtensions, true)

	invalidVersion := append([]byte(nil), validBody...)
	invalidVersion[0] = 2
	longSessionID := append([]byte(nil), validBody...)
	longSessionID[34] = 33
	emptyCipherSuites := append([]byte(nil), validBody...)
	binary.BigEndian.PutUint16(emptyCipherSuites[35:37], 0)
	oddCipherSuites := append([]byte(nil), validBody...)
	binary.BigEndian.PutUint16(oddCipherSuites[35:37], 1)
	emptyCompression := append([]byte(nil), validBody...)
	emptyCompression[39] = 0
	badExtensionsLength := append([]byte(nil), validBody...)
	binary.BigEndian.PutUint16(badExtensionsLength[41:43], binary.BigEndian.Uint16(badExtensionsLength[41:43])+1)

	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "missing fields", body: nil},
		{name: "invalid legacy version", body: invalidVersion},
		{name: "long session ID", body: longSessionID},
		{name: "empty cipher suites", body: emptyCipherSuites},
		{name: "odd cipher suites", body: oddCipherSuites},
		{name: "truncated cipher suites", body: validBody[:38]},
		{name: "empty compression methods", body: emptyCompression},
		{name: "truncated compression methods", body: append(append([]byte(nil), validBody[:39]...), 2, 0)},
		{name: "mismatched extensions length", body: badExtensionsLength},
		{name: "truncated extension header", body: testTLSClientHelloBody([]byte{0, 0, 0}, true)},
		{name: "truncated extension payload", body: testTLSClientHelloBody([]byte{0, 0, 0, 2, 0}, true)},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := testTLSHandshakeRecords(testTLSHandshake(test.body))
			probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
			if !errors.Is(err, errTLSClientHelloMalformed) {
				t.Fatalf("error = %v, want errTLSClientHelloMalformed", err)
			}
			if !bytes.Equal(probe.Raw, wire) {
				t.Fatal("malformed body did not retain the complete consumed record")
			}
		})
	}
}

func TestReadTLSClientHelloRejectsMalformedSNIAndALPN(t *testing.T) {
	duplicateHostNames := append(testTLSServerNameEntry(0, []byte("one.example")), testTLSServerNameEntry(0, []byte("two.example"))...)
	duplicateHostNames = testTLSVector16(duplicateHostNames)
	overlongName := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, ".")

	for _, test := range []struct {
		name          string
		extensionType uint16
		payload       []byte
	}{
		{name: "empty SNI list", extensionType: tlsExtensionServerName, payload: []byte{0, 0}},
		{name: "mismatched SNI list", extensionType: tlsExtensionServerName, payload: []byte{0, 1}},
		{name: "truncated SNI entry", extensionType: tlsExtensionServerName, payload: []byte{0, 2, 0, 0}},
		{name: "empty host name", extensionType: tlsExtensionServerName, payload: testTLSVector16(testTLSServerNameEntry(0, nil))},
		{name: "truncated host name", extensionType: tlsExtensionServerName, payload: []byte{0, 4, 0, 0, 2, 'x'}},
		{name: "NUL host name", extensionType: tlsExtensionServerName, payload: testTLSVector16(testTLSServerNameEntry(0, []byte{'x', 0, 'y'}))},
		{name: "non-ASCII host name", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("café.example")},
		{name: "host name with underscore", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("api_v1.example")},
		{name: "host name with wildcard", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("*.example")},
		{name: "host name with leading dot", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload(".example")},
		{name: "host name with trailing dot", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("example.")},
		{name: "host name with empty label", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("api..example")},
		{name: "host name with leading hyphen", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("-api.example")},
		{name: "host name with trailing hyphen", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload("api-.example")},
		{name: "host name with long label", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload(strings.Repeat("a", 64) + ".example")},
		{name: "host name longer than 253 bytes", extensionType: tlsExtensionServerName, payload: testTLSServerNamePayload(overlongName)},
		{name: "duplicate host name", extensionType: tlsExtensionServerName, payload: duplicateHostNames},
		{name: "empty ALPN list", extensionType: tlsExtensionALPN, payload: []byte{0, 0}},
		{name: "mismatched ALPN list", extensionType: tlsExtensionALPN, payload: []byte{0, 3, 1, 'h'}},
		{name: "empty ALPN protocol", extensionType: tlsExtensionALPN, payload: []byte{0, 1, 0}},
		{name: "truncated ALPN protocol", extensionType: tlsExtensionALPN, payload: []byte{0, 2, 2, 'h'}},
	} {
		t.Run(test.name, func(t *testing.T) {
			extensions := testTLSExtensions(testTLSExtension(test.extensionType, test.payload))
			wire := testTLSHandshakeRecords(testTLSHandshake(testTLSClientHelloBody(extensions, true)))
			probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
			if !errors.Is(err, errTLSClientHelloMalformed) {
				t.Fatalf("error = %v, want errTLSClientHelloMalformed", err)
			}
			if !bytes.Equal(probe.Raw, wire) {
				t.Fatal("malformed extension did not retain all consumed bytes")
			}
		})
	}
}

func TestReadTLSClientHelloAcceptsMaximumLengthASCIIHostName(t *testing.T) {
	serverName := strings.Join([]string{
		strings.Repeat("A", 63),
		strings.Repeat("b", 63),
		strings.Repeat("3", 63),
		strings.Repeat("d", 61),
	}, ".")
	if len(serverName) != tlsServerNameMaxLength {
		t.Fatalf("test host_name length = %d, want %d", len(serverName), tlsServerNameMaxLength)
	}
	wire := testTLSHandshakeRecords(testTLSClientHelloHandshake(serverName, nil))
	probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
	if err != nil {
		t.Fatalf("readTLSClientHello: %v", err)
	}
	if probe.ServerName != serverName {
		t.Fatalf("ServerName = %q, want %q", probe.ServerName, serverName)
	}
}

func TestReadTLSClientHelloCapsExtensionCount(t *testing.T) {
	for _, count := range []int{tlsClientHelloMaxExtensions, tlsClientHelloMaxExtensions + 1} {
		t.Run(testTLSLengthName(count), func(t *testing.T) {
			var extensions []byte
			for index := 0; index < count; index++ {
				extensions = append(extensions, testTLSExtension(uint16(0x1000+index), nil)...)
			}
			wire := testTLSHandshakeRecords(testTLSHandshake(testTLSClientHelloBody(extensions, true)))
			probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
			if count == tlsClientHelloMaxExtensions {
				if err != nil {
					t.Fatalf("maximum extension count rejected: %v", err)
				}
			} else if !errors.Is(err, errTLSClientHelloTooLarge) {
				t.Fatalf("error = %v, want errTLSClientHelloTooLarge", err)
			}
			if !bytes.Equal(probe.Raw, wire) {
				t.Fatal("extension-count boundary did not retain the consumed ClientHello")
			}
		})
	}
}

func TestReadTLSClientHelloCapsALPNProtocolCount(t *testing.T) {
	for _, count := range []int{tlsClientHelloMaxALPN, tlsClientHelloMaxALPN + 1} {
		t.Run(testTLSLengthName(count), func(t *testing.T) {
			protocols := make([]string, count)
			for index := range protocols {
				protocols[index] = "h2"
			}
			wire := testTLSHandshakeRecords(testTLSClientHelloHandshake("alpn.example", protocols))
			probe, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
			if count == tlsClientHelloMaxALPN {
				if err != nil {
					t.Fatalf("maximum ALPN protocol count rejected: %v", err)
				}
				if len(probe.ALPNProtocols) != tlsClientHelloMaxALPN {
					t.Fatalf("ALPN protocol count = %d, want %d", len(probe.ALPNProtocols), tlsClientHelloMaxALPN)
				}
			} else if !errors.Is(err, errTLSClientHelloTooLarge) {
				t.Fatalf("error = %v, want errTLSClientHelloTooLarge", err)
			}
			if !bytes.Equal(probe.Raw, wire) {
				t.Fatal("ALPN-count boundary did not retain the consumed ClientHello")
			}
		})
	}
}

func TestReadTLSClientHelloRejectsDuplicateExtensions(t *testing.T) {
	extension := testTLSExtension(tlsExtensionALPN, testTLSALPNPayload("h2"))
	body := testTLSClientHelloBody(testTLSExtensions(extension, extension), true)
	wire := testTLSHandshakeRecords(testTLSHandshake(body))
	_, err := readTLSClientHello(bytes.NewReader(wire), len(wire))
	if !errors.Is(err, errTLSClientHelloMalformed) {
		t.Fatalf("error = %v, want errTLSClientHelloMalformed", err)
	}
}

func FuzzReadTLSClientHello(f *testing.F) {
	valid := testTLSHandshakeRecords(testTLSClientHelloHandshake("fuzz.example.com", []string{"h2", "http/1.1"}), 1, 2, 5)
	invalidSNI := testTLSHandshakeRecords(testTLSClientHelloHandshake("bad_name.example", []string{"h2"}))
	overALPN := make([]string, tlsClientHelloMaxALPN+1)
	for index := range overALPN {
		overALPN[index] = "h2"
	}
	overALPNWire := testTLSHandshakeRecords(testTLSClientHelloHandshake("fuzz.example.com", overALPN))
	var overExtensions []byte
	for index := 0; index <= tlsClientHelloMaxExtensions; index++ {
		overExtensions = append(overExtensions, testTLSExtension(uint16(0x1000+index), nil)...)
	}
	overExtensionsWire := testTLSHandshakeRecords(testTLSHandshake(testTLSClientHelloBody(overExtensions, true)))
	f.Add(valid, uint16(len(valid)), uint8(1))
	f.Add(valid[:len(valid)/2], uint16(len(valid)), uint8(3))
	f.Add([]byte{tlsRecordTypeHandshake, 3, 1, 0xff, 0xff}, uint16(4096), uint8(7))
	f.Add([]byte("not tls"), uint16(32), uint8(2))
	f.Add(invalidSNI, uint16(len(invalidSNI)), uint8(5))
	f.Add(overALPNWire, uint16(len(overALPNWire)), uint8(11))
	f.Add(overExtensionsWire, uint16(len(overExtensionsWire)), uint8(13))

	f.Fuzz(func(t *testing.T, input []byte, encodedLimit uint16, encodedChunk uint8) {
		// Keep individual fuzz executions responsive while the deterministic
		// limit tests above cover every boundary of larger probes.
		limit := int(encodedLimit) % ((16 << 10) + 1)
		chunk := int(encodedChunk%32) + 1
		source := bytes.NewReader(input)
		reader := &testTLSShortReader{reader: source, maximum: chunk}
		probe, err := readTLSClientHello(reader, limit)

		if len(probe.Raw) > limit && limit >= 0 {
			t.Fatalf("read %d bytes with limit %d", len(probe.Raw), limit)
		}
		consumed := len(input) - source.Len()
		if consumed != len(probe.Raw) {
			t.Fatalf("consumed %d bytes but retained %d", consumed, len(probe.Raw))
		}
		if !bytes.Equal(probe.Raw, input[:consumed]) {
			t.Fatal("Raw is not the exact consumed prefix")
		}
		if err == nil {
			if len(probe.Raw) == 0 {
				t.Fatal("successful parse consumed no input")
			}
			if len(probe.ALPNProtocols) > tlsClientHelloMaxALPN {
				t.Fatalf("successful parse returned %d ALPN protocols, limit is %d", len(probe.ALPNProtocols), tlsClientHelloMaxALPN)
			}
			if probe.ServerName != "" {
				if len(probe.ServerName) > tlsServerNameMaxLength {
					t.Fatalf("successful parse returned %d-byte host_name, limit is %d", len(probe.ServerName), tlsServerNameMaxLength)
				}
				if validationErr := validateTLSClientHelloServerName([]byte(probe.ServerName)); validationErr != nil {
					t.Fatalf("successful parse returned invalid host_name %q: %v", probe.ServerName, validationErr)
				}
			}
			for _, protocol := range probe.ALPNProtocols {
				if protocol == "" {
					t.Fatal("successful parse returned an empty ALPN protocol")
				}
			}
		}
	})
}

type testTLSShortReader struct {
	reader  io.Reader
	maximum int
}

func (reader *testTLSShortReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		buffer = buffer[:reader.maximum]
	}
	return reader.reader.Read(buffer)
}

func testTLSClientHelloHandshake(serverName string, protocols []string) []byte {
	var extensions [][]byte
	if serverName != "" {
		extensions = append(extensions, testTLSExtension(tlsExtensionServerName, testTLSServerNamePayload(serverName)))
	}
	if protocols != nil {
		extensions = append(extensions, testTLSExtension(tlsExtensionALPN, testTLSALPNPayload(protocols...)))
	}
	return testTLSHandshake(testTLSClientHelloBody(testTLSExtensions(extensions...), true))
}

func testTLSClientHelloBody(extensions []byte, includeExtensions bool) []byte {
	body := make([]byte, 0, 64+len(extensions))
	body = append(body, 3, 3)
	body = append(body, bytes.Repeat([]byte{0x5a}, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	if includeExtensions {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		body = append(body, extensions...)
	}
	return body
}

func testTLSHandshake(body []byte) []byte {
	handshake := []byte{
		tlsHandshakeTypeClientHello,
		byte(len(body) >> 16),
		byte(len(body) >> 8),
		byte(len(body)),
	}
	return append(handshake, body...)
}

func testTLSHandshakeRecords(handshake []byte, fragmentSizes ...int) []byte {
	var wire []byte
	offset := 0
	for _, size := range fragmentSizes {
		if size < 0 || size > len(handshake)-offset {
			panic("invalid test TLS fragment size")
		}
		wire = append(wire, testTLSRecord(handshake[offset:offset+size])...)
		offset += size
	}
	if offset < len(handshake) {
		wire = append(wire, testTLSRecord(handshake[offset:])...)
	}
	return wire
}

func testTLSRecord(payload []byte) []byte {
	record := []byte{
		tlsRecordTypeHandshake,
		3,
		1,
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	return append(record, payload...)
}

func testTLSExtensions(extensions ...[]byte) []byte {
	return bytes.Join(extensions, nil)
}

func testTLSExtension(extensionType uint16, payload []byte) []byte {
	extension := []byte{
		byte(extensionType >> 8),
		byte(extensionType),
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	return append(extension, payload...)
}

func testTLSServerNamePayload(serverName string) []byte {
	return testTLSVector16(testTLSServerNameEntry(tlsServerNameTypeHostName, []byte(serverName)))
}

func testTLSServerNameEntry(nameType byte, name []byte) []byte {
	entry := []byte{nameType, byte(len(name) >> 8), byte(len(name))}
	return append(entry, name...)
}

func testTLSALPNPayload(protocols ...string) []byte {
	var list []byte
	for _, protocol := range protocols {
		list = append(list, byte(len(protocol)))
		list = append(list, protocol...)
	}
	return testTLSVector16(list)
}

func testTLSVector16(value []byte) []byte {
	result := []byte{byte(len(value) >> 8), byte(len(value))}
	return append(result, value...)
}

func testTLSLengthName(length int) string {
	const digits = "0123456789"
	if length == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for length > 0 {
		position--
		buffer[position] = digits[length%10]
		length /= 10
	}
	return string(buffer[position:])
}
