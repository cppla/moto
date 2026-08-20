package controller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestReadProxyProtocolHeaderReplaysOrdinaryTraffic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "HTTP", input: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")},
		{name: "shares first v1 byte", input: []byte("POST /upload HTTP/1.1\r\n")},
		{name: "shares v2 prefix", input: []byte("\r\nXbinary payload")},
		{name: "binary", input: []byte{0x00, 0x01, 0x02, 0xff}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reader := bytes.NewReader(test.input)
			result, err := readProxyProtocolHeader(reader)
			if err != nil {
				t.Fatal(err)
			}
			if result.Header != nil {
				t.Fatalf("unexpected PROXY protocol header: %+v", *result.Header)
			}
			if len(result.Replay) == 0 || len(result.Replay) > len(proxyProtocolV2Signature) {
				t.Fatalf("replay length = %d, want 1..%d", len(result.Replay), len(proxyProtocolV2Signature))
			}
			replayed, err := io.ReadAll(io.MultiReader(bytes.NewReader(result.Replay), reader))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replayed, test.input) {
				t.Fatalf("replayed bytes = %x, want %x", replayed, test.input)
			}
		})
	}
}

func TestReadProxyProtocolHeaderEmptyAndPartialSignatures(t *testing.T) {
	t.Parallel()

	result, err := readProxyProtocolHeader(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream error = %v, want EOF", err)
	}
	if result.Header != nil || len(result.Replay) != 0 {
		t.Fatalf("empty stream result = %+v, want empty", result)
	}

	partials := [][]byte{
		[]byte("P"),
		[]byte("PROXY"),
		proxyProtocolV2Signature[:len(proxyProtocolV2Signature)-1],
		append(append([]byte(nil), proxyProtocolV1Signature...), []byte("TCP4 192.0.2.1")...),
	}
	for _, partial := range partials {
		result, err := readProxyProtocolHeader(bytes.NewReader(partial))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("partial %x error = %v, want unexpected EOF", partial, err)
		}
		if result.Header != nil || len(result.Replay) != 0 {
			t.Errorf("partial %x result = %+v, want empty error result", partial, result)
		}
	}
}

func TestReadProxyProtocolHeaderPropagatesReaderFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read failed")
	reader := io.MultiReader(strings.NewReader("P"), proxyProtocolErrorReader{err: wantErr})
	if _, err := readProxyProtocolHeader(reader); !errors.Is(err, wantErr) {
		t.Fatalf("read error = %v, want %v", err, wantErr)
	}
}

func TestReadProxyProtocolV1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire string
		want proxyProtocolHeader
		tail string
	}{
		{
			name: "TCP4",
			wire: "PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n",
			want: proxyProtocolHeader{
				Version:     proxyProtocolVersion1,
				Command:     proxyProtocolCommandProxy,
				Source:      proxyProtocolTestAddrPort("192.0.2.10:12345"),
				Destination: proxyProtocolTestAddrPort("198.51.100.20:443"),
			},
			tail: "TLS",
		},
		{
			name: "TCP6",
			wire: "PROXY TCP6 2001:db8::10 2001:db8::20 65535 0\r\n",
			want: proxyProtocolHeader{
				Version:     proxyProtocolVersion1,
				Command:     proxyProtocolCommandProxy,
				Source:      proxyProtocolTestAddrPort("[2001:db8::10]:65535"),
				Destination: proxyProtocolTestAddrPort("[2001:db8::20]:0"),
			},
			tail: "SSH",
		},
		{
			name: "UNKNOWN",
			wire: "PROXY UNKNOWN\r\n",
			want: proxyProtocolHeader{
				Version: proxyProtocolVersion1,
				Command: proxyProtocolCommandLocal,
			},
			tail: "opaque",
		},
		{
			name: "UNKNOWN with ignored trailing fields",
			wire: "PROXY UNKNOWN sender-defined fields are ignored\r\n",
			want: proxyProtocolHeader{
				Version: proxyProtocolVersion1,
				Command: proxyProtocolCommandLocal,
			},
			tail: "payload",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reader := strings.NewReader(test.wire + test.tail)
			result, err := readProxyProtocolHeader(reader)
			if err != nil {
				t.Fatal(err)
			}
			if result.Header == nil {
				t.Fatal("header was not detected")
			}
			if !reflect.DeepEqual(*result.Header, test.want) {
				t.Fatalf("header = %+v, want %+v", *result.Header, test.want)
			}
			if len(result.Replay) != 0 {
				t.Fatalf("replay = %x, want empty", result.Replay)
			}
			tail, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(tail) != test.tail {
				t.Fatalf("tail = %q, want %q", tail, test.tail)
			}
		})
	}
}

func TestReadProxyProtocolV1RejectsMalformedHeaders(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"unsupported family":  "PROXY UDP4 192.0.2.1 192.0.2.2 1 2\r\n",
		"TCP4 with IPv6":      "PROXY TCP4 2001:db8::1 192.0.2.2 1 2\r\n",
		"TCP6 with IPv4":      "PROXY TCP6 192.0.2.1 2001:db8::2 1 2\r\n",
		"mapped TCP6":         "PROXY TCP6 ::ffff:192.0.2.1 2001:db8::2 1 2\r\n",
		"scoped IPv6":         "PROXY TCP6 fe80::1%lo0 2001:db8::2 1 2\r\n",
		"port overflow":       "PROXY TCP4 192.0.2.1 192.0.2.2 65536 2\r\n",
		"negative port":       "PROXY TCP4 192.0.2.1 192.0.2.2 -1 2\r\n",
		"leading zero port":   "PROXY TCP4 192.0.2.1 192.0.2.2 01 2\r\n",
		"repeated whitespace": "PROXY TCP4  192.0.2.1 192.0.2.2 1 2\r\n",
		"extra field":         "PROXY TCP4 192.0.2.1 192.0.2.2 1 2 extra\r\n",
	}
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := readProxyProtocolHeader(strings.NewReader(wire))
			if err == nil {
				t.Fatalf("accepted malformed header as %+v", result.Header)
			}
		})
	}

	overlong := "PROXY " + strings.Repeat("x", proxyProtocolV1MaxHeaderLength) + "\r\nTAIL"
	reader := strings.NewReader(overlong)
	if _, err := readProxyProtocolHeader(reader); err == nil {
		t.Fatal("accepted overlong v1 header")
	}
	if consumed := len(overlong) - reader.Len(); consumed != proxyProtocolV1MaxHeaderLength {
		t.Fatalf("overlong v1 consumed %d bytes, want hard cap %d", consumed, proxyProtocolV1MaxHeaderLength)
	}
}

func TestProxyProtocolEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []proxyProtocolHeader{
		{Version: proxyProtocolVersion1, Command: proxyProtocolCommandLocal},
		{
			Version:     proxyProtocolVersion1,
			Command:     proxyProtocolCommandProxy,
			Source:      proxyProtocolTestAddrPort("203.0.113.7:23456"),
			Destination: proxyProtocolTestAddrPort("198.51.100.8:8443"),
		},
		{
			Version:     proxyProtocolVersion1,
			Command:     proxyProtocolCommandProxy,
			Source:      proxyProtocolTestAddrPort("[2001:db8:1::7]:23456"),
			Destination: proxyProtocolTestAddrPort("[2001:db8:2::8]:8443"),
		},
		{Version: proxyProtocolVersion2, Command: proxyProtocolCommandLocal},
		{
			Version:     proxyProtocolVersion2,
			Command:     proxyProtocolCommandProxy,
			Source:      proxyProtocolTestAddrPort("203.0.113.7:23456"),
			Destination: proxyProtocolTestAddrPort("198.51.100.8:8443"),
		},
		{
			Version:     proxyProtocolVersion2,
			Command:     proxyProtocolCommandProxy,
			Source:      proxyProtocolTestAddrPort("[2001:db8:1::7]:23456"),
			Destination: proxyProtocolTestAddrPort("[2001:db8:2::8]:8443"),
		},
	}
	for _, want := range tests {
		want := want
		t.Run(proxyProtocolTestName(want), func(t *testing.T) {
			t.Parallel()

			var wire bytes.Buffer
			if err := writeProxyProtocolHeader(&wire, want); err != nil {
				t.Fatal(err)
			}
			wire.WriteString("application data")
			result, err := readProxyProtocolHeader(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if result.Header == nil {
				t.Fatal("encoded header was not detected")
			}
			if !reflect.DeepEqual(*result.Header, want) {
				t.Fatalf("decoded header = %+v, want %+v", *result.Header, want)
			}
			if got := wire.String(); got != "application data" {
				t.Fatalf("unconsumed stream = %q, want application data", got)
			}
		})
	}
}

func TestReadProxyProtocolV2AcceptsValidTLVs(t *testing.T) {
	t.Parallel()

	payload := []byte{
		192, 0, 2, 1,
		198, 51, 100, 2,
		0x30, 0x39,
		0x01, 0xbb,
		0x01, 0x00, 0x03, 'h', '2', 'c',
		0x04, 0x00, 0x00,
	}
	wire := proxyProtocolTestV2Packet(0x21, 0x11, payload)
	wire = append(wire, []byte("tail")...)
	reader := bytes.NewReader(wire)
	result, err := readProxyProtocolHeader(reader)
	if err != nil {
		t.Fatal(err)
	}
	want := proxyProtocolHeader{
		Version:     proxyProtocolVersion2,
		Command:     proxyProtocolCommandProxy,
		Source:      proxyProtocolTestAddrPort("192.0.2.1:12345"),
		Destination: proxyProtocolTestAddrPort("198.51.100.2:443"),
	}
	if result.Header == nil || !reflect.DeepEqual(*result.Header, want) {
		t.Fatalf("header = %+v, want %+v", result.Header, want)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(remaining) != "tail" {
		t.Fatalf("remaining = %q, want tail", remaining)
	}
}

func TestReadProxyProtocolV2LocalAddressForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		familyProtocol byte
		payload        []byte
	}{
		{name: "UNSPEC", familyProtocol: 0x00},
		{name: "TCP4", familyProtocol: 0x11, payload: make([]byte, 12)},
		{name: "TCP6", familyProtocol: 0x21, payload: make([]byte, 36)},
		{name: "unsupported family with opaque payload", familyProtocol: 0xff, payload: []byte{0x01, 0x00}},
		{name: "short address block is opaque", familyProtocol: 0x11, payload: []byte{0xde, 0xad, 0xbe}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			wire := append(proxyProtocolTestV2Packet(0x20, test.familyProtocol, test.payload), []byte("tail")...)
			reader := bytes.NewReader(wire)
			result, err := readProxyProtocolHeader(reader)
			if err != nil {
				t.Fatal(err)
			}
			want := proxyProtocolHeader{Version: proxyProtocolVersion2, Command: proxyProtocolCommandLocal}
			if result.Header == nil || !reflect.DeepEqual(*result.Header, want) {
				t.Fatalf("header = %+v, want %+v", result.Header, want)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(remaining) != "tail" {
				t.Fatalf("remaining = %q, want tail", remaining)
			}
		})
	}
}

func TestReadProxyProtocolV2RejectsMalformedHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		versionCommand byte
		familyProtocol byte
		payload        []byte
	}{
		{name: "wrong version", versionCommand: 0x11, familyProtocol: 0x11, payload: make([]byte, 12)},
		{name: "unknown command", versionCommand: 0x22, familyProtocol: 0x11, payload: make([]byte, 12)},
		{name: "PROXY UNSPEC", versionCommand: 0x21, familyProtocol: 0x00},
		{name: "UDP4", versionCommand: 0x21, familyProtocol: 0x12, payload: make([]byte, 12)},
		{name: "UDP6", versionCommand: 0x21, familyProtocol: 0x22, payload: make([]byte, 36)},
		{name: "UNIX stream", versionCommand: 0x21, familyProtocol: 0x31, payload: make([]byte, 216)},
		{name: "short TCP4", versionCommand: 0x21, familyProtocol: 0x11, payload: make([]byte, 11)},
		{name: "short TCP6", versionCommand: 0x21, familyProtocol: 0x21, payload: make([]byte, 35)},
		{name: "partial TLV header", versionCommand: 0x21, familyProtocol: 0x11, payload: make([]byte, 14)},
		{name: "TLV length overflow", versionCommand: 0x21, familyProtocol: 0x11, payload: append(make([]byte, 12), 0x01, 0x00, 0x02, 0xff)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := readProxyProtocolHeader(bytes.NewReader(
				proxyProtocolTestV2Packet(test.versionCommand, test.familyProtocol, test.payload),
			))
			if err == nil {
				t.Fatalf("accepted malformed header as %+v", result.Header)
			}
		})
	}

	declaredLength := proxyProtocolV2MaxPayloadLength + 1
	wire := append([]byte(nil), proxyProtocolV2Signature...)
	wire = append(wire, 0x21, 0x11, byte(declaredLength>>8), byte(declaredLength))
	wire = append(wire, []byte("must remain unread")...)
	reader := bytes.NewReader(wire)
	if _, err := readProxyProtocolHeader(reader); err == nil {
		t.Fatal("accepted payload length above the operational cap")
	}
	if reader.Len() != len("must remain unread") {
		t.Fatalf("oversized header consumed payload: %d bytes remain", reader.Len())
	}

	truncated := proxyProtocolTestV2Packet(0x21, 0x11, make([]byte, 12))
	binary.BigEndian.PutUint16(truncated[14:16], 13)
	if _, err := readProxyProtocolHeader(bytes.NewReader(truncated)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated payload error = %v, want unexpected EOF", err)
	}
}

func TestWriteProxyProtocolHeaderRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header proxyProtocolHeader
	}{
		{name: "unknown version", header: proxyProtocolHeader{Version: 3, Command: proxyProtocolCommandLocal}},
		{name: "unknown command", header: proxyProtocolHeader{Version: proxyProtocolVersion2, Command: 2}},
		{name: "missing endpoints", header: proxyProtocolHeader{Version: proxyProtocolVersion1, Command: proxyProtocolCommandProxy}},
		{
			name: "mixed address families",
			header: proxyProtocolHeader{
				Version:     proxyProtocolVersion2,
				Command:     proxyProtocolCommandProxy,
				Source:      proxyProtocolTestAddrPort("192.0.2.1:1"),
				Destination: proxyProtocolTestAddrPort("[2001:db8::1]:2"),
			},
		},
		{
			name: "scoped IPv6",
			header: proxyProtocolHeader{
				Version:     proxyProtocolVersion2,
				Command:     proxyProtocolCommandProxy,
				Source:      proxyProtocolTestAddrPort("[fe80::1%lo0]:1"),
				Destination: proxyProtocolTestAddrPort("[fe80::2%lo0]:2"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := writeProxyProtocolHeader(io.Discard, test.header); err == nil {
				t.Fatal("accepted invalid encoder input")
			}
		})
	}

	if err := writeProxyProtocolHeader(nil, proxyProtocolHeader{}); err == nil {
		t.Fatal("accepted nil writer")
	}
	if _, err := readProxyProtocolHeader(nil); err == nil {
		t.Fatal("accepted nil reader")
	}
}

func TestWriteProxyProtocolHeaderPropagatesWriterFailures(t *testing.T) {
	t.Parallel()

	header := proxyProtocolHeader{Version: proxyProtocolVersion1, Command: proxyProtocolCommandLocal}
	if err := writeProxyProtocolHeader(proxyProtocolShortWriter{}, header); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer error = %v, want ErrShortWrite", err)
	}
	wantErr := errors.New("write failed")
	if err := writeProxyProtocolHeader(proxyProtocolErrorWriter{err: wantErr}, header); !errors.Is(err, wantErr) {
		t.Fatalf("error writer error = %v, want %v", err, wantErr)
	}
}

func FuzzReadProxyProtocolHeader(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\npayload"))
	f.Add(proxyProtocolTestV2Packet(0x21, 0x11, make([]byte, 12)))

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := readProxyProtocolHeader(bytes.NewReader(input))
		if err != nil || result.Header != nil {
			return
		}
		if len(result.Replay) == 0 || len(result.Replay) > len(proxyProtocolV2Signature) {
			t.Fatalf("non-header replay length = %d", len(result.Replay))
		}
	})
}

func proxyProtocolTestAddrPort(value string) netip.AddrPort {
	return netip.MustParseAddrPort(value)
}

func proxyProtocolTestName(header proxyProtocolHeader) string {
	command := "PROXY"
	if header.Command == proxyProtocolCommandLocal {
		command = "LOCAL"
	}
	family := "none"
	if header.Source.IsValid() {
		if header.Source.Addr().Is4() {
			family = "TCP4"
		} else {
			family = "TCP6"
		}
	}
	return "v" + strconv.Itoa(int(header.Version)) + "/" + command + "/" + family
}

func proxyProtocolTestV2Packet(versionCommand, familyProtocol byte, payload []byte) []byte {
	packet := make([]byte, 16, 16+len(payload))
	copy(packet, proxyProtocolV2Signature)
	packet[12] = versionCommand
	packet[13] = familyProtocol
	binary.BigEndian.PutUint16(packet[14:16], uint16(len(payload)))
	return append(packet, payload...)
}

type proxyProtocolShortWriter struct{}

func (proxyProtocolShortWriter) Write(payload []byte) (int, error) {
	return len(payload) - 1, nil
}

type proxyProtocolErrorWriter struct {
	err error
}

func (writer proxyProtocolErrorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

type proxyProtocolErrorReader struct {
	err error
}

func (reader proxyProtocolErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
