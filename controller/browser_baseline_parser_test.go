package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// These parser checks run in ordinary offline go test, without a browser or
// MOTO_BROWSER_CAPTURE_DIR. The vectors intentionally include two distinct
// GREASE IDs, so normalization must not erase extension multiplicity.
func TestBrowserBaselineParserTLSNormalization(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var baseline map[string]any
			for _, reverse := range []bool{false, true} {
				hello := browserBaselineParserHello(protocol, reverse, nil)
				var features map[string]any
				if protocol == "h2" {
					// Fragment within the handshake header and ClientHello body.
					features = browserH2TLSFeatures(t, testTLSHandshakeRecords(hello, 2, 11))
				} else {
					datagram := make([]byte, 1250)
					datagram[0], datagram[4], datagram[5] = 0xc0, 1, 8
					features = browserH3Features(t, hello, datagram)
				}
				for key, want := range map[string][]string{
					"tls.cipher_suites":        {"0x1301"},
					"tls.supported_groups":     {"0x?a?a", "0x001d", "0x0017"},
					"tls.signature_algorithms": {"0x0403", "0x0804"},
					"tls.supported_versions":   {"0x?a?a", "0x0304"},
					"tls.alpn":                 {protocol},
				} {
					if !reflect.DeepEqual(features[key], want) {
						t.Fatalf("%s = %#v, want %#v", key, features[key], want)
					}
				}
				ids := features["tls.extension_ids"].([]string)
				if !slices.IsSorted(ids) {
					t.Fatalf("extension IDs are not sorted: %v", ids)
				}
				greaseCount := 0
				for _, id := range ids {
					if id == "0x?a?a" {
						greaseCount++
					}
				}
				if greaseCount != 2 || !slices.Contains(ids, "0x1a2a") {
					t.Fatalf("GREASE multiplicity or non-GREASE identity lost: %v", ids)
				}
				shares, err := json.Marshal(features["tls.key_share_groups"])
				if err != nil {
					t.Fatal(err)
				}
				if string(shares) != `[{"group":"0x?a?a","key_exchange_bytes":1},{"group":"0x001d","key_exchange_bytes":2}]` {
					t.Fatalf("key shares = %s; only group IDs and lengths should remain", shares)
				}
				if baseline == nil {
					baseline = features
				} else if !reflect.DeepEqual(features, baseline) {
					t.Fatal("extension permutation changed normalized features")
				}
			}
		})
	}
}

func TestBrowserBaselineParserTransportNormalization(t *testing.T) {
	versions := binary.BigEndian.AppendUint32(nil, 1)
	versions = binary.BigEndian.AppendUint32(versions, 0x7a1a2a3a)
	versions = binary.BigEndian.AppendUint32(versions, 1)
	parameters := map[uint64]chromeWireParameter{
		1:      {value: []byte{0x40, 0x64}}, // 100, encoded in a two-byte varint.
		12:     {value: nil},
		15:     {value: []byte("random connection ID")},
		17:     {value: versions},
		27:     {value: []byte("random GREASE")},
		0x3127: {value: []byte("cached RTT")},
		0x3128: {value: []byte("ORIG")},
	}
	got := browserH3TransportParameters(t, parameters)
	want := map[string]any{
		"0x1": uint64(100), "0xc": true, "0x3128": "0x4f524947",
		"0x11": map[string]any{"chosen": "0x00000001", "available": []string{"0x00000001", "0x?a?a?a?a"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized transport parameters = %#v, want %#v", got, want)
	}
}

func TestBrowserBaselineParserPeerIsolation(t *testing.T) {
	packets := &browserH3Packets{datagrams: []browserH3Datagram{
		{remote: "127.0.0.1:10001", data: []byte("speculative hello")},
		{remote: "127.0.0.1:10002", data: []byte("controlled hello part 1")},
		{remote: "127.0.0.1:10001", data: []byte("speculative continuation")},
		{remote: "127.0.0.1:10002", data: []byte("controlled hello part 2")},
	}}
	remote, datagrams := packets.snapshot("127.0.0.1:10002")
	if remote != "127.0.0.1:10002" || !reflect.DeepEqual(datagrams, [][]byte{[]byte("controlled hello part 1"), []byte("controlled hello part 2")}) {
		t.Fatalf("mixed speculative and controlled connection bytes: %s %q", remote, datagrams)
	}
	_, missing := packets.snapshot("127.0.0.1:10003")
	if len(missing) != 0 {
		t.Fatal("missing CONNECT peer silently fell back to another connection")
	}
}

// Capture parsers use t.Fatal to refuse malformed evidence. A child test
// process verifies those failure paths without turning the parent test into an
// expected failure or treating a parser panic as a successful rejection.
func TestBrowserBaselineParserRejectMalformed(t *testing.T) {
	const caseEnvironment = "MOTO_BROWSER_PARSER_MALFORMED_CASE"
	if selected := os.Getenv(caseEnvironment); selected != "" {
		switch selected {
		case "h2_odd_groups":
			hello := browserBaselineParserHello("h2", false, map[uint16][]byte{10: {0, 3, 0, 29, 0}})
			browserH2TLSFeatures(t, testTLSHandshakeRecords(hello))
		case "h3_truncated_key_share":
			browserH3KeyShares(t, []byte{0, 4, 0, 29, 0, 1})
		case "h3_truncated_number":
			browserH3TransportParameters(t, map[uint64]chromeWireParameter{1: {value: []byte{0x40}}})
		case "h3_truncated_parameters":
			chromeWireTransportParameters(t, []byte{1, 2, 0})
		default:
			t.Fatalf("unknown malformed parser case %q", selected)
		}
		return
	}
	for selected, message := range map[string]string{
		"h2_odd_groups":           "invalid ClientHello extension 10 vector length",
		"h3_truncated_key_share":  "truncated TLS key exchange bytes",
		"h3_truncated_number":     "is not one QUIC varint",
		"h3_truncated_parameters": "truncated transport parameter",
	} {
		t.Run(selected, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBrowserBaselineParserRejectMalformed$", "-test.count=1")
			command.Env = append(os.Environ(), caseEnvironment+"="+selected)
			output, err := command.CombinedOutput()
			if err == nil || ctx.Err() != nil || !bytes.Contains(output, []byte(message)) || strings.Contains(string(output), "panic:") {
				t.Fatalf("malformed case did not fail cleanly: %v\n%s", err, output)
			}
		})
	}
}

func browserBaselineParserHello(protocol string, reverse bool, overrides map[uint16][]byte) []byte {
	values := []struct {
		id   uint16
		data []byte
	}{
		{0x0a0a, nil}, {0x1a1a, nil}, {0x1a2a, nil},
		{10, []byte{0, 6, 0x2a, 0x2a, 0, 29, 0, 23}},
		{13, []byte{0, 4, 4, 3, 8, 4}},
		{16, testTLSALPNPayload(protocol)},
		{43, []byte{4, 0x3a, 0x3a, 3, 4}},
		{51, []byte{0, 11, 0x4a, 0x4a, 0, 1, 0xff, 0, 29, 0, 2, 0xee, 0xee}},
	}
	if protocol == "h3" {
		values = append(values, struct {
			id   uint16
			data []byte
		}{57, []byte{1, 1, 10}})
	}
	if reverse {
		slices.Reverse(values)
	}
	var extensions []byte
	for _, value := range values {
		if replacement, present := overrides[value.id]; present {
			value.data = replacement
		}
		extensions = append(extensions, testTLSExtension(value.id, value.data)...)
	}
	return testTLSHandshake(testTLSClientHelloBody(extensions, true))
}
