package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// The production Chrome QUIC hello offers P-256 but sends only X25519/ML-KEM
// key shares. A P-256-only server therefore requires a second ClientHello on
// the same Initial CRYPTO stream. The old Chrome tail-fragment implementation
// reused the first hello's already-sent offsets and stalled this cold handshake.
// Keep a no-HRR control so a broken fixture cannot look like an HRR regression.
func TestHTTP3ChromeHelloRetryRequestCONNECT(t *testing.T) {
	for _, test := range []struct {
		name  string
		curve tls.CurveID
	}{
		{name: "x25519_control", curve: tls.X25519},
		{name: "p256_hello_retry_request", curve: tls.CurveP256},
	} {
		t.Run(test.name, func(t *testing.T) {
			const destination = "hrr-destination.example:443"
			const username, password = "hrr-fixture", "local-test-password"
			wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
			var requests atomic.Int64
			endpoint, roots, packets := startHTTP3HRRServer(t, test.curve, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Method != http.MethodConnect || request.Host != destination || request.ProtoMajor != 3 || request.Header.Get("Proxy-Authorization") != wantAuth {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				echoHTTP3OwnershipTunnel(writer, request)
			}))
			physical := make(chan *quic.Conn, 3)
			manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
				transport := newHTTP3ConnectTransportWithOwner(key, owner)
				if transport.QUICConfig.ChromeParrotSessionCache != nil || transport.TLSClientConfig.ClientSessionCache != nil || transport.QUICConfig.Allow0RTT {
					t.Error("production Chrome H3 must retain full handshakes without a session cache or 0-RTT")
				}
				transport.TLSClientConfig.RootCAs = roots
				originalDial := transport.Dial
				transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
					connection, err := originalDial(ctx, address, tlsConfig, quicConfig)
					if err == nil {
						physical <- connection
					}
					return connection, err
				}
				return transport
			})
			t.Cleanup(manager.close)
			target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
				Protocols: []string{config.ConnectProxyH3}, ServerName: "example.com",
				BasicAuth: &config.BasicAuthConfig{Username: username, Password: password},
			}}

			var connection *quic.Conn
			for stream := 0; stream < 2; stream++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				tunnel, dialErr := manager.dial(ctx, target, destination)
				cancel()
				if stream == 0 {
					// Inspect the actual Initial even on dial failure. This pins the
					// prerequisite for HRR instead of trusting a profile flag.
					assertHTTP3HRRInitialKeyShares(t, packets.snapshot(), test.curve)
				}
				if dialErr != nil {
					t.Fatalf("verified CONNECT after curve %s negotiation: %v", test.curve, dialErr)
				}
				t.Cleanup(func() { _ = tunnel.Close() })
				if stream == 0 {
					select {
					case connection = <-physical:
					default:
						t.Fatal("CONNECT succeeded without a physical QUIC handshake")
					}
					quicState := connection.ConnectionState()
					state := quicState.TLS
					if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h3" || state.DidResume || quicState.Used0RTT || len(state.VerifiedChains) == 0 {
						t.Fatalf("cold verified TLS state = %+v", state)
					}
				}
				if err := connection.Context().Err(); err != nil {
					t.Fatalf("canceling completed setup closed the HRR connection: %v", err)
				}
				watchdog := time.AfterFunc(3*time.Second, func() { _ = tunnel.Close() })
				t.Cleanup(func() { watchdog.Stop() })
				assertConnectTunnelEcho(t, tunnel, "authenticated-payload-after-quic-hrr")
				if err := closeWrite(tunnel); err != nil {
					t.Fatalf("half-close CONNECT request: %v", err)
				}
				if _, err := tunnel.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("CONNECT response after half-close = %v, want EOF", err)
				}
				watchdog.Stop()
				_ = tunnel.Close()
			}
			if got := requests.Load(); got != 2 {
				t.Fatalf("authenticated CONNECT requests = %d, want 2", got)
			}
			select {
			case <-physical:
				t.Fatal("second CONNECT redialed instead of reusing the HRR connection")
			default:
			}
			manager.close()
			waitHTTP3PhysicalClosed(t, connection)
		})
	}
}

func startHTTP3HRRServer(t *testing.T, curve tls.CurveID, handler http.Handler) (string, *x509.CertPool, *chromeWirePackets) {
	t.Helper()
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	captured := &chromeWirePackets{PacketConn: packet}
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{certificate},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{curve},
		},
		Handler: handler,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(captured) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packet.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("close HRR fixture: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HRR fixture did not stop")
		}
	})
	return packet.LocalAddr().String(), roots, captured
}

func assertHTTP3HRRInitialKeyShares(t *testing.T, datagrams [][]byte, serverCurve tls.CurveID) {
	t.Helper()
	hello, _, err := chromeWireClientHello(datagrams)
	if err != nil {
		t.Fatalf("decode first QUIC ClientHello: %v", err)
	}
	_, extensions := chromeWireExtensions(t, hello)
	groups := extensions[10]
	if len(groups) < 2 || int(binary.BigEndian.Uint16(groups[:2])) != len(groups)-2 || len(groups)%2 != 0 {
		t.Fatal("invalid supported_groups in actual ClientHello")
	}
	var supported bool
	for offset := 2; offset < len(groups); offset += 2 {
		supported = supported || tls.CurveID(binary.BigEndian.Uint16(groups[offset:])) == serverCurve
	}
	if !supported {
		t.Fatalf("actual ClientHello does not support server curve %s", serverCurve)
	}
	shares := extensions[51]
	if len(shares) < 2 || int(binary.BigEndian.Uint16(shares[:2])) != len(shares)-2 {
		t.Fatal("invalid key_share vector in actual ClientHello")
	}
	var offered bool
	for shares = shares[2:]; len(shares) > 0; {
		if len(shares) < 4 {
			t.Fatal("truncated actual key_share entry")
		}
		group, size := tls.CurveID(binary.BigEndian.Uint16(shares)), int(binary.BigEndian.Uint16(shares[2:]))
		if size == 0 || size > len(shares)-4 {
			t.Fatal("invalid actual key_share size")
		}
		offered = offered || group == serverCurve
		shares = shares[4+size:]
	}
	if want := serverCurve == tls.X25519; offered != want {
		t.Fatalf("first ClientHello key share for %s = %t, want %t", serverCurve, offered, want)
	}
	t.Logf("actual first ClientHello supports %s; key share present=%t; HRR required=%t", serverCurve, offered, !offered)
}
