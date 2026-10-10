package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"moto/config"
	xhttp2 "moto/internal/browserhttp2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
)

// Experimental only: these factories never participate in production routing.
// Local: MOTO_RESUMPTION_EXPERIMENT=1 go test ./controller -run '^TestConnectProxyResumptionExperimentLocal$' -v
// Private routes require a second opt-in, and are never read by the local test:
// MOTO_RESUMPTION_EXPERIMENT=1 MOTO_RESUMPTION_REAL_CONFIG=/path/to/config.json \
//   go test ./controller -run '^TestConnectProxyResumptionExperimentReal$' -v
// Optional: MOTO_RESUMPTION_TARGETS=0,1 (indices after endpoint/SNI deduplication),
// MOTO_RESUMPTION_ROUNDS=3 (2..5). At most four targets, two configured protocols,
// and 11 new physical connections per target/protocol. Each real connection
// makes one bounded HTTPS GET to example.com; no probe repeats on failure.
// Caches live only in this test process, are bounded to two entries, and are
// never shared across target, SNI, authentication, protocol or TLS policy.

const resumptionExperimentPayload = "moto-session-resumption-local-payload"

type resumptionExperimentCache struct {
	utls.ClientSessionCache
	puts    atomic.Int64
	hits    atomic.Int64
	early   atomic.Bool
	noticed chan struct{}
}

func newResumptionExperimentCache() *resumptionExperimentCache {
	return &resumptionExperimentCache{ClientSessionCache: utls.NewLRUClientSessionCache(2), noticed: make(chan struct{}, 1)}
}

func (cache *resumptionExperimentCache) Get(key string) (*utls.ClientSessionState, bool) {
	state, ok := cache.ClientSessionCache.Get(key)
	if ok && state != nil {
		cache.hits.Add(1)
	}
	return state, ok
}

func (cache *resumptionExperimentCache) Put(key string, state *utls.ClientSessionState) {
	cache.ClientSessionCache.Put(key, state)
	if state == nil {
		return
	}
	cache.puts.Add(1)
	_, session, err := state.ResumptionState()
	if err == nil && session != nil && session.EarlyData {
		cache.early.Store(true)
	}
	select {
	case cache.noticed <- struct{}{}:
	default:
	}
}

type resumptionExperimentSample struct {
	Target             int     `json:"target"`
	Protocol           string  `json:"protocol"`
	Phase              string  `json:"phase"`
	Round              int     `json:"round"`
	PhysicalDials      int     `json:"physical_dials"`
	ConnectionReused   bool    `json:"connection_reused"`
	ClientLocalPort    int     `json:"client_local_port"`
	ServerObservedPort int     `json:"server_observed_client_port,omitempty"`
	ServerConnectionID int64   `json:"server_connection_id,omitempty"`
	DidResume          bool    `json:"did_resume"`
	ServerDidResume    *bool   `json:"server_did_resume,omitempty"`
	ServerHRR          *bool   `json:"server_hrr,omitempty"`
	Used0RTT           bool    `json:"used_0rtt"`
	CertificateChecked bool    `json:"certificate_checked"`
	TLSVersion         uint16  `json:"tls_version"`
	TicketStored       bool    `json:"ticket_stored"`
	CacheHit           bool    `json:"cache_hit"`
	PhysicalSetupMS    float64 `json:"physical_setup_ms"`
	ConnectMS          float64 `json:"connect_ms"`
	TotalMS            float64 `json:"total_ms"`
	PayloadBytes       int     `json:"payload_bytes"`
	ErrorClass         string  `json:"error_class,omitempty"`
}

type resumptionExperimentPhysical struct {
	mu      sync.Mutex
	sample  resumptionExperimentSample
	closers []func()
}

func (physical *resumptionExperimentPhysical) record(port int, resumed, verified, early bool, version uint16, elapsed time.Duration, closeConnection func()) {
	physical.mu.Lock()
	defer physical.mu.Unlock()
	physical.sample.PhysicalDials++
	physical.sample.ClientLocalPort = port
	physical.sample.DidResume = resumed
	physical.sample.CertificateChecked = verified
	physical.sample.Used0RTT = early
	physical.sample.TLSVersion = version
	physical.sample.PhysicalSetupMS = float64(elapsed) / float64(time.Millisecond)
	physical.closers = append(physical.closers, closeConnection)
}

func (physical *resumptionExperimentPhysical) snapshot() resumptionExperimentSample {
	physical.mu.Lock()
	defer physical.mu.Unlock()
	return physical.sample
}

func (physical *resumptionExperimentPhysical) close() {
	physical.mu.Lock()
	closers := append([]func(){}, physical.closers...)
	physical.mu.Unlock()
	for _, closeConnection := range closers {
		closeConnection()
	}
}

func resumptionExperimentPort(address net.Addr) int {
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}

func resumptionExperimentH2Dial(ctx context.Context, network, address string, settings *tls.Config, cache *resumptionExperimentCache, physical *resumptionExperimentPhysical) (net.Conn, error) {
	started := time.Now()
	clientConfig, err := newHTTP2UTLSConfig(settings)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		clientConfig.ClientSessionCache = cache
		clientConfig.OmitEmptyPsk = true
		// Append a real runtime PSK only when a ticket exists. Empty-cache wire
		// bytes retain the same fixed Chrome133 preset; no preset is rewritten.
		clientConfig.AlwaysIncludePSK = true
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, http2ConnectTLSHandshakeTimeout)
	defer cancel()
	connection := utls.UClient(raw, clientConfig, utls.HelloChrome_133)
	if err := connection.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	state := connection.ConnectionState()
	physical.record(resumptionExperimentPort(raw.LocalAddr()), state.DidResume, len(state.VerifiedChains) != 0, false, state.Version, time.Since(started), func() { _ = raw.Close() })
	return &http2UTLSConn{UConn: connection, rawConnection: raw}, nil
}

// A new manager and transport are constructed for EVERY sample. Only the
// explicitly supplied ticket cache survives; pooling cannot masquerade as TLS
// resumption. Both managers continue to use Moto's actual CONNECT code.
func resumptionExperimentDial(ctx context.Context, protocol string, target *config.Target, destination string, roots *x509.CertPool, cache *resumptionExperimentCache, physical *resumptionExperimentPhysical) (net.Conn, func(), error) {
	if protocol == config.ConnectProxyH2 {
		manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
			transport := newHTTP2ConnectTransport(key)
			transport.TLSClientConfig.RootCAs = roots
			transport.DialTLSContext = func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
				return resumptionExperimentH2Dial(ctx, network, address, config, cache, physical)
			}
			return transport
		})
		connection, err := manager.dial(ctx, target, destination)
		return connection, func() { physical.close(); manager.closeIdle() }, err
	}
	manager := newHTTP3ConnectManagerWithLogger(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		if cache != nil {
			transport.QUICConfig.ChromeParrotSessionCache = cache
		}
		original := transport.Dial
		transport.Dial = func(ctx context.Context, address string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			started := time.Now()
			connection, err := original(ctx, address, config, quicConfig)
			if err == nil {
				state := connection.ConnectionState()
				physical.record(resumptionExperimentPort(connection.LocalAddr()), state.TLS.DidResume, len(state.TLS.VerifiedChains) != 0, state.Used0RTT, state.TLS.Version, time.Since(started), func() { _ = connection.CloseWithError(0, "experiment sample complete") })
			}
			return connection, err
		}
		return transport
	}, zap.NewNop())
	connection, err := manager.dial(ctx, target, destination)
	return connection, func() { physical.close(); manager.close() }, err
}

func resumptionExperimentAttempt(target *config.Target, protocol string, roots *x509.CertPool, cache *resumptionExperimentCache, real bool) resumptionExperimentSample {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	destination := "resumption-experiment.invalid:443"
	if real {
		destination = "example.com:443"
	}
	var hitsBefore, putsBefore int64
	if cache != nil {
		hitsBefore, putsBefore = cache.hits.Load(), cache.puts.Load()
	}
	physical := &resumptionExperimentPhysical{}
	tunnel, closeManager, err := resumptionExperimentDial(ctx, protocol, target, destination, roots, cache, physical)
	defer closeManager()
	sample := physical.snapshot()
	sample.ConnectMS = float64(time.Since(started)) / float64(time.Millisecond)
	if err != nil {
		sample.ErrorClass = connectProxyAttemptOutcome(err)
	} else {
		stop := context.AfterFunc(ctx, func() { _ = tunnel.Close() })
		defer stop()
		defer tunnel.Close()
		if real {
			sample.PayloadBytes, err = resumptionExperimentHTTPS(ctx, tunnel)
		} else {
			err = resumptionExperimentEcho(tunnel)
			if err == nil {
				sample.PayloadBytes = len(resumptionExperimentPayload)
			}
		}
		if err != nil {
			sample.ErrorClass = "payload_failed"
		}
		if cache != nil && cache.puts.Load() == putsBefore {
			// Tickets are post-handshake messages. Allow a bounded, traffic-free
			// observation window before closing the physical connection.
			timer := time.NewTimer(500 * time.Millisecond)
			for cache.puts.Load() == putsBefore {
				select {
				case <-cache.noticed:
				case <-timer.C:
					goto ticketWaitDone
				case <-ctx.Done():
					goto ticketWaitDone
				}
			}
		ticketWaitDone:
			timer.Stop()
		}
	}
	if cache != nil {
		sample.TicketStored = cache.puts.Load() > putsBefore
		sample.CacheHit = cache.hits.Load() > hitsBefore
		if protocol == config.ConnectProxyH3 && cache.early.Load() {
			sample.ErrorClass = "early_data_ticket"
		}
	}
	sample.ConnectionReused = sample.PhysicalDials == 0 && err == nil
	if sample.ErrorClass == "" && (sample.PhysicalDials != 1 || !sample.CertificateChecked || sample.Used0RTT) {
		sample.ErrorClass = "physical_handshake_evidence_invalid"
	}
	sample.TotalMS = float64(time.Since(started)) / float64(time.Millisecond)
	return sample
}

func resumptionExperimentEcho(tunnel net.Conn) error {
	if _, err := io.WriteString(tunnel, resumptionExperimentPayload); err != nil {
		return err
	}
	if err := closeWrite(tunnel); err != nil {
		return err
	}
	payload, err := io.ReadAll(io.LimitReader(tunnel, int64(len(resumptionExperimentPayload)+1)))
	if err != nil || string(payload) != resumptionExperimentPayload {
		return errors.New("controlled_payload_mismatch")
	}
	return nil
}

func resumptionExperimentHTTPS(ctx context.Context, tunnel net.Conn) (int, error) {
	inner := tls.Client(tunnel, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := inner.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	request.Close = true
	if err := request.Write(inner); err != nil {
		return 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(inner), request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || response.StatusCode != http.StatusOK || len(body) == 0 || len(body) > 16<<10 {
		return len(body), errors.New("verified_https_response_invalid")
	}
	return len(body), nil
}

type resumptionExperimentServerObservation struct {
	id      int64
	port    int
	resumed bool
	hrr     bool
}

type resumptionExperimentServerContextKey struct{}

func resumptionExperimentServer(t *testing.T, protocol string, hrr bool) (*config.Target, *x509.CertPool, *atomic.Bool, <-chan resumptionExperimentServerObservation) {
	t.Helper()
	certificate, parsed := browserH2SuccessCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var reject atomic.Bool
	var connections atomic.Int64
	observed := make(chan resumptionExperimentServerObservation, 32)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}
	if hrr {
		serverTLS.CurvePreferences = []tls.CurveID{tls.CurveP256}
	} else {
		serverTLS.CurvePreferences = []tls.CurveID{tls.X25519}
	}
	var ticketKey [32]byte
	if _, err := rand.Read(ticketKey[:]); err != nil {
		t.Fatal(err)
	}
	serverTLS.SetSessionTicketKeys([][32]byte{ticketKey})
	serverTLS.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
		if reject.Load() {
			return nil, nil // Explicit refusal must perform a full verified handshake.
		}
		return serverTLS.DecryptTicket(identity, state)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("experiment:local-only"))
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "resumption-experiment.invalid:443" || request.Header.Get("Proxy-Authorization") != wantAuth || request.Header.Get("User-Agent") != connectProxyChromeUserAgent {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		_, rawPort, _ := net.SplitHostPort(request.RemoteAddr)
		port, _ := strconv.Atoi(rawPort)
		id, _ := request.Context().Value(resumptionExperimentServerContextKey{}).(int64)
		observed <- resumptionExperimentServerObservation{id: id, port: port, resumed: request.TLS.DidResume, hrr: request.TLS.HelloRetryRequest}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		body, err := io.ReadAll(io.LimitReader(request.Body, int64(len(resumptionExperimentPayload)+1)))
		if err == nil && bytes.Equal(body, []byte(resumptionExperimentPayload)) {
			_, _ = writer.Write(body)
			writer.(http.Flusher).Flush()
		}
	})
	var endpoint string
	if protocol == config.ConnectProxyH2 {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.TLS = serverTLS
		server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, resumptionExperimentServerContextKey{}, connections.Add(1))
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		endpoint = server.Listener.Addr().String()
	} else {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http3.Server{TLSConfig: serverTLS, Handler: handler, QUICConfig: &quic.Config{Allow0RTT: false}, ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			return context.WithValue(ctx, resumptionExperimentServerContextKey{}, connections.Add(1))
		}}
		done := make(chan error, 1)
		go func() { done <- server.Serve(packet) }()
		t.Cleanup(func() {
			_ = server.Close()
			_ = packet.Close()
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
					t.Error("local_h3_server_shutdown_failed")
				}
			case <-time.After(time.Second):
				t.Error("local_h3_server_shutdown_timeout")
			}
		})
		endpoint = packet.LocalAddr().String()
	}
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{ServerName: browserH2SuccessProxyHost, Protocols: []string{protocol}, BasicAuth: &config.BasicAuthConfig{Username: "experiment", Password: "local-only"}}}
	return target, roots, &reject, observed
}

func resumptionExperimentLog(t *testing.T, sample resumptionExperimentSample) {
	t.Helper()
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatal("experiment_result_encode_failed")
	}
	t.Logf("MOTO_RESUMPTION_SAMPLE %s", encoded)
}

func resumptionExperimentEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("MOTO_RESUMPTION_EXPERIMENT") != "1" {
		t.Skip("set MOTO_RESUMPTION_EXPERIMENT=1 for this test-only experiment")
	}
}

func TestConnectProxyResumptionExperimentLocal(t *testing.T) {
	resumptionExperimentEnabled(t)
	for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
		for _, hrr := range []bool{false, true} {
			for _, refuse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/HRR=%t/reject=%t", protocol, hrr, refuse), func(t *testing.T) {
					target, roots, reject, observed := resumptionExperimentServer(t, protocol, hrr)
					cache := newResumptionExperimentCache()
					lastConnection := int64(0)
					for _, phase := range []string{"seed", "cold", "warm", "warm", "cold"} {
						var activeCache *resumptionExperimentCache
						if phase != "cold" {
							activeCache = cache
						}
						sample := resumptionExperimentAttempt(target, protocol, roots, activeCache, false)
						sample.Protocol, sample.Phase = protocol, phase
						if sample.ErrorClass != "" {
							resumptionExperimentLog(t, sample)
							t.Fatal("controlled_CONNECT_failed")
						}
						select {
						case server := <-observed:
							sample.ServerDidResume, sample.ServerHRR = &server.resumed, &server.hrr
							sample.ServerObservedPort, sample.ServerConnectionID = server.port, server.id
							if server.id <= lastConnection || server.port != sample.ClientLocalPort || server.resumed != sample.DidResume || server.hrr != hrr {
								t.Fatal("client_server_handshake_evidence_mismatch")
							}
							lastConnection = server.id
						default:
							t.Fatal("missing_server_handshake_evidence")
						}
						resumptionExperimentLog(t, sample)
						wantResume := phase == "warm" && !refuse
						if sample.DidResume != wantResume || (phase == "warm" && !sample.CacheHit) || (phase == "seed" && !sample.TicketStored) || sample.TLSVersion != tls.VersionTLS13 {
							t.Fatal("unexpected_resumption_result")
						}
						if phase == "seed" {
							reject.Store(refuse)
						}
					}
				})
			}
		}
	}
}

func TestConnectProxyResumptionExperimentReal(t *testing.T) {
	resumptionExperimentEnabled(t)
	path := os.Getenv("MOTO_RESUMPTION_REAL_CONFIG")
	if path == "" {
		t.Skip("set MOTO_RESUMPTION_REAL_CONFIG explicitly to read a private config")
	}
	// The H2 package latches these substring matches during init. Check both
	// the environment and its latched flag before reading private configuration
	// or creating a connection: verbose frame/header logs can expose credentials.
	debug := os.Getenv("GODEBUG")
	if xhttp2.VerboseLogs || strings.Contains(debug, "http2debug=1") || strings.Contains(debug, "http2debug=2") {
		t.Fatal("http2_debug_must_be_disabled_for_private_experiment")
	}
	settings, err := config.Load(path)
	if err != nil {
		t.Fatal("private_config_invalid")
	}
	rounds := 3
	if text := os.Getenv("MOTO_RESUMPTION_ROUNDS"); text != "" {
		rounds, err = strconv.Atoi(text)
		if err != nil || rounds < 2 || rounds > 5 {
			t.Fatal("rounds_must_be_between_2_and_5")
		}
	}
	var targets []*config.Target
	seen := make(map[http3ConnectTransportKey]bool)
	for _, rule := range settings.Rules {
		if !config.IsConnectProtocol(rule.Protocol) {
			continue
		}
		for _, target := range rule.Targets {
			if target == nil || target.ConnectProxy == nil {
				continue
			}
			key := http3ConnectKey(target)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, target)
			}
		}
	}
	indices := []int{}
	if selection := os.Getenv("MOTO_RESUMPTION_TARGETS"); selection != "" {
		for _, raw := range strings.Split(selection, ",") {
			index, err := strconv.Atoi(strings.TrimSpace(raw))
			if err != nil || index < 0 || index >= len(targets) || slices.Contains(indices, index) {
				t.Fatal("invalid_target_selection")
			}
			indices = append(indices, index)
		}
	} else {
		for index := range min(len(targets), 4) {
			indices = append(indices, index)
		}
	}
	if len(indices) == 0 || len(indices) > 4 {
		t.Fatal("select_between_1_and_4_targets")
	}
	for _, index := range indices {
		for _, protocol := range []string{config.ConnectProxyH2, config.ConnectProxyH3} {
			if !slices.Contains(targets[index].ConnectProxy.Protocols, protocol) {
				continue
			}
			t.Run(fmt.Sprintf("target_%d/%s", index, protocol), func(t *testing.T) {
				cache := newResumptionExperimentCache()
				seed := resumptionExperimentAttempt(targets[index], protocol, nil, cache, true)
				seed.Target, seed.Protocol, seed.Phase = index, protocol, "seed"
				resumptionExperimentLog(t, seed)
				if seed.ErrorClass != "" {
					t.Error("seed_failed_details_redacted")
					return
				}
				for round := 0; round < rounds; round++ {
					phases := []string{"cold", "warm"}
					if round%2 != 0 {
						slices.Reverse(phases)
					}
					for _, phase := range phases {
						var activeCache *resumptionExperimentCache
						if phase == "warm" {
							activeCache = cache
						}
						sample := resumptionExperimentAttempt(targets[index], protocol, nil, activeCache, true)
						sample.Target, sample.Protocol, sample.Phase, sample.Round = index, protocol, phase, round+1
						resumptionExperimentLog(t, sample)
						if sample.ErrorClass != "" {
							t.Error("sample_failed_details_redacted")
							return
						}
					}
				}
			})
		}
	}
}

// Run the real entry point in a fresh process so the H2 init-time debug flag is
// exercised. A nonexistent config proves rejection happens before config I/O;
// no private file or network service is needed for this regression.
func TestConnectProxyResumptionExperimentRejectsHTTP2Debug(t *testing.T) {
	for _, debug := range []string{"http2debug=1", "http2debug=2", "http2debug=1,http2debug=0"} {
		t.Run(debug, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConnectProxyResumptionExperimentReal$", "-test.v")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "GODEBUG=") && !strings.HasPrefix(value, "MOTO_RESUMPTION_") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "GODEBUG="+debug, "MOTO_RESUMPTION_EXPERIMENT=1", "MOTO_RESUMPTION_REAL_CONFIG="+t.TempDir()+"/nonexistent-private-config.json")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil || err == nil || !bytes.Contains(output, []byte("http2_debug_must_be_disabled_for_private_experiment")) || bytes.Contains(output, []byte("private_config_invalid")) || bytes.Contains(output, []byte("MOTO_RESUMPTION_SAMPLE")) {
				t.Fatal("http2_debug_guard_did_not_reject_before_config_or_network")
			}
		})
	}
}
