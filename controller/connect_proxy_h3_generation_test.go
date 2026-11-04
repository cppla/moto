package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

type http3GenerationServerConnectionKey struct{}

type http3GenerationFixture struct {
	*http3OwnershipFixture
	oldServer         chan *quic.Conn
	candidateStarted  chan struct{}
	releaseCandidate  func()
	candidateRequests atomic.Int64
}

// All traffic stays on loopback. The server can close only the old physical
// connection and hold a replacement's CONNECT response while another request
// causes the serving transport to establish a newer physical generation.
func newHTTP3GenerationFixture(t *testing.T, candidateFails bool) *http3GenerationFixture {
	t.Helper()
	fixture := &http3GenerationFixture{
		oldServer:        make(chan *quic.Conn, 1),
		candidateStarted: make(chan struct{}),
	}
	candidateReady := make(chan struct{})
	var releaseOnce, startedOnce sync.Once
	fixture.releaseCandidate = func() { releaseOnce.Do(func() { close(candidateReady) }) }
	t.Cleanup(fixture.releaseCandidate)
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certificateSource.Certificate())
	certificateSource.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		ConnContext: func(ctx context.Context, connection *quic.Conn) context.Context {
			return context.WithValue(ctx, http3GenerationServerConnectionKey{}, connection)
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Host == "old.example:443" {
				fixture.oldServer <- request.Context().Value(http3GenerationServerConnectionKey{}).(*quic.Conn)
			}
			if request.Host == "candidate.example:443" {
				fixture.candidateRequests.Add(1)
				startedOnce.Do(func() { close(fixture.candidateStarted) })
				select {
				case <-candidateReady:
				case <-request.Context().Done():
					return
				}
				if candidateFails {
					panic(http.ErrAbortHandler)
				}
			}
			echoHTTP3OwnershipTunnel(writer, request)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(packet) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = packet.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("close generation fixture: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("generation fixture did not stop")
		}
	})
	fixture.http3OwnershipFixture = &http3OwnershipFixture{
		target: &config.Target{Address: packet.LocalAddr().String(), ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}},
		key:    http3ConnectTransportKey{address: packet.LocalAddr().String()},
	}
	fixture.manager = newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		originalDial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			connection, err := originalDial(ctx, address, tlsConfig, quicConfig)
			if err == nil {
				fixture.mu.Lock()
				fixture.conns = append(fixture.conns, connection)
				fixture.mu.Unlock()
			}
			return connection, err
		}
		return transport
	})
	t.Cleanup(fixture.manager.close)
	return fixture
}

type http3GenerationCandidateResult struct {
	connection net.Conn
	err        error
}

func (fixture *http3GenerationFixture) startCandidate(t *testing.T) <-chan http3GenerationCandidateResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	result := make(chan http3GenerationCandidateResult, 1)
	go func() {
		connection, err := fixture.manager.dial(ctx, fixture.target, "candidate.example:443")
		result <- http3GenerationCandidateResult{connection, err}
	}()
	select {
	case <-fixture.candidateStarted:
	case <-ctx.Done():
		t.Fatal("candidate did not start CONNECT")
	}
	return result
}

func readHTTP3GenerationCandidate(t *testing.T, result <-chan http3GenerationCandidateResult) http3GenerationCandidateResult {
	t.Helper()
	select {
	case value := <-result:
		if value.connection != nil {
			t.Cleanup(func() { _ = value.connection.Close() })
		}
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("candidate did not finish CONNECT")
		return http3GenerationCandidateResult{}
	}
}

func waitHTTP3GenerationCandidate(t *testing.T, fixture *http3GenerationFixture, source *http3ConnectTransportSlot) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		fixture.manager.mu.Lock()
		ready := source.replacement != nil && source.health == http3TransportDegraded
		fixture.manager.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("remote close did not create a rotation candidate")
		}
		time.Sleep(time.Millisecond)
	}
}

// The default fast cases explicitly inject an aged idle-progress timestamp;
// the opt-in natural case below reaches that same state using wall-clock time.
// Both use the real server, physical reconnect, allocator and CONNECT path.
func runHTTP3GenerationLateCandidate(t *testing.T, candidateFails bool, idle time.Duration, ageProgress bool, freshPayload bool) {
	t.Helper()
	fixture := newHTTP3GenerationFixture(t, candidateFails)
	oldTunnel := fixture.dial(t, "old.example:443")
	oldPhysical := fixture.physicalConnections()[0]
	var oldServer *quic.Conn
	select {
	case oldServer = <-fixture.oldServer:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe old CONNECT")
	}
	fixture.manager.mu.Lock()
	source := fixture.manager.transports[fixture.key][0]
	oldGeneration := source.generationID
	if ageProgress {
		source.lastPayloadProgress.Store(time.Now().Add(-time.Minute).UnixNano())
		source.lastSampledPayload = saturatingAdd(source.payloadRead.Load(), source.payloadWritten.Load())
	}
	fixture.manager.mu.Unlock()
	if idle > 0 {
		t.Logf("waiting %s naturally; production drain threshold=%s", idle, http3ForcedDrainStallTimeout)
		timer := time.NewTimer(idle)
		select {
		case <-timer.C:
		case <-oldPhysical.Context().Done():
			timer.Stop()
			t.Fatalf("old connection ended before remote close: %v", context.Cause(oldPhysical.Context()))
		}
		if elapsed := time.Since(time.Unix(0, source.lastPayloadProgress.Load())); elapsed < http3ForcedDrainStallTimeout {
			t.Fatalf("natural idle did not reach old-progress state: %s", elapsed)
		}
	}
	if err := oldServer.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "old connection ended by test server"); err != nil {
		t.Fatal(err)
	}
	waitHTTP3PhysicalClosed(t, oldPhysical)
	var remoteClose *quic.ApplicationError
	if !errors.As(context.Cause(oldPhysical.Context()), &remoteClose) || !remoteClose.Remote {
		t.Fatalf("old close was not remote: %v", context.Cause(oldPhysical.Context()))
	}
	waitHTTP3GenerationCandidate(t, fixture, source)
	fixture.manager.mu.Lock()
	candidateSlot := source.replacement
	fixture.manager.mu.Unlock()
	_ = oldTunnel.Close()
	candidateResult := fixture.startCandidate(t)
	fresh := fixture.dial(t, "fresh.example:443")
	watchdog := time.AfterFunc(4*time.Second, func() { _ = fresh.Close() })
	defer watchdog.Stop()
	fixture.manager.mu.Lock()
	freshPhysical := source.connection
	freshGeneration := source.generationID
	freshAt := source.closeObservation.establishedAt
	candidatePhysical := candidateSlot.connection.(*quic.Conn)
	var recovered atomic.Int64
	fixture.manager.onRecovered = func(http3ConnectTransportKey) { recovered.Add(1) }
	fixture.manager.mu.Unlock()
	if freshGeneration == oldGeneration || freshPhysical.Context().Err() != nil {
		t.Fatal("normal pool admission did not establish a live fresh generation")
	}
	if freshPayload {
		assertConnectTunnelEcho(t, fresh, "fresh-payload-before-late-candidate")
	}
	fixture.releaseCandidate()
	result := readHTTP3GenerationCandidate(t, candidateResult)
	if candidateFails {
		if result.err == nil || result.connection != nil {
			t.Fatal("reset candidate unexpectedly succeeded")
		}
		if got := fixture.candidateRequests.Load(); got != 1 {
			t.Errorf("stale candidate request retried on new source generation: requests=%d, want 1", got)
		}
	} else {
		if result.err != nil || result.connection == nil {
			t.Fatalf("late candidate CONNECT failed: %v", result.err)
		}
		assertConnectTunnelEcho(t, result.connection, "candidate-remains-usable")
	}
	if cause := context.Cause(freshPhysical.Context()); cause != nil {
		t.Fatalf("fresh generation closed at age %s after old candidate completed: %v", time.Since(freshAt), cause)
	}
	fixture.manager.mu.Lock()
	lifecycle, healthy := source.lifecycle, source.health
	failures, retryAt, armed := source.rotationFailures, source.retryAt, source.forcedDrainArmed
	fixture.manager.mu.Unlock()
	if lifecycle != http3TransportServing || healthy != http3TransportHealthy || failures != 0 || !retryAt.IsZero() || armed {
		t.Fatalf("old candidate modified fresh source: lifecycle=%s health=%s failures=%d retryAt=%s forcedDrain=%v", lifecycle, healthy, failures, retryAt, armed)
	}
	if recovered.Load() != 0 {
		t.Fatal("old candidate published recovery for the new source generation")
	}
	assertConnectTunnelEcho(t, fresh, "fresh-generation-survives-old-candidate")
	if result.connection != nil {
		_ = result.connection.Close()
	}
	waitHTTP3PhysicalClosed(t, candidatePhysical)
	fixture.manager.mu.Lock()
	candidateRetained := fixture.manager.containsSlotLocked(fixture.key, candidateSlot)
	fixture.manager.mu.Unlock()
	if candidateRetained {
		t.Fatal("completed stale candidate remained in the connection pool")
	}
	assertConnectTunnelEcho(t, fresh, "fresh-generation-survives-candidate-retirement")
	if err := fixture.manager.validateHTTP3RotationState(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3GenerationLateCandidatePromotionPreservesReconnectedSource(t *testing.T) {
	runHTTP3GenerationLateCandidate(t, false, 0, true, false)
}

func TestHTTP3GenerationLateCandidateFailurePreservesReconnectedSource(t *testing.T) {
	runHTTP3GenerationLateCandidate(t, true, 0, true, false)
}

func TestHTTP3GenerationSameSourcePromotionStillDrains(t *testing.T) {
	fixture := newHTTP3GenerationFixture(t, false)
	oldTunnel := fixture.dial(t, "old.example:443")
	oldPhysical := fixture.physicalConnections()[0]
	fixture.manager.mu.Lock()
	source := fixture.manager.transports[fixture.key][0]
	oldGeneration := source.generationID
	// Inject the degradation decision, not a connection replacement. This pins
	// ordinary same-generation promotion and graceful ownership semantics.
	source.health = http3TransportDegraded
	source.rotationReason = http3DegradationReasonSustainedSignals
	_, err := fixture.manager.ensureHTTP3RotationCandidateLocked(fixture.key, source, time.Now())
	fixture.manager.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	resultChannel := fixture.startCandidate(t)
	fixture.releaseCandidate()
	result := readHTTP3GenerationCandidate(t, resultChannel)
	if result.err != nil || result.connection == nil {
		t.Fatalf("same-generation candidate: %v", result.err)
	}
	fixture.manager.mu.Lock()
	unchanged := source.generationID == oldGeneration
	draining := source.lifecycle == http3TransportDraining
	fixture.manager.mu.Unlock()
	if !unchanged || !draining || oldPhysical.Context().Err() != nil {
		t.Fatal("same-generation source did not remain alive for graceful drain")
	}
	watchdog := time.AfterFunc(3*time.Second, func() { _ = oldTunnel.Close(); _ = result.connection.Close() })
	defer watchdog.Stop()
	assertConnectTunnelEcho(t, oldTunnel, "old-stream-continues-draining")
	assertConnectTunnelEcho(t, result.connection, "new-candidate-serves")
	_ = oldTunnel.Close()
	waitHTTP3PhysicalClosed(t, oldPhysical)
	assertConnectTunnelEcho(t, result.connection, "candidate-survives-old-drain")
}

func TestHTTP3GenerationRetryTicketRejectsReconnectedSource(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSource()
	now := time.Now()
	connection := attachHTTP3TestConnection(t, manager, key, source, now)
	degradeHTTP3TestSlot(t, manager, key, source, connection, now.Add(time.Minute))
	_, candidate, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatal(err)
	}
	retry, accepted := manager.markHTTP3CandidateFailed(key, candidate, errors.New("candidate stream reset"))
	if !accepted || retry == nil || retry.slot != source {
		t.Fatalf("candidate failure did not yield its own source ticket: retry=%+v accepted=%v", retry, accepted)
	}
	releaseCandidate()
	manager.mu.Lock()
	if retry.connectionID != source.connectionID {
		manager.mu.Unlock()
		t.Fatal("retry ticket did not capture the failed candidate's source generation")
	}
	// Exercise the interval between creating a retry ticket and reserving it.
	// All other eligibility checks still pass: only physical generation changes.
	source.connectionID++
	activeBefore := source.active
	manager.mu.Unlock()
	if _, _, _, err := manager.acquireHTTP3CandidateRetrySource(key, retry); !errors.Is(err, errHTTP3CandidateRetrySourceUnavailable) {
		t.Fatalf("retry crossed physical generations: %v", err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if source.active != activeBefore || len(manager.transports[key]) != 1 || manager.transports[key][0] != source {
		t.Fatal("rejected retry reserved or allocated another transport")
	}
}

func TestHTTP3GenerationCandidateCreationBindsSource(t *testing.T) {
	for _, entry := range []string{"rotation", "rule_probation"} {
		for _, outcome := range []string{"promotion", "failure"} {
			t.Run(entry+"/"+outcome, func(t *testing.T) {
				manager := newHTTP3RotationTestManager(t)
				key := http3ConnectTransportKey{address: "proxy.example:443"}
				_, source, releaseSource, err := manager.acquireTransport(key)
				if err != nil {
					t.Fatal(err)
				}
				defer releaseSource()
				now := time.Now()
				attachHTTP3TestConnection(t, manager, key, source, now)
				var candidate *http3ConnectTransportSlot
				var releaseCandidate func()
				if entry == "rotation" {
					manager.mu.Lock()
					_, err = manager.ensureHTTP3RotationCandidateLocked(key, source, now)
					manager.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
					_, candidate, releaseCandidate, err = manager.acquireTransport(key)
				} else {
					_, candidate, releaseCandidate, err = manager.acquireHTTP3RuleProbationTransport(key)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer releaseCandidate()
				var recovered atomic.Int64
				manager.mu.Lock()
				if candidate.replaces != source || candidate.replacesConnID != source.connectionID {
					manager.mu.Unlock()
					t.Fatal("candidate creation omitted its physical source generation")
				}
				// Retain the old link deliberately to test the completion-time guard
				// independently of observeHTTP3PhysicalDial's eager detachment.
				source.connectionID++
				manager.onRecovered = func(http3ConnectTransportKey) { recovered.Add(1) }
				manager.mu.Unlock()
				if outcome == "promotion" {
					manager.promoteHTTP3Candidate(key, candidate)
				} else if retry, _ := manager.markHTTP3CandidateFailed(key, candidate, errors.New("old candidate failed")); retry != nil {
					t.Fatal("stale failure returned a retry ticket for the new source generation")
				}
				manager.mu.Lock()
				defer manager.mu.Unlock()
				if source.lifecycle != http3TransportServing || source.rotationFailures != 0 || !source.retryAt.IsZero() || source.forcedDrainArmed || recovered.Load() != 0 {
					t.Fatalf("old candidate changed its new source generation: lifecycle=%s failures=%d retryAt=%s armed=%v recovery=%d", source.lifecycle, source.rotationFailures, source.retryAt, source.forcedDrainArmed, recovered.Load())
				}
			})
		}
	}
}

func TestHTTP3GenerationNaturalIdleIsolation(t *testing.T) {
	if os.Getenv("MOTO_H3_GENERATION_NATURAL") != "1" {
		t.Skip("set MOTO_H3_GENERATION_NATURAL=1 for the 32-second real-idle regression")
	}
	for _, test := range []struct {
		name         string
		idle         time.Duration
		freshPayload bool
	}{
		{"recent_progress_control", 0, false},
		{"fresh_payload_control", 32 * time.Second, true},
		{"natural_idle_1", 32 * time.Second, false},
		{"natural_idle_2", 32 * time.Second, false},
		{"natural_idle_3", 32 * time.Second, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runHTTP3GenerationLateCandidate(t, false, test.idle, false, test.freshPayload)
		})
	}
}
