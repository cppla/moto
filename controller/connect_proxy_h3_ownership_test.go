package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"moto/config"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type http3OwnershipFixture struct {
	manager *http3ConnectManager
	target  *config.Target
	key     http3ConnectTransportKey
	mu      sync.Mutex
	conns   []*quic.Conn
}

func newHTTP3OwnershipFixture(t *testing.T, handler http.Handler, afterDial func(*quic.Conn)) *http3OwnershipFixture {
	t.Helper()
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	t.Cleanup(closeServer)
	fixture := &http3OwnershipFixture{
		target: &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}},
		key:    http3ConnectTransportKey{address: endpoint},
	}
	fixture.manager = newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		originalDial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			connection, err := originalDial(ctx, address, tlsConfig, quicConfig)
			if connection != nil && err == nil {
				fixture.mu.Lock()
				fixture.conns = append(fixture.conns, connection)
				fixture.mu.Unlock()
				if afterDial != nil {
					afterDial(connection)
				}
			}
			return connection, err
		}
		return transport
	})
	t.Cleanup(func() {
		fixture.manager.close()
		// Also clean up a regression's orphaned connections, so a failing test
		// never leaves keepalive sockets behind for other tests.
		for _, connection := range fixture.physicalConnections() {
			_ = connection.CloseWithError(0, "test cleanup")
		}
	})
	return fixture
}

func (fixture *http3OwnershipFixture) physicalConnections() []*quic.Conn {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return append([]*quic.Conn(nil), fixture.conns...)
}

func (fixture *http3OwnershipFixture) dial(t *testing.T, destination string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := fixture.manager.dial(ctx, fixture.target, destination)
	if err != nil {
		t.Fatalf("dial %s: %v", destination, err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func waitHTTP3PhysicalClosed(t *testing.T, connection *quic.Conn) {
	t.Helper()
	select {
	case <-connection.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("physical QUIC connection was not reclaimed")
	}
}

func echoHTTP3OwnershipTunnel(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	buffer := make([]byte, 4096)
	for {
		read, err := request.Body.Read(buffer)
		if read > 0 {
			_, _ = writer.Write(buffer[:read])
			writer.(http.Flusher).Flush()
		}
		if err != nil {
			return
		}
	}
}

func TestHTTP3StreamResetClosesOrphanedPhysicalConnections(t *testing.T) {
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler) // Reset only this stream; QUIC stays connected.
	}), nil)
	fixture.manager.maxTransportsPerKey = 1
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		connection, err := fixture.manager.dial(ctx, fixture.target, "reset.example:443")
		cancel()
		if connection != nil || err == nil {
			t.Fatalf("reset CONNECT = (%v, %v), want failure", connection, err)
		}
		physical := fixture.physicalConnections()
		if len(physical) != attempt+1 {
			t.Fatalf("physical dials = %d, want %d", len(physical), attempt+1)
		}
		waitHTTP3PhysicalClosed(t, physical[attempt])
		fixture.manager.mu.Lock()
		slots := len(fixture.manager.transports[fixture.key])
		fixture.manager.mu.Unlock()
		if slots != 0 {
			t.Fatalf("idle errored slots = %d, want zero", slots)
		}
	}
	fixture.manager.close()
	for _, connection := range fixture.physicalConnections() {
		waitHTTP3PhysicalClosed(t, connection)
	}
}

func TestHTTP3StreamResetPreservesActiveSibling(t *testing.T) {
	for _, retire := range []bool{false, true} {
		name := "new_pool_connection"
		if retire {
			name = "routing_generation_retire"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Host == "reset.example:443" {
					panic(http.ErrAbortHandler)
				}
				echoHTTP3OwnershipTunnel(writer, request)
			}), nil)
			fixture.manager.maxTransportsPerKey = 2
			first := fixture.dial(t, "first.example:443")
			oldPhysical := fixture.physicalConnections()[0]
			assertConnectTunnelEcho(t, first, "before-reset")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := fixture.manager.dial(ctx, fixture.target, "reset.example:443")
			cancel()
			if err == nil {
				t.Fatal("expected peer stream reset")
			}
			fixture.manager.mu.Lock()
			oldSlot := fixture.manager.transports[fixture.key][0]
			state, active := oldSlot.lifecycle, oldSlot.active
			fixture.manager.mu.Unlock()
			if state != http3TransportDraining || active != 1 || oldPhysical.Context().Err() != nil {
				t.Fatalf("sibling was not preserved: state=%s active=%d closed=%v", state, active, oldPhysical.Context().Err())
			}
			if retire {
				fixture.manager.retire()
			}
			assertConnectTunnelEcho(t, first, "after-reset-or-retire")
			if !retire {
				second := fixture.dial(t, "second.example:443")
				assertConnectTunnelEcho(t, second, "new-slot")
				assertConnectTunnelEcho(t, first, "old-still-usable")
				if len(fixture.physicalConnections()) != 2 {
					t.Fatal("new CONNECT reused an errored slot instead of a fresh pool slot")
				}
			}
			_ = first.Close()
			waitHTTP3PhysicalClosed(t, oldPhysical)
			oldSlot.physicalMu.Lock()
			owned := len(oldSlot.physicalConns)
			oldSlot.physicalMu.Unlock()
			if owned != 0 {
				t.Fatalf("drained slot still owns %d physical connections", owned)
			}
		})
	}
}

func TestHTTP3PhysicalDialCompletingDuringCloseIsClosed(t *testing.T) {
	dialReturned := make(chan *quic.Conn, 1)
	releaseDial := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDial) }) }
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(echoHTTP3OwnershipTunnel), func(connection *quic.Conn) {
		dialReturned <- connection
		<-releaseDial
	})
	t.Cleanup(release)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connection, err := fixture.manager.dial(ctx, fixture.target, "late.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		result <- err
	}()
	var physical *quic.Conn
	select {
	case physical = <-dialReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("physical handshake did not finish")
	}
	fixture.manager.mu.Lock()
	slot := fixture.manager.transports[fixture.key][0]
	fixture.manager.mu.Unlock()
	closed := make(chan struct{})
	go func() { fixture.manager.close(); close(closed) }()
	deadline := time.Now().Add(2 * time.Second)
	for !slot.closeRequested.Load() {
		if time.Now().After(deadline) {
			t.Fatal("slot shutdown did not start")
		}
		time.Sleep(time.Millisecond)
	}
	release()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("manager close deadlocked with late physical Dial")
	}
	waitHTTP3PhysicalClosed(t, physical)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("late CONNECT unexpectedly succeeded after shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late CONNECT did not finish")
	}
}

func TestHTTP3IdleSlotClosesAllOwnedPhysicalConnections(t *testing.T) {
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(echoHTTP3OwnershipTunnel), nil)
	fixture.manager.maxTransportsPerKey = 1
	tunnel := fixture.dial(t, "active.example:443")
	first := fixture.physicalConnections()[0]
	fixture.manager.mu.Lock()
	slot := fixture.manager.transports[fixture.key][0]
	fixture.manager.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Exercise the exact instrumented Dial used by an already-admitted
	// RoundTrip's internal redial, without depending on quic-go retry timing.
	tlsConfig := slot.transport.TLSClientConfig.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	second, err := slot.transport.Dial(ctx, fixture.target.Address, tlsConfig, slot.transport.QUICConfig)
	if err != nil {
		t.Fatalf("second physical Dial: %v", err)
	}
	if !slot.hasMultiplePhysicalConnections() {
		t.Fatal("slot did not retain ownership of both live physical connections")
	}
	assertConnectTunnelEcho(t, tunnel, "old-physical-still-serving")
	_ = tunnel.Close()
	waitHTTP3PhysicalClosed(t, first)
	waitHTTP3PhysicalClosed(t, second)
	fixture.manager.mu.Lock()
	remaining := len(fixture.manager.transports[fixture.key])
	fixture.manager.mu.Unlock()
	if remaining != 0 {
		t.Fatal("multi-physical idle slot remained warm after its final user left")
	}
}

func TestHTTP3RemovedSlotRejectsLatePhysicalDial(t *testing.T) {
	ready := make(chan *quic.Conn, 1)
	releaseDial := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDial) }) }
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(echoHTTP3OwnershipTunnel), func(connection *quic.Conn) {
		ready <- connection
		<-releaseDial
	})
	t.Cleanup(release)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connection, err := fixture.manager.dial(ctx, fixture.target, "removed.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		result <- err
	}()
	var physical *quic.Conn
	select {
	case physical = <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("physical handshake did not finish")
	}
	fixture.manager.mu.Lock()
	slot := fixture.manager.transports[fixture.key][0]
	fixture.manager.removeSlotLocked(fixture.key, slot)
	fixture.manager.mu.Unlock()
	t.Cleanup(func() { release(); slot.close() })
	// Force the small interval between removing pool membership and calling
	// slot.close, so even this late Dial cannot escape ownership checks.
	release()
	waitHTTP3PhysicalClosed(t, physical)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("CONNECT on a removed slot unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("removed-slot CONNECT did not finish")
	}
	slot.close()
}

func TestHTTP3ValidStatusKeepsReusablePhysicalConnection(t *testing.T) {
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host == "forbidden.example:443" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	}), nil)
	for _, destination := range []string{"forbidden.example:443", "unavailable.example:443"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := fixture.manager.dial(ctx, fixture.target, destination)
		cancel()
		var statusErr *connectProxyStatusError
		if !errors.As(err, &statusErr) {
			t.Fatalf("CONNECT response = %v, want valid HTTP status", err)
		}
	}
	physical := fixture.physicalConnections()
	if len(physical) != 1 || physical[0].Context().Err() != nil {
		t.Fatal("403/503 incorrectly retired a reusable physical connection")
	}
	fixture.manager.close()
	waitHTTP3PhysicalClosed(t, physical[0])
}

func TestHTTP3CancelledSetupKeepsReusablePhysicalConnection(t *testing.T) {
	started := make(chan struct{}, 1)
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host == "cancel.example:443" {
			started <- struct{}{}
			<-request.Context().Done()
			return
		}
		echoHTTP3OwnershipTunnel(writer, request)
	}), nil)
	first := fixture.dial(t, "first.example:443")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := fixture.manager.dial(ctx, fixture.target, "cancel.example:443")
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelable CONNECT did not reach server")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled setup = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled setup did not finish")
	}
	second := fixture.dial(t, "second.example:443")
	assertConnectTunnelEcho(t, first, "existing-after-cancel")
	assertConnectTunnelEcho(t, second, "new-after-cancel")
	if len(fixture.physicalConnections()) != 1 {
		t.Fatal("caller cancellation retired a reusable slot")
	}
}

func TestHTTP3PhysicalConnectionNaturalCloseReleasesOwnership(t *testing.T) {
	fixture := newHTTP3OwnershipFixture(t, http.HandlerFunc(echoHTTP3OwnershipTunnel), nil)
	tunnel := fixture.dial(t, "natural.example:443")
	physical := fixture.physicalConnections()[0]
	fixture.manager.mu.Lock()
	slot := fixture.manager.transports[fixture.key][0]
	fixture.manager.mu.Unlock()
	_ = physical.CloseWithError(0, "test natural connection termination")
	waitHTTP3PhysicalClosed(t, physical)
	deadline := time.Now().Add(2 * time.Second)
	for {
		slot.physicalMu.Lock()
		owned := len(slot.physicalConns)
		slot.physicalMu.Unlock()
		if owned == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("naturally closed connection remained in ownership registry")
		}
		time.Sleep(time.Millisecond)
	}
	_ = tunnel.Close()
}

func TestHTTP3ErroredSlotPreservesWarmingCandidateLinks(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSource()
	started := time.Now().Add(-time.Minute)
	physical := attachHTTP3TestConnection(t, manager, key, source, started)
	degradeHTTP3TestSlot(t, manager, key, source, physical, time.Now())
	_, candidate, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseCandidate()
	manager.drainHTTP3ErroredTransport(key, source)
	manager.promoteHTTP3Candidate(key, candidate)
	manager.mu.Lock()
	valid := candidate.lifecycle == http3TransportServing && candidate.replaces == nil &&
		source.lifecycle == http3TransportDraining && source.replacement == nil && source.active == 1
	manager.mu.Unlock()
	if !valid {
		t.Fatal("errored source corrupted candidate promotion or prematurely released sibling")
	}
	releaseSource()
	if err := manager.validateHTTP3RotationState(); err != nil {
		t.Fatal(err)
	}
}
