package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type fakeHTTP3StatsConnection struct {
	ctx   context.Context
	stats quic.ConnectionStats
}

func (connection *fakeHTTP3StatsConnection) ConnectionStats() quic.ConnectionStats {
	return connection.stats
}

func (connection *fakeHTTP3StatsConnection) Context() context.Context {
	return connection.ctx
}

func newHTTP3RotationTestManager(t *testing.T) *http3ConnectManager {
	t.Helper()
	manager := newHTTP3ConnectManager(func(http3ConnectTransportKey, context.Context) *http3.Transport {
		return &http3.Transport{}
	})
	t.Cleanup(manager.close)
	return manager
}

func attachHTTP3TestConnection(
	t *testing.T,
	manager *http3ConnectManager,
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	started time.Time,
) *fakeHTTP3StatsConnection {
	t.Helper()
	connection := &fakeHTTP3StatsConnection{
		ctx: context.Background(),
		stats: quic.ConnectionStats{
			MinRTT:      50 * time.Millisecond,
			SmoothedRTT: 50 * time.Millisecond,
		},
	}
	manager.mu.Lock()
	slot.connection = connection
	slot.connectionID++
	slot.detector = newHTTP3DegradationDetector(started)
	manager.mu.Unlock()
	return connection
}

func degradeHTTP3TestSlot(
	t *testing.T,
	manager *http3ConnectManager,
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
	connection *fakeHTTP3StatsConnection,
	at time.Time,
) {
	t.Helper()
	manager.mu.Lock()
	connectionID := slot.connectionID
	manager.mu.Unlock()
	manager.applyHTTP3DegradationSample(http3DegradationSnapshot{
		key:          key,
		slot:         slot,
		connection:   connection,
		connectionID: connectionID,
	}, http3DegradationSample{At: at, ConnectionErr: errors.New("test QUIC path failed")})
}

func TestHTTP3DegradationCreatesExactlyOneWarmingCandidate(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	defer releaseSource()
	manager.mu.Lock()
	samplerStarted := manager.samplerCancel != nil && manager.samplerDone != nil
	manager.mu.Unlock()
	if !samplerStarted {
		t.Fatal("H3 transport did not automatically start degradation sampling")
	}
	started := time.Date(2026, 8, 26, 8, 30, 0, 0, time.UTC)
	connection := attachHTTP3TestConnection(t, manager, key, source, started)
	degradeHTTP3TestSlot(t, manager, key, source, connection, started.Add(time.Minute))
	for index := 0; index < 20; index++ {
		degradeHTTP3TestSlot(t, manager, key, source, connection, started.Add(time.Minute+time.Duration(index+1)*time.Second))
	}

	manager.mu.Lock()
	if got := len(manager.transports[key]); got != 2 {
		manager.mu.Unlock()
		t.Fatalf("rotation transports = %d, want source plus one candidate", got)
	}
	candidate := source.replacement
	manager.mu.Unlock()
	if candidate == nil || candidate.lifecycle != http3TransportWarming {
		t.Fatalf("candidate = %+v, want warming", candidate)
	}

	_, firstSelected, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire candidate: %v", err)
	}
	defer releaseCandidate()
	if firstSelected != candidate {
		t.Fatal("first request after degradation did not select warming candidate")
	}
	_, secondSelected, releaseSecond, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire while canary in flight: %v", err)
	}
	defer releaseSecond()
	if secondSelected != source {
		t.Fatal("concurrent request joined warming candidate instead of verified source")
	}
	if err := manager.validateHTTP3RotationState(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3PromotionKeepsNewServingUntilOldDrains(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	started := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	connection := attachHTTP3TestConnection(t, manager, key, source, started)
	degradeHTTP3TestSlot(t, manager, key, source, connection, started.Add(time.Minute))
	_, candidate, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire candidate: %v", err)
	}
	manager.promoteHTTP3Candidate(key, candidate)
	releaseCandidate()

	manager.mu.Lock()
	if candidate.lifecycle != http3TransportServing || source.lifecycle != http3TransportDraining {
		manager.mu.Unlock()
		t.Fatalf("post-promotion states = candidate:%s source:%s", candidate.lifecycle, source.lifecycle)
	}
	if !manager.containsSlotLocked(key, candidate) || !manager.containsSlotLocked(key, source) {
		manager.mu.Unlock()
		t.Fatal("promotion removed serving candidate or active draining source")
	}
	manager.mu.Unlock()

	_, selected, releaseNew, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire after promotion: %v", err)
	}
	if selected != candidate {
		t.Fatal("new request did not use promoted candidate")
	}
	releaseNew()
	releaseSource()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.containsSlotLocked(key, source) {
		t.Fatal("drained source remained in pool")
	}
	if !manager.containsSlotLocked(key, candidate) {
		t.Fatal("serving candidate was closed when source drained")
	}
}

func TestHTTP3WarmingFailureKeepsOldServingAndBacksOff(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	now := time.Date(2026, 8, 26, 9, 30, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	connection := attachHTTP3TestConnection(t, manager, key, source, now)
	degradeHTTP3TestSlot(t, manager, key, source, connection, now.Add(time.Minute))
	releaseSource()
	_, candidate, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire candidate: %v", err)
	}
	retrySource, accepted := manager.markHTTP3CandidateFailed(key, candidate, errors.New("candidate failed"))
	if !accepted || retrySource != source {
		t.Fatal("warming candidate failure was not accepted")
	}
	releaseCandidate()

	manager.mu.Lock()
	if source.lifecycle != http3TransportServing || source.active != 0 || !manager.containsSlotLocked(key, source) {
		manager.mu.Unlock()
		t.Fatalf("old source after candidate failure = lifecycle:%s active:%d", source.lifecycle, source.active)
	}
	if manager.containsSlotLocked(key, candidate) {
		manager.mu.Unlock()
		t.Fatal("failed candidate remained in pool")
	}
	if got, want := source.retryAt, now.Add(http3RotationBackoffBase); !got.Equal(want) {
		manager.mu.Unlock()
		t.Fatalf("first retryAt = %s, want %s", got, want)
	}
	if replacement, err := manager.ensureHTTP3RotationCandidateLocked(key, source, now.Add(29*time.Second)); err != nil || replacement != nil {
		manager.mu.Unlock()
		t.Fatalf("candidate created during backoff: replacement=%p err=%v", replacement, err)
	}
	replacement, err := manager.ensureHTTP3RotationCandidateLocked(key, source, now.Add(30*time.Second))
	manager.mu.Unlock()
	if err != nil || replacement == nil || replacement.lifecycle != http3TransportWarming {
		t.Fatalf("candidate after backoff = %p/%v", replacement, err)
	}
}

func TestHTTP3CandidateRetrySourceRejectsConcurrentDrain(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	releaseSource()
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	manager.mu.Lock()
	source.health = http3TransportDegraded
	source.rotationReason = http3DegradationReasonUDPBlackhole
	candidate, err := manager.ensureHTTP3RotationCandidateLocked(key, source, now)
	manager.mu.Unlock()
	if err != nil || candidate == nil {
		t.Fatalf("create warming candidate: candidate=%p err=%v", candidate, err)
	}
	_, selected, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil || selected != candidate {
		t.Fatalf("acquire warming candidate: selected=%p candidate=%p err=%v", selected, candidate, err)
	}
	retrySource, accepted := manager.markHTTP3CandidateFailed(key, candidate, errors.New("candidate failed"))
	if !accepted || retrySource != source {
		t.Fatalf("candidate retry source = %p accepted:%t, want source %p", retrySource, accepted, source)
	}
	releaseCandidate()

	// The source can enter a rule-level blackhole drain after candidate failure
	// was recorded but before the internal retry reserves it. The second exact
	// slot check must reject that transition without allocating a fresh H3 slot.
	manager.mu.Lock()
	source.lifecycle = http3TransportDraining
	manager.mu.Unlock()
	if _, _, _, err := manager.acquireHTTP3CandidateRetrySource(key, retrySource); !errors.Is(err, errHTTP3CandidateRetrySourceUnavailable) {
		t.Fatalf("retry drained source error = %v, want %v", err, errHTTP3CandidateRetrySourceUnavailable)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if got := len(manager.transports[key]); got != 1 || manager.transports[key][0] != source {
		t.Fatalf("candidate retry pool = %+v, want only original draining source", manager.transports[key])
	}
}

func TestHTTP3RotationBackoffCapsAtFiveMinutes(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: 30 * time.Second},
		{failures: 2, want: time.Minute},
		{failures: 3, want: 2 * time.Minute},
		{failures: 4, want: 4 * time.Minute},
		{failures: 5, want: 5 * time.Minute},
		{failures: 20, want: 5 * time.Minute},
	}
	for _, test := range tests {
		if got := http3RotationBackoff(test.failures); got != test.want {
			t.Fatalf("backoff(%d) = %s, want %s", test.failures, got, test.want)
		}
	}
}

func TestHTTP3RetireDuringWarmingNeverRepublishesCandidate(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	started := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	connection := attachHTTP3TestConnection(t, manager, key, source, started)
	degradeHTTP3TestSlot(t, manager, key, source, connection, started.Add(time.Minute))
	_, candidate, releaseCandidate, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire candidate: %v", err)
	}

	manager.retire()
	manager.promoteHTTP3Candidate(key, candidate)
	manager.mu.Lock()
	if source.lifecycle != http3TransportDraining || candidate.lifecycle != http3TransportDraining {
		manager.mu.Unlock()
		t.Fatalf("retired states = source:%s candidate:%s", source.lifecycle, candidate.lifecycle)
	}
	manager.mu.Unlock()
	releaseCandidate()
	releaseSource()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.transports[key]) != 0 {
		t.Fatalf("retired transports remaining = %d", len(manager.transports[key]))
	}
}

func TestHTTP3StaleConnectionCloseCannotDegradeReplacementConnection(t *testing.T) {
	manager := newHTTP3RotationTestManager(t)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "proxy.example"}
	_, source, releaseSource, err := manager.acquireTransport(key)
	if err != nil {
		t.Fatalf("acquire source: %v", err)
	}
	defer releaseSource()
	started := time.Date(2026, 8, 26, 10, 30, 0, 0, time.UTC)
	oldConnection := attachHTTP3TestConnection(t, manager, key, source, started)
	manager.mu.Lock()
	oldID := source.connectionID
	newConnection := &fakeHTTP3StatsConnection{
		ctx: context.Background(),
		stats: quic.ConnectionStats{
			MinRTT:      60 * time.Millisecond,
			SmoothedRTT: 60 * time.Millisecond,
		},
	}
	source.connection = newConnection
	source.connectionID++
	source.detector = newHTTP3DegradationDetector(started.Add(time.Minute))
	manager.mu.Unlock()

	manager.observeHTTP3ConnectionClosed(key, source, oldConnection, oldID, errors.New("stale connection closed"))
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if source.health != http3TransportHealthy || source.replacement != nil || len(manager.transports[key]) != 1 {
		t.Fatalf("stale close polluted replacement: health=%s replacement=%p slots=%d", source.health, source.replacement, len(manager.transports[key]))
	}
}

func TestHTTP3TunnelStatsCountsSuccessfulBytesAndBlockedWrites(t *testing.T) {
	slot := &http3ConnectTransportSlot{}
	first := &http3TunnelStats{slot: slot}
	second := &http3TunnelStats{slot: slot}
	first.beginWrite()
	second.beginWrite()
	if got := slot.pendingWrites.Load(); got != 2 {
		t.Fatalf("pending writes = %d, want 2", got)
	}
	if got := slot.maxBlockedWrites.Load(); got != 2 {
		t.Fatalf("max blocked writes = %d, want 2", got)
	}
	first.finishWrite(17)
	if got := slot.pendingWrites.Load(); got != 1 {
		t.Fatalf("pending writes after first finish = %d, want second write preserved", got)
	}
	second.finishWrite(23)
	first.recordRead(31)
	if got := slot.pendingWrites.Load(); got != 0 {
		t.Fatalf("pending writes after finish = %d", got)
	}
	if got := slot.payloadWritten.Load(); got != 40 {
		t.Fatalf("written payload = %d, want 40", got)
	}
	if got := slot.payloadRead.Load(); got != 31 {
		t.Fatalf("read payload = %d, want 31", got)
	}
}

func TestHTTP3BlockedReadDemandRequiresRecentMeaningfulDownstreamProgress(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	newBlockedRead := func(payload uint64, progressAt time.Time) *http3TunnelStats {
		tunnel := &http3TunnelStats{}
		tunnel.pendingReads.Store(1)
		tunnel.readStarted.Store(now.Add(-http3UDPBlackholeStallTimeout).UnixNano())
		tunnel.payloadRead.Store(payload)
		if !progressAt.IsZero() {
			tunnel.lastReadProgress.Store(progressAt.UnixNano())
		}
		return tunnel
	}

	idle := newBlockedRead(0, time.Time{})
	old := newBlockedRead(http3UDPBlackholeRecentReadMinBytes, now.Add(-http3UDPBlackholeRecentReadWindow-time.Nanosecond))
	active := newBlockedRead(http3UDPBlackholeRecentReadMinBytes, now.Add(-http3UDPBlackholeRecentReadWindow))
	blocked, oldest, recent := http3BlockedReadDemand(now, []*http3TunnelStats{idle, old, active})
	if blocked != 3 || oldest != http3UDPBlackholeStallTimeout || !recent {
		t.Fatalf("blocked read demand = blocked:%d oldest:%s recent:%t", blocked, oldest, recent)
	}

	active.pendingReads.Store(0)
	blocked, _, recent = http3BlockedReadDemand(now, []*http3TunnelStats{idle, old, active})
	if blocked != 2 || recent {
		t.Fatalf("idle/old pending Reads became demand: blocked:%d recent:%t", blocked, recent)
	}
}

func TestHTTP3BlockedWriteDurationsCountsEachAgedTunnel(t *testing.T) {
	now := time.Date(2026, 8, 26, 21, 0, 0, 0, time.UTC)
	old := &http3TunnelStats{}
	fresh := &http3TunnelStats{}
	old.writeStarted.Store(now.Add(-5 * time.Second).UnixNano())
	fresh.writeStarted.Store(now.Add(-time.Second).UnixNano())

	oldest, longBlocked := http3BlockedWriteDurations(now, []*http3TunnelStats{old, fresh})
	if oldest != 5*time.Second || longBlocked != 1 {
		t.Fatalf("mixed-age writes = oldest %s, long %d", oldest, longBlocked)
	}

	fresh.writeStarted.Store(now.Add(-http3DegradationMultiWriteBlock).UnixNano())
	oldest, longBlocked = http3BlockedWriteDurations(now, []*http3TunnelStats{old, fresh})
	if oldest != 5*time.Second || longBlocked != 2 {
		t.Fatalf("two aged writes = oldest %s, long %d", oldest, longBlocked)
	}
}

func TestHTTP3ValidErrorResponsePromotesCandidateAndDrainsSource(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var responseStatus atomic.Int64
			responseStatus.Store(http.StatusOK)
			handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				current := int(responseStatus.Load())
				writer.WriteHeader(current)
				writer.(http.Flusher).Flush()
				if current >= 200 && current <= 299 {
					_, _ = io.Copy(writer, request.Body)
				}
			})
			endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
			defer closeServer()
			manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
				transport := newHTTP3ConnectTransportWithOwner(key, owner)
				transport.TLSClientConfig.RootCAs = roots
				return transport
			})
			defer manager.close()
			target := &config.Target{
				Address: endpoint,
				ConnectProxy: &config.ConnectProxyConfig{
					Protocols: []string{config.ConnectProxyH3},
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			sourceTunnel, err := manager.dial(ctx, target, "first.example:443")
			cancel()
			if err != nil {
				t.Fatalf("establish source tunnel: %v", err)
			}
			defer sourceTunnel.Close()
			key := http3ConnectTransportKey{address: endpoint}
			manager.mu.Lock()
			source := manager.transports[key][0]
			connection := source.connection
			connectionID := source.connectionID
			manager.mu.Unlock()
			manager.applyHTTP3DegradationSample(http3DegradationSnapshot{
				key: key, slot: source, connection: connection, connectionID: connectionID,
			}, http3DegradationSample{At: time.Now(), ConnectionErr: errors.New("forced degradation")})
			responseStatus.Store(int64(status))

			candidateCtx, cancelCandidate := context.WithTimeout(context.Background(), 3*time.Second)
			candidateTunnel, candidateErr := manager.dial(candidateCtx, target, "candidate.example:443")
			cancelCandidate()
			if candidateTunnel != nil {
				_ = candidateTunnel.Close()
				t.Fatal("error response unexpectedly returned a tunnel")
			}
			var statusErr *connectProxyStatusError
			if !errors.As(candidateErr, &statusErr) || statusErr.statusCode != status {
				t.Fatalf("candidate error = %v, want status %d", candidateErr, status)
			}

			manager.mu.Lock()
			if len(manager.transports[key]) != 2 {
				manager.mu.Unlock()
				t.Fatalf("post-promotion transports = %d, want 2 until source drains", len(manager.transports[key]))
			}
			var serving *http3ConnectTransportSlot
			for _, slot := range manager.transports[key] {
				if slot.lifecycle == http3TransportServing {
					serving = slot
				}
			}
			if source.lifecycle != http3TransportDraining || serving == nil || serving == source {
				manager.mu.Unlock()
				t.Fatalf("valid %d response did not promote B and drain A", status)
			}
			manager.mu.Unlock()
		})
	}
}
