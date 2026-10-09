package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type http3CloseLogGate struct {
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func (gate *http3CloseLogGate) unblock() {
	gate.releaseOnce.Do(func() { close(gate.release) })
}

// Only the old physical-close observer's first diagnostic is blocked. The
// manager has no sampler or network in this test, so the ordering is entirely
// channel-driven and does not rely on timing a shutdown against a log write.
type http3CloseGatedCore struct {
	zapcore.Core
	gate *http3CloseLogGate
}

func (core *http3CloseGatedCore) With(fields []zapcore.Field) zapcore.Core {
	return &http3CloseGatedCore{Core: core.Core.With(fields), gate: core.gate}
}

func (core *http3CloseGatedCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if core.Enabled(entry.Level) {
		return checked.AddCore(entry, core)
	}
	return checked
}

func (core *http3CloseGatedCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if entry.Message == "HTTP/3 已结束连接的替换候选状态" {
		core.gate.enterOnce.Do(func() {
			close(core.gate.entered)
			<-core.gate.release
		})
	}
	return core.Core.Write(entry, fields)
}

func waitHTTP3CloseLogSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func http3CloseLogFixture(
	manager *http3ConnectManager, key http3ConnectTransportKey, generation uint64,
) (*http3ConnectTransportSlot, *fakeHTTP3StatsConnection, *http3ConnectionCloseObservation, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(context.Background())
	connection := &fakeHTTP3StatsConnection{ctx: ctx}
	slot := &http3ConnectTransportSlot{
		connection: connection, connectionID: 1, generationID: generation,
		lifecycle: http3TransportServing, health: http3TransportHealthy,
		tunnels: make(map[*http3TunnelStats]struct{}),
	}
	// Occupy the only slot so the close event cannot start a candidate sampler.
	manager.maxTransportsPerKey = 1
	manager.transports[key] = []*http3ConnectTransportSlot{slot}
	observation := &http3ConnectionCloseObservation{
		generation: generation, establishedAt: time.Now(), logger: manager.logger,
	}
	return slot, connection, observation, cancel
}

func TestHTTP3DelayedCloseLogsStayWithRetiredManager(t *testing.T) {
	oldCore, oldLogs := observer.New(zapcore.DebugLevel)
	gate := &http3CloseLogGate{entered: make(chan struct{}), release: make(chan struct{})}
	oldManager := newHTTP3ConnectManagerWithLogger(nil, zap.New(&http3CloseGatedCore{Core: oldCore, gate: gate}))
	// Release the sink before cleanup even when an assertion fails. Never leave
	// the observer stuck or make a failing test's cleanup wait on its own gate.
	defer oldManager.close()
	defer gate.unblock()
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	oldSlot, oldConnection, oldObservation, cancelOld := http3CloseLogFixture(oldManager, key, 1)
	defer cancelOld(context.Canceled)
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		<-oldConnection.Context().Done()
		cause := context.Cause(oldConnection.Context())
		oldManager.observeHTTP3ConnectionClosed(key, oldSlot, oldConnection, oldSlot.connectionID, cause)
		oldManager.recordHTTP3ConnectionClose(key, oldSlot, oldObservation, cause)
	}()
	cause := &quic.ApplicationError{Remote: true, ErrorCode: 23}
	cancelOld(cause)
	waitHTTP3CloseLogSignal(t, gate.entered, "old physical-close observer entering its sink")

	retired := make(chan struct{})
	go func() {
		oldManager.close()
		close(retired)
	}()
	waitHTTP3CloseLogSignal(t, retired, "manager retirement while its diagnostic sink is blocked")
	select {
	case <-oldDone:
		t.Fatal("old observer completed before its diagnostic sink was released")
	default:
	}
	if oldLogs.Len() != 0 {
		t.Fatal("old diagnostic bypassed its blocked sink")
	}

	newCore, newLogs := observer.New(zapcore.DebugLevel)
	newManager := newHTTP3ConnectManagerWithLogger(nil, zap.New(newCore))
	defer newManager.close()
	newSlot, newConnection, newObservation, cancelNew := http3CloseLogFixture(newManager, key, 2)
	defer cancelNew(context.Canceled)
	cancelNew(cause)
	newManager.observeHTTP3ConnectionClosed(key, newSlot, newConnection, newSlot.connectionID, cause)
	newManager.recordHTTP3ConnectionClose(key, newSlot, newObservation, cause)
	if newLogs.Len() != 2 {
		t.Fatalf("new manager logs = %d, want its degradation and physical-close events", newLogs.Len())
	}

	gate.unblock()
	waitHTTP3CloseLogSignal(t, oldDone, "old physical-close observer completing after retirement")
	// A duplicate delivery remains idempotent, including after pool removal.
	oldManager.recordHTTP3ConnectionClose(key, oldSlot, oldObservation, cause)
	for _, test := range []struct {
		name       string
		manager    *http3ConnectManager
		logs       *observer.ObservedLogs
		generation uint64
	}{
		{"old", oldManager, oldLogs, 1},
		{"new", newManager, newLogs, 2},
	} {
		if test.logs.Len() != 2 {
			t.Fatalf("%s manager logs = %d, want exactly two isolated events", test.name, test.logs.Len())
		}
		for _, entry := range test.logs.All() {
			if got := entry.ContextMap()["generation"]; got != test.generation {
				t.Errorf("%s sink received generation %v, want %d", test.name, got, test.generation)
			}
		}
		if got := test.logs.FilterField(zap.String("event", "h3_connection_closed")).Len(); got != 1 {
			t.Errorf("%s physical-close events = %d, want 1", test.name, got)
		}
		closures := test.manager.snapshotGauges().closures
		if len(closures) != 1 || closures[0].count != 1 || closures[0].reason != "remote_application_close" {
			t.Errorf("%s physical-close counters = %+v, want one remote close", test.name, closures)
		}
	}
}

func TestHTTP3NilInjectedLoggerIsSafe(t *testing.T) {
	manager := newHTTP3ConnectManagerWithLogger(nil, nil)
	defer manager.close()
	key := http3ConnectTransportKey{address: "proxy.example:443"}
	slot, connection, observation, cancel := http3CloseLogFixture(manager, key, 1)
	defer cancel(context.Canceled)
	cancel(context.Canceled)
	manager.observeHTTP3ConnectionClosed(key, slot, connection, slot.connectionID, context.Canceled)
	manager.recordHTTP3ConnectionClose(key, slot, observation, context.Canceled)
	if closures := manager.snapshotGauges().closures; len(closures) != 1 || closures[0].count != 1 {
		t.Fatalf("nil logger lost close bookkeeping: %+v", closures)
	}
}
