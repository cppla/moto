package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/utils"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestHTTP3CloseClassification(t *testing.T) {
	for _, test := range []struct {
		name, reason, origin string
		err                  error
		local                bool
		normal               bool
	}{
		{"handshake", "handshake_timeout", "unknown", &quic.HandshakeTimeoutError{}, false, false},
		{"idle", "idle_timeout", "unknown", &quic.IdleTimeoutError{}, false, false},
		{"reset", "stateless_reset", "remote", &quic.StatelessResetError{}, false, false},
		{"remote_app", "remote_application_close", "remote", &quic.ApplicationError{Remote: true, ErrorCode: 23, ErrorMessage: "private"}, false, false},
		{"remote_normal", "remote_application_close", "remote", &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError)}, false, true},
		{"local_app_failure", "local_application_close", "local", &quic.ApplicationError{ErrorCode: 42}, true, false},
		{"local_normal", "local_close", "local", &quic.ApplicationError{}, true, true},
		{"remote_wins_race", "remote_application_close", "remote", &quic.ApplicationError{Remote: true, ErrorCode: 42}, true, false},
		{"remote_transport", "remote_transport_error", "remote", &quic.TransportError{Remote: true, ErrorCode: quic.FlowControlError}, false, false},
		{"local_transport", "local_transport_error", "local", &quic.TransportError{ErrorCode: quic.FlowControlError}, false, false},
		{"version", "version_negotiation_error", "unknown", &quic.VersionNegotiationError{}, false, false},
		{"requested", "local_close", "local", net.ErrClosed, true, true},
		{"cancel", "canceled", "local", context.Canceled, false, true},
		{"deadline", "network_timeout", "unknown", context.DeadlineExceeded, false, false},
		{"other", "network_error", "unknown", errors.New("private-error"), false, false},
		{"unknown", "unknown", "unknown", nil, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.err
			if err != nil {
				err = fmt.Errorf("private wrapper: %w", err)
			}
			got := classifyHTTP3ConnectionClose(err, test.local)
			if got.reason != test.reason || got.origin != test.origin || got.normal != test.normal {
				t.Fatalf("classification = %+v, want %s/%s normal=%t", got, test.reason, test.origin, test.normal)
			}
		})
	}
}

func TestHTTP3CloseObservationOnceAndGenerationIsolation(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	previous := utils.Logger
	utils.Logger = zap.New(core)
	t.Cleanup(func() { utils.Logger = previous })
	now := time.Now()
	manager := newHTTP3ConnectManager(nil)
	manager.now = func() time.Time { return now }
	t.Cleanup(manager.close)
	key := http3ConnectTransportKey{address: "proxy.example:443", serverName: "private-server-name"}
	old := &http3ConnectionCloseObservation{generation: 1, establishedAt: now.Add(-time.Minute)}
	newer := &http3ConnectionCloseObservation{generation: 2, establishedAt: now.Add(-time.Second)}
	slot := &http3ConnectTransportSlot{generationID: 2, closeObservation: newer, tunnels: make(map[*http3TunnelStats]struct{})}
	for _, generation := range []uint64{1, 1, 2} {
		slot.tunnels[&http3TunnelStats{probation: http3RuleProbationBinding{generationID: generation}}] = struct{}{}
	}
	// Even after retirement/removal, the callback keeps its immutable identity.
	manager.retired = true
	const secret = "PRIVATE-PEER-REASON\nProxy-Authorization: secret"
	err := &quic.ApplicationError{Remote: true, ErrorCode: 23, ErrorMessage: secret}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() { manager.recordHTTP3ConnectionClose(key, slot, old, err) })
		workers.Go(func() { manager.recordHTTP3ConnectionClose(key, slot, newer, err) })
	}
	workers.Wait()
	if logs.Len() != 2 {
		t.Fatalf("close logs = %d, want one per physical connection", logs.Len())
	}
	for _, entry := range logs.All() {
		fields := entry.ContextMap()
		generation := fields["generation"].(uint64)
		wantActive, wantAge := int64(2), int64(60000)
		if generation == 2 {
			wantActive, wantAge = 1, 1000
		}
		if fields["activeTunnelsAtObservation"] != wantActive || fields["connectionAgeMs"] != wantAge {
			t.Fatalf("cross-generation close attribution: %+v", fields)
		}
		if entry.Level != zapcore.WarnLevel || fields["closeCode"] != uint64(23) {
			t.Fatalf("lost close severity/code: %+v", entry)
		}
		if text := fmt.Sprint(fields); strings.Contains(text, "PRIVATE") || strings.Contains(text, "Authorization") || strings.Contains(text, key.serverName) {
			t.Fatalf("peer content leaked: field keys=%v", entry.Context)
		}
	}
	snapshot := manager.snapshotGauges()
	if len(snapshot.closures) != 1 || snapshot.closures[0].count != 2 {
		t.Fatalf("close counters = %+v", snapshot.closures)
	}
	var output strings.Builder
	renderHTTP3CloseMetrics(&output, snapshot.closures)
	if !strings.Contains(output.String(), `moto_connect_proxy_h3_connection_closes_total{target="proxy.example:443",reason="remote_application_close"} 2`) ||
		strings.Contains(output.String(), "generation=") || strings.Contains(output.String(), "PRIVATE") {
		t.Fatalf("invalid metric output: %s", output.String())
	}
}

func TestHTTP3CloseLifecycleLogLevels(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		active bool
		local  bool
		level  zapcore.Level
	}{
		{"idle_unused", &quic.IdleTimeoutError{}, false, false, zapcore.DebugLevel},
		{"idle_with_tunnel", &quic.IdleTimeoutError{}, true, false, zapcore.WarnLevel},
		{"remote_normal_unused", &quic.ApplicationError{Remote: true}, false, false, zapcore.DebugLevel},
		{"remote_close_interrupts", &quic.ApplicationError{Remote: true}, true, false, zapcore.WarnLevel},
		{"local_shutdown", &quic.ApplicationError{}, true, true, zapcore.DebugLevel},
		{"local_protocol_error", &quic.TransportError{ErrorCode: quic.ProtocolViolation}, false, true, zapcore.WarnLevel},
	} {
		t.Run(test.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			previous := utils.Logger
			utils.Logger = zap.New(core)
			t.Cleanup(func() { utils.Logger = previous })
			manager := newHTTP3ConnectManager(nil)
			t.Cleanup(manager.close)
			slot := &http3ConnectTransportSlot{tunnels: make(map[*http3TunnelStats]struct{})}
			slot.closeRequested.Store(test.local)
			if test.active {
				slot.tunnels[&http3TunnelStats{probation: http3RuleProbationBinding{generationID: 1}}] = struct{}{}
			}
			manager.recordHTTP3ConnectionClose(http3ConnectTransportKey{address: "proxy.example:443"}, slot,
				&http3ConnectionCloseObservation{generation: 1, establishedAt: time.Now()}, test.err)
			if logs.Len() != 1 || logs.All()[0].Level != test.level {
				t.Fatalf("logs = %+v, want level=%s", logs.All(), test.level)
			}
		})
	}
}
