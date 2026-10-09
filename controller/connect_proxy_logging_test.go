package controller

import (
	"errors"
	"moto/config"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogConnectProxyFailureInfersProtocolForGenericMultiTargetErrors(t *testing.T) {
	tests := []struct {
		name      string
		protocols [][]string
		want      string
	}{
		{
			name:      "H3 only",
			protocols: [][]string{{config.ConnectProxyH3}, {config.ConnectProxyH3}},
			want:      config.ConnectProxyH3,
		},
		{
			name:      "H2 only",
			protocols: [][]string{{config.ConnectProxyH2}, {config.ConnectProxyH2}},
			want:      config.ConnectProxyH2,
		},
		{
			name:      "mixed fallback on every target",
			protocols: [][]string{{config.ConnectProxyH3, config.ConnectProxyH2}, {config.ConnectProxyH3, config.ConnectProxyH2}},
			want:      "mixed",
		},
		{
			name:      "different pure protocols",
			protocols: [][]string{{config.ConnectProxyH3}, {config.ConnectProxyH2}},
			want:      "mixed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			core, observed := observer.New(zapcore.DebugLevel)
			logger := zap.New(core)
			limiter := newConnectProxyErrorLogLimiter()

			rule := &config.Rule{
				Name:     "generic-failure-" + test.name,
				Protocol: config.ProtocolSOCKS5,
				Mode:     config.ModeBoost,
				Targets:  make([]*config.Target, 0, len(test.protocols)),
			}
			for index, protocols := range test.protocols {
				rule.Targets = append(rule.Targets, &config.Target{
					Address: string(rune('a'+index)) + ".proxy.example:443",
					ConnectProxy: &config.ConnectProxyConfig{
						Protocols: protocols,
					},
				})
			}

			logConnectProxyFailureTo(logger, limiter, rule, rule.Targets[len(rule.Targets)-1].Address,
				errors.New("generic transport failure"), "test CONNECT failure")
			entries := observed.AllUntimed()
			if len(entries) != 1 {
				t.Fatalf("log entries = %d, want 1", len(entries))
			}
			if got := entries[0].ContextMap()["protocol"]; got != test.want {
				t.Fatalf("protocol field = %#v, want %q", got, test.want)
			}
		})
	}
}

func TestLogConnectProxyFailureUsesUpstreamCONNECTResponseMessage(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		wantMessage string
		wantLevel   zapcore.Level
	}{
		{
			name:        "forbidden",
			statusCode:  http.StatusForbidden,
			wantMessage: "目标连接被上游策略拒绝",
			wantLevel:   zapcore.InfoLevel,
		},
		{
			name:        "service unavailable",
			statusCode:  http.StatusServiceUnavailable,
			wantMessage: "上游暂时无法处理目标连接",
			wantLevel:   zapcore.WarnLevel,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			core, observed := observer.New(zapcore.DebugLevel)
			logger := zap.New(core)
			limiter := newConnectProxyErrorLogLimiter()
			rule := &config.Rule{Name: "status-message", Protocol: config.ProtocolSOCKS5, Mode: config.ModeBoost}
			statusErr := &connectProxyStatusError{
				protocol:   config.ConnectProxyH2,
				target:     "proxy.example:443",
				statusCode: test.statusCode,
				class:      classifyConnectProxyStatus(test.statusCode),
			}

			logConnectProxyFailureTo(logger, limiter, rule, statusErr.target, statusErr, "缓存原生代理线路及备选均不可用")
			entries := observed.AllUntimed()
			if len(entries) != 1 {
				t.Fatalf("log entries = %d, want 1", len(entries))
			}
			entry := entries[0]
			if entry.Message != test.wantMessage {
				t.Fatalf("message = %q, want %q", entry.Message, test.wantMessage)
			}
			if entry.Level != test.wantLevel {
				t.Fatalf("level = %s, want %s", entry.Level, test.wantLevel)
			}
			if got := entry.ContextMap()["statusCode"]; got != int64(test.statusCode) {
				t.Fatalf("statusCode field = %#v, want %d", got, test.statusCode)
			}
		})
	}
}

func TestLogConnectProxyFailureIsolatesConcurrentSinksAndLimiters(t *testing.T) {
	for _, name := range []string{"old", "new"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			core, observed := observer.New(zapcore.DebugLevel)
			logger := zap.New(core)
			now := time.Unix(1, 0)
			limiter := newConnectProxyErrorLogLimiterWithNow(func() time.Time { return now })
			// Identical keys must not share capture sinks or rate-limit tokens.
			rule := &config.Rule{Name: "same-rule"}
			err := errors.New("transport failure")
			const attempts = 24
			var workers sync.WaitGroup
			start := make(chan struct{})
			for range attempts {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					logConnectProxyFailureTo(logger, limiter, rule, "proxy.example:443", err, name)
				}()
			}
			close(start)
			workers.Wait()
			if got := observed.Len(); got != connectProxyErrorLogBurst {
				t.Fatalf("initial log count = %d, want %d", got, connectProxyErrorLogBurst)
			}

			// Advance only after all workers exit; the injected clock is immutable
			// while concurrent calls are running.
			now = now.Add(connectProxyErrorLogWindow)
			logConnectProxyFailureTo(logger, limiter, rule, "proxy.example:443", err, name)
			entries := observed.AllUntimed()
			if len(entries) != connectProxyErrorLogBurst+1 {
				t.Fatalf("refilled log count = %d, want %d", len(entries), connectProxyErrorLogBurst+1)
			}
			for _, entry := range entries {
				if entry.Message != name {
					t.Fatalf("cross-sink message = %q, want %q", entry.Message, name)
				}
			}
			if got := entries[len(entries)-1].ContextMap()["suppressed"]; got != uint64(attempts-connectProxyErrorLogBurst) {
				t.Fatalf("suppressed = %#v, want %d", got, attempts-connectProxyErrorLogBurst)
			}
		})
	}
}
