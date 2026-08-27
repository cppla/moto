package controller

import (
	"errors"
	"moto/config"
	"moto/utils"
	"testing"

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

	previousLogger := utils.Logger
	previousLimiter := connectProxyFailureLogLimiter
	t.Cleanup(func() {
		utils.Logger = previousLogger
		connectProxyFailureLogLimiter = previousLimiter
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core, observed := observer.New(zapcore.DebugLevel)
			utils.Logger = zap.New(core)
			connectProxyFailureLogLimiter = newConnectProxyErrorLogLimiter()

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

			logConnectProxyFailure(rule, rule.Targets[len(rule.Targets)-1].Address,
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
