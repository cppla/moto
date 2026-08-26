package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"net/http"
	"testing"
)

func TestConnectProxyH2OnlyDoesNotStartHTTP3Sampler(t *testing.T) {
	manager := newConnectProxyManager()
	defer manager.close()
	wantErr := errors.New("test H2 failure")
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return nil, wantErr
	}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH2},
		},
	}
	if _, err := manager.dial(context.Background(), target, "destination.example:443"); !errors.Is(err, wantErr) {
		t.Fatalf("H2-only dial error = %v, want %v", err, wantErr)
	}
	manager.h3.mu.Lock()
	defer manager.h3.mu.Unlock()
	if manager.h3.samplerCancel != nil || manager.h3.samplerDone != nil {
		t.Fatal("H2-only dial unexpectedly started the H3 degradation sampler")
	}
}

func TestConnectProxyTargetAttemptLimit(t *testing.T) {
	targets := []*config.Target{
		{Address: "one.example:443"},
		{Address: "two.example:443"},
		{Address: "three.example:443"},
	}
	tests := []struct {
		name string
		rule *config.Rule
		want int
	}{
		{name: "nil rule", want: 0},
		{name: "no targets", rule: &config.Rule{Protocol: config.ProtocolSOCKS5}, want: 0},
		{name: "raw TCP keeps all targets", rule: &config.Rule{Protocol: config.ProtocolTCP, Targets: targets}, want: 3},
		{name: "SOCKS uses one available target", rule: &config.Rule{Protocol: config.ProtocolSOCKS5, Targets: targets[:1]}, want: 1},
		{name: "SOCKS caps target fanout", rule: &config.Rule{Protocol: config.ProtocolSOCKS5, Targets: targets}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connectProxyTargetAttemptLimit(test.rule); got != test.want {
				t.Fatalf("connectProxyTargetAttemptLimit() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestConnectProxyFinalStatusErrorUsesDeterministicPrecedence(t *testing.T) {
	capability := &connectProxyStatusError{protocol: config.ConnectProxyH3, target: "proxy.example:443", statusCode: http.StatusNotImplemented}
	service := &connectProxyStatusError{protocol: config.ConnectProxyH2, target: "proxy.example:443", statusCode: http.StatusServiceUnavailable}
	joined := errors.Join(
		errors.New("earlier transport failure"),
		capability,
		service,
	)
	if got := connectProxyFinalStatusError(joined); got != service {
		t.Fatalf("final status = %+v, want destination/service response %+v", got, service)
	}

	policy := &connectProxyStatusError{protocol: config.ConnectProxyH3, target: "policy.example:443", statusCode: http.StatusForbidden}
	for _, ordered := range []error{
		errors.Join(policy, service),
		errors.Join(service, policy),
	} {
		if got := connectProxyFinalStatusError(ordered); got != policy {
			t.Fatalf("completion order changed decisive status to %+v, want policy %+v", got, policy)
		}
	}
}
