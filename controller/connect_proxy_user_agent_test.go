package controller

import (
	"context"
	"net"
	"net/http"
	"testing"

	"moto/config"
)

func TestRandomConnectProxyUserAgentSelection(t *testing.T) {
	candidates := []string{"Browser-A/1", "Browser-B/2", "Browser-C/3"}
	allowed := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		allowed[candidate] = true
	}

	for range 256 {
		ctx := withRandomConnectProxyUserAgent(context.Background(), candidates)
		got, ok := connectProxyUserAgentFromContext(ctx)
		if !ok || !allowed[got] {
			t.Fatalf("selected User-Agent = %q, present = %t", got, ok)
		}
	}

	ctx := withRandomConnectProxyUserAgent(context.Background(), nil)
	if got, ok := connectProxyUserAgentFromContext(ctx); ok {
		t.Fatalf("empty candidates selected User-Agent %q", got)
	}
}

func TestConnectProxyUserAgentSurvivesHTTP3ToHTTP2Fallback(t *testing.T) {
	const userAgent = "Fallback-Browser/42"
	seen := make([]string, 0, 2)
	record := func(ctx context.Context) {
		value, ok := connectProxyUserAgentFromContext(ctx)
		if !ok {
			t.Fatal("CONNECT attempt did not inherit User-Agent")
		}
		seen = append(seen, value)
	}

	manager := &connectProxyManager{dialers: map[string]connectProxyDialFunc{
		config.ConnectProxyH3: func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
			record(ctx)
			return nil, &connectProxyStatusError{
				protocol:   config.ConnectProxyH3,
				statusCode: http.StatusNotImplemented,
			}
		},
		config.ConnectProxyH2: func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
			record(ctx)
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			return client, nil
		},
	}}
	target := &config.Target{
		Address: "proxy.example:443",
		ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
			config.ConnectProxyH3,
			config.ConnectProxyH2,
		}},
	}
	ctx := withRandomConnectProxyUserAgent(context.Background(), []string{userAgent})
	connection, err := manager.dial(ctx, target, "destination.example:443")
	if err != nil {
		t.Fatalf("dial() fallback error = %v", err)
	}
	_ = connection.Close()
	if len(seen) != 2 || seen[0] != userAgent || seen[1] != userAgent {
		t.Fatalf("fallback User-Agents = %q, want [%q %q]", seen, userAgent, userAgent)
	}
}
