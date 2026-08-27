package controller

import (
	"context"
	"net"
	"net/http"
	"testing"

	"moto/config"
)

func connectProxyUserAgentTestRule(name, listen string, userAgents []string) *config.Rule {
	return &config.Rule{
		Name:                name,
		Listen:              listen,
		Mode:                config.ModeNormal,
		Protocol:            config.ProtocolSOCKS5,
		Timeout:             1_000,
		MaxConnections:      32,
		MaxConnectionsPerIP: 32,
		UserAgent:           userAgents,
		Targets: []*config.Target{{
			Address: "proxy.example:443",
			ConnectProxy: &config.ConnectProxyConfig{
				Protocols:  []string{config.ConnectProxyH2},
				ServerName: "proxy.example",
			},
		}},
	}
}

func generationUserAgentByRuleName(t *testing.T, generation *routingGeneration, name string) string {
	t.Helper()
	for _, binding := range generation.bindings {
		if binding != nil && binding.rule != nil && binding.rule.Name == name {
			return binding.connectProxyUserAgent
		}
	}
	t.Fatalf("generation has no rule %q", name)
	return ""
}

func TestStableConnectProxyUserAgentSelection(t *testing.T) {
	candidates := []string{"Browser-A/1", "Browser-B/2", "Browser-C/3"}
	allowed := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		allowed[candidate] = true
	}

	selected := selectConnectProxyUserAgent(candidates, "")
	if !allowed[selected] {
		t.Fatalf("selected User-Agent = %q, want one of %q", selected, candidates)
	}
	for range 256 {
		ctx := withConnectProxyUserAgent(context.Background(), selected)
		got, ok := connectProxyUserAgentFromContext(ctx)
		if !ok || got != selected {
			t.Fatalf("request User-Agent = %q, present = %t, want stable %q", got, ok, selected)
		}
	}

	ctx := withConnectProxyUserAgent(context.Background(), selectConnectProxyUserAgent(nil, ""))
	if got, ok := connectProxyUserAgentFromContext(ctx); ok {
		t.Fatalf("empty candidates selected User-Agent %q", got)
	}
	if got := selectConnectProxyUserAgent(candidates, candidates[1]); got != candidates[1] {
		t.Fatalf("preferred User-Agent = %q, want %q", got, candidates[1])
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
	ctx := withConnectProxyUserAgent(context.Background(), userAgent)
	connection, err := manager.dial(ctx, target, "destination.example:443")
	if err != nil {
		t.Fatalf("dial() fallback error = %v", err)
	}
	_ = connection.Close()
	if len(seen) != 2 || seen[0] != userAgent || seen[1] != userAgent {
		t.Fatalf("fallback User-Agents = %q, want [%q %q]", seen, userAgent, userAgent)
	}
}

func TestServerConnectProxyUserAgentSurvivesReloadUntilRemoved(t *testing.T) {
	listen := unusedReloadAddress(t)
	candidates := []string{"Browser-A/1", "Browser-B/2"}
	initial := connectProxyUserAgentTestRule("stable-identity", listen, candidates)
	server, err := NewServer([]*config.Rule{initial})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()

	selected := generationUserAgentByRuleName(t, server.current.Load(), initial.Name)
	if selected != candidates[0] && selected != candidates[1] {
		t.Fatalf("initial User-Agent = %q, want one of %q", selected, candidates)
	}
	noop, err := server.ReloadRules(context.Background(), []*config.Rule{
		connectProxyUserAgentTestRule(initial.Name, listen, candidates),
	})
	if err != nil {
		t.Fatalf("ReloadRules with unchanged candidates: %v", err)
	}
	if !noop.Noop {
		t.Fatalf("unchanged reload = %+v, want noop", noop)
	}
	if got := generationUserAgentByRuleName(t, server.current.Load(), initial.Name); got != selected {
		t.Fatalf("User-Agent after noop reload = %q, want %q", got, selected)
	}

	retained := connectProxyUserAgentTestRule(initial.Name, listen, []string{
		"Browser-C/3",
		selected,
	})
	retained.MaxConnections++
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{retained}); err != nil {
		t.Fatalf("ReloadRules retaining selection: %v", err)
	}
	if got := generationUserAgentByRuleName(t, server.current.Load(), initial.Name); got != selected {
		t.Fatalf("User-Agent after retaining reload = %q, want %q", got, selected)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	blocked := connectProxyUserAgentTestRule("blocked-identity", occupied.Addr().String(), []string{"Browser-D/4"})
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{retained, blocked}); err == nil {
		t.Fatal("ReloadRules with occupied listener succeeded")
	}
	if got := generationUserAgentByRuleName(t, server.current.Load(), initial.Name); got != selected {
		t.Fatalf("failed reload changed User-Agent to %q, want %q", got, selected)
	}

	replacement := "Browser-A/1"
	if replacement == selected {
		replacement = "Browser-B/2"
	}
	replaced := connectProxyUserAgentTestRule(initial.Name, listen, []string{replacement})
	replaced.MaxConnections += 2
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{replaced}); err != nil {
		t.Fatalf("ReloadRules replacing selection: %v", err)
	}
	if got := generationUserAgentByRuleName(t, server.current.Load(), initial.Name); got != replacement {
		t.Fatalf("User-Agent after removal = %q, want replacement %q", got, replacement)
	}
}
