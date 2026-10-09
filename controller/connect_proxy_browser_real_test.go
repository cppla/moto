package controller

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// Opt-in: private configuration is read in memory only. Results contain indexed
// targets and bounded error classes, never credentials, authorities or payloads.
// The fallback case injects a UDP dial error; it does not claim a wire blackhole.
func TestBrowserProfileRealRoutes(t *testing.T) {
	path := os.Getenv("MOTO_BROWSER_REAL_CONFIG")
	if path == "" {
		t.Skip("set MOTO_BROWSER_REAL_CONFIG for the private-route compatibility test")
	}
	settings, err := config.Load(path)
	if err != nil {
		t.Fatal("private_config_invalid")
	}
	var targets []*config.Target
	seen := make(map[string]bool)
	for _, rule := range settings.Rules {
		if !config.IsConnectProtocol(rule.Protocol) {
			continue
		}
		for _, target := range rule.Targets {
			if target.ConnectProxy != nil && !seen[target.Address] {
				seen[target.Address] = true
				targets = append(targets, target)
			}
		}
	}
	if len(targets) == 0 {
		t.Fatal("no_connect_targets")
	}
	for index, original := range targets {
		for _, scenario := range []struct {
			name      string
			protocols []string
			injectUDP bool
		}{
			{"h2", []string{config.ConnectProxyH2}, false},
			{"h3", []string{config.ConnectProxyH3}, false},
			{"h3_h2", []string{config.ConnectProxyH3, config.ConnectProxyH2}, false},
			{"udp_dial_failure_fallback", []string{config.ConnectProxyH3, config.ConnectProxyH2}, true},
		} {
			t.Run(fmt.Sprintf("target_%d/%s", index, scenario.name), func(t *testing.T) {
				target := *original
				proxy := *original.ConnectProxy
				proxy.Protocols = scenario.protocols
				proxy.BrowserProfile = config.BrowserProfileChrome
				target.ConnectProxy = &proxy
				manager := newConnectProxyManager()
				defer manager.close()
				if scenario.injectUDP {
					manager.dialers[config.ConnectProxyH3] = func(context.Context, *config.Target, string) (net.Conn, error) {
						return nil, &net.OpError{Op: "dial", Net: "udp", Err: errors.New("test injected UDP failure")}
					}
				}
				for attempt := 0; attempt < 2; attempt++ {
					started := time.Now()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					tunnel, dialErr := manager.dial(ctx, &target, "example.com:443")
					cancel()
					result := map[string]any{"target": index, "scenario": scenario.name, "attempt": attempt, "setup_ms": time.Since(started).Milliseconds(), "setup_budget_ms": 10000}
					if dialErr != nil {
						result["error_class"] = connectProxyAttemptOutcome(dialErr)
						browserRealResult(t, result)
						t.Error("CONNECT failed (details intentionally redacted)")
						return
					}
					protocol := tunnel.RemoteAddr().Network()
					result["protocol"] = protocol
					if (scenario.injectUDP || scenario.name == "h2") && protocol != config.ConnectProxyH2 {
						_ = tunnel.Close()
						t.Fatal("unexpected_protocol")
					}
					if scenario.name == "h3" && protocol != config.ConnectProxyH3 {
						_ = tunnel.Close()
						t.Fatal("unexpected_protocol")
					}
					// Bound the data phase independently; successful CONNECT is not
					// enough to prove the tunnel carries a verified HTTPS response.
					closeTimer := time.AfterFunc(15*time.Second, func() { _ = tunnel.Close() })
					inner := tls.Client(tunnel, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
					request, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
					request.Close = true
					responseErr := request.Write(inner)
					var response *http.Response
					if responseErr == nil {
						response, responseErr = http.ReadResponse(bufio.NewReader(inner), request)
					}
					if responseErr == nil {
						result["status"] = response.StatusCode
						var count int64
						count, responseErr = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
						result["bytes"] = count
						_ = response.Body.Close()
						if response.StatusCode != http.StatusOK || count == 0 {
							responseErr = errors.New("unexpected_response")
						}
					}
					closeTimer.Stop()
					_ = tunnel.Close()
					result["total_ms"] = time.Since(started).Milliseconds()
					if responseErr != nil {
						result["error_class"] = "inner_https_failed"
						t.Error("verified HTTPS transfer failed (details intentionally redacted)")
					}
					browserRealResult(t, result)
				}
			})
		}
	}
}

func browserRealResult(t *testing.T, result map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("result_encode_failed")
	}
	t.Logf("MOTO_BROWSER_REAL_RESULT %s", encoded)
}
