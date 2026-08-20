package controller

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"moto/config"
)

func TestActiveHealthStateTransitions(t *testing.T) {
	rule := &config.Rule{Name: "state"}
	key := activeHealthKey{rule: rule, address: "127.0.0.1:9000"}
	check := config.HealthCheckConfig{FailureThreshold: 2, SuccessThreshold: 2}
	manager := newActiveHealthManager()
	manager.states[key] = &activeHealthState{}

	manager.observe(key, check, false)
	if manager.unhealthy(rule, key.address) {
		t.Fatal("one failed check marked target unhealthy before threshold")
	}
	manager.observe(key, check, false)
	if !manager.unhealthy(rule, key.address) {
		t.Fatal("failure threshold did not mark target unhealthy")
	}

	manager.observe(key, check, true)
	if !manager.unhealthy(rule, key.address) {
		t.Fatal("one successful check recovered target before threshold")
	}
	manager.observe(key, check, false)
	manager.observe(key, check, true)
	if !manager.unhealthy(rule, key.address) {
		t.Fatal("a failure did not reset the recovery streak")
	}
	manager.observe(key, check, true)
	if manager.unhealthy(rule, key.address) {
		t.Fatal("success threshold did not recover target")
	}
}

func TestActiveHealthManagerCancellationStopsInFlightProbe(t *testing.T) {
	rule := activeHealthTestRule("cancel", "127.0.0.1:9", config.HealthCheckTCP)
	manager := newActiveHealthManager()
	manager.initialDelay = func(time.Duration) time.Duration { return 0 }
	manager.nextDelay = func(time.Duration) time.Duration { return time.Hour }
	started := make(chan struct{})
	var once sync.Once
	manager.probe = func(ctx context.Context, _ string, _ config.HealthCheckConfig, _ string) error {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return ctx.Err()
	}

	parent, cancel := context.WithCancel(context.Background())
	manager.start(parent, []*config.Rule{rule})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("active probe did not start")
	}
	cancel()
	stopped := make(chan struct{})
	go func() {
		manager.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not cancel and join the in-flight probe")
	}
	if manager.unhealthy(rule, rule.Targets[0].Address) {
		t.Fatal("shutdown cancellation was recorded as a health failure")
	}
}

func TestActiveHealthGlobalConcurrencyLimit(t *testing.T) {
	rule := &config.Rule{
		Name: "concurrency",
		HealthCheck: &config.HealthCheckConfig{
			Type:             config.HealthCheckTCP,
			Interval:         30_000,
			Timeout:          30_000,
			FailureThreshold: 1,
			SuccessThreshold: 1,
		},
	}
	for index := 0; index < activeHealthMaxConcurrentProbes*2; index++ {
		rule.Targets = append(rule.Targets, &config.Target{Address: fmt.Sprintf("127.0.0.1:%d", 10_000+index)})
	}

	manager := newActiveHealthManager()
	manager.initialDelay = func(time.Duration) time.Duration { return 0 }
	manager.nextDelay = func(time.Duration) time.Duration { return time.Hour }
	var current atomic.Int64
	var peak atomic.Int64
	reachedLimit := make(chan struct{})
	var reachedOnce sync.Once
	manager.probe = func(ctx context.Context, _ string, _ config.HealthCheckConfig, _ string) error {
		now := current.Add(1)
		for {
			previous := peak.Load()
			if now <= previous || peak.CompareAndSwap(previous, now) {
				break
			}
		}
		if now == activeHealthMaxConcurrentProbes {
			reachedOnce.Do(func() { close(reachedLimit) })
		}
		<-ctx.Done()
		current.Add(-1)
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	manager.start(ctx, []*config.Rule{rule})
	select {
	case <-reachedLimit:
	case <-time.After(3 * time.Second):
		cancel()
		manager.stop()
		t.Fatalf("peak active probes = %d, want slot pool to fill to %d", peak.Load(), activeHealthMaxConcurrentProbes)
	}
	if got := peak.Load(); got > activeHealthMaxConcurrentProbes {
		t.Fatalf("peak active probes = %d, exceeds global limit %d", got, activeHealthMaxConcurrentProbes)
	}
	cancel()
	manager.stop()
	if got := current.Load(); got != 0 {
		t.Fatalf("active probes after stop = %d, want 0", got)
	}
}

func TestActiveHealthTCPProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fixture: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
			close(accepted)
		}
	}()

	check := config.HealthCheckConfig{Type: config.HealthCheckTCP}
	if err := check.Validate(); err != nil {
		t.Fatalf("validate check: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeActiveHealthTarget(ctx, listener.Addr().String(), check, ""); err != nil {
		t.Fatalf("TCP probe error = %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("TCP fixture did not accept probe connection")
	}
}

func TestActiveHealthHTTPProbeUsesDirectGETAndStatusRange(t *testing.T) {
	seen := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		seen <- request.Method + " " + request.URL.RequestURI()
		response.Header().Set("Location", "/must-not-follow")
		response.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	check := config.HealthCheckConfig{Type: config.HealthCheckHTTP, Path: "/ready?deep=1"}
	if err := check.Validate(); err != nil {
		t.Fatalf("validate check: %v", err)
	}
	address := strings.TrimPrefix(server.URL, "http://")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeActiveHealthTarget(ctx, address, check, ""); err != nil {
		t.Fatalf("default HTTP status range rejected redirect response: %v", err)
	}

	check.StatusMax = 299
	if err := probeActiveHealthTarget(ctx, address, check, ""); err == nil {
		t.Fatal("custom HTTP status range accepted status 302")
	}
	for index := 0; index < 2; index++ {
		select {
		case request := <-seen:
			if request != "GET /ready?deep=1" {
				t.Fatalf("request = %q, want direct GET without redirect", request)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTP fixture did not receive expected request")
		}
	}
	select {
	case extra := <-seen:
		t.Fatalf("health client followed redirect: %q", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestActiveHealthProbesWriteConfiguredProxyProtocolFirst(t *testing.T) {
	tests := []struct {
		name            string
		checkType       string
		proxyProtocol   string
		wantVersion     proxyProtocolVersion
		wantCommand     proxyProtocolCommand
		wantHTTPRequest bool
	}{
		{
			name:          "tcp/v1",
			checkType:     config.HealthCheckTCP,
			proxyProtocol: config.ProxyProtocolV1,
			wantVersion:   proxyProtocolVersion1,
			wantCommand:   proxyProtocolCommandProxy,
		},
		{
			name:          "tcp/v2",
			checkType:     config.HealthCheckTCP,
			proxyProtocol: config.ProxyProtocolV2,
			wantVersion:   proxyProtocolVersion2,
			wantCommand:   proxyProtocolCommandLocal,
		},
		{
			name:            "http/v1",
			checkType:       config.HealthCheckHTTP,
			proxyProtocol:   config.ProxyProtocolV1,
			wantVersion:     proxyProtocolVersion1,
			wantCommand:     proxyProtocolCommandProxy,
			wantHTTPRequest: true,
		},
		{
			name:            "http/v2",
			checkType:       config.HealthCheckHTTP,
			proxyProtocol:   config.ProxyProtocolV2,
			wantVersion:     proxyProtocolVersion2,
			wantCommand:     proxyProtocolCommandLocal,
			wantHTTPRequest: true,
		},
	}

	type backendResult struct {
		header              proxyProtocolHeader
		physicalSource      net.Addr
		physicalDestination net.Addr
		method              string
		requestTarget       string
		err                 error
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			resultCh := make(chan backendResult, 1)
			go func() {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					resultCh <- backendResult{err: acceptErr}
					return
				}
				defer connection.Close()
				parsed, readErr := readProxyProtocolHeader(connection)
				if readErr != nil {
					resultCh <- backendResult{err: readErr}
					return
				}
				if parsed.Header == nil {
					resultCh <- backendResult{err: fmt.Errorf("application data arrived before PROXY protocol header")}
					return
				}
				result := backendResult{
					header:              *parsed.Header,
					physicalSource:      connection.RemoteAddr(),
					physicalDestination: connection.LocalAddr(),
				}
				if test.wantHTTPRequest {
					request, requestErr := http.ReadRequest(bufio.NewReader(connection))
					if requestErr != nil {
						result.err = requestErr
						resultCh <- result
						return
					}
					result.method = request.Method
					result.requestTarget = request.URL.RequestURI()
					_ = request.Body.Close()
					_, result.err = io.WriteString(connection, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				}
				resultCh <- result
			}()

			check := config.HealthCheckConfig{Type: test.checkType}
			if test.wantHTTPRequest {
				check.Path = "/ready?deep=1"
			}
			if err := check.Validate(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := probeActiveHealthTarget(ctx, listener.Addr().String(), check, test.proxyProtocol); err != nil {
				t.Fatalf("probeActiveHealthTarget: %v", err)
			}

			select {
			case result := <-resultCh:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if result.header.Version != test.wantVersion || result.header.Command != test.wantCommand {
					t.Fatalf("header = %+v, want version=%d command=%d", result.header, test.wantVersion, test.wantCommand)
				}
				if test.wantCommand == proxyProtocolCommandProxy {
					wantSource, sourceErr := addrPortFromNetAddr(result.physicalSource)
					if sourceErr != nil {
						t.Fatal(sourceErr)
					}
					wantDestination, destinationErr := addrPortFromNetAddr(result.physicalDestination)
					if destinationErr != nil {
						t.Fatal(destinationErr)
					}
					if result.header.Source != wantSource || result.header.Destination != wantDestination {
						t.Fatalf("v1 endpoints = %s -> %s, want %s -> %s", result.header.Source, result.header.Destination, wantSource, wantDestination)
					}
				} else if result.header.Source.IsValid() || result.header.Destination.IsValid() {
					t.Fatalf("v2 LOCAL unexpectedly carried endpoints: %+v", result.header)
				}
				if test.wantHTTPRequest && (result.method != http.MethodGet || result.requestTarget != "/ready?deep=1") {
					t.Fatalf("HTTP request = %q %q", result.method, result.requestTarget)
				}
			case <-ctx.Done():
				t.Fatalf("backend did not observe health probe: %v", ctx.Err())
			}
		})
	}
}

func TestActiveHealthManagerPassesOutboundProxyProtocol(t *testing.T) {
	rule := activeHealthTestRule("proxy-job", "127.0.0.1:9", config.HealthCheckTCP)
	rule.ProxyProtocol = &config.ProxyProtocolConfig{Send: config.ProxyProtocolV2}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
	manager := newActiveHealthManager()
	manager.initialDelay = func(time.Duration) time.Duration { return 0 }
	manager.nextDelay = func(time.Duration) time.Duration { return time.Hour }
	seen := make(chan string, 1)
	manager.probe = func(_ context.Context, _ string, _ config.HealthCheckConfig, proxyProtocol string) error {
		seen <- proxyProtocol
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	manager.start(ctx, []*config.Rule{rule})
	select {
	case got := <-seen:
		if got != config.ProxyProtocolV2 {
			t.Fatalf("proxy protocol = %q, want %q", got, config.ProxyProtocolV2)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active health probe did not start")
	}
	cancel()
	manager.stop()
}

func TestActiveHealthDisabledRuleStartsNoChecker(t *testing.T) {
	rule := &config.Rule{
		Name:    "disabled",
		Targets: []*config.Target{{Address: "127.0.0.1:9"}},
	}
	manager := newActiveHealthManager()
	manager.initialDelay = func(time.Duration) time.Duration { return 0 }
	var probes atomic.Int64
	manager.probe = func(context.Context, string, config.HealthCheckConfig, string) error {
		probes.Add(1)
		return nil
	}
	manager.start(context.Background(), []*config.Rule{rule})
	manager.stop()
	if got := probes.Load(); got != 0 {
		t.Fatalf("disabled health check started %d probes", got)
	}
	if manager.unhealthy(rule, rule.Targets[0].Address) {
		t.Fatal("disabled health check reported target unhealthy")
	}
}

func activeHealthTestRule(name, targetAddress, checkType string) *config.Rule {
	rule := &config.Rule{
		Name:   name,
		Listen: "127.0.0.1:18080",
		Mode:   config.ModeNormal,
		Targets: []*config.Target{{
			Address: targetAddress,
		}},
		HealthCheck: &config.HealthCheckConfig{
			Type:             checkType,
			Interval:         250,
			Timeout:          250,
			FailureThreshold: 2,
			SuccessThreshold: 2,
		},
	}
	if err := rule.Validate(); err != nil {
		panic(fmt.Sprintf("invalid active health test rule: %v", err))
	}
	return rule
}
