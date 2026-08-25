package controller

import (
	"context"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type retryOnceTestListener struct {
	calls int
}

func (listener *retryOnceTestListener) Accept() (net.Conn, error) {
	listener.calls++
	if listener.calls == 1 {
		return nil, syscall.EMFILE
	}
	return nil, net.ErrClosed
}

func (*retryOnceTestListener) Close() error   { return nil }
func (*retryOnceTestListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptLoopRetriesTemporaryFailure(t *testing.T) {
	listener := &retryOnceTestListener{}
	server := &Server{}
	if err := server.acceptLoop(context.Background(), &listenerState{
		key:      "temporary-listener",
		listener: listener,
	}); err != nil {
		t.Fatalf("acceptLoop() error = %v", err)
	}
	if listener.calls != 2 {
		t.Fatalf("Accept calls = %d, want retry after temporary failure", listener.calls)
	}
}

func TestRemoteIPNormalizesIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		addr net.Addr
		want string
	}{
		{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}, want: "192.0.2.10"},
		{addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 1234}, want: "2001:db8::10"},
	}

	for _, test := range tests {
		got, err := remoteIP(test.addr)
		if err != nil {
			t.Fatalf("remoteIP(%v): %v", test.addr, err)
		}
		if got.String() != test.want {
			t.Fatalf("remoteIP(%v) = %s, want %s", test.addr, got, test.want)
		}
	}
}

func TestNewServerRejectsEmptyAndNilRules(t *testing.T) {
	if _, err := NewServer(nil); err == nil {
		t.Fatal("NewServer(nil) succeeded")
	}
	if _, err := NewServer([]*config.Rule{nil}); err == nil {
		t.Fatal("NewServer with a nil rule succeeded")
	}
}

func TestNewServerRejectsUnsafeRulesFromLibraryCallers(t *testing.T) {
	valid := func() *config.Rule {
		return &config.Rule{
			Name:                "library",
			Listen:              "127.0.0.1:0",
			Mode:                config.ModeNormal,
			MaxConnections:      2,
			MaxConnectionsPerIP: 1,
			Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*config.Rule)
	}{
		{name: "unknown mode", mutate: func(rule *config.Rule) { rule.Mode = "mystery" }},
		{name: "no targets", mutate: func(rule *config.Rule) { rule.Targets = nil }},
		{name: "nil target", mutate: func(rule *config.Rule) { rule.Targets[0] = nil }},
		{name: "empty target", mutate: func(rule *config.Rule) { rule.Targets[0].Address = "" }},
		{name: "negative rule limit", mutate: func(rule *config.Rule) { rule.MaxConnections = -1 }},
		{name: "negative per IP limit", mutate: func(rule *config.Rule) { rule.MaxConnectionsPerIP = -1 }},
		{name: "per IP above rule", mutate: func(rule *config.Rule) { rule.MaxConnectionsPerIP = 3 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := valid()
			test.mutate(rule)
			if server, err := NewServer([]*config.Rule{rule}); err == nil {
				server.Close()
				t.Fatal("NewServer accepted an unsafe rule")
			}
		})
	}
}

func TestNewServerPreparesLibraryAccessPoliciesAndRegex(t *testing.T) {
	rule := &config.Rule{
		Name:      "prepared-library-rule",
		Listen:    "127.0.0.1:0",
		Mode:      config.ModeRegex,
		Blacklist: map[string]bool{"127.0.0.1": true},
		Allowlist: []string{"127.0.0.0/8"},
		Targets: []*config.Target{{
			Address: "127.0.0.1:9",
			Regexp:  "^GET ",
		}},
	}
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()
	if !rule.Blocked(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("constructor left blacklist unprepared and fail-open")
	}
	if !rule.Allows(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("constructor did not compile allowlist")
	}
	if rule.Targets[0].Re == nil || !rule.Targets[0].Re.MatchString("GET / HTTP/1.1") {
		t.Fatal("constructor did not compile regex target")
	}
}

func TestNewServerWithMetricsRejectsNonLoopbackAddress(t *testing.T) {
	rule := &config.Rule{
		Name:                "metrics-security",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		MaxConnections:      1,
		MaxConnectionsPerIP: 1,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	for _, listen := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "localhost:9090"} {
		if server, err := NewServerWithMetrics([]*config.Rule{rule}, listen); err == nil {
			server.Close()
			t.Fatalf("NewServerWithMetrics accepted %q", listen)
		}
	}
}

func TestListenerAdmissionEnforcesPerIPAndRuleLimits(t *testing.T) {
	rule := &config.Rule{MaxConnections: 2, MaxConnectionsPerIP: 1}
	admission := &listenerAdmission{perIP: make(map[netip.Addr]int)}
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")
	ip3 := netip.MustParseAddr("192.0.2.3")

	if !admission.reserveRule(rule) || !admission.assignReservedIP(rule, ip1) {
		t.Fatal("first connection should be admitted")
	}
	if !admission.reserveRule(rule) {
		t.Fatal("second pending connection should fit the rule limit")
	}
	if admission.assignReservedIP(rule, ip1) {
		t.Fatal("second connection from the same IP should be rejected")
	}
	admission.releasePending()
	if !admission.reserveRule(rule) || !admission.assignReservedIP(rule, ip2) {
		t.Fatal("second global connection should be admitted")
	}
	if admission.reserveRule(rule) {
		t.Fatal("connection beyond the global limit should be rejected")
	}

	admission.releaseRule(ip1)
	if !admission.reserveRule(rule) || !admission.assignReservedIP(rule, ip3) {
		t.Fatal("released capacity should be reusable")
	}
	admission.releaseRule(ip2)
	admission.releaseRule(ip3)
}

func TestServerEnforcesProcessConnectionLimit(t *testing.T) {
	server := &Server{globalLimit: make(chan struct{}, 2)}
	for i := 0; i < 2; i++ {
		if !server.admitGlobal() {
			t.Fatalf("connection %d within process limit was rejected", i+1)
		}
	}
	if server.admitGlobal() {
		t.Fatal("connection beyond process limit was admitted")
	}
	server.releaseGlobal()
	if !server.admitGlobal() {
		t.Fatal("released process capacity was not reusable")
	}
	server.releaseGlobal()
	server.releaseGlobal()
}

func TestCloseActiveConnectionsCancelsHandlerContext(t *testing.T) {
	forceCtx, forceCancel := context.WithCancel(context.Background())
	server := &Server{forceCtx: forceCtx, forceCancel: forceCancel}
	client, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	server.active.Store(client, context.CancelFunc(cancel))
	server.closeActiveConnections()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("forced connection close did not cancel its handler context")
	}
	if _, err := client.Write([]byte("closed")); err == nil {
		t.Fatal("forced connection close left the inbound socket writable")
	}
	server.active.Delete(client)
}

func TestForcedShutdownCoversConnectionRegisteredAfterBroadcast(t *testing.T) {
	forceCtx, forceCancel := context.WithCancel(context.Background())
	server := &Server{forceCtx: forceCtx, forceCancel: forceCancel}
	server.closeActiveConnections()

	client, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel, stopForcedClose := server.newConnectionContext(context.Background(), client)
	defer cancel()
	defer stopForcedClose()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection registered after forced shutdown was not cancelled")
	}
	if _, err := client.Write([]byte("closed")); err == nil {
		t.Fatal("connection registered after forced shutdown remained writable")
	}
}

func TestServerStopsWhenContextIsCancelled(t *testing.T) {
	rule := &config.Rule{
		Name:                "test",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		Timeout:             100,
		MaxConnections:      4,
		MaxConnectionsPerIP: 2,
		Targets: []*config.Target{
			{Address: "127.0.0.1:9"},
		},
	}

	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
}

func TestServerCloseStopsServeWithoutContextCancellation(t *testing.T) {
	rule := &config.Rule{
		Name:                "explicit-close",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		Timeout:             100,
		MaxConnections:      2,
		MaxConnectionsPerIP: 1,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for !server.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.Ready() {
		t.Fatal("server did not become ready")
	}
	server.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not stop Serve")
	}
}

func TestServeReturnsWhenServerWasAlreadyClosed(t *testing.T) {
	rule := &config.Rule{
		Name:                "closed-before-serve",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		MaxConnections:      1,
		MaxConnectionsPerIP: 1,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve blocked after Close")
	}
}

func TestCloseBeforeServeReleasesMetricsListener(t *testing.T) {
	rule := &config.Rule{
		Name:                "metrics-close-before-serve",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		MaxConnections:      1,
		MaxConnectionsPerIP: 1,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	server, err := NewServerWithMetrics([]*config.Rule{rule}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsAddr := server.metricsListener.Addr().String()
	server.Close()

	rebound, err := net.Listen("tcp", metricsAddr)
	if err != nil {
		t.Fatalf("metrics listener remained bound after Close-before-Serve: %v", err)
	}
	_ = rebound.Close()
	if server.Ready() {
		t.Fatal("closed server reported ready")
	}
	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve after Close: %v", err)
	}
}

func TestMetricsHandlerDrainTracksActiveRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := &Server{
		metricsHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			close(started)
			<-release
		}),
	}
	requestDone := make(chan struct{})
	go func() {
		server.serveObservability(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
		close(requestDone)
	}()
	<-started
	server.closeMetricsHandlers()

	waitDone := make(chan bool, 1)
	go func() { waitDone <- server.waitForMetricsHandlers(time.Second) }()
	select {
	case <-waitDone:
		t.Fatal("active metrics request was not included in drain wait")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case waited := <-waitDone:
		if !waited {
			t.Fatal("metrics handler drain timed out after request completed")
		}
	case <-time.After(time.Second):
		t.Fatal("metrics handler drain did not finish")
	}
	<-requestDone

	rejected := httptest.NewRecorder()
	server.serveObservability(rejected, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("request admitted after metrics handler close: status=%d", rejected.Code)
	}
}

func TestConcurrentServeAndCloseNeverRepublishesReadiness(t *testing.T) {
	const iterations = 64
	for iteration := 0; iteration < iterations; iteration++ {
		rule := &config.Rule{
			Name:                "concurrent-start-close",
			Listen:              "127.0.0.1:0",
			Mode:                config.ModeNormal,
			MaxConnections:      1,
			MaxConnectionsPerIP: 1,
			Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
		}
		server, err := NewServer([]*config.Rule{rule})
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(entered)
			done <- server.Serve(context.Background())
		}()
		<-entered
		runtime.Gosched()
		server.Close()

		deadline := time.After(2 * time.Second)
		for {
			if server.Ready() {
				t.Fatalf("iteration %d: Ready became true after Close returned", iteration)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("iteration %d: Serve: %v", iteration, err)
				}
				goto nextIteration
			case <-deadline:
				t.Fatalf("iteration %d: Serve did not stop", iteration)
			default:
				runtime.Gosched()
			}
		}
	nextIteration:
	}
}

func TestServerRejectsClientOutsideAllowlist(t *testing.T) {
	rule := &config.Rule{
		Name:                "restricted",
		Listen:              "127.0.0.1:12345",
		Mode:                config.ModeNormal,
		Allowlist:           []string{"192.0.2.0/24"},
		MaxConnections:      4,
		MaxConnectionsPerIP: 2,
		Targets: []*config.Target{
			{Address: "127.0.0.1:9"},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate rule: %v", err)
	}
	// Port zero is used only by this integration test after validation.
	rule.Listen = "127.0.0.1:0"

	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	client, err := net.Dial("tcp", server.listeners[0].listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("dial server: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("connection outside allowlist remained open")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for allowlist rejection")
	}
	_ = client.Close()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerObservabilityLifecycle(t *testing.T) {
	rule := &config.Rule{
		Name:                "observable",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		Timeout:             100,
		MaxConnections:      4,
		MaxConnectionsPerIP: 2,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	server, err := NewServerWithMetrics([]*config.Rule{rule}, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewServerWithMetrics: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	client := &http.Client{Timeout: time.Second}
	baseURL := "http://" + server.metricsListener.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, requestErr := client.Get(baseURL + "/readyz")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("readiness endpoint did not become ready: %v", requestErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	response, err := client.Get(baseURL + "/metrics")
	if err != nil {
		cancel()
		t.Fatalf("GET /metrics: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		cancel()
		t.Fatalf("read metrics body: %v", err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "moto_route_circuit_open") {
		cancel()
		t.Fatalf("metrics response = (%d, %q)", response.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
	if server.Ready() {
		t.Fatal("server remained ready after shutdown")
	}
}

func TestNewServerWithMetricsFailsAtomically(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	rule := &config.Rule{
		Name:                "atomic-metrics",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		MaxConnections:      1,
		MaxConnectionsPerIP: 1,
		Targets:             []*config.Target{{Address: "127.0.0.1:9"}},
	}
	if server, err := NewServerWithMetrics([]*config.Rule{rule}, occupied.Addr().String()); err == nil {
		server.Close()
		t.Fatal("NewServerWithMetrics succeeded with an occupied metrics port")
	}
}
