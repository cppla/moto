package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type sequentialConnectProxyCase struct {
	name       string
	block      string
	blocked    int
	rejections int
	start      int
	duplicate  bool
	globalFull bool
	canceled   bool
	deadline   bool
}

func TestConnectProxySequentialLocalFailuresPreserveHTTPStatusSeverity(t *testing.T) {
	capacity := &dialBulkheadError{target: "proxy.example:443", saturated: true, scope: dialSaturationGlobal}
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "global_capacity", err: capacity, want: true},
		{name: "local_exclusions", err: errors.Join(ErrCircuitOpen, ErrActiveHealthUnhealthy, capacity), want: true},
		{name: "cancellation", err: errors.Join(ErrCircuitOpen, context.Canceled), want: true},
		{name: "transport_deadline", err: context.DeadlineExceeded},
		{name: "transport_error", err: errors.Join(capacity, errors.New("TCP connection refused"))},
		{name: "wrapped_transport_error", err: fmt.Errorf("wrapped: %w", errors.Join(capacity, errors.New("TCP connection refused")))},
		{name: "policy_status", err: errors.Join(capacity, &connectProxyStatusError{statusCode: http.StatusForbidden})},
		{name: "service_status", err: fmt.Errorf("wrapped: %w", errors.Join(capacity, &connectProxyStatusError{statusCode: http.StatusServiceUnavailable}))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := connectProxySequentialFailureIsLocal(test.err); got != test.want {
				t.Fatalf("local failure=%v want %v", got, test.want)
			}
		})
	}
}

func TestSOCKS5SequentialAdmissionBudgetUsesRealH2Attempts(t *testing.T) {
	cases := []sequentialConnectProxyCase{{name: "no_local_exclusions"}}
	for _, block := range []string{"circuit", "active_health", "target_capacity"} {
		for count := 1; count <= 2; count++ {
			cases = append(cases, sequentialConnectProxyCase{
				name: fmt.Sprintf("%s_%d", block, count), block: block, blocked: count,
			})
		}
	}
	for count := 0; count <= 2; count++ {
		cases = append(cases, sequentialConnectProxyCase{
			name: fmt.Sprintf("two_real_503_after_%d_exclusions", count), block: "circuit", blocked: count, rejections: 2,
		})
	}
	cases = append(cases,
		sequentialConnectProxyCase{name: "one_real_503_then_success", rejections: 1},
		sequentialConnectProxyCase{name: "duplicate_address_only_attempted_once", rejections: 1, duplicate: true},
		sequentialConnectProxyCase{name: "global_capacity_stops_without_network", globalFull: true},
		sequentialConnectProxyCase{name: "canceled_parent_stops_without_network", canceled: true},
		sequentialConnectProxyCase{name: "overall_deadline_is_not_restarted", deadline: true},
	)
	for _, mode := range []string{config.ModeNormal, config.ModeRoundRobin} {
		for _, test := range cases {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				runSequentialConnectProxyCase(t, mode, test)
			})
		}
	}
	t.Run("roundrobin/cyclic_fallback_skips_two_local_exclusions", func(t *testing.T) {
		runSequentialConnectProxyCase(t, config.ModeRoundRobin, sequentialConnectProxyCase{
			name: "cyclic", block: "circuit", blocked: 2, start: 1,
		})
	})
}

func runSequentialConnectProxyCase(t *testing.T, mode string, test sequentialConnectProxyCase) {
	t.Helper()
	count := max(3, test.blocked+test.rejections+1)
	calls := make([]atomic.Int64, count)
	proxies := make([]*httptest.Server, count)
	rejects := make(map[int]bool)
	for offset := 0; offset < test.rejections; offset++ {
		rejects[(test.start+test.blocked+offset)%count] = true
	}
	for index := range proxies {
		proxies[index] = newHTTP2ConnectTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			calls[index].Add(1)
			if request.ProtoMajor != 2 || request.Method != http.MethodConnect || request.Host != "destination.example:443" {
				t.Errorf("upstream received %s %s %s", request.Proto, request.Method, request.Host)
			}
			if test.deadline {
				<-request.Context().Done()
				return
			}
			if rejects[index] {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "H2-READY")
			writer.(http.Flusher).Flush()
			_, _ = io.Copy(io.Discard, request.Body)
		})
	}
	globalLimit := count + 1
	if test.globalFull {
		globalLimit = 1
	}
	bulkhead := newDialBulkhead(globalLimit, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	installHTTP2ConnectTestManager(runtime, proxies[0])
	rule := &config.Rule{
		Name: mode + "-" + test.name, Listen: "127.0.0.1:1080", Mode: mode,
		Protocol: config.ProtocolSOCKS5, Timeout: 2000, MaxConnections: 16, MaxConnectionsPerIP: 16,
	}
	for _, proxy := range proxies {
		target := http2ConnectTestTarget(proxy, "", "")
		target.ConnectProxy.BasicAuth = nil
		rule.Targets = append(rule.Targets, target)
	}
	if test.deadline {
		rule.Timeout = 300
	}
	if err := rule.Validate(); err != nil {
		t.Fatal(err)
	}
	if test.duplicate {
		// Config validation rejects duplicates, but the runtime budget must
		// still count distinct targets if an embedded caller bypasses it.
		rule.Targets = append([]*config.Target{rule.Targets[0]}, rule.Targets...)
	}
	for offset := 0; offset < test.blocked; offset++ {
		target := rule.Targets[(test.start+offset)%count]
		switch test.block {
		case "circuit":
			for failure := 0; failure < routeFailureThreshold; failure++ {
				attempt, err := runtime.routes.begin(rule, target.Address, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				routeObserve(attempt, 0, errors.New("independent setup failure"), time.Now())
			}
		case "active_health":
			runtime.health.states[activeHealthKey{rule: rule, address: target.Address}] = &activeHealthState{unhealthy: true}
		case "target_capacity":
			permit, _, err := bulkhead.acquire(context.Background(), target.Address)
			if err != nil {
				t.Fatal(err)
			}
			defer permit.release()
		}
	}
	if test.globalFull {
		permit, _, err := bulkhead.acquire(context.Background(), "held.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer permit.release()
	}
	for advance := 0; advance < test.start; advance++ {
		runtime.nextRoundRobinIndex(rule)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if test.canceled {
		cancel()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		accepted, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		runtime.dispatch(ctx, accepted, rule)
		done <- nil
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	started := time.Now()
	performSOCKS5DomainRequest(t, client, "destination.example", 443)
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	wantSuccess := test.rejections < 2 && !test.globalFull && !test.canceled && !test.deadline
	if (reply[1] == socks5ReplySuccess) != wantSuccess {
		t.Fatalf("SOCKS reply=%d wantSuccess=%v", reply[1], wantSuccess)
	}
	if wantSuccess {
		var banner [8]byte
		if _, err := io.ReadFull(client, banner[:]); err != nil || string(banner[:]) != "H2-READY" {
			t.Fatalf("real H2 relay banner=%q err=%v", banner, err)
		}
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS handler did not stop within its bounded decision")
	}
	if (test.globalFull || test.canceled || test.deadline) && time.Since(started) > time.Second {
		t.Fatalf("local exclusion/deadline took %s", time.Since(started))
	}
	got := make([]int64, count)
	for index := range calls {
		got[index] = calls[index].Load()
	}
	if test.deadline {
		if got[0] > 1 {
			t.Fatalf("timed-out target was retried: %v", got)
		}
		for _, calls := range got[1:] {
			if calls != 0 {
				t.Fatalf("deadline was reset for later targets: %v", got)
			}
		}
		return
	}
	want := make([]int64, count)
	if !test.globalFull && !test.canceled {
		attempts := min(2, test.rejections+1)
		for offset := 0; offset < attempts; offset++ {
			want[(test.start+test.blocked+offset)%count] = 1
		}
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("actual upstream H2 CONNECT calls=%v want=%v", got, want)
		}
	}
}
