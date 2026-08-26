package controller

import (
	"context"
	"io"
	"moto/config"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestRoundRobinCountersAreIndependentPerRule(t *testing.T) {
	newRule := func(name string) *config.Rule {
		return &config.Rule{
			Name: name,
			Targets: []*config.Target{
				{Address: "one:1"},
				{Address: "two:2"},
			},
		}
	}
	first := newRule("first")
	second := newRule("second")

	for _, want := range []int{0, 1, 0} {
		got, ok := nextRoundRobinIndex(first)
		if !ok || got != want {
			t.Fatalf("first rule index = %d, %v; want %d, true", got, ok, want)
		}
	}
	got, ok := nextRoundRobinIndex(second)
	if !ok || got != 0 {
		t.Fatalf("second rule should start at index 0, got %d, %v", got, ok)
	}
}

func TestRoundRobinCounterIsConcurrentSafe(t *testing.T) {
	rule := &config.Rule{
		Targets: []*config.Target{
			{Address: "one:1"},
			{Address: "two:2"},
			{Address: "three:3"},
			{Address: "four:4"},
		},
	}
	const calls = 400
	counts := make([]int, len(rule.Targets))
	var countsMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			index, ok := nextRoundRobinIndex(rule)
			if !ok {
				t.Error("nextRoundRobinIndex returned false")
				return
			}
			countsMu.Lock()
			counts[index]++
			countsMu.Unlock()
		}()
	}
	wg.Wait()

	for index, count := range counts {
		if count != calls/len(rule.Targets) {
			t.Fatalf("target %d received %d selections, want %d", index, count, calls/len(rule.Targets))
		}
	}
}

func TestRoundRobinSOCKS5CapacityFallbackPreservesHTTPStatus(t *testing.T) {
	bulkhead := newDialBulkhead(2, 1, 0)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()

	const (
		firstTarget  = "capacity.example:443"
		secondTarget = "policy.example:443"
	)
	holder, _, err := bulkhead.acquire(context.Background(), firstTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	proxyConfig := &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH2}}
	rule := &config.Rule{
		Name:     "roundrobin-capacity-status",
		Mode:     config.ModeRoundRobin,
		Protocol: config.ProtocolSOCKS5,
		Timeout:  1000,
		Targets: []*config.Target{
			{Address: firstTarget, ConnectProxy: proxyConfig},
			{Address: secondTarget, ConnectProxy: proxyConfig},
		},
	}
	runtime.connectProxy.dialers = map[string]connectProxyDialFunc{
		config.ConnectProxyH2: func(_ context.Context, target *config.Target, _ string) (net.Conn, error) {
			if target.Address != secondTarget {
				t.Errorf("CONNECT reached unexpected target %q", target.Address)
			}
			return nil, &connectProxyStatusError{
				protocol:   config.ConnectProxyH2,
				target:     target.Address,
				statusCode: http.StatusForbidden,
			}
		},
	}

	motoSide, clientSide := net.Pipe()
	defer clientSide.Close()
	client := &socks5ClientConn{Conn: motoSide, destination: "destination.example:443"}
	done := make(chan struct{})
	go func() {
		runtime.handleRoundrobin(
			withConnectDestination(context.Background(), client.destination),
			client,
			rule,
		)
		close(done)
	}()

	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, reply); err != nil {
		t.Fatalf("read SOCKS5 failure: %v", err)
	}
	if reply[1] != socks5ReplyNotAllowed {
		t.Fatalf("SOCKS5 reply = %#x, want policy denied %#x", reply[1], socks5ReplyNotAllowed)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RoundRobin handler did not stop")
	}
}
