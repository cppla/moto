package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"sync"
	"testing"
)

func TestRoutingRuntimeExcludesActivelyUnhealthyTarget(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	check := config.HealthCheckConfig{FailureThreshold: 1, SuccessThreshold: 1}
	rule := &config.Rule{
		Name:        "active-routing",
		Listen:      "127.0.0.1:19090",
		Mode:        config.ModeBoost,
		HealthCheck: &check,
		Targets: []*config.Target{
			{Address: "unhealthy:443"},
			{Address: "healthy:443"},
		},
	}
	runtime.health.observe(activeHealthKey{rule: rule, address: "unhealthy:443"}, check, false)
	if _, _, err := runtime.outboundDialRoute(context.Background(), rule, "unhealthy:443"); !errors.Is(err, ErrActiveHealthUnhealthy) {
		t.Fatalf("outboundDialRoute error = %v", err)
	}

	var mu sync.Mutex
	var dialed []string
	winner, err := runtime.raceBoostTargets(context.Background(), rule, func(_ context.Context, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = winner.conn.Close()
	if winner.addr != "healthy:443" {
		t.Fatalf("winner = %q", winner.addr)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, address := range dialed {
		if address == "unhealthy:443" {
			t.Fatalf("actively unhealthy target was dialed: %v", dialed)
		}
	}
}
