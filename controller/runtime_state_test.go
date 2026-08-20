package controller

import (
	"errors"
	"moto/config"
	"testing"
	"time"
)

func TestRoutingRuntimeIsolation(t *testing.T) {
	runtimeA := newRoutingRuntime()
	runtimeB := newRoutingRuntime()
	rule := &config.Rule{
		Name:   "shared-name",
		Listen: "127.0.0.1:19001",
		Mode:   config.ModeBoost,
		Targets: []*config.Target{
			{Address: "first:443"},
			{Address: "second:443"},
		},
	}

	now := time.Unix(1_900_000_000, 0)
	for index := 0; index < routeFailureThreshold; index++ {
		attempt, err := runtimeA.routes.begin(rule, "first:443", now.Add(time.Duration(index)*time.Second))
		if err != nil {
			t.Fatalf("runtime A begin attempt %d: %v", index, err)
		}
		routeObserve(attempt, time.Millisecond, errors.New("dial failed"), now.Add(time.Duration(index)*time.Second))
	}
	if !runtimeA.routes.snapshot(rule, "first:443", now.Add(time.Minute)).CircuitOpen {
		t.Fatal("runtime A circuit did not open")
	}
	if got := runtimeB.routes.snapshot(rule, "first:443", now.Add(time.Minute)); got.Observed || got.CircuitOpen {
		t.Fatalf("runtime B inherited route state: %+v", got)
	}

	key := boostRuleKey(rule)
	runtimeA.storeBoostWinner(key, "first:443")
	if _, ok := runtimeB.loadBoostWinnerToken(key); ok {
		t.Fatal("runtime B inherited runtime A boost winner")
	}

	if index, ok := runtimeA.nextRoundRobinIndex(rule); !ok || index != 0 {
		t.Fatalf("runtime A first round-robin index = %d, ok = %t", index, ok)
	}
	if index, ok := runtimeA.nextRoundRobinIndex(rule); !ok || index != 1 {
		t.Fatalf("runtime A second round-robin index = %d, ok = %t", index, ok)
	}
	if index, ok := runtimeB.nextRoundRobinIndex(rule); !ok || index != 0 {
		t.Fatalf("runtime B inherited round-robin cursor: index = %d, ok = %t", index, ok)
	}

	pool := runtimeA.prewarm.newPool("first:443", 1)
	runtimeA.prewarm.pools[pool.addr] = pool
	if _, ok := runtimeB.prewarm.pools[pool.addr]; ok {
		t.Fatal("runtime B inherited runtime A prewarm pool")
	}
}

func TestBoostWinnerGenerationPreventsStaleEviction(t *testing.T) {
	runtime := newRoutingRuntime()
	key := "boost-generation"
	stale := runtime.storeBoostWinner(key, "old:443")
	current := runtime.storeBoostWinner(key, "new:443")

	if runtime.deleteBoostWinnerIfCurrent(stale) {
		t.Fatal("stale relay result deleted a newer boost winner")
	}
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != current.addr || entry.generation != current.generation {
		t.Fatalf("current winner changed after stale eviction: entry = %+v, ok = %t", entry, ok)
	}
	if !runtime.deleteBoostWinnerIfCurrent(current) {
		t.Fatal("current winner token did not evict itself")
	}
	if _, ok := runtime.loadBoostWinnerToken(key); ok {
		t.Fatal("winner remained after current-token eviction")
	}
}
