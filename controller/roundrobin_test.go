package controller

import (
	"moto/config"
	"sync"
	"testing"
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
