package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"moto/config"
	"sync"
)

const maxRetiredGenerations = 8

// ReloadResult describes the listener and generation transition committed by
// ReloadRules. A successful reload is linearized by one atomic generation
// pointer swap; existing streams retain a lease on their previous generation.
type ReloadResult struct {
	FromGeneration uint64
	ToGeneration   uint64
	Added          []string
	Reused         []string
	Removed        []string
	Noop           bool
}

type ruleBinding struct {
	rule *config.Rule
}

// routingGeneration is immutable after publication except for its lease gate.
// The gate prevents cleanup from racing an acceptor that read the old pointer
// just before a reload committed.
type routingGeneration struct {
	id          uint64
	fingerprint [sha256.Size]byte
	rules       []*config.Rule
	bindings    map[string]*ruleBinding
	runtime     *routingRuntime
	done        chan struct{}

	mu                sync.Mutex
	retired           bool
	backgroundStopped bool
	refs              int
	started           sync.Once
	cleaning          sync.Once
	metricsRegistered bool
}

func cloneRuntimeRules(rules []*config.Rule, allowEphemeral bool) ([]*config.Rule, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	encoded, err := json.Marshal(rules)
	if err != nil {
		return nil, zero, fmt.Errorf("encode rules snapshot: %w", err)
	}
	var clone []*config.Rule
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return nil, zero, fmt.Errorf("decode rules snapshot: %w", err)
	}
	if allowEphemeral {
		err = config.PrepareRuntimeRules(clone)
	} else {
		probe := &config.Config{
			Log:   config.LogConfig{Level: "info"},
			Rules: clone,
		}
		err = probe.Validate()
	}
	if err != nil {
		return nil, zero, err
	}
	canonical, err := json.Marshal(clone)
	if err != nil {
		return nil, zero, fmt.Errorf("encode validated rules snapshot: %w", err)
	}
	return clone, sha256.Sum256(canonical), nil
}

func newRoutingGeneration(
	id uint64,
	rules []*config.Rule,
	listenerKeys []string,
	sharedPrewarmDialSem chan struct{},
	sharedTrafficDials *dialBulkhead,
) (*routingGeneration, error) {
	if len(listenerKeys) != len(rules) {
		return nil, fmt.Errorf("listener key count %d does not match rule count %d", len(listenerKeys), len(rules))
	}
	clone, fingerprint, err := cloneRuntimeRules(rules, true)
	if err != nil {
		return nil, err
	}
	generation := &routingGeneration{
		id:          id,
		fingerprint: fingerprint,
		rules:       clone,
		bindings:    make(map[string]*ruleBinding, len(clone)),
		runtime:     newRoutingRuntimeWithDialResources(sharedPrewarmDialSem, sharedTrafficDials),
		done:        make(chan struct{}),
	}
	for index, rule := range clone {
		key := listenerKeys[index]
		if key == "" {
			generation.retire()
			return nil, fmt.Errorf("rules[%d]: empty listener key", index)
		}
		if _, duplicate := generation.bindings[key]; duplicate {
			generation.retire()
			return nil, fmt.Errorf("rules[%d]: duplicate listener key %q", index, key)
		}
		generation.bindings[key] = &ruleBinding{rule: rule}
	}
	processMetrics.registerRules(clone)
	generation.metricsRegistered = true
	return generation, nil
}

func (generation *routingGeneration) tryAcquire() bool {
	if generation == nil {
		return false
	}
	generation.mu.Lock()
	defer generation.mu.Unlock()
	if generation.retired {
		return false
	}
	generation.refs++
	return true
}

func (generation *routingGeneration) release() {
	if generation == nil {
		return
	}
	cleanup := false
	generation.mu.Lock()
	if generation.refs > 0 {
		generation.refs--
	}
	cleanup = generation.retired && generation.backgroundStopped && generation.refs == 0
	generation.mu.Unlock()
	if cleanup {
		generation.cleanup()
	}
}

func (generation *routingGeneration) startBackground() {
	if generation == nil {
		return
	}
	generation.started.Do(func() {
		generation.runtime.health.start(generation.runtime.ctx, generation.rules)
		for _, rule := range generation.rules {
			if rule.Prewarm {
				generation.runtime.prewarm.init(rule)
			}
		}
	})
}

func (generation *routingGeneration) retire() {
	if generation == nil {
		return
	}
	generation.mu.Lock()
	if generation.retired {
		generation.mu.Unlock()
		return
	}
	generation.retired = true
	generation.mu.Unlock()

	// Stop background I/O immediately; established streams retain route state
	// until their generation leases have drained.
	generation.runtime.stopBackground()
	generation.mu.Lock()
	generation.backgroundStopped = true
	cleanup := generation.refs == 0
	generation.mu.Unlock()
	if cleanup {
		generation.cleanup()
	}
}

func (generation *routingGeneration) cleanup() {
	generation.cleaning.Do(func() {
		generation.runtime.clear(generation.rules)
		if generation.metricsRegistered {
			processMetrics.unregisterRules(generation.rules)
		}
		close(generation.done)
	})
}
