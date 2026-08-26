package controller

import (
	"context"
	"encoding/json"
	"moto/config"
	"sync"
	"time"
)

// routingRuntime owns every mutable routing decision for one server
// generation. Keeping it separate from process metrics lets multiple embedded
// servers and draining reload generations coexist without sharing circuits,
// winner caches, prewarm sockets, or round-robin cursors.
type routingRuntime struct {
	ctx          context.Context
	cancel       context.CancelFunc
	routes       *routeHealthRegistry
	health       *activeHealthManager
	boost        *boostRuntime
	prewarm      *prewarmManager
	connectProxy *connectProxyManager
	trafficDials *dialBulkhead
	roundRobin   sync.Map // map[*config.Rule]*atomic.Uint64
}

type boostWinnerCacheRegistry struct {
	sync.Mutex
	entries        map[string]boostWinnerEntry
	nextGeneration uint64
}

type boostRuntime struct {
	cache        *boostWinnerCacheRegistry
	revalidating sync.Map // map[string]*boostRevalidation
}

type prewarmManager struct {
	runtime *routingRuntime

	mu      sync.Mutex
	pools   map[string]*prewarmPool
	dialSem chan struct{}
}

func newRoutingRuntime() *routingRuntime {
	return newRoutingRuntimeWithDialResources(
		make(chan struct{}, prewarmGlobalDialLimit),
		newTrafficDialBulkhead(),
	)
}

func newRoutingRuntimeWithDialResources(prewarmDialSem chan struct{}, trafficDials *dialBulkhead) *routingRuntime {
	if prewarmDialSem == nil {
		prewarmDialSem = make(chan struct{}, prewarmGlobalDialLimit)
	}
	if trafficDials == nil {
		trafficDials = newTrafficDialBulkhead()
	}
	ctx, cancel := context.WithCancel(context.Background())
	connectProxy := newConnectProxyManager()
	runtime := &routingRuntime{
		ctx:          ctx,
		cancel:       cancel,
		routes:       newRouteHealthRegistry(connectProxy.http3RoutePenalty),
		health:       newActiveHealthManager(),
		connectProxy: connectProxy,
		trafficDials: trafficDials,
		boost: &boostRuntime{
			cache: &boostWinnerCacheRegistry{entries: make(map[string]boostWinnerEntry)},
		},
	}
	runtime.routes.protocolProbeClaim = connectProxy.claimHTTP3BoostProbe
	runtime.routes.protocolProbeRelease = connectProxy.releaseHTTP3BoostProbe
	runtime.prewarm = &prewarmManager{
		runtime: runtime,
		pools:   make(map[string]*prewarmPool),
		dialSem: prewarmDialSem,
	}
	return runtime
}

func (runtime *routingRuntime) stopBackground() {
	if runtime == nil {
		return
	}
	if runtime.cancel != nil {
		runtime.cancel()
	}
	runtime.prewarm.shutdown()
	runtime.health.stop()
	runtime.connectProxy.retire()
}

type unchangedRulePair struct {
	old *config.Rule
	new *config.Rule
}

// inheritUnchangedState preserves learned decisions only for rules whose full
// serialized configuration is unchanged. Connections already leased from the
// old generation keep using its independent runtime; copied state contains no
// sockets, goroutines, in-flight attempts, or half-open ownership.
func (runtime *routingRuntime) inheritUnchangedState(previous *routingRuntime, oldRules, newRules []*config.Rule) {
	if runtime == nil || previous == nil || runtime == previous {
		return
	}
	pairs := unchangedRulePairs(oldRules, newRules)
	if len(pairs) == 0 {
		return
	}

	previous.routes.Lock()
	runtime.routes.Lock()
	for _, pair := range pairs {
		for _, target := range pair.new.Targets {
			key, ok := routeKey(pair.old, target.Address)
			if !ok {
				continue
			}
			state := previous.routes.states[key]
			if state == nil {
				continue
			}
			clone := *state
			clone.halfOpen = false
			clone.halfOpenAttempt = 0
			clone.minValidAttempt = 0
			runtime.routes.states[key] = &clone
		}
	}
	runtime.routes.Unlock()
	previous.routes.Unlock()

	now := time.Now()
	previous.boost.cache.Lock()
	runtime.boost.cache.Lock()
	for _, pair := range pairs {
		key := boostRuleKey(pair.old)
		entry, ok := previous.boost.cache.entries[key]
		if ok && now.Before(entry.expires) {
			runtime.boost.cache.entries[key] = entry
			if entry.generation > runtime.boost.cache.nextGeneration {
				runtime.boost.cache.nextGeneration = entry.generation
			}
		}
	}
	runtime.boost.cache.Unlock()
	previous.boost.cache.Unlock()

	previous.health.mu.RLock()
	runtime.health.mu.Lock()
	for _, pair := range pairs {
		for _, target := range pair.new.Targets {
			state := previous.health.states[activeHealthKey{rule: pair.old, address: target.Address}]
			if state == nil {
				continue
			}
			clone := *state
			runtime.health.states[activeHealthKey{rule: pair.new, address: target.Address}] = &clone
		}
	}
	runtime.health.mu.Unlock()
	previous.health.mu.RUnlock()
}

func unchangedRulePairs(oldRules, newRules []*config.Rule) []unchangedRulePair {
	oldByConfig := make(map[string][]*config.Rule, len(oldRules))
	for _, rule := range oldRules {
		encoded, err := json.Marshal(rule)
		if err == nil {
			key := string(encoded)
			oldByConfig[key] = append(oldByConfig[key], rule)
		}
	}
	pairs := make([]unchangedRulePair, 0, min(len(oldRules), len(newRules)))
	for _, rule := range newRules {
		encoded, err := json.Marshal(rule)
		if err != nil {
			continue
		}
		key := string(encoded)
		candidates := oldByConfig[key]
		if len(candidates) == 0 {
			continue
		}
		pairs = append(pairs, unchangedRulePair{old: candidates[0], new: rule})
		oldByConfig[key] = candidates[1:]
	}
	return pairs
}

// The package-level routing helpers remain as compatibility entry points for
// callers and focused unit tests. Production Server instances always allocate
// their own runtime and never use this process-wide fallback.
var defaultRoutingRuntime = newRoutingRuntime()

var (
	routeHealth       = defaultRoutingRuntime.routes
	boostWinnerCache  = defaultRoutingRuntime.boost.cache
	boostRevalidating = &defaultRoutingRuntime.boost.revalidating
	prewarmPoolsMu    = &defaultRoutingRuntime.prewarm.mu
	prewarmPools      = defaultRoutingRuntime.prewarm.pools
)

// clearRuntimeRoutingState removes gauges and routing decisions owned by one
// compatibility-runtime configuration after all of its work has stopped.
func clearRuntimeRoutingState(rules []*config.Rule) {
	defaultRoutingRuntime.clear(rules)
}

func (runtime *routingRuntime) clear(rules []*config.Rule) {
	if runtime == nil {
		return
	}
	runtime.waitBoostRevalidations(rules)
	runtime.routes.clear(rules)
	runtime.connectProxy.close()

	runtime.boost.cache.Lock()
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		key := boostRuleKey(rule)
		delete(runtime.boost.cache.entries, key)
		runtime.boost.revalidating.Delete(key)
		runtime.roundRobin.Delete(rule)
	}
	runtime.boost.cache.Unlock()
}
