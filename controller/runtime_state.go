package controller

import (
	"context"
	"moto/config"
	"sync"
)

// routingRuntime owns every mutable routing decision for one server
// generation. Keeping it separate from process metrics lets multiple embedded
// servers and draining reload generations coexist without sharing circuits,
// winner caches, prewarm sockets, or round-robin cursors.
type routingRuntime struct {
	ctx        context.Context
	cancel     context.CancelFunc
	routes     *routeHealthRegistry
	health     *activeHealthManager
	boost      *boostRuntime
	prewarm    *prewarmManager
	roundRobin sync.Map // map[*config.Rule]*atomic.Uint64
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
	return newRoutingRuntimeWithDialSem(make(chan struct{}, prewarmGlobalDialLimit))
}

func newRoutingRuntimeWithDialSem(dialSem chan struct{}) *routingRuntime {
	if dialSem == nil {
		dialSem = make(chan struct{}, prewarmGlobalDialLimit)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &routingRuntime{
		ctx:    ctx,
		cancel: cancel,
		routes: newRouteHealthRegistry(),
		health: newActiveHealthManager(),
		boost: &boostRuntime{
			cache: &boostWinnerCacheRegistry{entries: make(map[string]boostWinnerEntry)},
		},
	}
	runtime.prewarm = &prewarmManager{
		runtime: runtime,
		pools:   make(map[string]*prewarmPool),
		dialSem: dialSem,
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
