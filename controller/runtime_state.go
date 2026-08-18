package controller

import "moto/config"

// clearRuntimeRoutingState removes gauges and routing decisions owned by one
// server configuration after all of that server's work has stopped. Process
// counters remain monotonic; only per-route runtime state is lifecycle-scoped.
func clearRuntimeRoutingState(rules []*config.Rule) {
	// Serve invokes this only after all connection handlers have returned, so no
	// new refresh for these rules can be admitted while this wait is in progress.
	waitBoostRevalidations(rules)
	clearRouteHealth(rules)

	boostWinnerCache.Lock()
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		key := boostRuleKey(rule)
		delete(boostWinnerCache.entries, key)
		boostRevalidating.Delete(key)
		roundRobinCounters.Delete(rule)
	}
	boostWinnerCache.Unlock()
}
