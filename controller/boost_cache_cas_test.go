package controller

import (
	"errors"
	"fmt"
	"moto/config"
	"sync"
	"testing"
	"time"
)

// Read without the normal expiry cleanup so rejected completions must leave
// the cache exactly as they found it, including a still-stored expired entry.
func cachedBoostRawEntry(runtime *routingRuntime, key string) (boostWinnerEntry, bool) {
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	entry, ok := runtime.boost.cache.entries[key]
	return entry, ok
}

func TestCachedBoostReplacementHonorsCacheLifecycle(t *testing.T) {
	for _, hardFailure := range []bool{false, true} {
		for _, mutation := range []string{
			"unchanged", "new_address", "same_address_new_generation", "expired", "deleted",
			"zero_token", "wrong_address", "zero_generation", "wrong_key",
		} {
			t.Run(fmt.Sprintf("hard_failure_%t/%s", hardFailure, mutation), func(t *testing.T) {
				runtime := newRoutingRuntime()
				defer runtime.stopBackground()
				key := "cached-boost-cas-lifecycle"
				original := runtime.storeBoostWinner(key, "cached.example:443")
				token := original
				switch mutation {
				case "new_address":
					runtime.storeBoostWinner(key, "new.example:443")
				case "same_address_new_generation":
					runtime.storeBoostWinner(key, original.addr)
				case "expired":
					runtime.boost.cache.Lock()
					entry := runtime.boost.cache.entries[key]
					entry.expires = time.Now().Add(-time.Second)
					runtime.boost.cache.entries[key] = entry
					runtime.boost.cache.Unlock()
				case "deleted":
					runtime.deleteBoostWinner(key)
				case "zero_token":
					token = boostWinnerToken{}
				case "wrong_address":
					token.addr = "unrelated.example:443"
				case "zero_generation":
					token.generation = 0
				case "wrong_key":
					token.key = "unrelated-rule"
				}
				before, existedBefore := cachedBoostRawEntry(runtime, key)
				outcome := cachedBoostOutcome{
					winner:          dialResult{addr: "fallback.example:443"},
					cachedFailed:    hardFailure,
					fallbackStarted: true,
					hedged:          !hardFailure,
				}
				hit, replacement := runtime.reconcileCachedBoostWinner(key, token, outcome, true)
				if hit {
					t.Fatal("fallback winner was counted as a cache hit")
				}
				after, existsAfter := cachedBoostRawEntry(runtime, key)
				if mutation == "unchanged" {
					if replacement.key != key || replacement.addr != outcome.winner.addr || replacement.generation == 0 || replacement.generation == original.generation {
						t.Fatalf("valid fallback did not receive a fresh cache token: %+v", replacement)
					}
					if !existsAfter || after.addr != replacement.addr || after.generation != replacement.generation || !time.Now().Before(after.expires) {
						t.Fatalf("valid fallback was not cached: entry=%+v exists=%t token=%+v", after, existsAfter, replacement)
					}
					if runtime.deleteBoostWinnerIfCurrent(original) {
						t.Fatal("replaced generation could still delete the new winner")
					}
					return
				}
				if replacement != (boostWinnerToken{}) {
					t.Fatalf("stale completion acquired cache ownership: %+v", replacement)
				}
				if existsAfter != existedBefore || after != before {
					t.Fatalf("stale completion changed cache: before=%+v exists=%t after=%+v exists=%t", before, existedBefore, after, existsAfter)
				}
			})
		}
	}
}

func TestCachedBoostLateFailureCannotDeleteNewGeneration(t *testing.T) {
	for _, address := range []string{"cached.example:443", "new.example:443"} {
		t.Run(address, func(t *testing.T) {
			runtime := newRoutingRuntime()
			defer runtime.stopBackground()
			key := "cached-boost-late-failure"
			original := runtime.storeBoostWinner(key, "cached.example:443")
			current := runtime.storeBoostWinner(key, address)
			hit, token := runtime.reconcileCachedBoostWinner(key, original, cachedBoostOutcome{cachedFailed: true}, false)
			if hit || token != (boostWinnerToken{}) {
				t.Fatalf("failed attempt obtained cache ownership: hit=%t token=%+v", hit, token)
			}
			entry, ok := runtime.loadBoostWinnerToken(key)
			if !ok || entry.addr != current.addr || entry.generation != current.generation {
				t.Fatalf("late failure evicted a newer winner: entry=%+v exists=%t current=%+v", entry, ok, current)
			}
		})
	}
}

func TestCachedBoostConcurrentReplacementsHaveSingleOwner(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	key := "cached-boost-concurrent-replacement"
	original := runtime.storeBoostWinner(key, "cached.example:443")
	const competitors = 32
	start := make(chan struct{})
	results := make(chan boostWinnerToken, competitors)
	var done sync.WaitGroup
	for index := 0; index < competitors; index++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			<-start
			_, token := runtime.reconcileCachedBoostWinner(key, original, cachedBoostOutcome{
				winner: dialResult{addr: fmt.Sprintf("fallback-%d.example:443", index)},
				hedged: true,
			}, true)
			results <- token
		}(index)
	}
	close(start)
	done.Wait()
	close(results)
	var owner boostWinnerToken
	owners := 0
	for token := range results {
		if token != (boostWinnerToken{}) {
			owners++
			owner = token
		}
	}
	if owners != 1 {
		t.Fatalf("concurrent completions received %d cache tokens, want exactly one", owners)
	}
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != owner.addr || entry.generation != owner.generation || entry.generation != original.generation+1 {
		t.Fatalf("cache differs from its sole replacement owner: entry=%+v exists=%t owner=%+v", entry, ok, owner)
	}
}

func TestCachedBoostReplacementTokenCannotInvalidateLaterWinner(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	key := "cached-boost-replacement-relay"
	original := runtime.storeBoostWinner(key, "cached.example:443")
	_, replacement := runtime.reconcileCachedBoostWinner(key, original, cachedBoostOutcome{
		winner: dialResult{addr: "fallback.example:443"},
		hedged: true,
	}, true)
	if replacement.generation == 0 {
		t.Fatal("valid fallback did not obtain a replacement token")
	}
	// Refreshing the same address still creates a different cache generation.
	current := runtime.storeBoostWinner(key, replacement.addr)
	runtime.finishBoostRelay(replacement, routeAttempt{}, relayResult{
		ClientToTarget: relayDirectionResult{Err: errors.New("old fallback stream failed")},
	})
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || entry.addr != current.addr || entry.generation != current.generation {
		t.Fatalf("old replacement relay evicted the refreshed winner: entry=%+v exists=%t current=%+v", entry, ok, current)
	}
}

func requireNoBoostWinnerDecisions(t *testing.T, runtime *routingRuntime) {
	t.Helper()
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	if count := len(runtime.boost.cache.decisions); count != 0 {
		t.Fatalf("completed decisions retained %d ownership records", count)
	}
}

func TestFreshBoostCacheDecisionRejectsABA(t *testing.T) {
	for _, mutation := range []string{"store_delete", "delete_absent", "replace_delete", "conditional_delete", "expiry_load", "clear", "cached_replace"} {
		t.Run(mutation, func(t *testing.T) {
			runtime := newRoutingRuntime()
			defer runtime.stopBackground()
			rule := boostTestRule(t.Name(), "127.0.0.1:19901", "one.example:443", "two.example:443")
			key := boostRuleKey(rule)
			decision := runtime.beginBoostWinnerDecision(key)
			defer runtime.releaseBoostWinnerDecision(decision)
			switch mutation {
			case "store_delete":
				runtime.storeBoostWinner(key, "new.example:443")
				runtime.deleteBoostWinner(key)
			case "delete_absent":
				runtime.deleteBoostWinner(key)
			case "replace_delete":
				runtime.storeBoostWinner(key, "same.example:443")
				runtime.storeBoostWinner(key, "same.example:443")
				runtime.deleteBoostWinner(key)
			case "conditional_delete":
				token := runtime.storeBoostWinner(key, "new.example:443")
				runtime.deleteBoostWinnerIfCurrent(token)
			case "expiry_load":
				runtime.storeBoostWinner(key, "new.example:443")
				runtime.boost.cache.Lock()
				entry := runtime.boost.cache.entries[key]
				entry.expires = time.Now().Add(-time.Second)
				runtime.boost.cache.entries[key] = entry
				runtime.boost.cache.Unlock()
				runtime.loadBoostWinnerToken(key)
			case "clear":
				runtime.clear([]*config.Rule{rule})
			case "cached_replace":
				token := runtime.storeBoostWinner(key, "current.example:443")
				runtime.releaseBoostWinnerDecision(decision)
				decision = runtime.beginBoostWinnerDecision(key)
				runtime.replaceBoostWinnerIfCurrent(token, "new.example:443")
			}
			before, existed := cachedBoostRawEntry(runtime, key)
			if token := runtime.publishBoostWinnerDecision(decision, "stale.example:443"); token != (boostWinnerToken{}) {
				t.Fatalf("superseded decision acquired cache ownership: %+v", token)
			}
			after, exists := cachedBoostRawEntry(runtime, key)
			if exists != existed || after != before {
				t.Fatalf("old result changed newer cache state: before=%+v exists=%t after=%+v exists=%t", before, existed, after, exists)
			}
			requireNoBoostWinnerDecisions(t, runtime)
		})
	}
}

func TestFreshBoostCacheDecisionIsolationAndCleanup(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	first := runtime.beginBoostWinnerDecision("first")
	other := runtime.beginBoostWinnerDecision("other")
	if token := runtime.publishBoostWinnerDecision(other, "other.example:443"); token.generation == 0 {
		t.Fatal("first successful decision did not populate an empty cache")
	}
	if token := runtime.publishBoostWinnerDecision(first, "first.example:443"); token.generation == 0 {
		t.Fatal("unrelated rule write invalidated this decision")
	}
	// An unchanged cached entry can still be replaced by a real recovery or
	// maintenance result; ownership must not suppress every existing-cache race.
	recovery := runtime.beginBoostWinnerDecision("first")
	if token := runtime.publishBoostWinnerDecision(recovery, "recovered.example:443"); token.generation == 0 {
		t.Fatal("unchanged cached baseline prevented recovery publication")
	}
	old := runtime.beginBoostWinnerDecision("first")
	runtime.deleteBoostWinner("first")
	current := runtime.beginBoostWinnerDecision("first")
	runtime.releaseBoostWinnerDecision(old)
	runtime.releaseBoostWinnerDecision(old)
	if token := runtime.publishBoostWinnerDecision(current, "current.example:443"); token.generation == 0 {
		t.Fatal("releasing an invalidated lease removed the new decision's ownership")
	}
	if token := runtime.publishBoostWinnerDecision(old, "old.example:443"); token.generation != 0 {
		t.Fatal("released decision was allowed to publish")
	}
	failed := runtime.beginBoostWinnerDecision("failed")
	runtime.releaseBoostWinnerDecision(failed)
	if _, exists := runtime.loadBoostWinnerToken("failed"); exists {
		t.Fatal("failed decision created a cache entry")
	}
	requireNoBoostWinnerDecisions(t, runtime)
	// No permanently retained key revisions, including rules that never won.
	for index := 0; index < 1024; index++ {
		decision := runtime.beginBoostWinnerDecision(fmt.Sprintf("one-off-%d", index))
		runtime.releaseBoostWinnerDecision(decision)
	}
	requireNoBoostWinnerDecisions(t, runtime)
}

func TestFreshBoostCacheDecisionExpiryAndRuntimeIsolation(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	runtime.storeBoostWinner("rule", "original.example:443")
	decision := runtime.beginBoostWinnerDecision("rule")
	// Model expiry during the race without sleeping for the production TTL.
	decision.expires = time.Now().Add(-time.Second)
	if token := runtime.publishBoostWinnerDecision(decision, "late.example:443"); token.generation != 0 {
		t.Fatal("expired baseline was revived by a late decision")
	}
	other := newRoutingRuntime()
	defer other.stopBackground()
	active := runtime.beginBoostWinnerDecision("rule")
	if token := other.publishBoostWinnerDecision(active, "other.example:443"); token.generation != 0 {
		t.Fatal("decision escaped into another runtime")
	}
	other.releaseBoostWinnerDecision(active)
	if token := runtime.publishBoostWinnerDecision(active, "own.example:443"); token.generation == 0 {
		t.Fatal("other runtime consumed this runtime's ownership")
	}
	requireNoBoostWinnerDecisions(t, runtime)
	requireNoBoostWinnerDecisions(t, other)
}

func TestFreshBoostConcurrentCacheDecisionsHaveSinglePublisher(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	const callers = 32
	decisions := make([]*boostWinnerDecision, callers)
	for index := range decisions {
		decisions[index] = runtime.beginBoostWinnerDecision("shared")
	}
	start := make(chan struct{})
	results := make(chan boostWinnerToken, callers)
	var done sync.WaitGroup
	for index, decision := range decisions {
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			results <- runtime.publishBoostWinnerDecision(decision, fmt.Sprintf("winner-%d.example:443", index))
			runtime.releaseBoostWinnerDecision(decision)
		}()
	}
	close(start)
	done.Wait()
	close(results)
	owners := 0
	for result := range results {
		if result.generation != 0 {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("got %d publishers from the same cache view, want 1", owners)
	}
	requireNoBoostWinnerDecisions(t, runtime)
}

func TestFreshBoostCacheEvictionInvalidatesDecision(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	decisions := make(map[string]*boostWinnerDecision, boostWinnerCacheMax)
	for index := 0; index < boostWinnerCacheMax; index++ {
		key := fmt.Sprintf("rule-%d", index)
		runtime.storeBoostWinner(key, "cached.example:443")
		decisions[key] = runtime.beginBoostWinnerDecision(key)
	}
	defer func() {
		for _, decision := range decisions {
			runtime.releaseBoostWinnerDecision(decision)
		}
	}()
	runtime.storeBoostWinner("overflow", "new.example:443")
	evicted := 0
	for key, decision := range decisions {
		if _, exists := runtime.loadBoostWinnerToken(key); !exists {
			evicted++
			if token := runtime.publishBoostWinnerDecision(decision, "late.example:443"); token.generation != 0 {
				t.Fatal("late decision recreated an evicted entry")
			}
		}
		runtime.releaseBoostWinnerDecision(decision)
	}
	if evicted != 1 {
		t.Fatalf("evicted %d entries, want 1", evicted)
	}
	requireNoBoostWinnerDecisions(t, runtime)
}
