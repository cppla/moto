package controller

import (
	"errors"
	"fmt"
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
