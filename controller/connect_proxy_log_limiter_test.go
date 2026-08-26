package controller

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type connectProxyLogLimiterTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *connectProxyLogLimiterTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *connectProxyLogLimiterTestClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func TestConnectProxyErrorLogLimiterBurstWindowAndSuppressedCount(t *testing.T) {
	clock := &connectProxyLogLimiterTestClock{now: time.Unix(100, 0)}
	limiter := newConnectProxyErrorLogLimiterWithNow(clock.Now)

	for attempt := 1; attempt <= connectProxyErrorLogBurst; attempt++ {
		allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns")
		if !allowed || suppressed != 0 {
			t.Fatalf("initial attempt %d = (%t, %d), want (true, 0)", attempt, allowed, suppressed)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns")
		if allowed || suppressed != 0 {
			t.Fatalf("limited attempt %d = (%t, %d), want (false, 0)", attempt, allowed, suppressed)
		}
	}

	clock.Advance(connectProxyErrorLogWindow - time.Nanosecond)
	if allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns"); allowed || suppressed != 0 {
		t.Fatalf("attempt before complete window = (%t, %d), want (false, 0)", allowed, suppressed)
	}
	clock.Advance(time.Nanosecond)
	if allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns"); !allowed || suppressed != 3 {
		t.Fatalf("attempt after one window = (%t, %d), want (true, 3)", allowed, suppressed)
	}

	if allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns"); allowed || suppressed != 0 {
		t.Fatalf("attempt after replenished token was consumed = (%t, %d), want (false, 0)", allowed, suppressed)
	}
	clock.Advance(connectProxyErrorLogWindow)
	if allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "dns"); !allowed || suppressed != 1 {
		t.Fatalf("next window attempt = (%t, %d), want (true, 1)", allowed, suppressed)
	}
}

func TestConnectProxyErrorLogLimiterKeysAreIndependent(t *testing.T) {
	clock := &connectProxyLogLimiterTestClock{now: time.Unix(200, 0)}
	limiter := newConnectProxyErrorLogLimiterWithNow(clock.Now)

	for attempt := 0; attempt < connectProxyErrorLogBurst; attempt++ {
		if allowed, _ := limiter.allow("boost", "proxy-a:443", "h2", "forbidden"); !allowed {
			t.Fatalf("attempt %d unexpectedly limited", attempt)
		}
	}
	if allowed, _ := limiter.allow("boost", "proxy-a:443", "h2", "forbidden"); allowed {
		t.Fatal("third matching key was not limited")
	}

	variations := []connectProxyErrorLogKey{
		{rule: "normal", target: "proxy-a:443", protocol: "h2", class: "forbidden"},
		{rule: "boost", target: "proxy-b:443", protocol: "h2", class: "forbidden"},
		{rule: "boost", target: "proxy-a:443", protocol: "h3", class: "forbidden"},
		{rule: "boost", target: "proxy-a:443", protocol: "h2", class: "dns"},
	}
	for _, key := range variations {
		if allowed, suppressed := limiter.allow(key.rule, key.target, key.protocol, key.class); !allowed || suppressed != 0 {
			t.Fatalf("independent key %+v = (%t, %d), want (true, 0)", key, allowed, suppressed)
		}
	}
}

func TestConnectProxyErrorLogLimiterMapHasHardLimitAndEvictsLRU(t *testing.T) {
	clock := &connectProxyLogLimiterTestClock{now: time.Unix(300, 0)}
	limiter := newConnectProxyErrorLogLimiterWithNow(clock.Now)

	for index := 0; index < connectProxyErrorLogMaxEntries; index++ {
		target := fmt.Sprintf("proxy-%d:443", index)
		if allowed, _ := limiter.allow("boost", target, "h2", "transport"); !allowed {
			t.Fatalf("new key %d unexpectedly limited", index)
		}
	}
	if got := len(limiter.entries); got != connectProxyErrorLogMaxEntries {
		t.Fatalf("entry count = %d, want %d", got, connectProxyErrorLogMaxEntries)
	}

	if allowed, _ := limiter.allow("boost", "replacement:443", "h2", "transport"); !allowed {
		t.Fatal("replacement key unexpectedly limited")
	}
	if got := len(limiter.entries); got != connectProxyErrorLogMaxEntries {
		t.Fatalf("entry count after replacement = %d, want %d", got, connectProxyErrorLogMaxEntries)
	}
	oldest := connectProxyErrorLogKey{rule: "boost", target: "proxy-0:443", protocol: "h2", class: "transport"}
	if _, exists := limiter.entries[oldest]; exists {
		t.Fatal("least recently used key was not evicted")
	}
	replacement := connectProxyErrorLogKey{rule: "boost", target: "replacement:443", protocol: "h2", class: "transport"}
	if _, exists := limiter.entries[replacement]; !exists {
		t.Fatal("replacement key was not retained")
	}
}

func TestConnectProxyErrorLogLimiterReclaimsIdleEntries(t *testing.T) {
	clock := &connectProxyLogLimiterTestClock{now: time.Unix(400, 0)}
	limiter := newConnectProxyErrorLogLimiterWithNow(clock.Now)
	oldKey := connectProxyErrorLogKey{rule: "boost", target: "old:443", protocol: "h3", class: "timeout"}

	limiter.allow(oldKey.rule, oldKey.target, oldKey.protocol, oldKey.class)
	clock.Advance(connectProxyErrorLogIdleTTL)
	limiter.allow("boost", "new:443", "h3", "timeout")

	if _, exists := limiter.entries[oldKey]; exists {
		t.Fatal("idle key was not reclaimed")
	}
	if got := len(limiter.entries); got != 1 {
		t.Fatalf("entry count after reclamation = %d, want 1", got)
	}
}

func TestConnectProxyErrorLogLimiterConcurrentAccess(t *testing.T) {
	clock := &connectProxyLogLimiterTestClock{now: time.Unix(500, 0)}
	limiter := newConnectProxyErrorLogLimiterWithNow(clock.Now)

	const (
		workers = 32
		calls   = 100
	)
	var allowed atomic.Uint64
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for call := 0; call < calls; call++ {
				if ok, _ := limiter.allow("boost", "proxy.example:443", "h3", "transport"); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wait.Wait()

	if got := allowed.Load(); got != connectProxyErrorLogBurst {
		t.Fatalf("concurrent allowed count = %d, want %d", got, connectProxyErrorLogBurst)
	}
	clock.Advance(connectProxyErrorLogWindow)
	wantSuppressed := uint64(workers*calls - connectProxyErrorLogBurst)
	if ok, suppressed := limiter.allow("boost", "proxy.example:443", "h3", "transport"); !ok || suppressed != wantSuppressed {
		t.Fatalf("post-window decision = (%t, %d), want (true, %d)", ok, suppressed, wantSuppressed)
	}
}

func TestConnectProxyErrorLogLimiterNilReceiverFailsOpen(t *testing.T) {
	var limiter *connectProxyErrorLogLimiter
	if allowed, suppressed := limiter.allow("boost", "proxy.example:443", "h2", "dns"); !allowed || suppressed != 0 {
		t.Fatalf("nil limiter = (%t, %d), want (true, 0)", allowed, suppressed)
	}
}
