package controller

import (
	"sync"
	"time"
)

const (
	connectProxyErrorLogBurst      = 2
	connectProxyErrorLogWindow     = 10 * time.Second
	connectProxyErrorLogMaxEntries = 1024
	connectProxyErrorLogIdleTTL    = 5 * time.Minute
)

// connectProxyErrorLogKey deliberately contains only bounded routing and
// classification fields. In particular, destinations and raw error strings
// must never become limiter keys because clients can create them without
// bound.
type connectProxyErrorLogKey struct {
	rule     string
	target   string
	protocol string
	class    string
}

type connectProxyErrorLogEntry struct {
	tokens     int
	lastRefill time.Time
	lastSeen   time.Time
	lastUsed   uint64
	suppressed uint64
}

// connectProxyErrorLogLimiter limits repeated CONNECT error logs per
// rule/target/protocol/class tuple. All mutable state, including calls to an
// injected clock, is serialized by mu.
type connectProxyErrorLogLimiter struct {
	mu         sync.Mutex
	entries    map[connectProxyErrorLogKey]*connectProxyErrorLogEntry
	now        func() time.Time
	window     time.Duration
	burst      int
	maxEntries int
	idleTTL    time.Duration
	nextSweep  time.Time
	nextUse    uint64
}

func newConnectProxyErrorLogLimiter() *connectProxyErrorLogLimiter {
	return newConnectProxyErrorLogLimiterWithNow(time.Now)
}

// newConnectProxyErrorLogLimiterWithNow permits deterministic tests without
// changing production timing semantics.
func newConnectProxyErrorLogLimiterWithNow(now func() time.Time) *connectProxyErrorLogLimiter {
	if now == nil {
		now = time.Now
	}
	return &connectProxyErrorLogLimiter{
		entries:    make(map[connectProxyErrorLogKey]*connectProxyErrorLogEntry),
		now:        now,
		window:     connectProxyErrorLogWindow,
		burst:      connectProxyErrorLogBurst,
		maxEntries: connectProxyErrorLogMaxEntries,
		idleTTL:    connectProxyErrorLogIdleTTL,
	}
}

// allow reports whether the current event may be logged. When allowed is
// true, suppressed is the number of matching events omitted since the
// preceding allowed log. A denied event always returns a zero count.
func (limiter *connectProxyErrorLogLimiter) allow(rule, target, protocol, class string) (allowed bool, suppressed uint64) {
	if limiter == nil {
		return true, 0
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	limiter.reclaimIdleLocked(now, false)

	key := connectProxyErrorLogKey{
		rule:     rule,
		target:   target,
		protocol: protocol,
		class:    class,
	}
	entry := limiter.entries[key]
	if entry == nil {
		if len(limiter.entries) >= limiter.maxEntries {
			limiter.reclaimIdleLocked(now, true)
		}
		if len(limiter.entries) >= limiter.maxEntries {
			limiter.evictOldestLocked()
		}
		entry = &connectProxyErrorLogEntry{
			tokens:     limiter.burst,
			lastRefill: now,
			lastSeen:   now,
		}
		limiter.entries[key] = entry
	}

	limiter.nextUse++
	entry.lastUsed = limiter.nextUse
	if now.After(entry.lastSeen) {
		entry.lastSeen = now
	}
	limiter.refillLocked(entry, now)

	if entry.tokens > 0 {
		entry.tokens--
		suppressed = entry.suppressed
		entry.suppressed = 0
		return true, suppressed
	}
	if entry.suppressed != ^uint64(0) {
		entry.suppressed++
	}
	return false, 0
}

func (limiter *connectProxyErrorLogLimiter) refillLocked(entry *connectProxyErrorLogEntry, now time.Time) {
	if entry.tokens >= limiter.burst || now.Before(entry.lastRefill) {
		return
	}
	elapsed := now.Sub(entry.lastRefill)
	steps := elapsed / limiter.window
	if steps <= 0 {
		return
	}
	missing := limiter.burst - entry.tokens
	if steps >= time.Duration(missing) {
		entry.tokens = limiter.burst
	} else {
		entry.tokens += int(steps)
	}
	// Preserve a partial interval so sustained errors are admitted at most once
	// per complete window after the initial burst.
	entry.lastRefill = entry.lastRefill.Add(steps * limiter.window)
}

func (limiter *connectProxyErrorLogLimiter) reclaimIdleLocked(now time.Time, force bool) {
	if !force && !limiter.nextSweep.IsZero() && now.Before(limiter.nextSweep) {
		return
	}
	for key, entry := range limiter.entries {
		if !now.Before(entry.lastSeen) && now.Sub(entry.lastSeen) >= limiter.idleTTL {
			delete(limiter.entries, key)
		}
	}
	limiter.nextSweep = now.Add(limiter.idleTTL)
}

func (limiter *connectProxyErrorLogLimiter) evictOldestLocked() {
	var oldestKey connectProxyErrorLogKey
	var oldestUse uint64
	found := false
	for key, entry := range limiter.entries {
		if !found || entry.lastUsed < oldestUse {
			oldestKey = key
			oldestUse = entry.lastUsed
			found = true
		}
	}
	if found {
		delete(limiter.entries, oldestKey)
	}
}
