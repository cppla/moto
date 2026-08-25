package controller

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"moto/config"
	"sync"
	"time"
)

const (
	// Foreground dials are short lived, so these limits still permit a high
	// connection establishment rate while preventing an upstream black hole from
	// consuming one socket per admitted client (or two per Boost race).
	trafficDialGlobalLimit    = 256
	trafficDialPerTargetLimit = 64
	trafficDialWaitLimit      = 250 * time.Millisecond
)

var errDialBulkheadSaturated = errors.New("foreground dial capacity saturated")

// dialBulkheadError marks failures that happened before a network dial began.
// The optional cause remains visible to errors.Is so shutdown and client
// cancellation retain their normal context semantics without being attributed
// to an upstream route.
type dialBulkheadError struct {
	target    string
	cause     error
	saturated bool
	scope     dialSaturationScope
}

type dialSaturationScope uint8

const (
	dialSaturationUnknown dialSaturationScope = iota
	dialSaturationGlobal
	dialSaturationTarget
)

func (err *dialBulkheadError) Error() string {
	if err == nil {
		return "foreground dial capacity unavailable"
	}
	if err.saturated {
		return fmt.Sprintf("foreground dial capacity for %s remained saturated", err.target)
	}
	return fmt.Sprintf("wait for foreground dial capacity for %s: %v", err.target, err.cause)
}

func (err *dialBulkheadError) Unwrap() error {
	if err == nil {
		return nil
	}
	if err.saturated {
		return errDialBulkheadSaturated
	}
	return err.cause
}

func isDialBulkheadError(err error) bool {
	var capacityErr *dialBulkheadError
	return errors.As(err, &capacityErr)
}

func isDialTargetBulkheadSaturation(err error) bool {
	var capacityErr *dialBulkheadError
	return errors.As(err, &capacityErr) && capacityErr.saturated && capacityErr.scope == dialSaturationTarget
}

type dialBulkheadWaiter struct {
	target  string
	ready   chan struct{}
	element *list.Element
	granted bool
}

// dialBulkhead atomically accounts for both a server-wide dial limit and a
// per-target limit. It is shared by every routing generation owned by a Server,
// so an old draining generation and a newly published generation cannot each
// consume a full independent allowance.
type dialBulkhead struct {
	mu sync.Mutex

	globalLimit    int
	perTargetLimit int
	waitLimit      time.Duration
	active         int
	waiting        int
	activeByTarget map[string]int
	waiters        list.List // *dialBulkheadWaiter
}

type dialPermit struct {
	bulkhead *dialBulkhead
	target   string
	once     sync.Once
}

type dialBulkheadSnapshot struct {
	GlobalLimit    int
	PerTargetLimit int
	Active         int
	Waiting        int
	ActiveByTarget map[string]int
}

func newDialBulkhead(globalLimit, perTargetLimit int, waitLimit time.Duration) *dialBulkhead {
	if globalLimit < 1 {
		globalLimit = 1
	}
	if perTargetLimit < 1 {
		perTargetLimit = 1
	}
	if perTargetLimit > globalLimit {
		perTargetLimit = globalLimit
	}
	if waitLimit < 0 {
		waitLimit = 0
	}
	return &dialBulkhead{
		globalLimit:    globalLimit,
		perTargetLimit: perTargetLimit,
		waitLimit:      waitLimit,
		activeByTarget: make(map[string]int),
	}
}

func newTrafficDialBulkhead() *dialBulkhead {
	return newDialBulkhead(trafficDialGlobalLimit, trafficDialPerTargetLimit, trafficDialWaitLimit)
}

func (bulkhead *dialBulkhead) canAdmitLocked(target string) bool {
	return bulkhead.active < bulkhead.globalLimit &&
		bulkhead.activeByTarget[target] < bulkhead.perTargetLimit
}

func (bulkhead *dialBulkhead) saturationScopeLocked(target string) dialSaturationScope {
	if bulkhead.active >= bulkhead.globalLimit {
		return dialSaturationGlobal
	}
	if bulkhead.activeByTarget[target] >= bulkhead.perTargetLimit {
		return dialSaturationTarget
	}
	return dialSaturationUnknown
}

func (bulkhead *dialBulkhead) admitLocked(target string) *dialPermit {
	bulkhead.active++
	bulkhead.activeByTarget[target]++
	return &dialPermit{bulkhead: bulkhead, target: target}
}

// acquire waits only for the small bulkhead-specific budget. The caller keeps
// using its original context for the actual dial, so waiting cannot silently
// extend the rule's decision deadline.
func (bulkhead *dialBulkhead) acquire(ctx context.Context, target string) (*dialPermit, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, 0, &dialBulkheadError{target: target, cause: err}
	}
	if bulkhead == nil {
		return &dialPermit{}, 0, nil
	}

	bulkhead.mu.Lock()
	if bulkhead.canAdmitLocked(target) {
		permit := bulkhead.admitLocked(target)
		bulkhead.mu.Unlock()
		if err := ctx.Err(); err != nil {
			permit.release()
			return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
		}
		return permit, time.Since(started), nil
	}
	waiter := &dialBulkheadWaiter{target: target, ready: make(chan struct{})}
	waiter.element = bulkhead.waiters.PushBack(waiter)
	bulkhead.waiting++
	waitLimit := bulkhead.waitLimit
	bulkhead.mu.Unlock()

	if waitLimit == 0 {
		scope := bulkhead.cancelWaiter(waiter)
		if err := ctx.Err(); err != nil {
			return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
		}
		return nil, time.Since(started), &dialBulkheadError{target: target, saturated: true, scope: scope}
	}
	timer := time.NewTimer(waitLimit)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case <-waiter.ready:
		if err := ctx.Err(); err != nil {
			bulkhead.cancelWaiter(waiter)
			return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
		}
		return &dialPermit{bulkhead: bulkhead, target: target}, time.Since(started), nil
	case <-ctx.Done():
		bulkhead.cancelWaiter(waiter)
		return nil, time.Since(started), &dialBulkheadError{target: target, cause: ctx.Err()}
	case <-timer.C:
		scope := bulkhead.cancelWaiter(waiter)
		if err := ctx.Err(); err != nil {
			return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
		}
		return nil, time.Since(started), &dialBulkheadError{target: target, saturated: true, scope: scope}
	}
}

// tryAcquire admits a dial only when capacity is available at the instant of
// the call. Unlike acquire, it never creates a waiter or starts a wait timer;
// this is suitable for optional work such as a delayed hedge that must not add
// pressure while foreground dial capacity is already saturated.
func (bulkhead *dialBulkhead) tryAcquire(ctx context.Context, target string) (*dialPermit, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, 0, &dialBulkheadError{target: target, cause: err}
	}
	if bulkhead == nil {
		return &dialPermit{}, 0, nil
	}

	bulkhead.mu.Lock()
	if !bulkhead.canAdmitLocked(target) {
		scope := bulkhead.saturationScopeLocked(target)
		bulkhead.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
		}
		return nil, time.Since(started), &dialBulkheadError{target: target, saturated: true, scope: scope}
	}
	permit := bulkhead.admitLocked(target)
	bulkhead.mu.Unlock()
	if err := ctx.Err(); err != nil {
		permit.release()
		return nil, time.Since(started), &dialBulkheadError{target: target, cause: err}
	}
	return permit, time.Since(started), nil
}

// cancelWaiter removes a queued waiter, or returns a concurrently granted slot
// if cancellation won the select race with admission.
func (bulkhead *dialBulkhead) cancelWaiter(waiter *dialBulkheadWaiter) dialSaturationScope {
	if bulkhead == nil || waiter == nil {
		return dialSaturationUnknown
	}
	bulkhead.mu.Lock()
	scope := bulkhead.saturationScopeLocked(waiter.target)
	if waiter.granted {
		bulkhead.releaseLocked(waiter.target)
		bulkhead.grantWaitersLocked()
	} else if waiter.element != nil {
		bulkhead.waiters.Remove(waiter.element)
		waiter.element = nil
		bulkhead.waiting--
	}
	bulkhead.mu.Unlock()
	return scope
}

func (bulkhead *dialBulkhead) grantWaitersLocked() {
	for element := bulkhead.waiters.Front(); element != nil && bulkhead.active < bulkhead.globalLimit; {
		next := element.Next()
		waiter, ok := element.Value.(*dialBulkheadWaiter)
		if !ok || waiter == nil {
			bulkhead.waiters.Remove(element)
			bulkhead.waiting--
			element = next
			continue
		}
		if bulkhead.activeByTarget[waiter.target] >= bulkhead.perTargetLimit {
			element = next
			continue
		}
		bulkhead.waiters.Remove(element)
		waiter.element = nil
		bulkhead.waiting--
		bulkhead.active++
		bulkhead.activeByTarget[waiter.target]++
		waiter.granted = true
		close(waiter.ready)
		element = next
	}
}

func (bulkhead *dialBulkhead) releaseLocked(target string) {
	if bulkhead.active > 0 {
		bulkhead.active--
	}
	if count := bulkhead.activeByTarget[target]; count > 1 {
		bulkhead.activeByTarget[target] = count - 1
	} else {
		delete(bulkhead.activeByTarget, target)
	}
}

func (permit *dialPermit) release() {
	if permit == nil || permit.bulkhead == nil {
		return
	}
	permit.once.Do(func() {
		bulkhead := permit.bulkhead
		bulkhead.mu.Lock()
		bulkhead.releaseLocked(permit.target)
		bulkhead.grantWaitersLocked()
		bulkhead.mu.Unlock()
	})
}

func (bulkhead *dialBulkhead) snapshot() dialBulkheadSnapshot {
	if bulkhead == nil {
		return dialBulkheadSnapshot{}
	}
	bulkhead.mu.Lock()
	defer bulkhead.mu.Unlock()
	return dialBulkheadSnapshot{
		GlobalLimit:    bulkhead.globalLimit,
		PerTargetLimit: bulkhead.perTargetLimit,
		Active:         bulkhead.active,
		Waiting:        bulkhead.waiting,
		ActiveByTarget: cloneMetricMap(bulkhead.activeByTarget),
	}
}

func (runtime *routingRuntime) acquireTrafficDial(ctx context.Context, rule *config.Rule, target string) (*dialPermit, error) {
	if runtime == nil || runtime.trafficDials == nil {
		return &dialPermit{}, nil
	}
	permit, waited, err := runtime.trafficDials.acquire(ctx, target)
	if rule != nil {
		metricDialBulkhead(rule.Name, target, waited, err)
	}
	return permit, err
}

// tryAcquireTrafficDial performs non-blocking foreground admission while
// retaining the same wait/rejection metrics as the regular bounded acquire.
func (runtime *routingRuntime) tryAcquireTrafficDial(ctx context.Context, rule *config.Rule, target string) (*dialPermit, error) {
	if runtime == nil || runtime.trafficDials == nil {
		return &dialPermit{}, nil
	}
	permit, waited, err := runtime.trafficDials.tryAcquire(ctx, target)
	if rule != nil {
		metricDialBulkhead(rule.Name, target, waited, err)
	}
	return permit, err
}

func (runtime *routingRuntime) acquireBoostTrafficDial(ctx context.Context, rule *config.Rule, target string, tryOnly bool) (boostDialRelease, error) {
	var permit *dialPermit
	var err error
	if tryOnly {
		permit, err = runtime.tryAcquireTrafficDial(ctx, rule, target)
	} else {
		permit, err = runtime.acquireTrafficDial(ctx, rule, target)
	}
	if err != nil {
		return nil, err
	}
	return permit.release, nil
}

// Lazy Boost revalidation is maintenance work, so it borrows only an
// immediately available slot from the Server-shared background dial semaphore.
// It never queues behind or consumes the foreground traffic bulkhead.
func (runtime *routingRuntime) acquireBoostMaintenanceDial(ctx context.Context, _ *config.Rule, target string, _ bool) (boostDialRelease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime == nil || runtime.prewarm == nil || runtime.prewarm.dialSem == nil {
		return func() {}, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case runtime.prewarm.dialSem <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-runtime.prewarm.dialSem
			return nil, err
		}
		var releaseOnce sync.Once
		return func() {
			releaseOnce.Do(func() { <-runtime.prewarm.dialSem })
		}, nil
	default:
		return nil, fmt.Errorf("background dial capacity for %s unavailable: %w", target, errBoostMaintenanceSaturated)
	}
}
