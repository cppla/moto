package controller

import (
	"context"
	"errors"
	"sync"
)

type http2SetupWaiterContextKey struct{}

// http2SetupWaiter tracks only this request's physical connection setup. A
// transport-wide snapshot would also group CONNECT or stream-capacity waits
// with an unrelated dial that happens to be in progress.
type http2SetupWaiter struct {
	mu   sync.Mutex
	call *http2ConnectDialCall
}

func withHTTP2SetupWaiter(ctx context.Context, waiter *http2SetupWaiter) context.Context {
	return context.WithValue(ctx, http2SetupWaiterContextKey{}, waiter)
}

func http2SetupWaiterFromContext(ctx context.Context) *http2SetupWaiter {
	if ctx == nil {
		return nil
	}
	waiter, _ := ctx.Value(http2SetupWaiterContextKey{}).(*http2SetupWaiter)
	return waiter
}

func (waiter *http2SetupWaiter) waitingOn(call *http2ConnectDialCall) {
	if waiter == nil {
		return
	}
	waiter.mu.Lock()
	waiter.call = call
	waiter.mu.Unlock()
}

func (waiter *http2SetupWaiter) finished(call *http2ConnectDialCall) {
	if waiter == nil {
		return
	}
	waiter.mu.Lock()
	if waiter.call == call {
		waiter.call = nil
	}
	waiter.mu.Unlock()
}

func (waiter *http2SetupWaiter) failureGroup() *routeFailureGroup {
	if waiter == nil {
		return nil
	}
	waiter.mu.Lock()
	defer waiter.mu.Unlock()
	call := waiter.call
	if call == nil {
		return nil
	}
	select {
	case <-call.done:
		// Closing done publishes the dial result. A successful setup must
		// never deduplicate later, independent CONNECT response timeouts.
		if call.err == nil {
			return nil
		}
	default:
		// The physical setup is still pending; its immutable group was
		// allocated before any request could start waiting on this call.
	}
	return call.group
}

// http2SetupCallerError keeps the caller's deadline/cancellation cause without
// discarding the identity of a shared physical setup. Call before canceling
// the detached stream, which can otherwise change the pool's waiting state.
func http2SetupCallerError(waiter *http2SetupWaiter, previous, caller error) error {
	if caller == nil {
		return previous
	}
	if !errors.Is(caller, context.DeadlineExceeded) {
		return caller
	}
	var setup *http2SetupError
	if errors.As(previous, &setup) && setup.group != nil {
		return &http2SetupError{cause: caller, group: setup.group}
	}
	if group := waiter.failureGroup(); group != nil {
		return &http2SetupError{cause: caller, group: group}
	}
	return caller
}
