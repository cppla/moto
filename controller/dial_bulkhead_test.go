package controller

import (
	"context"
	"errors"
	"moto/config"
	"sync"
	"testing"
	"time"
)

type dialBulkheadAcquireResult struct {
	permit *dialPermit
	waited time.Duration
	err    error
}

func acquireDialBulkheadAsync(ctx context.Context, bulkhead *dialBulkhead, target string) <-chan dialBulkheadAcquireResult {
	result := make(chan dialBulkheadAcquireResult, 1)
	go func() {
		permit, waited, err := bulkhead.acquire(ctx, target)
		result <- dialBulkheadAcquireResult{permit: permit, waited: waited, err: err}
	}()
	return result
}

func waitForDialBulkheadState(t *testing.T, bulkhead *dialBulkhead, wantActive, wantWaiting int) dialBulkheadSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := bulkhead.snapshot()
		if snapshot.Active == wantActive && snapshot.Waiting == wantWaiting {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial bulkhead state = active %d, waiting %d, want active %d, waiting %d",
				snapshot.Active, snapshot.Waiting, wantActive, wantWaiting)
		}
		time.Sleep(time.Millisecond)
	}
}

func receiveDialBulkheadResult(t *testing.T, result <-chan dialBulkheadAcquireResult) dialBulkheadAcquireResult {
	t.Helper()
	select {
	case acquired := <-result:
		return acquired
	case <-time.After(2 * time.Second):
		t.Fatal("dial bulkhead acquire did not finish")
		return dialBulkheadAcquireResult{}
	}
}

func TestDialBulkheadEnforcesGlobalAndPerTargetLimits(t *testing.T) {
	bulkhead := newDialBulkhead(3, 2, time.Second)

	firstA, _, err := bulkhead.acquire(context.Background(), "target-a:443")
	if err != nil {
		t.Fatal(err)
	}
	secondA, _, err := bulkhead.acquire(context.Background(), "target-a:443")
	if err != nil {
		t.Fatal(err)
	}
	firstB, _, err := bulkhead.acquire(context.Background(), "target-b:443")
	if err != nil {
		t.Fatal(err)
	}

	snapshot := bulkhead.snapshot()
	if snapshot.Active != 3 || snapshot.ActiveByTarget["target-a:443"] != 2 || snapshot.ActiveByTarget["target-b:443"] != 1 {
		t.Fatalf("full bulkhead snapshot = %+v", snapshot)
	}

	thirdAResult := acquireDialBulkheadAsync(context.Background(), bulkhead, "target-a:443")
	firstCResult := acquireDialBulkheadAsync(context.Background(), bulkhead, "target-c:443")
	waitForDialBulkheadState(t, bulkhead, 3, 2)

	// Releasing B creates one global slot. A is already at its per-target
	// limit, so the waiter for C must be admitted without allowing A to exceed
	// its own limit.
	firstB.release()
	firstC := receiveDialBulkheadResult(t, firstCResult)
	if firstC.err != nil || firstC.permit == nil {
		t.Fatalf("acquire C after releasing global capacity = (%v, %v)", firstC.permit, firstC.err)
	}
	snapshot = waitForDialBulkheadState(t, bulkhead, 3, 1)
	if snapshot.ActiveByTarget["target-a:443"] != 2 || snapshot.ActiveByTarget["target-c:443"] != 1 {
		t.Fatalf("per-target counts after admitting C = %+v", snapshot.ActiveByTarget)
	}

	firstA.release()
	thirdA := receiveDialBulkheadResult(t, thirdAResult)
	if thirdA.err != nil || thirdA.permit == nil {
		t.Fatalf("third A acquire after releasing target capacity = (%v, %v)", thirdA.permit, thirdA.err)
	}
	snapshot = waitForDialBulkheadState(t, bulkhead, 3, 0)
	if snapshot.ActiveByTarget["target-a:443"] != 2 {
		t.Fatalf("active A dials = %d, want per-target limit 2", snapshot.ActiveByTarget["target-a:443"])
	}

	secondA.release()
	thirdA.permit.release()
	firstC.permit.release()
	// Permit release is deliberately idempotent; a defensive duplicate cleanup
	// must not free another caller's slot or make accounting negative.
	firstC.permit.release()
	snapshot = waitForDialBulkheadState(t, bulkhead, 0, 0)
	if len(snapshot.ActiveByTarget) != 0 {
		t.Fatalf("released bulkhead retained target counts: %+v", snapshot.ActiveByTarget)
	}
}

func TestDialBulkheadSaturatedTargetWaiterDoesNotOccupyGlobalCapacity(t *testing.T) {
	bulkhead := newDialBulkhead(2, 1, time.Second)
	holder, _, err := bulkhead.acquire(context.Background(), "target-a:443")
	if err != nil {
		t.Fatal(err)
	}

	waitingA := acquireDialBulkheadAsync(context.Background(), bulkhead, "target-a:443")
	waitForDialBulkheadState(t, bulkhead, 1, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	otherTarget, _, err := bulkhead.acquire(ctx, "target-b:443")
	if err != nil {
		t.Fatalf("free global capacity was blocked behind a saturated target: %v", err)
	}
	snapshot := waitForDialBulkheadState(t, bulkhead, 2, 1)
	if snapshot.ActiveByTarget["target-a:443"] != 1 || snapshot.ActiveByTarget["target-b:443"] != 1 {
		t.Fatalf("active targets = %+v, want one A and one B", snapshot.ActiveByTarget)
	}

	otherTarget.release()
	snapshot = waitForDialBulkheadState(t, bulkhead, 1, 1)
	if snapshot.ActiveByTarget["target-a:443"] != 1 {
		t.Fatalf("blocked A waiter exceeded its target limit: %+v", snapshot.ActiveByTarget)
	}

	holder.release()
	acquiredA := receiveDialBulkheadResult(t, waitingA)
	if acquiredA.err != nil || acquiredA.permit == nil {
		t.Fatalf("waiting A acquire after release = (%v, %v)", acquiredA.permit, acquiredA.err)
	}
	acquiredA.permit.release()
	waitForDialBulkheadState(t, bulkhead, 0, 0)
}

func TestDialBulkheadTimeoutAndCancellationCleanUpWaiters(t *testing.T) {
	tests := []struct {
		name      string
		waitLimit time.Duration
		newCtx    func() (context.Context, context.CancelFunc)
		trigger   func(context.CancelFunc)
		wantErr   error
	}{
		{
			name:      "canceled context",
			waitLimit: time.Second,
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			trigger: func(cancel context.CancelFunc) { cancel() },
			wantErr: context.Canceled,
		},
		{
			name:      "context deadline",
			waitLimit: time.Second,
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 100*time.Millisecond)
			},
			trigger: func(context.CancelFunc) {},
			wantErr: context.DeadlineExceeded,
		},
		{
			name:      "bulkhead wait limit",
			waitLimit: 25 * time.Millisecond,
			newCtx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			trigger: func(context.CancelFunc) {},
			wantErr: errDialBulkheadSaturated,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bulkhead := newDialBulkhead(1, 1, test.waitLimit)
			holder, _, err := bulkhead.acquire(context.Background(), "holder:443")
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := test.newCtx()
			defer cancel()
			waiting := acquireDialBulkheadAsync(ctx, bulkhead, "waiter:443")
			waitForDialBulkheadState(t, bulkhead, 1, 1)
			test.trigger(cancel)

			result := receiveDialBulkheadResult(t, waiting)
			if result.permit != nil {
				result.permit.release()
				t.Fatalf("capacity wait unexpectedly returned a permit with error %v", result.err)
			}
			if !errors.Is(result.err, test.wantErr) || !isDialBulkheadError(result.err) {
				t.Fatalf("capacity wait error = %v, want wrapped %v", result.err, test.wantErr)
			}
			snapshot := waitForDialBulkheadState(t, bulkhead, 1, 0)
			if len(snapshot.ActiveByTarget) != 1 || snapshot.ActiveByTarget["holder:443"] != 1 {
				t.Fatalf("failed wait changed active accounting: %+v", snapshot.ActiveByTarget)
			}

			holder.release()
			reused, _, err := bulkhead.acquire(context.Background(), "waiter:443")
			if err != nil {
				t.Fatalf("capacity was not reusable after failed wait: %v", err)
			}
			reused.release()
			snapshot = waitForDialBulkheadState(t, bulkhead, 0, 0)
			if len(snapshot.ActiveByTarget) != 0 {
				t.Fatalf("cleanup retained active target state: %+v", snapshot.ActiveByTarget)
			}
		})
	}
}

func TestDialBulkheadTryAcquireNeverQueuesAndCapacityIsReusable(t *testing.T) {
	tests := []struct {
		name      string
		waitLimit time.Duration
	}{
		{name: "default wait limit", waitLimit: trafficDialWaitLimit},
		{name: "arbitrary nonzero wait limit", waitLimit: time.Hour},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bulkhead := newDialBulkhead(1, 1, test.waitLimit)
			holder, _, err := bulkhead.acquire(context.Background(), "holder:443")
			if err != nil {
				t.Fatal(err)
			}

			result := make(chan dialBulkheadAcquireResult, 1)
			go func() {
				permit, waited, acquireErr := bulkhead.tryAcquire(context.Background(), "optional:443")
				result <- dialBulkheadAcquireResult{permit: permit, waited: waited, err: acquireErr}
			}()

			var attempted dialBulkheadAcquireResult
			select {
			case attempted = <-result:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("tryAcquire waited instead of returning immediately")
			}
			if attempted.permit != nil {
				attempted.permit.release()
				t.Fatal("saturated tryAcquire unexpectedly returned a permit")
			}
			if !errors.Is(attempted.err, errDialBulkheadSaturated) || !isDialBulkheadError(attempted.err) {
				t.Fatalf("tryAcquire error = %v, want wrapped saturation", attempted.err)
			}
			snapshot := bulkhead.snapshot()
			if snapshot.Active != 1 || snapshot.Waiting != 0 || snapshot.ActiveByTarget["holder:443"] != 1 {
				t.Fatalf("saturated tryAcquire changed accounting: %+v", snapshot)
			}

			holder.release()
			reused, _, err := bulkhead.tryAcquire(context.Background(), "optional:443")
			if err != nil || reused == nil {
				t.Fatalf("tryAcquire after release = (%v, %v), want permit", reused, err)
			}
			snapshot = bulkhead.snapshot()
			if snapshot.Active != 1 || snapshot.Waiting != 0 || snapshot.ActiveByTarget["optional:443"] != 1 {
				t.Fatalf("reused tryAcquire accounting = %+v", snapshot)
			}
			reused.release()
			waitForDialBulkheadState(t, bulkhead, 0, 0)
		})
	}
}

func TestRuntimeTryAcquireTrafficDialRecordsSaturationMetrics(t *testing.T) {
	resetProcessMetricsForTest()
	defer resetProcessMetricsForTest()

	bulkhead := newDialBulkhead(1, 1, trafficDialWaitLimit)
	runtime := newRoutingRuntimeWithDialResources(make(chan struct{}, 1), bulkhead)
	defer runtime.stopBackground()
	rule := &config.Rule{Name: "try-acquire-metrics"}
	target := "optional:443"

	holder, _, err := bulkhead.acquire(context.Background(), "holder:443")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.release()

	permit, err := runtime.tryAcquireTrafficDial(context.Background(), rule, target)
	if permit != nil {
		permit.release()
		t.Fatal("runtime tryAcquire unexpectedly returned a permit")
	}
	if !errors.Is(err, errDialBulkheadSaturated) {
		t.Fatalf("runtime tryAcquire error = %v, want saturation", err)
	}

	key := dialMetricKey{rule: rule.Name, target: target}
	snapshot := processMetrics.snapshot()
	if snapshot.dialBulkheadWaitCount[key] != 1 || snapshot.dialBulkheadRejected[key] != 1 {
		t.Fatalf("runtime tryAcquire metrics = waits %d, rejected %d, want 1/1",
			snapshot.dialBulkheadWaitCount[key], snapshot.dialBulkheadRejected[key])
	}
	if state := bulkhead.snapshot(); state.Waiting != 0 {
		t.Fatalf("runtime tryAcquire created %d waiter(s)", state.Waiting)
	}
}

func TestDialBulkheadConcurrentCancellationAndReleaseDoesNotLeak(t *testing.T) {
	const (
		iterations = 50
		waiters    = 12
	)

	for iteration := 0; iteration < iterations; iteration++ {
		bulkhead := newDialBulkhead(1, 1, 5*time.Second)
		holder, _, err := bulkhead.acquire(context.Background(), "shared:443")
		if err != nil {
			t.Fatalf("iteration %d: acquire holder: %v", iteration, err)
		}

		results := make([]<-chan dialBulkheadAcquireResult, 0, waiters)
		cancels := make([]context.CancelFunc, 0, waiters)
		for waiter := 0; waiter < waiters; waiter++ {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)
			results = append(results, acquireDialBulkheadAsync(ctx, bulkhead, "shared:443"))
		}
		waitForDialBulkheadState(t, bulkhead, 1, waiters)

		start := make(chan struct{})
		var racers sync.WaitGroup
		racers.Add(len(cancels) + 1)
		go func() {
			defer racers.Done()
			<-start
			holder.release()
		}()
		for _, cancel := range cancels {
			cancel := cancel
			go func() {
				defer racers.Done()
				<-start
				cancel()
			}()
		}
		close(start)

		for index, resultChannel := range results {
			result := receiveDialBulkheadResult(t, resultChannel)
			switch {
			case result.err == nil && result.permit != nil:
				result.permit.release()
			case errors.Is(result.err, context.Canceled) && result.permit == nil:
			default:
				t.Fatalf("iteration %d waiter %d returned permit=%v error=%v", iteration, index, result.permit, result.err)
			}
		}
		racers.Wait()

		snapshot := waitForDialBulkheadState(t, bulkhead, 0, 0)
		if len(snapshot.ActiveByTarget) != 0 {
			t.Fatalf("iteration %d leaked target state: %+v", iteration, snapshot.ActiveByTarget)
		}
		probe, _, err := bulkhead.acquire(context.Background(), "probe:443")
		if err != nil {
			t.Fatalf("iteration %d: leaked capacity prevented reuse: %v", iteration, err)
		}
		probe.release()
		waitForDialBulkheadState(t, bulkhead, 0, 0)
	}
}
