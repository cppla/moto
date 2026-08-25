package controller

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cancelOnSecondErrContext struct {
	context.Context
	calls atomic.Int32
}

func (ctx *cancelOnSecondErrContext) Err() error {
	if ctx.calls.Add(1) >= 2 {
		return context.Canceled
	}
	return nil
}

type reloadEchoBackend struct {
	listener net.Listener
	id       string
	wg       sync.WaitGroup
	active   sync.Map
}

func newReloadEchoBackend(t *testing.T, id string) *reloadEchoBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &reloadEchoBackend{listener: listener, id: id}
	backend.wg.Add(1)
	go func() {
		defer backend.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			backend.active.Store(conn, struct{}{})
			backend.wg.Add(1)
			go func() {
				defer backend.wg.Done()
				defer backend.active.Delete(conn)
				defer conn.Close()
				_, _ = io.WriteString(conn, id+"\n")
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		backend.active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		backend.wg.Wait()
	})
	return backend
}

func (backend *reloadEchoBackend) addr() string { return backend.listener.Addr().String() }

func unusedReloadAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func reloadRule(name, listen, target string) *config.Rule {
	return &config.Rule{
		Name:                name,
		Listen:              listen,
		Mode:                config.ModeNormal,
		Timeout:             500,
		MaxConnections:      32,
		MaxConnectionsPerIP: 32,
		Targets:             []*config.Target{{Address: target}},
	}
}

func findGenerationRule(t *testing.T, generation *routingGeneration, name string) *config.Rule {
	t.Helper()
	for _, rule := range generation.rules {
		if rule.Name == name {
			return rule
		}
	}
	t.Fatalf("generation %d has no rule %q", generation.id, name)
	return nil
}

func TestReloadPreservesStateForExactlyUnchangedRules(t *testing.T) {
	keptListen := unusedReloadAddress(t)
	changedListen := unusedReloadAddress(t)
	keptTarget := "kept.example:443"
	health := &config.HealthCheckConfig{
		Type:             config.HealthCheckTCP,
		Interval:         10_000,
		Timeout:          2_000,
		FailureThreshold: 1,
		SuccessThreshold: 1,
	}
	kept := reloadRule("kept", keptListen, keptTarget)
	kept.Mode = config.ModeBoost
	kept.HealthCheck = health
	kept.Targets = append(kept.Targets, &config.Target{Address: "kept-backup.example:443"})
	changed := reloadRule("changed", changedListen, "old.example:443")

	server, err := NewServer([]*config.Rule{kept, changed})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	oldGeneration := server.current.Load()
	oldKept := findGenerationRule(t, oldGeneration, "kept")
	oldChanged := findGenerationRule(t, oldGeneration, "changed")
	now := time.Now()
	for range routeFailureThreshold {
		attempt, beginErr := oldGeneration.runtime.routes.begin(oldKept, keptTarget, now)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		routeObserve(attempt, time.Millisecond, errors.New("kept route failed"), now)
	}
	oldGeneration.runtime.health.observe(
		activeHealthKey{rule: oldKept, address: keptTarget},
		*oldKept.HealthCheck,
		false,
	)
	winner := oldGeneration.runtime.storeBoostWinner(boostRuleKey(oldKept), keptTarget)
	changedAttempt, err := oldGeneration.runtime.routes.begin(oldChanged, oldChanged.Targets[0].Address, now)
	if err != nil {
		t.Fatal(err)
	}
	routeObserve(changedAttempt, time.Millisecond, errors.New("changed route failed"), now)

	keptReload := reloadRule("kept", keptListen, keptTarget)
	keptReload.Mode = config.ModeBoost
	keptReload.HealthCheck = &config.HealthCheckConfig{
		Type:             config.HealthCheckTCP,
		Interval:         10_000,
		Timeout:          2_000,
		FailureThreshold: 1,
		SuccessThreshold: 1,
	}
	keptReload.Targets = append(keptReload.Targets, &config.Target{Address: "kept-backup.example:443"})
	changedReload := reloadRule("changed", changedListen, "new.example:443")
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{keptReload, changedReload}); err != nil {
		t.Fatal(err)
	}

	newGeneration := server.current.Load()
	newKept := findGenerationRule(t, newGeneration, "kept")
	if snapshot := newGeneration.runtime.routes.snapshot(newKept, keptTarget, now); !snapshot.CircuitOpen || snapshot.ConsecutiveFailures < routeFailureThreshold {
		t.Fatalf("unchanged route lost circuit state: %+v", snapshot)
	}
	if !newGeneration.runtime.health.unhealthy(newKept, keptTarget) {
		t.Fatal("unchanged rule lost active-health state")
	}
	entry, ok := newGeneration.runtime.loadBoostWinnerToken(boostRuleKey(newKept))
	if !ok || entry.addr != winner.addr || entry.generation != winner.generation {
		t.Fatalf("unchanged rule lost Boost winner: entry=%+v ok=%v", entry, ok)
	}
	newChanged := findGenerationRule(t, newGeneration, "changed")
	if snapshot := newGeneration.runtime.routes.snapshot(newChanged, newChanged.Targets[0].Address, now); snapshot.Observed || snapshot.CircuitOpen {
		t.Fatalf("changed rule inherited stale route state: %+v", snapshot)
	}
}

func waitReloadServerReady(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !server.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.Ready() {
		t.Fatal("server did not become ready")
	}
}

func readBackendID(t *testing.T, conn net.Conn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read backend id: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestReloadRulesKeepsOldStreamAndSwitchesNewConnections(t *testing.T) {
	backendA := newReloadEchoBackend(t, "backend-a")
	backendB := newReloadEchoBackend(t, "backend-b")
	listen := unusedReloadAddress(t)
	server, err := NewServer([]*config.Rule{reloadRule("switch", listen, backendA.addr())})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	waitReloadServerReady(t, server)

	oldConn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer oldConn.Close()
	if got := readBackendID(t, oldConn); got != "backend-a" {
		t.Fatalf("old stream backend = %q", got)
	}

	result, err := server.ReloadRules(context.Background(), []*config.Rule{reloadRule("switch", listen, backendB.addr())})
	if err != nil {
		t.Fatalf("ReloadRules: %v", err)
	}
	if result.FromGeneration != 1 || result.ToGeneration != 2 || len(result.Reused) != 1 {
		t.Fatalf("reload result = %+v", result)
	}

	newConn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	if got := readBackendID(t, newConn); got != "backend-b" {
		t.Fatalf("new stream backend = %q", got)
	}
	_ = newConn.Close()

	if _, err := io.WriteString(oldConn, "still-old\n"); err != nil {
		t.Fatalf("write old stream after reload: %v", err)
	}
	buffer := make([]byte, len("still-old\n"))
	if _, err := io.ReadFull(oldConn, buffer); err != nil {
		t.Fatalf("read old stream after reload: %v", err)
	}
	if string(buffer) != "still-old\n" {
		t.Fatalf("old stream echo = %q", buffer)
	}

	_ = oldConn.Close()
	cancel()
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Fatalf("Serve: %v", serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestReloadRulesRollsBackAllStagedListenersOnBindFailure(t *testing.T) {
	backend := newReloadEchoBackend(t, "stable")
	listen := unusedReloadAddress(t)
	stagedAddress := unusedReloadAddress(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	server, err := NewServer([]*config.Rule{reloadRule("stable", listen, backend.addr())})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	before := server.Generation()
	_, err = server.ReloadRules(context.Background(), []*config.Rule{
		reloadRule("stable", listen, backend.addr()),
		reloadRule("staged", stagedAddress, backend.addr()),
		reloadRule("occupied", occupied.Addr().String(), backend.addr()),
	})
	if err == nil {
		t.Fatal("ReloadRules succeeded with an occupied staged listener")
	}
	if server.Generation() != before {
		t.Fatalf("failed reload changed generation from %d to %d", before, server.Generation())
	}
	rebound, bindErr := net.Listen("tcp", stagedAddress)
	if bindErr != nil {
		t.Fatalf("staged listener leaked after rollback: %v", bindErr)
	}
	_ = rebound.Close()
}

func TestReloadRulesNoopAndEphemeralRejection(t *testing.T) {
	backend := newReloadEchoBackend(t, "noop")
	listen := unusedReloadAddress(t)
	rule := reloadRule("noop", listen, backend.addr())
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	result, err := server.ReloadRules(context.Background(), []*config.Rule{reloadRule("noop", listen, backend.addr())})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Noop || server.Generation() != 1 {
		t.Fatalf("equivalent reload = %+v, generation = %d", result, server.Generation())
	}
	_, err = server.ReloadRules(context.Background(), []*config.Rule{reloadRule("ephemeral", "127.0.0.1:0", backend.addr())})
	if err == nil || !strings.Contains(err.Error(), "does not support ephemeral") {
		t.Fatalf("ephemeral reload error = %v", err)
	}
	if server.Generation() != 1 {
		t.Fatalf("rejected reload changed generation to %d", server.Generation())
	}
}

func TestServeAfterCloseWaitsForPreexistingRetiredWatcher(t *testing.T) {
	backendA := newReloadEchoBackend(t, "watcher-a")
	backendB := newReloadEchoBackend(t, "watcher-b")
	listen := unusedReloadAddress(t)
	server, err := NewServer([]*config.Rule{reloadRule("watcher", listen, backendA.addr())})
	if err != nil {
		t.Fatal(err)
	}
	old, binding := server.acquireBinding(listen)
	if old == nil || binding == nil {
		t.Fatal("failed to acquire old generation lease")
	}
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{reloadRule("watcher", listen, backendB.addr())}); err != nil {
		old.release()
		t.Fatal(err)
	}
	server.Close()

	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background()) }()
	select {
	case err := <-done:
		old.release()
		t.Fatalf("Serve returned before retired lease drained: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	old.release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not join retired watcher after lease release")
	}
}

func TestReloadRulesAddsAndRemovesListener(t *testing.T) {
	backend := newReloadEchoBackend(t, "listener")
	first := unusedReloadAddress(t)
	second := unusedReloadAddress(t)
	server, err := NewServer([]*config.Rule{reloadRule("first", first, backend.addr())})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	waitReloadServerReady(t, server)

	result, err := server.ReloadRules(context.Background(), []*config.Rule{reloadRule("second", second, backend.addr())})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(result.Added) != fmt.Sprint([]string{second}) || fmt.Sprint(result.Removed) != fmt.Sprint([]string{first}) {
		t.Fatalf("listener diff = %+v", result)
	}
	conn, err := net.DialTimeout("tcp", second, time.Second)
	if err != nil {
		t.Fatalf("dial added listener: %v", err)
	}
	if got := readBackendID(t, conn); got != "listener" {
		t.Fatalf("added listener backend = %q", got)
	}
	_ = conn.Close()
	if removedConn, dialErr := net.DialTimeout("tcp", first, 100*time.Millisecond); dialErr == nil {
		_ = removedConn.Close()
		t.Fatal("removed listener still accepted connections")
	}

	cancel()
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestConcurrentReloadAndConnectionsUseWholeGenerations(t *testing.T) {
	backendA := newReloadEchoBackend(t, "generation-a")
	backendB := newReloadEchoBackend(t, "generation-b")
	listen := unusedReloadAddress(t)
	server, err := NewServer([]*config.Rule{reloadRule("concurrent", listen, backendA.addr())})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	waitReloadServerReady(t, server)

	const workers = 12
	const connectionsPerWorker = 20
	errorsSeen := make(chan error, workers*connectionsPerWorker)
	var workersDone sync.WaitGroup
	workersDone.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer workersDone.Done()
			for attempt := 0; attempt < connectionsPerWorker; attempt++ {
				conn, dialErr := net.DialTimeout("tcp", listen, time.Second)
				if dialErr != nil {
					errorsSeen <- dialErr
					continue
				}
				if deadlineErr := conn.SetReadDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
					errorsSeen <- deadlineErr
					_ = conn.Close()
					continue
				}
				line, readErr := bufio.NewReader(conn).ReadString('\n')
				_ = conn.Close()
				if readErr != nil {
					errorsSeen <- readErr
					continue
				}
				if line != "generation-a\n" && line != "generation-b\n" {
					errorsSeen <- fmt.Errorf("mixed generation response %q", line)
				}
			}
		}()
	}
	for generation := 0; generation < 20; generation++ {
		target := backendA.addr()
		if generation%2 == 0 {
			target = backendB.addr()
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			_, reloadErr := server.ReloadRules(context.Background(), []*config.Rule{reloadRule("concurrent", listen, target)})
			if reloadErr == nil {
				break
			}
			if !strings.Contains(reloadErr.Error(), "still draining") || time.Now().After(deadline) {
				t.Fatalf("reload %d: %v", generation, reloadErr)
			}
			time.Sleep(time.Millisecond)
		}
	}
	workersDone.Wait()
	close(errorsSeen)
	for workerErr := range errorsSeen {
		t.Error(workerErr)
	}

	cancel()
	select {
	case serveErr := <-serveDone:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestReloadRulesDoesNotCommitWhenContextCancelsAtCommitGate(t *testing.T) {
	listen := unusedReloadAddress(t)
	initial := reloadRule("cancel-commit", listen, "127.0.0.1:1")
	server, err := NewServer([]*config.Rule{initial})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	reloadCtx := &cancelOnSecondErrContext{Context: context.Background()}
	_, err = server.ReloadRules(reloadCtx, []*config.Rule{
		reloadRule("cancel-commit", listen, "127.0.0.1:2"),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReloadRules error = %v, want context.Canceled", err)
	}
	if got := server.Generation(); got != 1 {
		t.Fatalf("cancelled reload committed generation %d", got)
	}
	current := server.current.Load()
	if current == nil || current.bindings[listen] == nil {
		t.Fatal("cancelled reload removed the original binding")
	}
	if got := current.bindings[listen].rule.Targets[0].Address; got != "127.0.0.1:1" {
		t.Fatalf("cancelled reload changed target to %q", got)
	}
}

func TestReloadRulesReusesAdmissionWhileRemovedGenerationLeaseIsActive(t *testing.T) {
	firstListen := unusedReloadAddress(t)
	secondListen := unusedReloadAddress(t)
	firstRule := reloadRule("admission-first", firstListen, "127.0.0.1:1")
	firstRule.MaxConnections = 1
	firstRule.MaxConnectionsPerIP = 1
	server, err := NewServer([]*config.Rule{firstRule})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	oldState := server.listenersByKey[firstListen]
	oldGeneration, oldBinding := server.acquireBinding(firstListen)
	if oldState == nil || oldGeneration == nil || oldBinding == nil {
		t.Fatal("failed to acquire the original listener generation")
	}
	defer oldGeneration.release()

	if _, err := server.ReloadRules(context.Background(), []*config.Rule{
		reloadRule("admission-second", secondListen, "127.0.0.1:2"),
	}); err != nil {
		t.Fatalf("remove first listener: %v", err)
	}
	if server.admissionsByKey[firstListen] != oldState.admission {
		t.Fatal("removed listener admission was discarded while its generation still had a lease")
	}

	if !oldState.admission.reserveRule(oldBinding.rule) {
		t.Fatal("simulated pre-commit acceptor could not reserve the original admission")
	}
	defer oldState.admission.releasePending()

	readdedRule := reloadRule("admission-readded", firstListen, "127.0.0.1:3")
	readdedRule.MaxConnections = 1
	readdedRule.MaxConnectionsPerIP = 1
	if _, err := server.ReloadRules(context.Background(), []*config.Rule{readdedRule}); err != nil {
		t.Fatalf("re-add first listener: %v", err)
	}
	readded := server.listenersByKey[firstListen]
	if readded == nil {
		t.Fatal("re-added listener is missing")
	}
	if readded.admission != oldState.admission {
		t.Fatal("re-added listener reset admission accounting")
	}
	if readded.admission.reserveRule(server.current.Load().bindings[firstListen].rule) {
		readded.admission.releasePending()
		t.Fatal("re-added listener bypassed maxConnections held by the old generation")
	}
}
