package controller

import (
	"bufio"
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type boostPublicationReplyGate struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (conn *boostPublicationReplyGate) Write(body []byte) (int, error) {
	conn.once.Do(func() { close(conn.started) })
	return conn.Conn.Write(body)
}

type boostPublicationFixture struct {
	runtime  *routingRuntime
	rule     *config.Rule
	ctx      context.Context
	reversed atomic.Bool
	peers    chan net.Conn
	mu       sync.Mutex
	conns    []net.Conn
	handlers sync.WaitGroup
}

func newBoostPublicationFixture(t *testing.T) *boostPublicationFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture := &boostPublicationFixture{
		runtime: newRoutingRuntime(),
		rule:    boostTestRule(t.Name(), "127.0.0.1:19902", "old.example:443", "new.example:443"),
		ctx:     ctx,
		peers:   make(chan net.Conn, 4),
	}
	fixture.rule.Protocol = config.ProtocolHTTP
	fixture.rule.Timeout = 200
	for _, target := range fixture.rule.Targets {
		target.ConnectProxy = &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH2}}
	}
	fixture.runtime.connectProxy.dialers[config.ConnectProxyH2] = func(ctx context.Context, target *config.Target, _ string) (net.Conn, error) {
		winner := "old.example:443"
		if fixture.reversed.Load() {
			winner = "new.example:443"
		}
		if target.Address != winner {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		connection, peer := net.Pipe()
		fixture.track(connection, peer)
		fixture.peers <- peer
		return connection, nil
	}
	t.Cleanup(func() {
		cancel()
		fixture.mu.Lock()
		for _, conn := range fixture.conns {
			_ = conn.Close()
		}
		fixture.mu.Unlock()
		done := make(chan struct{})
		go func() { fixture.handlers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Boost handlers did not stop")
		}
		fixture.runtime.stopBackground()
	})
	return fixture
}

func (fixture *boostPublicationFixture) track(conns ...net.Conn) {
	fixture.mu.Lock()
	fixture.conns = append(fixture.conns, conns...)
	fixture.mu.Unlock()
}

func (fixture *boostPublicationFixture) start(gate bool) (net.Conn, <-chan struct{}, <-chan struct{}) {
	server, client := net.Pipe()
	fixture.track(server, client)
	var inbound net.Conn = server
	var started chan struct{}
	if gate {
		started = make(chan struct{})
		inbound = &boostPublicationReplyGate{Conn: server, started: started}
	}
	done := make(chan struct{})
	fixture.handlers.Add(1)
	go func() {
		defer fixture.handlers.Done()
		defer close(done)
		// Every request has exactly the same CONNECT authority. Only upstream
		// availability changes, never the destination-specific route preference.
		fixture.runtime.handleBoost(withConnectDestination(fixture.ctx, "same-destination.example:443"),
			&httpConnectClientConn{Conn: inbound}, fixture.rule)
	}()
	return client, started, done
}

func awaitBoostPublicationSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Boost synchronization point was not reached")
	}
}

func (fixture *boostPublicationFixture) peer(t *testing.T) net.Conn {
	t.Helper()
	select {
	case peer := <-fixture.peers:
		return peer
	case <-time.After(2 * time.Second):
		t.Fatal("successful upstream tunnel missing")
		return nil
	}
}

func readBoostPublicationReply(t *testing.T, client net.Conn) int {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	return response.StatusCode
}

// A payload reaching the upstream is an event barrier after cache publication.
// Unlike a sleep/poll loop it remains fast both before and after the fix.
func proveBoostPublicationRelay(t *testing.T, client, peer net.Conn) {
	t.Helper()
	forwarded := make(chan error, 1)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	go func() { _, err := io.ReadFull(peer, make([]byte, 1)); forwarded <- err }()
	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	_ = client.SetWriteDeadline(time.Time{})
	select {
	case err := <-forwarded:
		if err != nil {
			t.Fatalf("forward tunnel payload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not enter relay")
	}
	_ = peer.SetReadDeadline(time.Time{})
}

func TestFreshBoostLateReplyCannotReplaceNewWinner(t *testing.T) {
	fixture := newBoostPublicationFixture(t)
	first, blocked, _ := fixture.start(true)
	firstPeer := fixture.peer(t)
	awaitBoostPublicationSignal(t, blocked)
	key := boostRuleKey(fixture.rule)
	if _, ok := fixture.runtime.loadBoostWinnerToken(key); ok {
		t.Fatal("older acknowledgment unexpectedly finished")
	}
	fixture.reversed.Store(true)
	second, _, _ := fixture.start(false)
	secondPeer := fixture.peer(t)
	if status := readBoostPublicationReply(t, second); status != http.StatusOK {
		t.Fatalf("new healthy route reply=%d", status)
	}
	proveBoostPublicationRelay(t, second, secondPeer)
	newer, ok := fixture.runtime.loadBoostWinnerToken(key)
	if !ok || newer.addr != "new.example:443" {
		t.Fatalf("newer winner missing: %+v exists=%t", newer, ok)
	}
	if status := readBoostPublicationReply(t, first); status != http.StatusOK {
		t.Fatalf("older valid tunnel reply=%d", status)
	}
	proveBoostPublicationRelay(t, first, firstPeer)
	current, ok := fixture.runtime.loadBoostWinnerToken(key)
	if !ok || current.addr != newer.addr || current.generation != newer.generation {
		t.Fatalf("old setup replaced newer cache: before=%+v after=%+v exists=%t", newer, current, ok)
	}
	requireNoBoostWinnerDecisions(t, fixture.runtime)
	third, _, _ := fixture.start(false)
	if status := readBoostPublicationReply(t, third); status != http.StatusOK {
		t.Fatalf("next request returned %d despite newer route remaining healthy", status)
	}
	proveBoostPublicationRelay(t, third, fixture.peer(t))
}

func TestCachedBoostHitDoesNotCreateDecisionLease(t *testing.T) {
	fixture := newBoostPublicationFixture(t)
	fixture.reversed.Store(true)
	fixture.runtime.storeBoostWinner(boostRuleKey(fixture.rule), "new.example:443")
	client, _, _ := fixture.start(false)
	if status := readBoostPublicationReply(t, client); status != http.StatusOK {
		t.Fatalf("cached reply=%d", status)
	}
	proveBoostPublicationRelay(t, client, fixture.peer(t))
	fixture.runtime.boost.cache.Lock()
	defer fixture.runtime.boost.cache.Unlock()
	if fixture.runtime.boost.cache.decisions != nil {
		t.Fatal("ordinary cache hit allocated a decision registry")
	}
}

func TestFreshBoostReplyFailureReleasesDecision(t *testing.T) {
	fixture := newBoostPublicationFixture(t)
	client, blocked, done := fixture.start(true)
	awaitBoostPublicationSignal(t, blocked)
	_ = client.Close()
	awaitBoostPublicationSignal(t, done)
	if _, ok := fixture.runtime.loadBoostWinnerToken(boostRuleKey(fixture.rule)); ok {
		t.Fatal("failed local acknowledgment published a winner")
	}
	requireNoBoostWinnerDecisions(t, fixture.runtime)
}

func TestFreshBoostFailedDialReleasesDecision(t *testing.T) {
	fixture := newBoostPublicationFixture(t)
	fixture.runtime.connectProxy.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		return nil, errors.New("injected dial failure")
	}
	client, _, done := fixture.start(false)
	if status := readBoostPublicationReply(t, client); status == http.StatusOK {
		t.Fatal("failed routes returned success")
	}
	awaitBoostPublicationSignal(t, done)
	if _, ok := fixture.runtime.loadBoostWinnerToken(boostRuleKey(fixture.rule)); ok {
		t.Fatal("failed race published a winner")
	}
	requireNoBoostWinnerDecisions(t, fixture.runtime)
}

func TestLazyBoostRefreshCannotReplaceNewWinner(t *testing.T) {
	for _, mutation := range []string{"unchanged", "new_winner", "delete", "aba"} {
		t.Run(mutation, func(t *testing.T) {
			runtime := newRoutingRuntime()
			defer runtime.stopBackground()
			rule := boostTestRule(t.Name(), "127.0.0.1:19903", "old.example:443", "other.example:443")
			key := boostRuleKey(rule)
			runtime.storeBoostWinner(key, "original.example:443")
			loserStarted, loserCanceled, releaseLoser := make(chan struct{}), make(chan struct{}), make(chan struct{})
			done := make(chan struct{})
			var releaseOnce sync.Once
			defer func() { releaseOnce.Do(func() { close(releaseLoser) }); awaitBoostPublicationSignal(t, done) }()
			connection, peer := net.Pipe()
			defer peer.Close()
			go func() {
				defer close(done)
				runtime.lazyRevalidateWithDial(context.Background(), rule, key, func(ctx context.Context, address string) (net.Conn, error) {
					if address == "old.example:443" {
						select {
						case <-loserStarted:
							return connection, nil
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					close(loserStarted)
					<-ctx.Done()
					close(loserCanceled)
					<-releaseLoser
					return nil, ctx.Err()
				})
			}()
			awaitBoostPublicationSignal(t, loserCanceled)
			switch mutation {
			case "new_winner":
				runtime.storeBoostWinner(key, "new.example:443")
			case "delete":
				runtime.deleteBoostWinner(key)
			case "aba":
				runtime.storeBoostWinner(key, "new.example:443")
				runtime.deleteBoostWinner(key)
			}
			before, existed := cachedBoostRawEntry(runtime, key)
			releaseOnce.Do(func() { close(releaseLoser) })
			awaitBoostPublicationSignal(t, done)
			after, exists := cachedBoostRawEntry(runtime, key)
			if mutation == "unchanged" {
				if !exists || after.addr != "old.example:443" || after.generation == before.generation {
					t.Fatalf("valid lazy refresh did not publish: %+v", after)
				}
			} else if exists != existed || after != before {
				t.Fatalf("stale lazy refresh changed current cache: before=%+v exists=%t after=%+v exists=%t", before, existed, after, exists)
			}
			requireNoBoostWinnerDecisions(t, runtime)
		})
	}
}
