package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	xhttp2 "golang.org/x/net/http2"
)

// TestHTTP3NetemDegradationCreatesAndPromotesCandidate is intentionally opt-in:
// it changes the loopback qdisc and therefore must run only in a disposable
// privileged Linux container or network namespace.
func TestHTTP3NetemDegradationCreatesAndPromotesCandidate(t *testing.T) {
	if os.Getenv("MOTO_NETEM_TEST") != "1" {
		t.Skip("set MOTO_NETEM_TEST=1 in a disposable privileged Linux container")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("netem test requires Linux root")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("netem test requires tc from iproute2")
	}
	deleteNetem := func() {
		_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
	}
	deleteNetem()
	t.Cleanup(deleteNetem)

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer manager.close()
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH3},
		},
	}

	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
	sourceTunnel, err := manager.dial(setupCtx, target, "netem-source.example:443")
	cancelSetup()
	if err != nil {
		t.Fatalf("establish source H3 tunnel: %v", err)
	}
	defer sourceTunnel.Close()
	key := http3ConnectTransportKey{address: endpoint}
	manager.mu.Lock()
	source := manager.transports[key][0]
	// Keep production thresholds while skipping only the initial 15-second
	// learning delay; the test still requires real traffic, three consecutive
	// 2-second observations, and two independent QUIC signals.
	source.detector.establishedAt = time.Now().Add(-http3DegradationWarmup)
	samplerCancel, samplerDone := manager.detachHTTP3SamplerLocked()
	manager.mu.Unlock()
	stopHTTP3Sampler(samplerCancel, samplerDone)

	trafficCtx, cancelTraffic := context.WithCancel(context.Background())
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		payload := bytes.Repeat([]byte("moto-netem-h3"), 4096)
		for trafficCtx.Err() == nil {
			if _, writeErr := sourceTunnel.Write(payload); writeErr != nil {
				return
			}
		}
	}()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = io.Copy(io.Discard, sourceTunnel)
	}()

	manager.sampleHTTP3DegradationAt(time.Now())
	time.Sleep(http3DegradationSampleInterval)
	manager.sampleHTTP3DegradationAt(time.Now())
	if output, tcErr := exec.Command(
		"tc", "qdisc", "replace", "dev", "lo", "root", "netem",
		"delay", "350ms", "30ms", "loss", "10%", "rate", "2mbit",
	).CombinedOutput(); tcErr != nil {
		cancelTraffic()
		_ = sourceTunnel.Close()
		<-trafficDone
		<-readDone
		t.Fatalf("enable loopback netem: %v: %s", tcErr, output)
	}

	deadline := time.Now().Add(20 * time.Second)
	var candidate *http3ConnectTransportSlot
	for time.Now().Before(deadline) {
		time.Sleep(http3DegradationSampleInterval)
		manager.sampleHTTP3DegradationAt(time.Now())
		manager.mu.Lock()
		candidate = source.replacement
		manager.mu.Unlock()
		if candidate != nil {
			break
		}
	}
	deleteNetem()
	if candidate == nil {
		cancelTraffic()
		_ = sourceTunnel.Close()
		<-trafficDone
		<-readDone
		manager.mu.Lock()
		decision := source.lastDecision
		manager.mu.Unlock()
		t.Fatalf("real netem did not create a warming candidate: %+v", decision)
	}

	candidateCtx, cancelCandidate := context.WithTimeout(context.Background(), 5*time.Second)
	candidateTunnel, err := manager.dial(candidateCtx, target, "netem-candidate.example:443")
	cancelCandidate()
	if err != nil {
		cancelTraffic()
		_ = sourceTunnel.Close()
		<-trafficDone
		<-readDone
		t.Fatalf("promote recovered candidate: %v", err)
	}
	_ = candidateTunnel.Close()
	cancelTraffic()
	_ = sourceTunnel.Close()
	<-trafficDone
	<-readDone

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if candidate.lifecycle != http3TransportServing || manager.containsSlotLocked(key, source) {
		t.Fatalf("netem rotation state = candidate:%s sourceRetained:%t", candidate.lifecycle, manager.containsSlotLocked(key, source))
	}
	if candidate == source {
		t.Fatal("netem rotation reused source slot")
	}
}

// TestHTTP3NetemRepeatedDegradationCooldownAndHalfOpenRecovery is the
// production-isomorphic lifecycle gate. It runs real HTTP/3 and HTTP/2 CONNECT
// servers on the same IP:port, degrades only UDP twice, validates the TCP
// fallback, and proves the cooldown's single half-open QUIC recovery.
//
// The test is intentionally opt-in because it replaces the loopback qdisc. Run
// it only in a disposable privileged Linux container or network namespace.
func TestHTTP3NetemRepeatedDegradationCooldownAndHalfOpenRecovery(t *testing.T) {
	if os.Getenv("MOTO_NETEM_LIFECYCLE_TEST") != "1" {
		t.Skip("set MOTO_NETEM_LIFECYCLE_TEST=1 in a disposable privileged Linux container")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("netem lifecycle test requires Linux root")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("netem lifecycle test requires tc from iproute2")
	}

	deleteNetem := func() {
		_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
	}
	deleteNetem()
	t.Cleanup(deleteNetem)

	var h2Requests atomic.Int64
	var h3Requests atomic.Int64
	var blockHalfOpen atomic.Bool
	halfOpenStarted := make(chan struct{}, 1)
	releaseHalfOpen := make(chan struct{})
	var releaseHalfOpenOnce sync.Once
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor == 3 {
			h3Requests.Add(1)
			if blockHalfOpen.Load() {
				select {
				case halfOpenStarted <- struct{}{}:
				default:
				}
				select {
				case <-releaseHalfOpen:
				case <-request.Context().Done():
					return
				}
			}
		} else if request.ProtoMajor == 2 {
			h2Requests.Add(1)
		}
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.Copy(writer, request.Body)
	})
	endpoint, roots, closeServers, connectionCount := startHTTP2And3ConnectTestServer(t, handler)
	defer closeServers()

	h3Manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer h3Manager.close()
	h2Manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer h2Manager.closeIdle()

	var policyNow atomic.Int64
	policyNow.Store(time.Now().UnixNano())
	manager := &connectProxyManager{
		h2:                     h2Manager,
		h3:                     h3Manager,
		h3Fallback:             make(map[http3ConnectTransportKey]*http3FallbackState),
		now:                    func() time.Time { return time.Unix(0, policyNow.Load()) },
		cooldownBase:           http3FallbackCooldownBase,
		cooldownMax:            http3FallbackCooldownMax,
		degradedCooldownBase:   http3DegradedCooldownBase,
		degradedCooldownMax:    http3DegradedCooldownMax,
		degradationWindow:      http3DegradationStrikeWindow,
		degradationPenaltyBase: http3DegradationPenaltyBase,
		degradationPenaltyMax:  http3DegradationPenaltyMax,
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH2: h2Manager.dial,
			config.ConnectProxyH3: h3Manager.dial,
		},
	}
	h3Manager.onDegraded = manager.noteHTTP3Degradation
	h3Manager.onRecovered = manager.noteHTTP3Recovery
	target := &config.Target{
		Address: endpoint,
		ConnectProxy: &config.ConnectProxyConfig{
			ServerName: "127.0.0.1",
			Protocols:  []string{config.ConnectProxyH3, config.ConnectProxyH2},
		},
	}
	key := http3ConnectTransportKey{address: endpoint, serverName: "127.0.0.1"}

	dial := func(destination string) net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		connection, err := manager.dial(ctx, target, destination)
		if err != nil {
			t.Fatalf("dial %s: %v", destination, err)
		}
		return connection
	}

	firstTunnel := dial("generation-a.example:443")
	if got := connectionCount.Load(); got != 1 {
		_ = firstTunnel.Close()
		t.Fatalf("initial physical QUIC connections = %d, want 1", got)
	}
	source := servingHTTP3SlotForTest(t, h3Manager, key)
	stopSamplerForNetemTest(h3Manager)
	stopFirstTraffic := startHTTP3NetemTraffic(firstTunnel)
	defer stopFirstTraffic()
	prepareHTTP3SlotForNetemTest(h3Manager, source)
	warmHTTP3NetemSamples(h3Manager)
	enableHTTP3OnlyLoopbackNetem(t, endpoint)
	second := waitForHTTP3Replacement(t, h3Manager, source, "first degradation")
	deleteNetem()

	secondTunnel := dial("generation-b.example:443")
	h3Manager.mu.Lock()
	secondLifecycle := second.lifecycle
	sourceLifecycle := source.lifecycle
	h3Manager.mu.Unlock()
	if secondLifecycle != http3TransportServing || sourceLifecycle != http3TransportDraining {
		stopFirstTraffic()
		_ = firstTunnel.Close()
		_ = secondTunnel.Close()
		t.Fatalf("first promotion lifecycle = source:%s candidate:%s", sourceLifecycle, secondLifecycle)
	}
	assertHTTP3PolicyState(t, manager, key, 1, false, false, false)
	if got := connectionCount.Load(); got != 2 {
		t.Fatalf("physical QUIC connections after first promotion = %d, want 2", got)
	}
	stopFirstTraffic()
	_ = firstTunnel.Close()

	stopSecondTraffic := startHTTP3NetemTraffic(secondTunnel)
	defer stopSecondTraffic()
	prepareHTTP3SlotForNetemTest(h3Manager, second)
	warmHTTP3NetemSamples(h3Manager)
	enableHTTP3OnlyLoopbackNetem(t, endpoint)
	_ = waitForHTTP3Replacement(t, h3Manager, second, "second degradation")
	assertHTTP3PolicyState(t, manager, key, 2, true, false, false)
	if got := connectionCount.Load(); got != 2 {
		t.Fatalf("lazy second replacement established QUIC before H2 validation: %d", got)
	}
	stopSecondTraffic()
	_ = secondTunnel.Close()

	h2Validation := dial("h2-validation.example:443")
	if network := h2Validation.RemoteAddr().Network(); network != config.ConnectProxyH2 {
		_ = h2Validation.Close()
		t.Fatalf("validation protocol = %s, want h2", network)
	}
	_ = h2Validation.Close()
	assertHTTP3PolicyState(t, manager, key, 2, false, true, false)
	manager.h3FallbackMu.Lock()
	cooldownUntil := manager.h3Fallback[key].retryAt
	manager.h3FallbackMu.Unlock()
	if duration := cooldownUntil.Sub(time.Unix(0, policyNow.Load())); duration != http3DegradedCooldownBase {
		t.Fatalf("degradation cooldown = %s, want %s", duration, http3DegradedCooldownBase)
	}
	h3BeforeCooldown := h3Requests.Load()
	h2BeforeCooldown := h2Requests.Load()
	quicBeforeCooldown := connectionCount.Load()
	cooldownTunnel := dial("during-cooldown.example:443")
	if network := cooldownTunnel.RemoteAddr().Network(); network != config.ConnectProxyH2 {
		_ = cooldownTunnel.Close()
		t.Fatalf("cooldown protocol = %s, want h2", network)
	}
	_ = cooldownTunnel.Close()
	if h3Requests.Load() != h3BeforeCooldown || h2Requests.Load() != h2BeforeCooldown+1 ||
		connectionCount.Load() != quicBeforeCooldown {
		t.Fatalf("cooldown traffic changed unexpected protocol counters: h3=%d->%d h2=%d->%d quic=%d->%d",
			h3BeforeCooldown, h3Requests.Load(), h2BeforeCooldown, h2Requests.Load(),
			quicBeforeCooldown, connectionCount.Load())
	}
	// The selective qdisc is still degrading UDP here. Both the validation and
	// this cooldown request succeeding over H2 prove TCP fallback is unaffected.
	deleteNetem()

	policyNow.Store(cooldownUntil.UnixNano())
	const concurrent = 8
	start := make(chan struct{})
	results := make(chan net.Conn, concurrent)
	errorsFound := make(chan error, concurrent)
	probeCtx, cancelProbes := context.WithCancel(context.Background())
	var probeWG sync.WaitGroup
	defer func() {
		// This defer is registered after the transport/server defers, so a
		// failed assertion cannot leave the test handler blocked while server
		// shutdown waits for it. Cancel and join every concurrent dial before
		// closing any shared transport.
		releaseHalfOpenOnce.Do(func() { close(releaseHalfOpen) })
		cancelProbes()
		probeWG.Wait()
		for {
			select {
			case connection := <-results:
				if connection != nil {
					_ = connection.Close()
				}
			default:
				return
			}
		}
	}()
	blockHalfOpen.Store(true)
	for request := 0; request < concurrent; request++ {
		probeWG.Add(1)
		go func(index int) {
			defer probeWG.Done()
			<-start
			ctx, cancel := context.WithTimeout(probeCtx, 10*time.Second)
			defer cancel()
			connection, err := manager.dial(ctx, target, "half-open-"+strconv.Itoa(index)+".example:443")
			if err != nil {
				errorsFound <- err
				return
			}
			results <- connection
		}(request)
	}
	close(start)
	select {
	case <-halfOpenStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("single HTTP/3 half-open request did not reach the proxy")
	}

	h2WhileProbe := 0
	for h2WhileProbe < concurrent-1 {
		select {
		case err := <-errorsFound:
			t.Fatalf("concurrent cooldown fallback failed: %v", err)
		case connection := <-results:
			if network := connection.RemoteAddr().Network(); network != config.ConnectProxyH2 {
				_ = connection.Close()
				t.Fatalf("more than one half-open H3 request completed before release: %s", network)
			}
			h2WhileProbe++
			_ = connection.Close()
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/%d concurrent requests used H2 while the probe was blocked", h2WhileProbe, concurrent-1)
		}
	}
	assertHTTP3PolicyState(t, manager, key, 2, false, true, true)
	releaseHalfOpenOnce.Do(func() { close(releaseHalfOpen) })
	select {
	case err := <-errorsFound:
		t.Fatalf("HTTP/3 half-open failed: %v", err)
	case connection := <-results:
		if network := connection.RemoteAddr().Network(); network != config.ConnectProxyH3 {
			_ = connection.Close()
			t.Fatalf("half-open protocol = %s, want h3", network)
		}
		_ = connection.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/3 half-open did not complete after release")
	}
	assertHTTP3PolicyState(t, manager, key, 0, false, false, false)
	if got := connectionCount.Load(); got != 3 {
		t.Fatalf("physical QUIC connections after half-open = %d, want 3", got)
	}

	h2BeforeRecovered := h2Requests.Load()
	quicBeforeRecovered := connectionCount.Load()
	recoveredTunnel := dial("recovered-h3.example:443")
	if network := recoveredTunnel.RemoteAddr().Network(); network != config.ConnectProxyH3 {
		_ = recoveredTunnel.Close()
		t.Fatalf("post-recovery protocol = %s, want h3", network)
	}
	_ = recoveredTunnel.Close()
	if h2Requests.Load() != h2BeforeRecovered || connectionCount.Load() != quicBeforeRecovered {
		t.Fatalf("post-recovery request did not reuse H3: h2=%d->%d quic=%d->%d",
			h2BeforeRecovered, h2Requests.Load(), quicBeforeRecovered, connectionCount.Load())
	}
}

func startHTTP2And3ConnectTestServer(
	t *testing.T,
	handler http.Handler,
) (string, *x509.CertPool, func(), *atomic.Int64) {
	t.Helper()
	h2Server := httptest.NewUnstartedServer(handler)
	h2Server.EnableHTTP2 = true
	h2Server.StartTLS()

	packetConn, err := net.ListenPacket("udp", h2Server.Listener.Addr().String())
	if err != nil {
		h2Server.Close()
		t.Fatalf("listen HTTP/3 on the HTTP/2 port: %v", err)
	}
	var connectionCount atomic.Int64
	h3Server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: h2Server.TLS.Certificates},
		Handler:   handler,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			connectionCount.Add(1)
			return ctx
		},
	}
	done := make(chan error, 1)
	go func() { done <- h3Server.Serve(packetConn) }()
	closeServers := func() {
		_ = h3Server.Close()
		_ = packetConn.Close()
		h2Server.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(h2Server.Certificate())
	return h2Server.Listener.Addr().String(), roots, closeServers, &connectionCount
}

func servingHTTP3SlotForTest(
	t *testing.T,
	manager *http3ConnectManager,
	key http3ConnectTransportKey,
) *http3ConnectTransportSlot {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, slot := range manager.transports[key] {
		if slot != nil && slot.lifecycle == http3TransportServing {
			return slot
		}
	}
	t.Fatal("HTTP/3 serving slot was not found")
	return nil
}

func stopSamplerForNetemTest(manager *http3ConnectManager) {
	manager.mu.Lock()
	cancel, done := manager.detachHTTP3SamplerLocked()
	manager.mu.Unlock()
	stopHTTP3Sampler(cancel, done)
}

func prepareHTTP3SlotForNetemTest(manager *http3ConnectManager, slot *http3ConnectTransportSlot) {
	manager.mu.Lock()
	slot.detector.establishedAt = time.Now().Add(-http3DegradationWarmup)
	manager.mu.Unlock()
}

func warmHTTP3NetemSamples(manager *http3ConnectManager) {
	manager.sampleHTTP3DegradationAt(time.Now())
	time.Sleep(http3DegradationSampleInterval)
	manager.sampleHTTP3DegradationAt(time.Now())
}

func enableHTTP3OnlyLoopbackNetem(t *testing.T, endpoint string) {
	t.Helper()
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("split HTTP/3 endpoint: %v", err)
	}
	commands := [][]string{
		{"qdisc", "replace", "dev", "lo", "root", "handle", "1:", "prio"},
		{"qdisc", "replace", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", "350ms", "30ms", "loss", "10%", "rate", "2mbit"},
		{"filter", "replace", "dev", "lo", "protocol", "ip", "parent", "1:0", "prio", "3", "u32", "match", "ip", "protocol", "17", "0xff", "match", "ip", "dport", portText, "0xffff", "flowid", "1:3"},
		{"filter", "replace", "dev", "lo", "protocol", "ip", "parent", "1:0", "prio", "4", "u32", "match", "ip", "protocol", "17", "0xff", "match", "ip", "sport", portText, "0xffff", "flowid", "1:3"},
	}
	for _, arguments := range commands {
		if output, commandErr := exec.Command("tc", arguments...).CombinedOutput(); commandErr != nil {
			t.Fatalf("enable HTTP/3-only loopback netem: tc %v: %v: %s", arguments, commandErr, output)
		}
	}
}

func waitForHTTP3Replacement(
	t *testing.T,
	manager *http3ConnectManager,
	source *http3ConnectTransportSlot,
	stage string,
) *http3ConnectTransportSlot {
	t.Helper()
	deadline := time.Now().Add(24 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(http3DegradationSampleInterval)
		manager.sampleHTTP3DegradationAt(time.Now())
		manager.mu.Lock()
		replacement := source.replacement
		decision := source.lastDecision
		manager.mu.Unlock()
		if replacement != nil {
			// Creating a lazy replacement restarts the production sampler. Keep
			// this opt-in test on its explicit 2-second sampling schedule so the
			// number of consecutive degraded windows remains deterministic.
			stopSamplerForNetemTest(manager)
			return replacement
		}
		if decision.Rotate && decision.Reason == http3DegradationReasonConnectionError {
			break
		}
	}
	manager.mu.Lock()
	decision := source.lastDecision
	manager.mu.Unlock()
	t.Fatalf("%s did not create a warming HTTP/3 replacement: %+v", stage, decision)
	return nil
}

func startHTTP3NetemTraffic(connection net.Conn) func() {
	var once sync.Once
	doneWriting := make(chan struct{})
	doneReading := make(chan struct{})
	go func() {
		defer close(doneWriting)
		payload := bytes.Repeat([]byte("moto-netem-h3"), 4096)
		for {
			if _, err := connection.Write(payload); err != nil {
				return
			}
		}
	}()
	go func() {
		defer close(doneReading)
		_, _ = io.Copy(io.Discard, connection)
	}()
	return func() {
		once.Do(func() {
			_ = connection.Close()
			<-doneWriting
			<-doneReading
		})
	}
}

func assertHTTP3PolicyState(
	t *testing.T,
	manager *connectProxyManager,
	key http3ConnectTransportKey,
	strikes int,
	pending, coolingDown, probing bool,
) {
	t.Helper()
	manager.h3FallbackMu.Lock()
	state := *manager.h3Fallback[key]
	manager.h3FallbackMu.Unlock()
	if state.degradationStrikes != strikes || state.pending != pending ||
		(state.failures > 0) != coolingDown || state.probing != probing {
		t.Fatalf("HTTP/3 policy state = %+v, want strikes=%d pending=%t coolingDown=%t probing=%t",
			state, strikes, pending, coolingDown, probing)
	}
}
