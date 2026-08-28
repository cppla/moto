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

// TestHTTP3NetemRuleBreakerCooldownAndDataPlaneProbation is the
// production-isomorphic rule-breaker lifecycle gate. It runs real HTTP/3 and
// HTTP/2 CONNECT servers on the same IP:port, degrades two independent QUIC
// generations, validates the TCP fallback, and proves that only one half-open
// QUIC probation is admitted. A successful CONNECT alone is insufficient: the
// rule returns to H3 only after the probation carries real payload and records
// three healthy samples over the production minimum duration.
//
// The test is intentionally opt-in because it replaces the loopback qdisc. Run
// it only in a disposable privileged Linux container or network namespace.
func TestHTTP3NetemRuleBreakerCooldownAndDataPlaneProbation(t *testing.T) {
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
	var blockProbation atomic.Bool
	probationStarted := make(chan struct{}, 1)
	releaseProbation := make(chan struct{})
	var releaseProbationOnce sync.Once
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor == 3 {
			h3Requests.Add(1)
			if blockProbation.Load() {
				select {
				case probationStarted <- struct{}{}:
				default:
				}
				select {
				case <-releaseProbation:
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
	manager.h3RuleBreaker = newHTTP3RuleBreaker(manager.timeNow)
	h3Manager.onDegraded = manager.noteHTTP3Degradation
	h3Manager.onRecovered = manager.noteHTTP3Recovery
	h3Manager.onConnectionDegraded = manager.noteHTTP3RuleDegradation
	h3Manager.onConnectionSample = manager.noteHTTP3RuleSample
	const ruleName = "netem-mixed"
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
		connection, err := manager.dialForRule(ctx, ruleName, target, destination)
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
	assertHTTP3RuleBreakerPhase(t, manager, ruleName, http3RuleBreakerEvaluating)
	manager.h3RuleBreaker.mu.Lock()
	ruleEvents := append([]http3RuleDegradationEvent(nil), manager.h3RuleBreaker.rules[ruleName].recent...)
	manager.h3RuleBreaker.mu.Unlock()
	if len(ruleEvents) != 2 || ruleEvents[0].generationID == ruleEvents[1].generationID {
		t.Fatalf("rule breaker degradation generations = %+v, want two independent generations", ruleEvents)
	}
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
	assertHTTP3RuleBreakerPhase(t, manager, ruleName, http3RuleBreakerCooldown)
	manager.h3FallbackMu.Lock()
	targetCooldownUntil := manager.h3Fallback[key].retryAt
	manager.h3FallbackMu.Unlock()
	if duration := targetCooldownUntil.Sub(time.Unix(0, policyNow.Load())); duration != http3DegradedCooldownBase {
		t.Fatalf("degradation cooldown = %s, want %s", duration, http3DegradedCooldownBase)
	}
	manager.h3RuleBreaker.mu.Lock()
	ruleCooldownUntil := manager.h3RuleBreaker.rules[ruleName].retryAt
	ruleFailures := manager.h3RuleBreaker.rules[ruleName].failures
	manager.h3RuleBreaker.mu.Unlock()
	if duration := ruleCooldownUntil.Sub(time.Unix(0, policyNow.Load())); duration != http3RuleCooldownSteps[0] || ruleFailures != 1 {
		t.Fatalf("rule cooldown = %s failures=%d, want %s/1", duration, ruleFailures, http3RuleCooldownSteps[0])
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

	policyNow.Store(ruleCooldownUntil.UnixNano())
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
		releaseProbationOnce.Do(func() { close(releaseProbation) })
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
	blockProbation.Store(true)
	for request := 0; request < concurrent; request++ {
		probeWG.Add(1)
		go func(index int) {
			defer probeWG.Done()
			<-start
			ctx, cancel := context.WithTimeout(probeCtx, 10*time.Second)
			defer cancel()
			connection, err := manager.dialForRule(ctx, ruleName, target, "probation-"+strconv.Itoa(index)+".example:443")
			if err != nil {
				errorsFound <- err
				return
			}
			results <- connection
		}(request)
	}
	close(start)
	select {
	case <-probationStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("single HTTP/3 probation request did not reach the proxy")
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
	assertHTTP3RuleBreakerPhase(t, manager, ruleName, http3RuleBreakerProbation)
	releaseProbationOnce.Do(func() { close(releaseProbation) })
	var probationTunnel net.Conn
	select {
	case err := <-errorsFound:
		t.Fatalf("HTTP/3 probation failed: %v", err)
	case connection := <-results:
		if network := connection.RemoteAddr().Network(); network != config.ConnectProxyH3 {
			_ = connection.Close()
			t.Fatalf("probation protocol = %s, want h3", network)
		}
		probationTunnel = connection
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/3 probation did not complete after release")
	}
	defer probationTunnel.Close()
	assertHTTP3PolicyState(t, manager, key, 0, false, false, false)
	assertHTTP3RuleBreakerPhase(t, manager, ruleName, http3RuleBreakerProbation)
	if got := connectionCount.Load(); got != 3 {
		t.Fatalf("physical QUIC connections after probation CONNECT = %d, want 3", got)
	}

	// CONNECT success must not restore H3 for sibling requests. The admitted
	// probation remains the only H3 stream until its data-plane evidence passes.
	h2BeforeEvidence := h2Requests.Load()
	beforeEvidence := dial("before-data-plane-evidence.example:443")
	if network := beforeEvidence.RemoteAddr().Network(); network != config.ConnectProxyH2 {
		_ = beforeEvidence.Close()
		t.Fatalf("pre-evidence sibling protocol = %s, want h2", network)
	}
	_ = beforeEvidence.Close()
	if h2Requests.Load() != h2BeforeEvidence+1 {
		t.Fatalf("pre-evidence sibling did not use H2: %d->%d", h2BeforeEvidence, h2Requests.Load())
	}

	exerciseHTTP3NetemTunnel(t, probationTunnel, int(http3RuleProbationMinPayload)*2)
	stopSamplerForNetemTest(h3Manager)
	manager.h3RuleBreaker.mu.Lock()
	probationEstablishedAt := manager.h3RuleBreaker.rules[ruleName].probation.establishedAt
	manager.h3RuleBreaker.mu.Unlock()

	// The payload threshold alone cannot recover early. This first real sample
	// is deliberately inside the 30-second production probation interval.
	earlySampleAt := probationEstablishedAt.Add(2 * time.Second)
	policyNow.Store(earlySampleAt.UnixNano())
	h3Manager.sampleHTTP3DegradationAt(earlySampleAt)
	manager.h3RuleBreaker.mu.Lock()
	earlyState := *manager.h3RuleBreaker.rules[ruleName]
	manager.h3RuleBreaker.mu.Unlock()
	if earlyState.phase != http3RuleBreakerProbation ||
		earlyState.probation.payloadBytes < http3RuleProbationMinPayload {
		t.Fatalf("early data-plane probation state = %+v, want probation with >=%d payload bytes",
			earlyState, http3RuleProbationMinPayload)
	}

	// Two further healthy samples at and after the minimum duration complete
	// three consecutive observations without changing production constants.
	for _, sampleAt := range []time.Time{
		probationEstablishedAt.Add(http3RuleProbationMinDuration),
		probationEstablishedAt.Add(http3RuleProbationMinDuration + http3DegradationSampleInterval),
	} {
		policyNow.Store(sampleAt.UnixNano())
		h3Manager.sampleHTTP3DegradationAt(sampleAt)
	}
	assertHTTP3RuleBreakerPhase(t, manager, ruleName, http3RuleBreakerClosed)
	manager.h3RuleBreaker.mu.Lock()
	recoveredState := *manager.h3RuleBreaker.rules[ruleName]
	manager.h3RuleBreaker.mu.Unlock()
	if recoveredState.failures != 0 || recoveredState.events["recovered"] != 1 {
		t.Fatalf("data-plane recovery state = %+v", recoveredState)
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
		// Keep enough wire traffic in the 12-second production window to cross
		// the packet/byte gate while making both RTT and loss independently bad.
		// A very low rate here makes the test host's CPU scheduling determine
		// whether enough QUIC packets are observed, which is unnecessarily flaky.
		{"qdisc", "replace", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", "175ms", "20ms", "loss", "12%", "rate", "10mbit"},
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
	deadline := time.Now().Add(30 * time.Second)
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

func exerciseHTTP3NetemTunnel(t *testing.T, connection net.Conn, size int) {
	t.Helper()
	if size <= 0 {
		t.Fatal("HTTP/3 netem payload size must be positive")
	}
	payload := bytes.Repeat([]byte("moto-h3-probation"), size/len("moto-h3-probation")+1)[:size]
	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload)
		writeDone <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatalf("read HTTP/3 probation echo: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write HTTP/3 probation payload: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("HTTP/3 probation echo payload mismatch")
	}
}

func assertHTTP3RuleBreakerPhase(
	t *testing.T,
	manager *connectProxyManager,
	rule string,
	want http3RuleBreakerPhase,
) {
	t.Helper()
	if manager == nil || manager.h3RuleBreaker == nil {
		t.Fatal("HTTP/3 rule breaker is not configured")
	}
	manager.h3RuleBreaker.mu.Lock()
	state := manager.h3RuleBreaker.rules[rule]
	if state == nil {
		manager.h3RuleBreaker.mu.Unlock()
		t.Fatalf("HTTP/3 rule breaker state for %q was not registered", rule)
	}
	got := state.phase
	manager.h3RuleBreaker.mu.Unlock()
	if got != want {
		t.Fatalf("HTTP/3 rule breaker phase = %s, want %s", got, want)
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
