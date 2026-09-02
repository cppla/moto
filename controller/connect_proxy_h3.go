package controller

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// This is a defensive cap for one physical DNS+QUIC setup. The configured
	// rule/attempt deadline remains authoritative whenever it is shorter.
	http3ConnectMaxHandshakeTimeout = 30 * time.Second
	http3ConnectIdleTimeout         = 90 * time.Second
	http3ConnectKeepAlivePeriod     = 10 * time.Second
	http3ConnectMaxResponseHeaders  = 16 << 10
	// Stay below common peer-controlled bidirectional stream ceilings and
	// open another pooled QUIC connection before a long CONNECT can consume all
	// stream credit. The pool remains bounded at the default rule connection cap.
	http3ConnectStreamsPerTransport = 64
	http3ConnectMaxTransportsPerKey = 64
)

var (
	errHTTP3TunnelFastFailed                = fmt.Errorf("HTTP/3 tunnel canceled after sustained stalled I/O once a replacement path was validated: %w", net.ErrClosed)
	errHTTP3CandidateRetrySourceUnavailable = errors.New("HTTP/3 rotation source is no longer serving")
)

type http3ConnectTransportKey struct {
	address    string
	serverName string
}

type http3AddressResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type http3ConnectTransportSlot struct {
	transport    *http3.Transport
	setupFlights *http3SetupFlightTracker
	cancelSetup  context.CancelFunc
	closeOnce    sync.Once
	active       int
	limit        int

	lifecycle          http3TransportLifecycle
	health             http3TransportHealth
	connection         http3StatsConnection
	connectionID       uint64
	generationID       uint64
	remoteIP           string
	detector           *http3DegradationDetector
	lastDecision       http3DegradationDecision
	replaces           *http3ConnectTransportSlot
	replacement        *http3ConnectTransportSlot
	rotationFailures   int
	rotationReason     http3DegradationReason
	retryAt            time.Time
	forcedDrainArmed   bool
	forcedDrainConnID  uint64
	forcedDrainMonitor *http3ForcedDrainMonitor
	tunnels            map[*http3TunnelStats]struct{}
	lastSampledPayload uint64

	payloadRead         atomic.Uint64
	payloadWritten      atomic.Uint64
	pendingWrites       atomic.Int64
	maxBlockedWrites    atomic.Int64
	lastPayloadProgress atomic.Int64
	demandStarted       atomic.Int64
}

func (slot *http3ConnectTransportSlot) close() {
	if slot == nil {
		return
	}
	slot.closeOnce.Do(func() {
		// quic-go's Transport.Close waits for an in-flight Dial to return. Cancel
		// the slot-owned physical setup first so retire/reload cannot wait for the
		// entire handshake budget after the last logical user has gone away.
		if slot.cancelSetup != nil {
			slot.cancelSetup()
		}
		if slot.transport != nil {
			_ = slot.transport.Close()
		}
	})
}

// http3SetupDeadlineContextKey carries only the setup deadline into the
// detached HTTP/3 request context. The established CONNECT stream must not
// inherit this deadline, because it may remain active long after route
// selection has completed.
type http3SetupDeadlineContextKey struct{}

type http3SetupFlight struct {
	sequence uint64
	group    *routeFailureGroup
	failed   bool
}

type http3SetupFlightSnapshot struct {
	sequence uint64
	active   *http3SetupFlight
}

// http3SetupFlightTracker mirrors quic-go's per-host shared connection setup.
// It lets logical waiters attribute their route-health observation to the one
// physical DNS+QUIC dial they shared, even when a waiter deadline wins the race
// against the final transport error.
type http3SetupFlightTracker struct {
	mu       sync.Mutex
	sequence uint64
	active   *http3SetupFlight
	last     *http3SetupFlight
}

type http3SetupError struct {
	cause error
	group *routeFailureGroup
}

func (err *http3SetupError) Error() string {
	if err == nil || err.cause == nil {
		return "HTTP/3 setup failed"
	}
	return err.cause.Error()
}

func (err *http3SetupError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// http3ConnectManager keeps a bounded HTTP/3 transport pool per configured
// proxy endpoint. Each transport reuses one QUIC connection, while every SOCKS
// CONNECT request gets an independent HTTP/3 stream. Pooling avoids waiting on
// the peer's MAX_STREAMS credit when many long tunnels are active.
type http3ConnectManager struct {
	mu                   sync.Mutex
	observerMu           sync.Mutex
	transports           map[http3ConnectTransportKey][]*http3ConnectTransportSlot
	learnedStreamLimits  map[http3ConnectTransportKey]int
	newTransport         func(http3ConnectTransportKey, context.Context) *http3.Transport
	dialCtx              context.Context
	cancelDials          context.CancelFunc
	streamsPerTransport  int
	maxTransportsPerKey  int
	retired              bool
	now                  func() time.Time
	healthyRTT           map[http3ConnectTransportKey]time.Duration
	rotationEvents       map[http3RotationMetricKey]uint64
	samplerCancel        context.CancelFunc
	samplerDone          chan struct{}
	onDegraded           func(http3ConnectTransportKey, http3DegradationReason)
	onRecovered          func(http3ConnectTransportKey)
	onConnectionDegraded func(http3RuleDegradationEvent)
	onConnectionSample   func(http3RuleSampleEvent)
	onUDPBlackhole       func(http3UDPBlackholeEvent)
	nextGenerationID     uint64
}

func newHTTP3ConnectManager(factory func(http3ConnectTransportKey, context.Context) *http3.Transport) *http3ConnectManager {
	dialCtx, cancelDials := context.WithCancel(context.Background())
	if factory == nil {
		factory = newHTTP3ConnectTransportWithOwner
	}
	return &http3ConnectManager{
		transports:          make(map[http3ConnectTransportKey][]*http3ConnectTransportSlot),
		learnedStreamLimits: make(map[http3ConnectTransportKey]int),
		newTransport:        factory,
		dialCtx:             dialCtx,
		cancelDials:         cancelDials,
		streamsPerTransport: http3ConnectStreamsPerTransport,
		maxTransportsPerKey: http3ConnectMaxTransportsPerKey,
		now:                 time.Now,
		healthyRTT:          make(map[http3ConnectTransportKey]time.Duration),
		rotationEvents:      make(map[http3RotationMetricKey]uint64),
	}
}

func newHTTP3ConnectTransportWithOwner(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
	return newHTTP3ConnectTransportWithResolver(key, owner, net.DefaultResolver)
}

func newHTTP3ConnectTransportWithResolver(
	key http3ConnectTransportKey,
	owner context.Context,
	resolver http3AddressResolver,
) *http3.Transport {
	if owner == nil {
		owner = context.Background()
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: key.serverName,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: http3ConnectMaxHandshakeTimeout,
			MaxIdleTimeout:       http3ConnectIdleTimeout,
			KeepAlivePeriod:      http3ConnectKeepAlivePeriod,
		},
		DisableCompression:     true,
		MaxResponseHeaderBytes: http3ConnectMaxResponseHeaders,
	}
	// quic-go coalesces the first connection setup per proxy host. Its default
	// dial inherits the first request's context, so canceling one Boost loser can
	// otherwise abort the shared handshake for unrelated callers. Parent the
	// physical dial to the routing generation while copying only the attempt's
	// absolute setup deadline; individual stream contexts still cancel their own
	// requests immediately and established tunnels remain detached.
	transport.Dial = func(requestCtx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
		deadline := http3SetupDeadline(requestCtx, time.Now())
		dialCtx, cancel := context.WithDeadline(owner, deadline)
		defer cancel()
		resolved, err := resolveHTTP3DialAddress(dialCtx, resolver, address)
		if err != nil {
			return nil, err
		}
		actualDeadline, ok := dialCtx.Deadline()
		if !ok {
			actualDeadline = deadline
		}
		remaining := time.Until(actualDeadline)
		if remaining <= 0 {
			if err := dialCtx.Err(); err != nil {
				return nil, err
			}
			return nil, context.DeadlineExceeded
		}
		dialQUICConfig := cloneHTTP3QUICConfigForSetup(quicConfig, remaining)
		return quic.DialAddr(dialCtx, resolved, tlsConfig, dialQUICConfig)
	}
	return transport
}

func withHTTP3SetupDeadline(base, attempt context.Context) context.Context {
	if base == nil {
		base = context.Background()
	}
	if attempt == nil {
		return base
	}
	if rule, ok := connectProxyRuleNameFromContext(attempt); ok {
		base = withConnectProxyRuleName(base, rule)
	}
	if deadline, ok := attempt.Deadline(); ok {
		return context.WithValue(base, http3SetupDeadlineContextKey{}, deadline)
	}
	return base
}

func http3SetupDeadlineFromContext(ctx context.Context) (time.Time, bool) {
	if ctx == nil {
		return time.Time{}, false
	}
	deadline, ok := ctx.Value(http3SetupDeadlineContextKey{}).(time.Time)
	return deadline, ok && !deadline.IsZero()
}

func http3SetupDeadline(ctx context.Context, now time.Time) time.Time {
	maximum := now.Add(http3ConnectMaxHandshakeTimeout)
	if deadline, ok := http3SetupDeadlineFromContext(ctx); ok && deadline.Before(maximum) {
		return deadline
	}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(maximum) {
			return deadline
		}
	}
	return maximum
}

func cloneHTTP3QUICConfigForSetup(source *quic.Config, timeout time.Duration) *quic.Config {
	var cloned *quic.Config
	if source == nil {
		cloned = &quic.Config{}
	} else {
		cloned = source.Clone()
	}
	cloned.HandshakeIdleTimeout = timeout
	return cloned
}

func (tracker *http3SetupFlightTracker) begin() *http3SetupFlight {
	if tracker == nil {
		return nil
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.sequence++
	flight := &http3SetupFlight{
		sequence: tracker.sequence,
		group:    newRouteFailureGroup(),
	}
	tracker.active = flight
	return flight
}

func (tracker *http3SetupFlightTracker) finish(flight *http3SetupFlight, err error) {
	if tracker == nil || flight == nil {
		return
	}
	tracker.mu.Lock()
	flight.failed = err != nil
	if tracker.active == flight {
		tracker.active = nil
	}
	tracker.last = flight
	tracker.mu.Unlock()
}

func (tracker *http3SetupFlightTracker) snapshot() http3SetupFlightSnapshot {
	if tracker == nil {
		return http3SetupFlightSnapshot{}
	}
	tracker.mu.Lock()
	snapshot := http3SetupFlightSnapshot{sequence: tracker.sequence, active: tracker.active}
	tracker.mu.Unlock()
	return snapshot
}

func (tracker *http3SetupFlightTracker) failureGroupAfter(snapshot http3SetupFlightSnapshot) *routeFailureGroup {
	if tracker == nil {
		return nil
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if snapshot.active != nil {
		if tracker.active == snapshot.active || (tracker.last == snapshot.active && tracker.last.failed) {
			return snapshot.active.group
		}
		return nil
	}
	if tracker.active != nil && tracker.active.sequence > snapshot.sequence {
		return tracker.active.group
	}
	if tracker.last != nil && tracker.last.sequence > snapshot.sequence && tracker.last.failed {
		return tracker.last.group
	}
	return nil
}

func instrumentHTTP3SetupFlights(
	key http3ConnectTransportKey,
	transport *http3.Transport,
	tracker *http3SetupFlightTracker,
	observeDial func(*quic.Conn, error),
) {
	if transport == nil || tracker == nil || transport.Dial == nil {
		return
	}
	originalDial := transport.Dial
	transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
		flight := tracker.begin()
		connection, err := originalDial(ctx, address, tlsConfig, quicConfig)
		tracker.finish(flight, err)
		if observeDial != nil {
			observeDial(connection, err)
		}
		if rule, ok := connectProxyRuleNameFromContext(ctx); ok {
			metricConnectProxyHandshake(rule, key.address, connectProxyAttemptOutcome(err))
		}
		if err == nil {
			return connection, nil
		}
		return connection, &http3SetupError{cause: err, group: flight.group}
	}
}

func http3SetupFailureGroup(err error) *routeFailureGroup {
	var setupErr *http3SetupError
	if errors.As(err, &setupErr) && setupErr != nil {
		return setupErr.group
	}
	return nil
}

func resolveHTTP3DialAddress(ctx context.Context, resolver http3AddressResolver, address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("split HTTP/3 proxy address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid HTTP/3 proxy port %q", portText)
	}
	if net.ParseIP(host) != nil {
		return address, nil
	}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve HTTP/3 proxy %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("resolve HTTP/3 proxy %q: no addresses", host)
	}
	selected := addresses[0]
	for _, candidate := range addresses {
		if candidate.IP.To4() != nil {
			selected = candidate
			break
		}
	}
	resolvedHost := selected.IP.String()
	if selected.Zone != "" {
		resolvedHost += "%" + selected.Zone
	}
	return net.JoinHostPort(resolvedHost, portText), nil
}

func (manager *http3ConnectManager) acquireTransport(
	key http3ConnectTransportKey,
) (*http3.Transport, *http3ConnectTransportSlot, func(), error) {
	manager.mu.Lock()
	streamsPerTransport := manager.streamsPerTransport
	if streamsPerTransport <= 0 {
		streamsPerTransport = http3ConnectStreamsPerTransport
	}
	if learned := manager.learnedStreamLimits[key]; learned > 0 && learned < streamsPerTransport {
		streamsPerTransport = learned
	}
	maxTransports := manager.maxTransportsPerKey
	if maxTransports <= 0 {
		maxTransports = http3ConnectMaxTransportsPerKey
	}
	var selected *http3ConnectTransportSlot
	for _, slot := range manager.transports[key] {
		if slot == nil {
			continue
		}
		if slot.lifecycle == http3TransportWarming && slot.active == 0 {
			selected = slot
			break
		}
	}
	// Only one request is allowed to exercise a warming candidate. While that
	// canary is in flight, later requests continue on a verified serving slot.
	if selected == nil {
		for _, slot := range manager.transports[key] {
			if slot != nil && slot.transport != nil && slot.lifecycle == http3TransportServing && slot.active < slot.limit &&
				(selected == nil || http3TransportHealthRank(slot.health) < http3TransportHealthRank(selected.health) ||
					http3TransportHealthRank(slot.health) == http3TransportHealthRank(selected.health) && slot.active < selected.active) {
				selected = slot
			}
		}
	}
	if selected == nil {
		if len(manager.transports[key]) >= maxTransports {
			manager.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("%w: %d HTTP/3 transports reached their active tunnel limits (initial limit %d)",
				errConnectProxyProtocolCapacity, maxTransports, streamsPerTransport)
		}
		var createErr error
		selected, createErr = manager.newTransportSlotLocked(key, http3TransportServing, streamsPerTransport)
		if createErr != nil {
			manager.mu.Unlock()
			return nil, nil, nil, createErr
		}
	}
	selected.active++
	manager.mu.Unlock()

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			manager.releaseTransport(key, selected)
		})
	}
	return selected.transport, selected, release, nil
}

// acquireHTTP3CandidateRetrySource reserves exactly the verified serving slot
// that a failed warming candidate was intended to replace. It must never fall
// through to the general pool allocator: the rule breaker may have moved that
// source to draining while the candidate handshake was in flight, and creating
// a fresh H3 slot here would bypass a newly committed H2 cooldown.
func (manager *http3ConnectManager) acquireHTTP3CandidateRetrySource(
	key http3ConnectTransportKey,
	source *http3ConnectTransportSlot,
) (*http3.Transport, *http3ConnectTransportSlot, func(), error) {
	if manager == nil || source == nil {
		return nil, nil, nil, errHTTP3CandidateRetrySourceUnavailable
	}
	manager.mu.Lock()
	limit := source.limit
	if limit <= 0 {
		limit = manager.streamsPerTransport
		if limit <= 0 {
			limit = http3ConnectStreamsPerTransport
		}
	}
	if manager.retired || !manager.containsSlotLocked(key, source) || source.transport == nil ||
		source.lifecycle != http3TransportServing || source.active >= limit {
		manager.mu.Unlock()
		return nil, nil, nil, errHTTP3CandidateRetrySourceUnavailable
	}
	source.active++
	manager.mu.Unlock()

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			manager.releaseTransport(key, source)
		})
	}
	return source.transport, source, release, nil
}

func http3TransportHealthRank(health http3TransportHealth) int {
	switch health {
	case http3TransportHealthy:
		return 0
	case http3TransportSuspect:
		return 1
	case http3TransportDegraded:
		return 2
	default:
		return 3
	}
}

func (manager *http3ConnectManager) releaseTransport(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
) {
	if manager == nil || slot == nil {
		return
	}
	var closeSlot *http3ConnectTransportSlot
	manager.mu.Lock()
	if slot.active > 0 {
		slot.active--
	}
	if slot.active == 0 {
		remove := manager.retired || slot.lifecycle == http3TransportDraining || slot.lifecycle == http3TransportFailed
		if slot.lifecycle == http3TransportServing && !remove {
			for _, candidate := range manager.transports[key] {
				if candidate != nil && candidate != slot && candidate.lifecycle == http3TransportServing {
					remove = true
					break
				}
			}
		}
		if remove && manager.removeSlotLocked(key, slot) {
			closeSlot = slot
		}
	}
	manager.mu.Unlock()
	if closeSlot != nil {
		closeSlot.close()
	}
}

// retire closes idle QUIC transports immediately and arranges for active
// transports to close as soon as their last CONNECT stream releases its slot.
// Existing tunnels remain intact while unrelated old-generation connections
// can no longer pin a warm UDP socket indefinitely.
func (manager *http3ConnectManager) retire() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	manager.retired = true
	samplerCancel, samplerDone := manager.detachHTTP3SamplerLocked()
	var closeSlots []*http3ConnectTransportSlot
	for key, slots := range manager.transports {
		kept := slots[:0]
		for _, slot := range slots {
			if slot != nil {
				slot.lifecycle = http3TransportDraining
			}
			if slot != nil && slot.active > 0 {
				kept = append(kept, slot)
				continue
			}
			if slot != nil {
				closeSlots = append(closeSlots, slot)
			}
		}
		clear(slots[len(kept):])
		if len(kept) == 0 {
			delete(manager.transports, key)
		} else {
			manager.transports[key] = kept
		}
	}
	manager.mu.Unlock()
	stopHTTP3Sampler(samplerCancel, samplerDone)
	for _, slot := range closeSlots {
		slot.close()
	}
}

// noteStreamCreditTimeout adapts to peers advertising fewer bidirectional
// streams than Moto's conservative initial limit. A timeout while another long
// tunnel is active may be OpenStreamSync waiting for MAX_STREAMS. Lower this
// slot to the already-proven concurrency; the next request opens a fresh QUIC
// connection. If the real cause was network loss, that fresh connection fails
// without siblings and is classified as a transport failure normally.
func (manager *http3ConnectManager) noteStreamCreditTimeout(
	key http3ConnectTransportKey,
	slot *http3ConnectTransportSlot,
) bool {
	if manager == nil || slot == nil {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if slot.active <= 1 {
		return false
	}
	observedLimit := slot.active - 1
	if observedLimit < 1 {
		observedLimit = 1
	}
	if slot.limit == 0 || observedLimit < slot.limit {
		slot.limit = observedLimit
	}
	if learned := manager.learnedStreamLimits[key]; learned == 0 || observedLimit < learned {
		manager.learnedStreamLimits[key] = observedLimit
		for _, candidate := range manager.transports[key] {
			if candidate != nil && (candidate.limit == 0 || observedLimit < candidate.limit) {
				candidate.limit = observedLimit
			}
		}
	}
	return true
}

func (manager *http3ConnectManager) dial(ctx context.Context, target *config.Target, destination string) (net.Conn, error) {
	return manager.dialWithCandidateRetrySource(ctx, target, destination, nil)
}

func (manager *http3ConnectManager) dialWithCandidateRetrySource(
	ctx context.Context,
	target *config.Target,
	destination string,
	retrySource *http3ConnectTransportSlot,
) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == nil || target.ConnectProxy == nil {
		return nil, errors.New("HTTP/3 CONNECT target is not configured")
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	var transport *http3.Transport
	var transportSlot *http3ConnectTransportSlot
	var releaseTransport func()
	var err error
	if retrySource != nil {
		transport, transportSlot, releaseTransport, err = manager.acquireHTTP3CandidateRetrySource(key, retrySource)
	} else if http3RuleProbationFromContext(ctx) {
		transport, transportSlot, releaseTransport, err = manager.acquireHTTP3RuleProbationTransport(key)
	} else {
		transport, transportSlot, releaseTransport, err = manager.acquireTransport(key)
	}
	if err != nil {
		return nil, err
	}
	manager.mu.Lock()
	candidateAttempt := transportSlot.lifecycle == http3TransportWarming
	selectedLifecycle := transportSlot.lifecycle
	selectedHealth := transportSlot.health
	manager.mu.Unlock()
	managedProbe := http3ManagedProbeFromContext(ctx)
	if managedProbe && selectedLifecycle == http3TransportServing && selectedHealth == http3TransportDegraded {
		releaseTransport()
		return nil, fmt.Errorf("%w: no healthy HTTP/3 recovery candidate is ready", errConnectProxyProtocolCoolingDown)
	}

	requestReader, requestWriter := io.Pipe()
	streamBase := withHTTP3SetupDeadline(context.Background(), ctx)
	streamCtx, cancelStream := context.WithCancel(streamBase)
	var gotConnection atomic.Bool
	var wroteHeaders atomic.Bool
	streamCtx = httptrace.WithClientTrace(streamCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			gotConnection.Store(true)
		},
		WroteHeaders: func() {
			wroteHeaders.Store(true)
		},
	})
	setupDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			cancelStream()
		case <-setupDone:
		}
	}()
	finishSetup := func() {
		close(setupDone)
		<-watcherDone
	}
	request := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: target.Address},
		Host:          destination,
		Header:        make(http.Header),
		Body:          requestReader,
		ContentLength: -1,
	}
	request = request.WithContext(streamCtx)
	if auth := target.ConnectProxy.BasicAuth; auth != nil {
		token := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		request.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if userAgent, ok := connectProxyUserAgentFromContext(ctx); ok {
		request.Header.Set("User-Agent", userAgent)
	}

	setupFlightSnapshot := transportSlot.setupFlights.snapshot()
	response, err := transport.RoundTrip(request)
	finishSetup()
	if err != nil {
		setupErr := err
		if ctxErr := ctx.Err(); ctxErr != nil {
			// streamCtx is detached after setup so a successful tunnel survives
			// its decision context. During setup the watcher cancels streamCtx;
			// restore the parent's cause so deadlines are not mislabeled as a
			// harmless Boost-loser cancellation.
			setupErr = ctxErr
		}
		if !gotConnection.Load() && http3SetupFailureGroup(setupErr) == nil {
			if group := transportSlot.setupFlights.failureGroupAfter(setupFlightSnapshot); group != nil {
				setupErr = &http3SetupError{cause: setupErr, group: group}
			}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && gotConnection.Load() &&
			!wroteHeaders.Load() && manager.noteStreamCreditTimeout(key, transportSlot) {
			setupErr = errors.Join(errConnectProxyProtocolCapacity, setupErr)
		}
		candidateFailed := false
		var candidateRetrySource *http3ConnectTransportSlot
		if candidateAttempt && ctx.Err() == nil {
			candidateRetrySource, candidateFailed = manager.markHTTP3CandidateFailed(key, transportSlot, setupErr)
		}
		releaseTransport()
		cancelStream()
		_ = requestWriter.CloseWithError(setupErr)
		_ = requestReader.CloseWithError(setupErr)
		if candidateFailed && candidateRetrySource != nil && ctx.Err() == nil && !managedProbe && !http3RuleProbationFromContext(ctx) {
			// The canary is an internal maintenance choice. If it fails while the
			// exact verified old transport is still available, retry this untouched
			// CONNECT request there instead of leaking the maintenance failure into
			// H2 fallback, route health, or the browser. The exact-slot reservation
			// prevents a concurrent blackhole drain from creating a fresh H3 transport
			// behind an already committed rule cooldown. Rule-level probation is
			// already the exclusive recovery attempt, so its failure must return to
			// dialForRule instead of recursively creating replacement candidates.
			connection, retryErr := manager.dialWithCandidateRetrySource(ctx, target, destination, candidateRetrySource)
			if errors.Is(retryErr, errHTTP3CandidateRetrySourceUnavailable) {
				return nil, setupErr
			}
			return connection, retryErr
		}
		return nil, setupErr
	}
	// Any syntactically valid HTTP response proves the warming QUIC path before
	// application policy (including 403/503) is interpreted.
	if candidateAttempt {
		manager.promoteHTTP3Candidate(key, transportSlot)
	}
	manager.noteHTTP3ServingTakeoverValidated(key, transportSlot)
	if ctx.Err() != nil {
		releaseTransport()
		cancelStream()
		_ = response.Body.Close()
		_ = requestWriter.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		statusErr := newConnectProxyStatusError(config.ConnectProxyH3, target.Address, response)
		releaseTransport()
		cancelStream()
		_ = response.Body.Close()
		_ = requestWriter.CloseWithError(errors.New("CONNECT proxy rejected stream"))
		return nil, statusErr
	}
	ruleName, _ := connectProxyRuleNameFromContext(ctx)
	userAgent, _ := connectProxyUserAgentFromContext(ctx)
	tunnelStats := &http3TunnelStats{
		slot:        transportSlot,
		ruleName:    ruleName,
		target:      target,
		destination: destination,
		userAgent:   userAgent,
	}
	conn := &http3TunnelConn{
		reader:     response.Body,
		writer:     requestWriter,
		cancel:     cancelStream,
		remoteAddr: tunnelAddr{network: config.ConnectProxyH3, value: target.Address},
		stats:      tunnelStats,
	}
	conn.release = func() {
		manager.unregisterHTTP3Tunnel(transportSlot, tunnelStats)
		releaseTransport()
	}
	tunnelStats.fastFail = func() bool {
		_, closed := conn.closeWithCause(errHTTP3TunnelFastFailed)
		return closed
	}
	manager.registerHTTP3Tunnel(tunnelStats)
	return conn, nil
}

// close is called only after a routing generation has no leased client
// streams. Closing (rather than merely idling) also releases the UDP socket.
func (manager *http3ConnectManager) close() {
	if manager == nil {
		return
	}
	if manager.cancelDials != nil {
		manager.cancelDials()
	}
	manager.mu.Lock()
	manager.retired = true
	samplerCancel, samplerDone := manager.detachHTTP3SamplerLocked()
	var closeSlots []*http3ConnectTransportSlot
	for _, slots := range manager.transports {
		for _, slot := range slots {
			if slot != nil {
				closeSlots = append(closeSlots, slot)
			}
		}
	}
	manager.transports = make(map[http3ConnectTransportKey][]*http3ConnectTransportSlot)
	manager.learnedStreamLimits = make(map[http3ConnectTransportKey]int)
	manager.healthyRTT = make(map[http3ConnectTransportKey]time.Duration)
	manager.mu.Unlock()
	stopHTTP3Sampler(samplerCancel, samplerDone)
	for _, slot := range closeSlots {
		slot.close()
	}
}

type http3TunnelConn struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	release    func()
	remoteAddr net.Addr
	closeOnce  sync.Once
	fastFailed atomic.Bool
	stats      *http3TunnelStats
}

func (conn *http3TunnelConn) http3RuleProbationBinding() (http3RuleProbationBinding, bool) {
	if conn == nil || conn.stats == nil || conn.stats.slot == nil {
		return http3RuleProbationBinding{}, false
	}
	binding := conn.stats.probation
	if binding.generationID == 0 {
		return http3RuleProbationBinding{}, false
	}
	return binding, true
}

func (conn *http3TunnelConn) Read(buffer []byte) (int, error) {
	conn.stats.beginRead()
	read, err := conn.reader.Read(buffer)
	conn.stats.finishRead(read)
	if err != nil && conn.fastFailed.Load() {
		return read, errHTTP3TunnelFastFailed
	}
	return read, err
}

func (conn *http3TunnelConn) Write(buffer []byte) (int, error) {
	conn.stats.beginWrite()
	written, err := conn.writer.Write(buffer)
	conn.stats.finishWrite(written)
	if err != nil && conn.fastFailed.Load() {
		return written, errHTTP3TunnelFastFailed
	}
	return written, err
}

func (conn *http3TunnelConn) CloseWrite() error {
	if conn.writer == nil {
		return nil
	}
	return conn.writer.Close()
}

func (conn *http3TunnelConn) Close() error {
	closeErr, _ := conn.closeWithCause(nil)
	return closeErr
}

func (conn *http3TunnelConn) closeWithCause(cause error) (error, bool) {
	var closeErr error
	closed := false
	conn.closeOnce.Do(func() {
		closed = true
		if cause != nil {
			conn.fastFailed.Store(true)
		}
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.writer != nil {
			if cause != nil {
				closeErr = conn.writer.CloseWithError(cause)
			} else {
				closeErr = conn.writer.Close()
			}
		}
		if conn.reader != nil {
			if err := conn.reader.Close(); closeErr == nil {
				closeErr = err
			}
		}
		if conn.release != nil {
			conn.release()
		}
	})
	return closeErr, closed
}

func (conn *http3TunnelConn) LocalAddr() net.Addr {
	return tunnelAddr{network: config.ConnectProxyH3, value: "local"}
}

func (conn *http3TunnelConn) RemoteAddr() net.Addr { return conn.remoteAddr }

func (conn *http3TunnelConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (conn *http3TunnelConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (conn *http3TunnelConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }
