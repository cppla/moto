package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"moto/utils"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	errConnectProxyProtocolUnavailable = errors.New("CONNECT proxy protocol is unavailable in this build")
	errConnectProxyProtocolCoolingDown = errors.New("CONNECT proxy protocol is cooling down after a transport failure")
	errConnectProxyProtocolCapacity    = errors.New("CONNECT proxy protocol stream capacity is exhausted")
)

const (
	http3FallbackCooldownBase    = 5 * time.Second
	http3FallbackCooldownMax     = time.Minute
	http3DegradedCooldownBase    = time.Minute
	http3DegradedCooldownMax     = 5 * time.Minute
	http3DegradationStrikeWindow = 5 * time.Minute
	http3DegradationPenaltyBase  = time.Second
	http3DegradationPenaltyMax   = 4 * time.Second
	http3BoostCanaryInterval     = 30 * time.Second
)

type connectProxyDialFunc func(context.Context, *config.Target, string) (net.Conn, error)

type connectProxyRuleContextKey struct{}
type http3ManagedProbeContextKey struct{}

type http3FallbackCause uint8

const (
	http3FallbackCauseNone http3FallbackCause = iota
	http3FallbackCauseTransport
	http3FallbackCauseDegradation
)

func withConnectProxyRuleName(ctx context.Context, rule string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == "" {
		return ctx
	}
	return context.WithValue(ctx, connectProxyRuleContextKey{}, rule)
}

func connectProxyRuleNameFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	rule, ok := ctx.Value(connectProxyRuleContextKey{}).(string)
	return rule, ok && rule != ""
}

func withHTTP3ManagedProbe(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, http3ManagedProbeContextKey{}, true)
}

func http3ManagedProbeFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	managed, _ := ctx.Value(http3ManagedProbeContextKey{}).(bool)
	return managed
}

// connectProxyManager owns protocol transports for one routing generation.
// Protocol order is configuration order, so H3 can fail into H2 without
// changing normal/boost target selection.
type connectProxyManager struct {
	dialers                map[string]connectProxyDialFunc
	h2                     *http2ConnectManager
	h3                     *http3ConnectManager
	h3FallbackMu           sync.Mutex
	h3Fallback             map[http3ConnectTransportKey]*http3FallbackState
	h3Epoch                uint64
	h3BoostCanaryEpoch     uint64
	now                    func() time.Time
	cooldownBase           time.Duration
	cooldownMax            time.Duration
	degradedCooldownBase   time.Duration
	degradedCooldownMax    time.Duration
	degradationWindow      time.Duration
	degradationPenaltyBase time.Duration
	degradationPenaltyMax  time.Duration
}

type http3FallbackState struct {
	epoch           uint64
	failures        int
	retryAt         time.Time
	probing         bool
	pending         bool
	h3InFlight      int
	fallbackPending int
	fallbackReady   bool
	pendingCause    http3FallbackCause
	cooldownCause   http3FallbackCause

	degradationStrikes  int
	lastDegradation     time.Time
	degradationActive   bool
	degradationReason   http3DegradationReason
	degradationRetryAt  time.Time
	lastBoostCanary     time.Time
	boostCanaryInFlight bool
	boostCanaryToken    uint64
}

func newConnectProxyManager() *connectProxyManager {
	h2 := newHTTP2ConnectManager(nil)
	h3 := newHTTP3ConnectManager(nil)
	manager := &connectProxyManager{
		h2:                     h2,
		h3:                     h3,
		h3Fallback:             make(map[http3ConnectTransportKey]*http3FallbackState),
		now:                    time.Now,
		cooldownBase:           http3FallbackCooldownBase,
		cooldownMax:            http3FallbackCooldownMax,
		degradedCooldownBase:   http3DegradedCooldownBase,
		degradedCooldownMax:    http3DegradedCooldownMax,
		degradationWindow:      http3DegradationStrikeWindow,
		degradationPenaltyBase: http3DegradationPenaltyBase,
		degradationPenaltyMax:  http3DegradationPenaltyMax,
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH2: h2.dial,
			config.ConnectProxyH3: h3.dial,
		},
	}
	h3.onDegraded = manager.noteHTTP3Degradation
	h3.onRecovered = manager.noteHTTP3Recovery
	return manager
}

func (manager *connectProxyManager) dial(ctx context.Context, target *config.Target, destination string) (net.Conn, error) {
	return manager.dialForRule(ctx, "", target, destination)
}

// dialForRule is the production entry point. Keeping dial as a rule-less
// wrapper preserves focused transport tests and callers that predate CONNECT
// observability, while runtime traffic always supplies its validated rule name.
func (manager *connectProxyManager) dialForRule(ctx context.Context, rule string, target *config.Target, destination string) (net.Conn, error) {
	if manager == nil || target == nil || target.ConnectProxy == nil {
		return nil, errors.New("CONNECT proxy target is not configured")
	}
	ctx = withConnectProxyRuleName(ctx, rule)
	var failures []error
	var pendingHTTP3Failure error
	var pendingHTTP3ManagedProbe bool
	var pendingHTTP3Token uint64
	var pendingHTTP3FallbackReason string
	var joinedHTTP3PendingToken uint64
	fallbackReachable := false
	defer func() {
		if pendingHTTP3Failure != nil {
			manager.observeHTTP3Attempt(
				target,
				pendingHTTP3Token,
				pendingHTTP3ManagedProbe,
				pendingHTTP3Failure,
				ctx.Err(),
				fallbackReachable,
			)
		}
		if joinedHTTP3PendingToken != 0 {
			manager.observeHTTP3PendingFallback(
				target,
				joinedHTTP3PendingToken,
				ctx.Err(),
				fallbackReachable,
			)
		}
	}()
	protocols := target.ConnectProxy.Protocols
	for index, protocol := range protocols {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if protocol == config.ConnectProxyH2 && pendingHTTP3FallbackReason != "" {
			metricConnectProxyFallback(rule, target.Address, pendingHTTP3FallbackReason)
			pendingHTTP3FallbackReason = ""
		}
		useHTTP3Cooldown := protocol == config.ConnectProxyH3 && protocolAppearsAfter(protocols, index, config.ConnectProxyH2)
		dial := manager.dialers[protocol]
		if dial == nil {
			metricConnectProxyAttempt(rule, target.Address, protocol, connectProxyAttemptUnavailable, 0, false)
			if useHTTP3Cooldown {
				pendingHTTP3FallbackReason = connectProxyFallbackUnavailable
			}
			failures = append(failures, fmt.Errorf("%s: %w", protocol, errConnectProxyProtocolUnavailable))
			continue
		}
		var attemptToken uint64
		managedProbe := false
		if useHTTP3Cooldown {
			var allowed bool
			attemptToken, managedProbe, allowed = manager.beginHTTP3Attempt(ctx, target)
			if !allowed {
				// A non-zero token means this request joined an H3 failure
				// window that is still waiting for a useful H2 observation.
				// Its fallback result must participate so an earlier request
				// cannot clear the window while this H2 attempt is in flight.
				joinedHTTP3PendingToken = attemptToken
				metricConnectProxyAttempt(rule, target.Address, protocol, connectProxyAttemptCooldown, 0, false)
				pendingHTTP3FallbackReason = connectProxyFallbackCooldown
				failures = append(failures, fmt.Errorf("%s: %w", protocol, errConnectProxyProtocolCoolingDown))
				continue
			}
		}
		attemptCtx, cancelAttempt := connectProxyAttemptContext(ctx, len(protocols)-index)
		if protocol == config.ConnectProxyH3 && managedProbe {
			attemptCtx = withHTTP3ManagedProbe(attemptCtx)
		}
		setupStarted := time.Now()
		connection, err := dial(attemptCtx, target, destination)
		setupDuration := time.Since(setupStarted)
		cancelAttempt()
		metricConnectProxyAttempt(rule, target.Address, protocol, connectProxyAttemptOutcome(err), setupDuration, true)
		if err == nil {
			if protocol == config.ConnectProxyH3 && useHTTP3Cooldown {
				manager.observeHTTP3Attempt(target, attemptToken, managedProbe, nil, ctx.Err(), false)
			}
			if protocol == config.ConnectProxyH2 && (pendingHTTP3Failure != nil || joinedHTTP3PendingToken != 0) {
				fallbackReachable = true
			}
			return connection, nil
		}
		failures = append(failures, fmt.Errorf("%s CONNECT: %w", protocol, err))
		var statusErr *connectProxyStatusError
		if errors.As(err, &statusErr) {
			if protocol == config.ConnectProxyH2 && (pendingHTTP3Failure != nil || joinedHTTP3PendingToken != 0) {
				// Any H2 HTTP response proves that the fallback path reached the
				// proxy. The requested destination may still be denied or broken,
				// but future requests should not repeat a failed H3 handshake while
				// this working fallback exists.
				fallbackReachable = true
			}
			if connectProxyStatusAllowsProtocolFallback(statusErr.statusCode) && index+1 < len(protocols) {
				if protocol == config.ConnectProxyH3 && useHTTP3Cooldown {
					pendingHTTP3FallbackReason = connectProxyStatusFallbackReason(statusErr.statusCode)
					pendingHTTP3Failure = err
					pendingHTTP3Token = attemptToken
					pendingHTTP3ManagedProbe = managedProbe
					manager.markHTTP3FailurePending(target, attemptToken)
				}
				continue
			}
			if protocol == config.ConnectProxyH3 && useHTTP3Cooldown {
				manager.observeHTTP3Attempt(target, attemptToken, managedProbe, err, ctx.Err(), false)
			}
			// Other concrete HTTP responses prove that this transport reached the
			// proxy. Retrying them over another protocol could duplicate or bypass
			// auth, ACL, and rate-limit decisions.
			return nil, errors.Join(failures...)
		}
		if protocol == config.ConnectProxyH3 && useHTTP3Cooldown &&
			errors.Is(err, errConnectProxyProtocolCapacity) {
			// Local pool saturation says nothing about UDP or proxy health.
			// Release this admitted H3 state participant and use H2 without
			// activating endpoint-wide failure cooldown.
			pendingHTTP3FallbackReason = connectProxyFallbackCapacity
			manager.abandonHTTP3Attempt(target, attemptToken)
			continue
		}
		if protocol == config.ConnectProxyH3 && useHTTP3Cooldown {
			pendingHTTP3FallbackReason = connectProxyFallbackReason(err)
			pendingHTTP3Failure = err
			pendingHTTP3Token = attemptToken
			pendingHTTP3ManagedProbe = managedProbe
			manager.markHTTP3FailurePending(target, attemptToken)
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("CONNECT proxy has no protocols")
	}
	return nil, errors.Join(failures...)
}

func connectProxyAttemptOutcome(err error) string {
	if err == nil {
		return connectProxyAttemptSuccess
	}
	var statusErr *connectProxyStatusError
	if errors.As(err, &statusErr) {
		switch class := connectProxyStatusFailureClass(statusErr); class {
		case connectProxyFailureStatusUnknown:
			return connectProxyAttemptStatusError
		default:
			return string(class)
		}
	}
	if errors.Is(err, errConnectProxyProtocolCapacity) {
		return connectProxyAttemptCapacity
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return connectProxyAttemptTimeout
	}
	if errors.Is(err, context.Canceled) {
		return connectProxyAttemptCanceled
	}
	return connectProxyAttemptTransportError
}

func connectProxyFallbackReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return connectProxyFallbackTimeout
	}
	if errors.Is(err, context.Canceled) {
		return connectProxyFallbackCanceled
	}
	return connectProxyFallbackTransportError
}

func connectProxyStatusFallbackReason(statusCode int) string {
	switch statusCode {
	case http.StatusMethodNotAllowed:
		return connectProxyFallbackStatus405
	case http.StatusNotImplemented:
		return connectProxyFallbackStatus501
	case http.StatusHTTPVersionNotSupported:
		return connectProxyFallbackStatus505
	default:
		return connectProxyFallbackTransportError
	}
}

func protocolAppearsAfter(protocols []string, index int, want string) bool {
	for next := index + 1; next < len(protocols); next++ {
		if protocols[next] == want {
			return true
		}
	}
	return false
}

func (manager *connectProxyManager) beginHTTP3Attempt(_ context.Context, target *config.Target) (token uint64, managedProbe, allowed bool) {
	if manager == nil || target == nil || target.ConnectProxy == nil {
		return 0, false, false
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	now := manager.timeNow()
	manager.h3FallbackMu.Lock()
	if manager.h3Fallback == nil {
		manager.h3Fallback = make(map[http3ConnectTransportKey]*http3FallbackState)
	}
	state := manager.h3Fallback[key]
	if state == nil {
		token = manager.nextHTTP3EpochLocked()
		manager.h3Fallback[key] = &http3FallbackState{epoch: token, h3InFlight: 1}
		manager.h3FallbackMu.Unlock()
		return token, false, true
	}
	if state.pending {
		// This request will skip H3 and try H2. Keep the pending epoch
		// alive until that fallback finishes; a successful sibling can
		// then commit cooldown even if the original fallback fails first.
		state.fallbackPending++
		token = state.epoch
		manager.h3FallbackMu.Unlock()
		return token, false, false
	}
	if state.failures == 0 && state.degradationActive && state.degradationStrikes >= 2 &&
		!state.degradationRetryAt.IsZero() && !now.Before(state.degradationRetryAt) {
		manager.startHTTP3DegradationFallbackLocked(state)
		state.fallbackPending++
		token = state.epoch
		manager.h3FallbackMu.Unlock()
		return token, false, false
	}
	if state.failures == 0 {
		token = state.epoch
		state.h3InFlight++
		manager.h3FallbackMu.Unlock()
		return token, false, true
	}
	if state.probing {
		// A half-open H3 probe is already deciding this epoch. Let this
		// request use H2 immediately, but retain its result so a successful
		// fallback can be committed if the probe later fails.
		state.fallbackPending++
		token = state.epoch
		manager.h3FallbackMu.Unlock()
		return token, false, false
	}
	if now.Before(state.retryAt) {
		manager.h3FallbackMu.Unlock()
		return 0, false, false
	}
	// Admit one half-open probe. Concurrent requests use the configured H2
	// fallback immediately instead of repeating a slow QUIC handshake.
	state.probing = true
	state.epoch = manager.nextHTTP3EpochLocked()
	state.h3InFlight = 1
	state.fallbackPending = 0
	state.fallbackReady = false
	state.pendingCause = http3FallbackCauseNone
	token = state.epoch
	manager.h3FallbackMu.Unlock()
	return token, true, true
}

func (manager *connectProxyManager) observeHTTP3PendingFallback(
	target *config.Target,
	token uint64,
	parentErr error,
	fallbackReachable bool,
) {
	// A cooldown-skipped request did not make its own H3 attempt, but it joined
	// an existing pending failure window in beginHTTP3Attempt. Use a transport
	// sentinel so observeHTTP3Attempt resolves only that fallback participation
	// and never treats the skip as proof that H3 itself recovered.
	manager.observeHTTP3Attempt(
		target,
		token,
		false,
		errConnectProxyProtocolCoolingDown,
		parentErr,
		fallbackReachable,
	)
}

func (manager *connectProxyManager) nextHTTP3EpochLocked() uint64 {
	manager.h3Epoch++
	if manager.h3Epoch == 0 {
		manager.h3Epoch++
	}
	return manager.h3Epoch
}

func (manager *connectProxyManager) markHTTP3FailurePending(target *config.Target, token uint64) {
	if manager == nil || target == nil || target.ConnectProxy == nil {
		return
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil || state.epoch != token {
		return
	}
	if state.h3InFlight <= 0 {
		return
	}
	state.h3InFlight--
	state.fallbackPending++
	state.pending = true
	if state.probing && state.cooldownCause != http3FallbackCauseNone {
		state.pendingCause = state.cooldownCause
	} else if state.pendingCause == http3FallbackCauseNone {
		state.pendingCause = http3FallbackCauseTransport
	}
	state.probing = false
	manager.resolveHTTP3FailureWindowLocked(state)
}

func (manager *connectProxyManager) abandonHTTP3Attempt(target *config.Target, token uint64) {
	if manager == nil || target == nil || target.ConnectProxy == nil {
		return
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil || state.epoch != token || state.h3InFlight <= 0 {
		return
	}
	state.h3InFlight--
	if state.probing {
		// Capacity prevented the half-open H3 probe from reaching the network.
		// Invalidate this probe epoch and all of its H2-only observers without
		// changing the existing network-failure backoff.
		state.probing = false
		state.pending = false
		state.h3InFlight = 0
		state.fallbackPending = 0
		state.fallbackReady = false
		state.pendingCause = http3FallbackCauseNone
		state.epoch = manager.nextHTTP3EpochLocked()
		return
	}
	manager.resolveHTTP3FailureWindowLocked(state)
}

func (manager *connectProxyManager) observeHTTP3Attempt(
	target *config.Target,
	token uint64,
	managedProbe bool,
	attemptErr error,
	parentErr error,
	fallbackReachable bool,
) {
	if manager == nil || target == nil || target.ConnectProxy == nil {
		return
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	if manager.h3Fallback == nil {
		manager.h3Fallback = make(map[http3ConnectTransportKey]*http3FallbackState)
	}

	state := manager.h3Fallback[key]
	if state == nil || state.epoch != token {
		return
	}
	// Any HTTP response proves that the H3 path is usable, even when the status
	// itself rejects authentication or the destination. A successful stream does
	// the same and resets exponential backoff.
	var statusErr *connectProxyStatusError
	if attemptErr == nil || (errors.As(attemptErr, &statusErr) &&
		!connectProxyStatusAllowsProtocolFallback(statusErr.statusCode)) {
		manager.resetHTTP3FallbackStateLocked(state, managedProbe)
		return
	}
	if state.fallbackPending <= 0 {
		return
	}
	state.fallbackPending--
	if parentErr == nil && fallbackReachable {
		// Record H2 reachability, but wait for every H3 attempt in this epoch.
		// A concrete H2 error status is sufficient: it proves the fallback path
		// works even though the requested destination did not get a tunnel.
		// Any later H3 success wins and resets the path instead of making the
		// outcome depend on goroutine completion order.
		state.fallbackReady = true
	}
	manager.resolveHTTP3FailureWindowLocked(state)
}

func (manager *connectProxyManager) resolveHTTP3FailureWindowLocked(state *http3FallbackState) {
	if state == nil || state.h3InFlight > 0 {
		return
	}
	if state.fallbackReady {
		manager.commitHTTP3CooldownLocked(state)
		return
	}
	if state.fallbackPending > 0 {
		return
	}
	// Failed/canceled H2 attempts say nothing useful enough to suppress H3.
	// Preserve the existing failure count after a failed half-open probe, but
	// expire this epoch so the next request may probe again immediately.
	state.pending = false
	state.probing = false
	state.h3InFlight = 0
	state.fallbackPending = 0
	state.fallbackReady = false
	if state.pendingCause == http3FallbackCauseDegradation {
		delay := manager.cooldownBase
		if delay <= 0 {
			delay = http3FallbackCooldownBase
		}
		state.degradationRetryAt = manager.timeNow().Add(delay)
	}
	state.pendingCause = http3FallbackCauseNone
	state.epoch = manager.nextHTTP3EpochLocked()
}

func (manager *connectProxyManager) commitHTTP3CooldownLocked(state *http3FallbackState) {
	if state == nil {
		return
	}
	cause := state.pendingCause
	if cause == http3FallbackCauseNone {
		cause = state.cooldownCause
	}
	if cause == http3FallbackCauseNone {
		cause = http3FallbackCauseTransport
	}
	state.pending = false
	state.probing = false
	state.h3InFlight = 0
	state.fallbackPending = 0
	state.fallbackReady = false
	state.pendingCause = http3FallbackCauseNone
	state.cooldownCause = cause
	state.degradationRetryAt = time.Time{}
	state.failures++
	state.retryAt = manager.timeNow().Add(manager.http3CooldownForCause(cause, state.failures))
	state.epoch = manager.nextHTTP3EpochLocked()
}

func (manager *connectProxyManager) resetHTTP3FallbackStateLocked(state *http3FallbackState, resetDegradation bool) {
	if state == nil {
		return
	}
	state.failures = 0
	state.pending = false
	state.probing = false
	state.h3InFlight = 0
	state.fallbackPending = 0
	state.fallbackReady = false
	state.pendingCause = http3FallbackCauseNone
	state.cooldownCause = http3FallbackCauseNone
	state.retryAt = time.Time{}
	if resetDegradation {
		state.degradationStrikes = 0
		state.lastDegradation = time.Time{}
		state.degradationActive = false
		state.degradationReason = http3DegradationReasonNone
		state.degradationRetryAt = time.Time{}
		state.lastBoostCanary = time.Time{}
		state.boostCanaryInFlight = false
		state.boostCanaryToken = 0
	}
	state.epoch = manager.nextHTTP3EpochLocked()
}

func (manager *connectProxyManager) startHTTP3DegradationFallbackLocked(state *http3FallbackState) {
	if state == nil {
		return
	}
	state.epoch = manager.nextHTTP3EpochLocked()
	state.pending = true
	state.probing = false
	state.h3InFlight = 0
	state.fallbackPending = 0
	state.fallbackReady = false
	state.pendingCause = http3FallbackCauseDegradation
	state.degradationRetryAt = time.Time{}
}

func (manager *connectProxyManager) noteHTTP3Degradation(key http3ConnectTransportKey, reason http3DegradationReason) {
	if manager == nil {
		return
	}
	now := manager.timeNow()
	activatedFallback := false
	strikes := 0
	manager.h3FallbackMu.Lock()
	defer func() {
		manager.h3FallbackMu.Unlock()
		if activatedFallback {
			utils.Logger.Warn("HTTP/3 短时间内连续退化，进入恢复评估窗口",
				zap.String("targetAddr", key.address),
				zap.Int("degradationStrikes", strikes),
				zap.String("reason", string(reason)))
		}
	}()
	if manager.h3Fallback == nil {
		manager.h3Fallback = make(map[http3ConnectTransportKey]*http3FallbackState)
	}
	state := manager.h3Fallback[key]
	if state == nil {
		state = &http3FallbackState{epoch: manager.nextHTTP3EpochLocked()}
		manager.h3Fallback[key] = state
	}
	window := manager.degradationWindow
	if window <= 0 {
		window = http3DegradationStrikeWindow
	}
	if !state.lastDegradation.IsZero() && now.Sub(state.lastDegradation) > window {
		state.degradationStrikes = 0
	}
	if state.degradationActive {
		return
	}
	state.degradationActive = true
	state.degradationReason = reason
	state.lastDegradation = now
	if state.degradationStrikes < 8 {
		state.degradationStrikes++
	}
	if state.degradationStrikes < 2 || state.pending || state.probing ||
		state.failures > 0 && now.Before(state.retryAt) {
		return
	}
	manager.startHTTP3DegradationFallbackLocked(state)
	activatedFallback = true
	strikes = state.degradationStrikes
}

// noteHTTP3Recovery clears the active routing penalty after a replacement QUIC
// connection is promoted or a degraded serving connection physically redials.
// The recent strike is intentionally retained: a second independent QUIC
// session degrading inside the window is what activates H2 cooldown.
func (manager *connectProxyManager) noteHTTP3Recovery(key http3ConnectTransportKey) {
	if manager == nil {
		return
	}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil {
		return
	}
	state.degradationActive = false
	state.degradationReason = http3DegradationReasonNone
	state.lastBoostCanary = time.Time{}
	state.boostCanaryInFlight = false
	state.boostCanaryToken = 0
}

// http3RoutePenalty is a protocol-only Boost signal. It never mutates the
// target-wide circuit breaker, so a slow H3 path cannot suppress healthy H2.
func (manager *connectProxyManager) http3RoutePenalty(_ *config.Rule, target *config.Target, now time.Time) time.Duration {
	if manager == nil || target == nil || target.ConnectProxy == nil || len(target.ConnectProxy.Protocols) == 0 ||
		target.ConnectProxy.Protocols[0] != config.ConnectProxyH3 {
		return 0
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	mixedFallback := protocolAppearsAfter(target.ConnectProxy.Protocols, 0, config.ConnectProxyH2)
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil {
		return 0
	}
	window := manager.degradationWindow
	if window <= 0 {
		window = http3DegradationStrikeWindow
	}
	if !state.degradationActive && !state.lastDegradation.IsZero() && now.Sub(state.lastDegradation) > window {
		state.degradationStrikes = 0
		state.lastDegradation = time.Time{}
	}
	if !state.degradationActive {
		return 0
	}
	// A mixed target already using H2 remains a healthy Boost candidate. Once a
	// validation retry is due, also admit the target so beginHTTP3Attempt can run
	// the H2 check rather than leaving the endpoint permanently unprobed.
	if mixedFallback && (state.pending || state.probing || state.failures > 0 ||
		!state.degradationRetryAt.IsZero() && !now.Before(state.degradationRetryAt)) {
		return 0
	}
	return manager.http3DegradationPenaltyLocked(state)
}

// claimHTTP3BoostProbe reserves one real Boost request for a lazy H3 rotation
// candidate. The reservation is target-wide and rate-limited, so concurrent
// selectors keep preferring healthy alternatives while a single canary gets a
// chance to promote the replacement connection. The H3 transport itself also
// enforces one warming canary in flight.
func (manager *connectProxyManager) claimHTTP3BoostProbe(_ *config.Rule, target *config.Target, now time.Time) (uint64, bool) {
	if manager == nil || target == nil || target.ConnectProxy == nil || len(target.ConnectProxy.Protocols) == 0 ||
		target.ConnectProxy.Protocols[0] != config.ConnectProxyH3 {
		return 0, false
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil || !state.degradationActive {
		return 0, false
	}
	// Mixed-protocol cooldown and half-open recovery already have their own
	// singleflight policy. This canary is only for the pre-cooldown smooth H3
	// replacement that would otherwise be starved by its Boost penalty.
	if protocolAppearsAfter(target.ConnectProxy.Protocols, 0, config.ConnectProxyH2) &&
		(state.pending || state.probing || state.failures > 0) {
		return 0, false
	}
	if state.boostCanaryInFlight {
		return 0, false
	}
	interval := http3BoostCanaryInterval
	if !state.lastBoostCanary.IsZero() && now.Sub(state.lastBoostCanary) < interval {
		return 0, false
	}
	manager.h3BoostCanaryEpoch++
	if manager.h3BoostCanaryEpoch == 0 {
		manager.h3BoostCanaryEpoch++
	}
	token := manager.h3BoostCanaryEpoch
	state.lastBoostCanary = now
	state.boostCanaryInFlight = true
	state.boostCanaryToken = token
	return token, true
}

func (manager *connectProxyManager) releaseHTTP3BoostProbe(_ *config.Rule, target *config.Target, token uint64) {
	if manager == nil || target == nil || target.ConnectProxy == nil || token == 0 {
		return
	}
	key := http3ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	manager.h3FallbackMu.Lock()
	defer manager.h3FallbackMu.Unlock()
	state := manager.h3Fallback[key]
	if state == nil || !state.boostCanaryInFlight || state.boostCanaryToken != token {
		return
	}
	state.boostCanaryInFlight = false
	state.boostCanaryToken = 0
}

func (manager *connectProxyManager) http3DegradationPenaltyLocked(state *http3FallbackState) time.Duration {
	if manager == nil || state == nil || !state.degradationActive {
		return 0
	}
	base := manager.degradationPenaltyBase
	if base <= 0 {
		base = http3DegradationPenaltyBase
	}
	maximum := manager.degradationPenaltyMax
	if maximum <= 0 {
		maximum = http3DegradationPenaltyMax
	}
	penalty := base
	for strike := 1; strike < state.degradationStrikes && penalty < maximum; strike++ {
		if penalty > maximum/2 {
			return maximum
		}
		penalty *= 2
	}
	if penalty > maximum {
		return maximum
	}
	return penalty
}

func (manager *connectProxyManager) timeNow() time.Time {
	if manager != nil && manager.now != nil {
		return manager.now()
	}
	return time.Now()
}

func (manager *connectProxyManager) http3Cooldown(failures int) time.Duration {
	base := manager.cooldownBase
	if base <= 0 {
		base = http3FallbackCooldownBase
	}
	maximum := manager.cooldownMax
	if maximum <= 0 {
		maximum = http3FallbackCooldownMax
	}
	delay := base
	for count := 1; count < failures && delay < maximum; count++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func (manager *connectProxyManager) http3CooldownForCause(cause http3FallbackCause, failures int) time.Duration {
	if cause != http3FallbackCauseDegradation {
		return manager.http3Cooldown(failures)
	}
	base := manager.degradedCooldownBase
	if base <= 0 {
		base = http3DegradedCooldownBase
	}
	maximum := manager.degradedCooldownMax
	if maximum <= 0 {
		maximum = http3DegradedCooldownMax
	}
	delay := base
	for count := 1; count < failures && delay < maximum; count++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

// connectProxyAttemptContext reserves part of an overall decision deadline for
// every remaining protocol. Without this split, an unavailable UDP path could
// consume the entire rule timeout and prevent the configured H2 fallback.
func connectProxyAttemptContext(parent context.Context, remainingProtocols int) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if remainingProtocols <= 1 {
		return context.WithCancel(parent)
	}
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return context.WithTimeout(parent, remaining/time.Duration(remainingProtocols))
		}
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, dialTimeout/time.Duration(remainingProtocols))
}

func (manager *connectProxyManager) close() {
	if manager != nil && manager.h2 != nil {
		manager.h2.closeIdle()
	}
	if manager != nil && manager.h3 != nil {
		manager.h3.close()
	}
}

func (manager *connectProxyManager) retire() {
	if manager != nil && manager.h2 != nil {
		manager.h2.retire()
	}
	if manager != nil && manager.h3 != nil {
		manager.h3.retire()
	}
}

// connectProxyErrorIsRouteNeutral reports failures that came from an HTTP
// response or local protocol availability rather than from reaching the proxy
// endpoint. A requested destination can be denied, unresolved, or down without
// proving that the shared proxy route is unhealthy for subsequent clients.
func connectProxyErrorIsRouteNeutral(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		// Fallback errors are ordered. If the final protocol reached the proxy
		// and got an HTTP response, that response is the strongest observation
		// for composite route health and supersedes an earlier H3 transport
		// failure. Explicit 403/502/503/504 responses therefore prove
		// reachability and stay neutral, while auth and rate-limit responses keep
		// their separate failure policy.
		var finalStatus *connectProxyStatusError
		if errors.As(children[len(children)-1], &finalStatus) {
			return connectProxyStatusIsRouteNeutral(finalStatus.statusCode)
		}
		// Stream-credit capacity is a local scheduling observation. It may be
		// joined with the setup deadline that revealed exhausted peer credit.
		// Treat that composite as neutral only after giving any concrete final
		// HTTP response precedence, so capacity cannot mask a 407 or 429.
		if errors.Is(err, errConnectProxyProtocolCapacity) {
			return true
		}
		for _, child := range children {
			if !connectProxyErrorIsRouteNeutral(child) {
				return false
			}
		}
		return true
	}
	if errors.Is(err, errConnectProxyProtocolCapacity) {
		return true
	}
	var statusErr *connectProxyStatusError
	if errors.As(err, &statusErr) {
		return connectProxyStatusIsRouteNeutral(statusErr.statusCode)
	}
	if err == errConnectProxyProtocolUnavailable {
		return true
	}
	if err == errConnectProxyProtocolCoolingDown {
		return true
	}
	if err == errConnectProxyProtocolCapacity {
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return connectProxyErrorIsRouteNeutral(wrapped)
	}
	return false
}

// A concrete 403/502/503/504 CONNECT response proves that the configured proxy
// route is reachable, even though the requested tunnel failed. Moto does not
// inspect vendor-specific headers or response bodies, so every 503 receives the
// same reachability treatment regardless of its upstream-specific cause.
func connectProxyStatusIsRouteNeutral(statusCode int) bool {
	switch statusCode {
	case http.StatusForbidden, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		// Unknown HTTP responses default to a proxy-route failure. The SOCKS
		// destination is already strictly validated, so statuses such as 400,
		// 404, 408, 426, 431, and unexpected 5xx responses more strongly imply
		// a wrong endpoint, missing forward-proxy handler, or broken proxy.
		return false
	}
}

// These statuses explicitly say that this HTTP version or handler cannot
// provide CONNECT. They are safe protocol-capability fallbacks, unlike auth,
// ACL, rate-limit, or ambiguous probe-resistance responses.
func connectProxyStatusAllowsProtocolFallback(statusCode int) bool {
	switch statusCode {
	case http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
		return true
	default:
		return false
	}
}

func connectProxyRouteObservationError(err error) error {
	if connectProxyErrorIsRouteNeutral(err) {
		return errRouteReachable
	}
	if group, ok := connectProxyExclusiveSetupFailureGroup(err); ok {
		return &routeFailureObservation{cause: err, group: group}
	}
	return err
}

// connectProxyExclusiveSetupFailureGroup returns a shared physical H3 setup
// group only when every non-neutral failure in the composite came from that
// same group. A later independent H2 transport/auth failure must remain a full
// route failure and must never be hidden behind H3 setup de-duplication.
func connectProxyExclusiveSetupFailureGroup(err error) (*routeFailureGroup, bool) {
	if err == nil || connectProxyErrorIsRouteNeutral(err) {
		return nil, false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var selected *routeFailureGroup
		found := false
		for _, child := range joined.Unwrap() {
			if child == nil || connectProxyErrorIsRouteNeutral(child) {
				continue
			}
			group, grouped := connectProxyExclusiveSetupFailureGroup(child)
			if !grouped || group == nil {
				return nil, false
			}
			if selected != nil && selected != group {
				return nil, false
			}
			selected = group
			found = true
		}
		return selected, found
	}
	var setupErr *http3SetupError
	if errors.As(err, &setupErr) && setupErr != nil && setupErr.group != nil {
		return setupErr.group, true
	}
	return nil, false
}

func (runtime *routingRuntime) dialRouteTarget(ctx context.Context, rule *config.Rule, address string) (net.Conn, error) {
	if rule == nil || rule.Protocol != config.ProtocolSOCKS5 {
		return DialFastContext(ctx, address)
	}
	destination, ok := connectDestinationFromContext(ctx)
	if !ok {
		return nil, errors.New("SOCKS5 CONNECT destination is missing")
	}
	for _, target := range rule.Targets {
		if target != nil && target.Address == address {
			return runtime.connectProxy.dialForRule(ctx, rule.Name, target, destination)
		}
	}
	return nil, fmt.Errorf("CONNECT proxy target %q is not part of rule", address)
}
