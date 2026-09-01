package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"moto/utils"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	boostWinnerTTL       = 30 * time.Second // 胜出线路缓存时长
	boostRevalidateAfter = boostWinnerTTL / 2
	boostRevalidateLimit = 2 * time.Second
	boostWinnerCacheMax  = 256
)

var errBoostMaintenanceSaturated = errors.New("boost maintenance dial capacity saturated")

type boostWinnerEntry struct {
	addr       string
	expires    time.Time
	generation uint64
}

type boostWinnerToken struct {
	key        string
	addr       string
	generation uint64
}

type boostRevalidation struct {
	done chan struct{}
}

type dialResult struct {
	conn    net.Conn
	addr    string
	attempt routeAttempt
	err     error
	delayed bool
}

type boostDialFunc func(context.Context, string) (net.Conn, error)
type boostPrepareFunc func(context.Context, net.Conn, string) error
type boostDialRelease func()
type boostDialAcquireFunc func(context.Context, *config.Rule, string, bool) (boostDialRelease, error)

type boostRouteDialOptions struct {
	tryOnly bool
	onStart func()
}

type boostRouteDialFunc func(context.Context, *config.Rule, string, boostRouteDialOptions) (net.Conn, routeAttempt, error)

type cachedBoostOutcome struct {
	winner               dialResult
	cachedFailed         bool
	cachedFailureNeutral bool
	fallbackStarted      bool
	hedged               bool
}

func targetByAddress(rule *config.Rule, address string) *config.Target {
	if rule == nil || address == "" {
		return nil
	}
	for _, target := range rule.Targets {
		if target != nil && target.Address == address {
			return target
		}
	}
	return nil
}

// boostRuleKey includes the listener and the ordered target set. Rules with the
// same display name must not share a winner after a reload or across listeners.
func boostRuleKey(rule *config.Rule) string {
	if rule == nil {
		return "<nil>"
	}
	var key strings.Builder
	key.WriteString(rule.Name)
	key.WriteByte(0)
	key.WriteString(rule.Listen)
	key.WriteByte(0)
	key.WriteString(rule.Mode)
	for _, target := range rule.Targets {
		key.WriteByte(0)
		key.WriteString(target.Address)
	}
	return key.String()
}

func loadBoostWinner(key string) (string, bool, time.Time) {
	return defaultRoutingRuntime.loadBoostWinner(key)
}

func (runtime *routingRuntime) loadBoostWinner(key string) (string, bool, time.Time) {
	now := time.Now()
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	entry, ok := runtime.boost.cache.entries[key]
	if !ok {
		return "", false, time.Time{}
	}
	if !now.Before(entry.expires) {
		delete(runtime.boost.cache.entries, key)
		return "", false, time.Time{}
	}
	return entry.addr, true, entry.expires
}

func (runtime *routingRuntime) loadBoostWinnerToken(key string) (boostWinnerEntry, bool) {
	now := time.Now()
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	entry, ok := runtime.boost.cache.entries[key]
	if !ok {
		return boostWinnerEntry{}, false
	}
	if !now.Before(entry.expires) {
		delete(runtime.boost.cache.entries, key)
		return boostWinnerEntry{}, false
	}
	return entry, true
}

// loadUsableBoostWinnerToken rejects a cached winner whose currently selected
// protocol is degraded. Eviction uses the generation token loaded with the
// entry, so a concurrent refresh cannot be deleted by this stale observation.
func (runtime *routingRuntime) loadUsableBoostWinnerToken(key string, rule *config.Rule, now time.Time) (boostWinnerEntry, bool) {
	if runtime == nil {
		return boostWinnerEntry{}, false
	}
	entry, ok := runtime.loadBoostWinnerToken(key)
	if !ok || runtime.routes == nil {
		return entry, ok
	}
	var target *config.Target
	if rule != nil {
		for _, candidate := range rule.Targets {
			if candidate != nil && candidate.Address == entry.addr {
				target = candidate
				break
			}
		}
	}
	if target == nil || runtime.routes.protocolPenalty(rule, target, now) == 0 {
		return entry, true
	}
	runtime.deleteBoostWinnerIfCurrent(boostWinnerToken{
		key:        key,
		addr:       entry.addr,
		generation: entry.generation,
	})
	return boostWinnerEntry{}, false
}

func storeBoostWinner(key, addr string) boostWinnerToken {
	return defaultRoutingRuntime.storeBoostWinner(key, addr)
}

func (runtime *routingRuntime) storeBoostWinner(key, addr string) boostWinnerToken {
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	if _, exists := runtime.boost.cache.entries[key]; !exists && len(runtime.boost.cache.entries) >= boostWinnerCacheMax {
		for oldKey := range runtime.boost.cache.entries {
			delete(runtime.boost.cache.entries, oldKey)
			break
		}
	}
	runtime.boost.cache.nextGeneration++
	if runtime.boost.cache.nextGeneration == 0 {
		runtime.boost.cache.nextGeneration++
	}
	token := boostWinnerToken{key: key, addr: addr, generation: runtime.boost.cache.nextGeneration}
	runtime.boost.cache.entries[key] = boostWinnerEntry{
		addr:       addr,
		expires:    time.Now().Add(boostWinnerTTL),
		generation: token.generation,
	}
	return token
}

func deleteBoostWinner(key string) {
	defaultRoutingRuntime.deleteBoostWinner(key)
}

func (runtime *routingRuntime) deleteBoostWinner(key string) {
	runtime.boost.cache.Lock()
	delete(runtime.boost.cache.entries, key)
	runtime.boost.cache.Unlock()
}

func (runtime *routingRuntime) deleteBoostWinnerIfCurrent(token boostWinnerToken) bool {
	if token.key == "" || token.generation == 0 {
		return false
	}
	runtime.boost.cache.Lock()
	defer runtime.boost.cache.Unlock()
	entry, ok := runtime.boost.cache.entries[token.key]
	if !ok || entry.generation != token.generation || entry.addr != token.addr {
		return false
	}
	delete(runtime.boost.cache.entries, token.key)
	return true
}

// reconcileCachedBoostWinner keeps destination-specific CONNECT failures from
// mutating the rule-wide Boost winner. A fallback may serve this one request,
// but a 403/502/504 from the cached proxy is not evidence that another proxy is
// globally faster or healthier for unrelated destinations.
func (runtime *routingRuntime) reconcileCachedBoostWinner(
	key string,
	cachedToken boostWinnerToken,
	outcome cachedBoostOutcome,
	succeeded bool,
) (cacheHit bool, winnerToken boostWinnerToken) {
	if !succeeded {
		if outcome.cachedFailed {
			runtime.deleteBoostWinnerIfCurrent(cachedToken)
		}
		return false, boostWinnerToken{}
	}
	cacheHit = outcome.winner.addr == cachedToken.addr
	if cacheHit {
		return true, cachedToken
	}
	if outcome.cachedFailureNeutral {
		return false, boostWinnerToken{}
	}
	return false, runtime.storeBoostWinner(key, outcome.winner.addr)
}

// finishBoostRelay never feeds an ambiguous io.Copy error into route health.
// It discards the exact cached winner only when the relay termination remains
// actionable after excluding proven client disconnects and expected shutdown
// errors. A generation token prevents an old stream from deleting a newer lazy
// refresh or hedge winner.
func (runtime *routingRuntime) finishBoostRelay(token boostWinnerToken, attempt routeAttempt, result relayResult) {
	if relayInvalidatesBoostWinner(result) {
		runtime.deleteBoostWinnerIfCurrent(token)
	}
	reportRouteRelay(attempt, result)
}

// cachedBoostHedgeDelay turns the cached route's foreground dial EWMA into the
// configured tail-latency threshold. Configuration validation guarantees the
// bounds fit inside the rule decision timeout.
func (runtime *routingRuntime) cachedBoostHedgeDelay(rule *config.Rule, addr string) time.Duration {
	if rule == nil || rule.Hedge == nil {
		return 0
	}
	minimum := time.Duration(rule.Hedge.MinDelay) * time.Millisecond
	maximum := time.Duration(rule.Hedge.MaxDelay) * time.Millisecond
	delay := minimum
	if runtime != nil && runtime.routes != nil {
		snapshot := runtime.routes.snapshot(rule, addr, time.Now())
		if snapshot.HasEWMA {
			delay = 2 * snapshot.EWMA
		}
	}
	if delay < minimum {
		delay = minimum
	}
	if delay > maximum {
		delay = maximum
	}
	return delay
}

func (runtime *routingRuntime) raceCachedBoostTarget(
	ctx context.Context,
	rule *config.Rule,
	cachedAddr string,
	prepare boostPrepareFunc,
) (cachedBoostOutcome, error) {
	delay := runtime.cachedBoostHedgeDelay(rule, cachedAddr)
	dial := func(dialCtx context.Context, dialRule *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
		return runtime.outboundDialRouteWithOptions(dialCtx, dialRule, addr, options.tryOnly, options.onStart)
	}
	return runtime.raceCachedBoostTargetWithDial(
		ctx,
		rule,
		cachedAddr,
		dial,
		prepare,
		delay,
		nil,
	)
}

// raceCachedBoostTargetWithDial starts only the cached route initially. A hard
// failure immediately fills the normal Top-2 decision window from other
// routes, while a merely slow dial starts one hedge only after hedgeReady. All
// candidates use the supplied route dialer; production wraps
// outboundDialRouteWithOptions, which owns active-health checks, route attempts,
// prewarm, metrics, foreground dial-bulkhead admission, and precise start
// notifications. Delayed alternatives use immediate-only admission.
func (runtime *routingRuntime) raceCachedBoostTargetWithDial(
	ctx context.Context,
	rule *config.Rule,
	cachedAddr string,
	dial boostRouteDialFunc,
	prepare boostPrepareFunc,
	hedgeDelay time.Duration,
	hedgeReady <-chan time.Time,
) (outcome cachedBoostOutcome, returnErr error) {
	var delayedStarted atomic.Bool
	defer func() { outcome.hedged = delayedStarted.Load() }()
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return outcome, errors.New("cached boost rule has no targets")
	}
	if cachedAddr == "" {
		return outcome, errors.New("cached boost target is empty")
	}
	if dial == nil {
		dial = func(dialCtx context.Context, dialRule *config.Rule, addr string, options boostRouteDialOptions) (net.Conn, routeAttempt, error) {
			return runtime.outboundDialRouteWithOptions(dialCtx, dialRule, addr, options.tryOnly, options.onStart)
		}
	}
	if err := ctx.Err(); err != nil {
		return outcome, err
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timerCtx, cancelTimer := context.WithCancel(ctx)
	defer cancelTimer()
	results := make(chan dialResult, len(rule.Targets))
	attempted := map[string]struct{}{cachedAddr: {}}
	cachedTarget := targetByAddress(rule, cachedAddr)
	var cachedProtocolProbe routeProtocolProbeLease
	protocolProbeNow := time.Now()
	if cachedTarget != nil && runtime.routes.protocolPenalty(rule, cachedTarget, protocolProbeNow) > 0 {
		cachedProtocolProbe, _ = runtime.routes.claimProtocolProbe(rule, cachedTarget, protocolProbeNow)
	}
	// A due protocol-recovery probe owns this request's complete setup window.
	// In particular, don't let the normal cached-route hedge cancel a slow H3
	// canary before it can collect the data-plane evidence needed for recovery.
	exclusiveCachedProtocolProbe := cachedProtocolProbe.token != 0
	targetAttemptLimit := connectProxyTargetAttemptLimit(rule)
	actualAttempts := 1
	active := 0
	hedgingEnabled := false
	delayedHedge := false
	primaryFailed := false
	healthExcluded := false
	globalCapacityLimited := false
	capacityFallbackTryOnly := false
	var capacityErr error
	var dialErrors []error

	controlledHedgeSignal := hedgeReady != nil
	var internalHedgeSignal chan time.Time
	if rule.Hedge != nil && !controlledHedgeSignal {
		internalHedgeSignal = make(chan time.Time, 1)
		hedgeReady = internalHedgeSignal
	}

	var hedgeScheduled atomic.Bool
	var primaryStartOnce sync.Once
	onPrimaryStart := func() {
		primaryStartOnce.Do(func() {
			if rule.Hedge == nil || exclusiveCachedProtocolProbe {
				return
			}
			if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= hedgeDelay {
				metricBoostHedgeEvent(rule.Name, boostHedgeSkippedDeadline)
				return
			}
			hedgeScheduled.Store(true)
			metricBoostHedgeEvent(rule.Name, boostHedgeScheduled)
			metricBoostHedgeDelay(rule.Name, hedgeDelay)
			if controlledHedgeSignal {
				return
			}
			go func() {
				timer := time.NewTimer(hedgeDelay)
				defer timer.Stop()
				select {
				case fired := <-timer.C:
					select {
					case internalHedgeSignal <- fired:
					case <-timerCtx.Done():
					}
				case <-timerCtx.Done():
				}
			}()
		})
	}

	var delayedStartOnce sync.Once
	onDelayedStart := func() {
		delayedStartOnce.Do(func() {
			delayedStarted.Store(true)
			metricBoostHedgeEvent(rule.Name, boostHedgeLaunched)
		})
	}

	launch := func(
		addr string,
		primary, delayed, tryOnly bool,
		probe routeProtocolProbeLease,
		exploration routeExplorationLease,
	) {
		active++
		go func() {
			dialCtx := withRouteProtocolProbeLease(raceCtx, probe)
			options := boostRouteDialOptions{tryOnly: tryOnly}
			if primary {
				options.onStart = onPrimaryStart
			} else if delayed {
				options.onStart = onDelayedStart
			}
			connection, attempt, err := dial(dialCtx, rule, addr, options)
			if err == nil && connection == nil {
				err = errors.New("cached boost dial returned a nil connection")
			}
			if err != nil && connection != nil {
				_ = connection.Close()
				connection = nil
			}
			if err == nil && prepare != nil {
				if prepareErr := prepare(raceCtx, connection, addr); prepareErr != nil {
					routeReportFailure(attempt, prepareErr, time.Now())
					_ = connection.Close()
					connection = nil
					err = prepareErr
				}
			}
			runtime.routes.releaseProtocolProbe(rule, targetByAddress(rule, addr), probe)
			runtime.routes.releaseExploration(exploration)
			results <- dialResult{conn: connection, addr: addr, attempt: attempt, err: err, delayed: delayed}
		}()
	}

	launchAlternatives := func(limit int, delayed, tryOnly bool) int {
		if limit <= 0 || globalCapacityLimited || actualAttempts >= targetAttemptLimit {
			return 0
		}
		launched := 0
		for launched == 0 && actualAttempts < targetAttemptLimit && len(attempted) < len(rule.Targets) {
			// A protocol recovery canary must get one complete setup attempt;
			// otherwise a still-healthy cached primary can repeatedly win and
			// cancel the lazy warming H3 candidate forever.
			reserveProtocolProbe := active == 0 && actualAttempts == 0
			candidates := runtime.routes.selectTargetSelections(
				rule,
				len(rule.Targets),
				time.Now(),
				attempted,
				reserveProtocolProbe,
			)
			if len(candidates) == 0 {
				break
			}
			before := len(attempted)
			for _, candidate := range candidates {
				if launched == limit || actualAttempts >= targetAttemptLimit {
					break
				}
				target := candidate.target
				addr := target.Address
				attempted[addr] = struct{}{}
				if runtime.health.unhealthy(rule, addr) {
					healthExcluded = true
					runtime.routes.releaseProtocolProbe(rule, target, candidate.protocolProbe)
					continue
				}
				if candidate.periodicExplorer {
					lease, claimed := runtime.routes.claimExploration(rule, target, time.Now())
					if !claimed {
						// Exploration is optional. A sibling already owns it, so keep
						// this request moving through the ordinary candidate list.
						runtime.routes.releaseProtocolProbe(rule, target, candidate.protocolProbe)
						continue
					}
					candidate.explorationLease = lease
				}
				actualAttempts++
				launch(addr, false, delayed, tryOnly, candidate.protocolProbe, candidate.explorationLease)
				launched++
				if candidate.protocolProbe.token != 0 {
					break
				}
			}
			if len(attempted) == before {
				break
			}
		}
		if launched > 0 {
			outcome.fallbackStarted = true
		}
		return launched
	}

	observeDelayedResult := func(result dialResult) {
		if !result.delayed || result.addr == cachedAddr {
			return
		}
		if errors.Is(result.err, errDialBulkheadSaturated) {
			metricBoostHedgeEvent(rule.Name, boostHedgeSkippedCapacity)
		}
	}

	drainLate := func(remaining int) {
		for i := 0; i < remaining; i++ {
			result := <-results
			observeDelayedResult(result)
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}
	}

	launch(cachedAddr, true, false, false, cachedProtocolProbe, routeExplorationLease{})
	for active > 0 {
		select {
		case result := <-results:
			active--
			if result.err == nil && result.conn != nil {
				observeDelayedResult(result)
				if hedgeScheduled.Load() && result.addr == cachedAddr && !hedgingEnabled {
					metricBoostHedgeEvent(rule.Name, boostHedgeAvoided)
				}
				if result.delayed && result.addr != cachedAddr {
					metricBoostHedgeEvent(rule.Name, boostHedgeWon)
				}
				cancel()
				drainLate(active)
				outcome.winner = result
				return outcome, nil
			}
			if result.conn != nil {
				_ = result.conn.Close()
			}
			observeDelayedResult(result)

			isCached := result.addr == cachedAddr
			if errors.Is(result.err, ErrActiveHealthUnhealthy) || errors.Is(result.err, ErrCircuitOpen) {
				// The target became unhealthy after selection/admission and no
				// network dial was made, or another request won its half-open route
				// claim. Keep the address excluded from this request, but return its
				// SOCKS target-attempt budget to a later candidate.
				if errors.Is(result.err, ErrActiveHealthUnhealthy) {
					healthExcluded = true
				}
				if actualAttempts > 0 {
					actualAttempts--
				}
				if isCached {
					outcome.cachedFailed = true
					primaryFailed = true
					delayedHedge = false
					hedgingEnabled = true
					hedgeReady = nil
				}
				if hedgingEnabled && !globalCapacityLimited {
					launchAlternatives(2-active, delayedHedge, delayedHedge || capacityFallbackTryOnly)
				}
				continue
			}
			if isDialBulkheadError(result.err) {
				if result.delayed && !isCached {
					// A delayed hedge is optional and uses immediate-only admission.
					// If it cannot start, keep the primary alive without turning the
					// transient miss into a terminal capacity error. Should the primary
					// later fail, this address becomes eligible again as a required
					// fallback using the normal bounded admission wait.
					delete(attempted, result.addr)
					if actualAttempts > 0 {
						actualAttempts--
					}
					if primaryFailed {
						delayedHedge = false
						launchAlternatives(2-active, false, capacityFallbackTryOnly)
					}
					continue
				}
				capacityErr = result.err
				if isDialTargetBulkheadSaturation(result.err) {
					// Per-target capacity rejected this address before any socket was
					// created. Keep it excluded, but return its target-attempt budget
					// so unrelated upstream capacity remains usable.
					if actualAttempts > 0 {
						actualAttempts--
					}
					// A per-target limit leaves unrelated foreground capacity usable.
					// Fill the open Top-2 slot only with immediate admission so this
					// degraded request cannot create another waiter.
					capacityFallbackTryOnly = true
					delayedHedge = false
					hedgingEnabled = true
					hedgeReady = nil
					launchAlternatives(2-active, false, true)
					continue
				}
				// Global (or unknown) saturation means another target cannot make
				// progress without amplifying local pressure. Keep any independent
				// candidate already in flight, but stop further fan-out.
				globalCapacityLimited = true
				hedgeReady = nil
				continue
			}
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				dialErrors = append(dialErrors, fmt.Errorf("%s: %w", result.addr, result.err))
				if isCached {
					if rule.Protocol == config.ProtocolSOCKS5 && connectProxyErrorIsRouteNeutral(result.err) {
						outcome.cachedFailureNeutral = true
					} else {
						outcome.cachedFailed = true
					}
					primaryFailed = true
				}
			}
			if isCached && !globalCapacityLimited {
				// Do not wait for the hedge timer after a confirmed cached-route
				// failure. Match the cache-miss path's Top-2 concurrency immediately.
				delayedHedge = false
				hedgingEnabled = true
				hedgeReady = nil
			}
			if hedgingEnabled && !globalCapacityLimited {
				launchAlternatives(2-active, delayedHedge, delayedHedge || capacityFallbackTryOnly)
			}
		case <-hedgeReady:
			hedgeReady = nil
			if !hedgeScheduled.Load() {
				continue
			}
			hedgingEnabled = true
			delayedHedge = true
			if launchAlternatives(2-active, true, true) == 0 {
				metricBoostHedgeEvent(rule.Name, boostHedgeNoCandidate)
			}
		case <-ctx.Done():
			cancel()
			drainLate(active)
			return outcome, ctx.Err()
		}
	}

	if err := ctx.Err(); err != nil {
		return outcome, err
	}
	if capacityErr != nil {
		if len(dialErrors) > 0 {
			return outcome, errors.Join(append(dialErrors, capacityErr)...)
		}
		return outcome, capacityErr
	}
	if len(dialErrors) > 0 {
		return outcome, fmt.Errorf("cached boost targets failed: %w", errors.Join(dialErrors...))
	}
	if healthExcluded {
		return outcome, fmt.Errorf("all cached boost alternatives unavailable: %w", ErrActiveHealthUnhealthy)
	}
	return outcome, fmt.Errorf("all cached boost alternatives unavailable: %w", ErrCircuitOpen)
}

// raceBoostTargets uses fresh connections and keeps at most two candidates in
// flight. A failed or concurrently claimed slot is immediately filled from a
// target not yet attempted by this inbound connection. This preserves the
// Top-2 concurrency bound without turning a healthy third target into an
// avoidable request failure.
func raceBoostTargets(ctx context.Context, rule *config.Rule, dial boostDialFunc) (dialResult, error) {
	return defaultRoutingRuntime.raceBoostTargets(ctx, rule, dial)
}

func (runtime *routingRuntime) raceBoostTargets(ctx context.Context, rule *config.Rule, dial boostDialFunc) (dialResult, error) {
	return runtime.raceBoostTargetsPrepared(ctx, rule, dial, nil)
}

func (runtime *routingRuntime) raceBoostTargetsPrepared(
	ctx context.Context,
	rule *config.Rule,
	dial boostDialFunc,
	prepare boostPrepareFunc,
) (dialResult, error) {
	return runtime.raceBoostTargetsPreparedWithAdmission(ctx, rule, dial, prepare, runtime.acquireBoostTrafficDial)
}

func (runtime *routingRuntime) raceBoostTargetsPreparedWithAdmission(
	ctx context.Context,
	rule *config.Rule,
	dial boostDialFunc,
	prepare boostPrepareFunc,
	acquire boostDialAcquireFunc,
) (dialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return dialResult{}, errors.New("boost rule has no targets")
	}
	if dial == nil {
		dial = DialFastContext
	}
	if acquire == nil {
		acquire = runtime.acquireBoostTrafficDial
	}
	if err := ctx.Err(); err != nil {
		return dialResult{}, err
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(rule.Targets))
	attempted := make(map[string]struct{}, len(rule.Targets))
	targetAttemptLimit := connectProxyTargetAttemptLimit(rule)
	actualAttempts := 0
	active := 0
	healthExcluded := false
	maintenanceCapacityLimited := false
	foregroundGlobalCapacityLimited := false
	foregroundFallbackTryOnly := false
	var foregroundCapacityErr error
	launchAvailable := func(tryOnly bool) bool {
		if actualAttempts >= targetAttemptLimit {
			return false
		}
		capacity := 2 - active
		if capacity <= 0 {
			return false
		}
		launched := 0
		for launched == 0 && actualAttempts < targetAttemptLimit && len(attempted) < len(rule.Targets) {
			candidates := runtime.routes.selectTargetSelections(
				rule,
				len(rule.Targets),
				time.Now(),
				attempted,
				active == 0 && actualAttempts == 0,
			)
			if len(candidates) == 0 {
				break
			}
			before := len(attempted)
			for _, candidate := range candidates {
				if launched == capacity || actualAttempts >= targetAttemptLimit {
					break
				}
				target := candidate.target
				addr := target.Address
				attempted[addr] = struct{}{}
				if runtime.health.unhealthy(rule, addr) {
					healthExcluded = true
					runtime.routes.releaseProtocolProbe(rule, target, candidate.protocolProbe)
					continue
				}
				if candidate.periodicExplorer {
					lease, claimed := runtime.routes.claimExploration(rule, target, time.Now())
					if !claimed {
						// Do not wait for another request's optional explorer and do not
						// consume one of this request's actual target attempts.
						runtime.routes.releaseProtocolProbe(rule, target, candidate.protocolProbe)
						continue
					}
					candidate.explorationLease = lease
				}
				actualAttempts++
				active++
				launched++
				go func() {
					finish := func(result dialResult) {
						runtime.routes.releaseProtocolProbe(rule, target, candidate.protocolProbe)
						runtime.routes.releaseExploration(candidate.explorationLease)
						results <- result
					}
					dialCtx := withRouteProtocolProbeLease(raceCtx, candidate.protocolProbe)
					releaseDial, acquireErr := acquire(dialCtx, rule, addr, tryOnly)
					if acquireErr != nil {
						finish(dialResult{addr: addr, err: acquireErr})
						return
					}
					if runtime.health.unhealthy(rule, addr) {
						releaseDial()
						finish(dialResult{addr: addr, err: ErrActiveHealthUnhealthy})
						return
					}
					started := time.Now()
					attempt, err := runtime.routes.begin(rule, addr, started)
					if err != nil {
						releaseDial()
						finish(dialResult{addr: addr, err: err})
						return
					}
					// The selected admission budget protects the socket-creating operation.
					// Any protocol setup runs after release under the decision context.
					conn, err := func() (net.Conn, error) {
						defer releaseDial()
						return dial(dialCtx, addr)
					}()
					if err == nil && conn == nil {
						err = errors.New("dial returned a nil connection")
					}
					if err == nil && prepare != nil {
						if prepareErr := prepare(raceCtx, conn, addr); prepareErr != nil {
							_ = conn.Close()
							conn = nil
							err = prepareErr
						}
					}
					latency := time.Since(started)
					routeObserve(attempt, latency, connectProxyRouteObservationError(err), time.Now())
					metricDial(rule.Name, addr, latency, err)
					finish(dialResult{conn: conn, addr: addr, attempt: attempt, err: err})
				}()
				if candidate.protocolProbe.token != 0 {
					// Do not race a recovery canary against a healthy route. The
					// canary must receive one legal response (or fail) to promote the
					// lazy H3 replacement; ordinary alternatives refill on failure.
					break
				}
			}
			if len(attempted) == before {
				break
			}
		}
		return launched > 0
	}
	drainLate := func(remaining int) {
		for i := 0; i < remaining; i++ {
			result := <-results
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}
	}

	var dialErrors []error
	launchAvailable(false)
	for active > 0 {
		select {
		case result := <-results:
			active--
			if result.err == nil && result.conn != nil {
				cancel()
				for active > 0 {
					select {
					case loser := <-results:
						active--
						if loser.conn != nil {
							_ = loser.conn.Close()
						}
					case <-ctx.Done():
						_ = result.conn.Close()
						drainLate(active)
						return dialResult{}, ctx.Err()
					}
				}
				return result, nil
			}
			if result.conn != nil {
				_ = result.conn.Close()
			}
			if errors.Is(result.err, ErrActiveHealthUnhealthy) || errors.Is(result.err, ErrCircuitOpen) {
				// The post-admission health recheck prevented any network attempt.
				// A concurrent circuit half-open claim is likewise route admission,
				// not a network attempt. Preserve the address exclusion but give its
				// bounded attempt slot to another configured target.
				if errors.Is(result.err, ErrActiveHealthUnhealthy) {
					healthExcluded = true
				}
				if actualAttempts > 0 {
					actualAttempts--
				}
				if !maintenanceCapacityLimited && !foregroundGlobalCapacityLimited {
					launchAvailable(foregroundFallbackTryOnly)
				}
				continue
			}
			// Local overload is not evidence that another route is healthier. Stop
			// launching new candidates, but let an independent candidate that is
			// already in flight finish instead of canceling a likely success.
			if isDialBulkheadError(result.err) {
				foregroundCapacityErr = result.err
				if isDialTargetBulkheadSaturation(result.err) {
					// Admission failed before the network dial. Preserve this address
					// in attempted while returning its SOCKS target-attempt slot.
					if actualAttempts > 0 {
						actualAttempts--
					}
					foregroundFallbackTryOnly = true
					launchAvailable(true)
					continue
				}
				foregroundGlobalCapacityLimited = true
				continue
			}
			if errors.Is(result.err, errBoostMaintenanceSaturated) {
				// A lazy refresh uses only idle background capacity. Let any candidate
				// that already acquired a slot finish, but do not fan out further.
				maintenanceCapacityLimited = true
				continue
			}
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				dialErrors = append(dialErrors, fmt.Errorf("%s: %w", result.addr, result.err))
			}
			if !maintenanceCapacityLimited && !foregroundGlobalCapacityLimited {
				launchAvailable(foregroundFallbackTryOnly)
			}
		case <-ctx.Done():
			cancel()
			drainLate(active)
			return dialResult{}, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return dialResult{}, err
	}
	if len(dialErrors) == 0 {
		if foregroundCapacityErr != nil {
			return dialResult{}, foregroundCapacityErr
		}
		if maintenanceCapacityLimited {
			return dialResult{}, errBoostMaintenanceSaturated
		}
		if healthExcluded {
			return dialResult{}, fmt.Errorf("all boost targets unavailable: %w", ErrActiveHealthUnhealthy)
		}
		return dialResult{}, fmt.Errorf("all boost targets unavailable: %w", ErrCircuitOpen)
	}
	if foregroundCapacityErr != nil {
		return dialResult{}, errors.Join(
			fmt.Errorf("all attempted boost targets failed: %w", errors.Join(dialErrors...)),
			foregroundCapacityErr,
		)
	}
	return dialResult{}, fmt.Errorf("all boost targets failed: %w", errors.Join(dialErrors...))
}

// startLazyRevalidate deduplicates background races and publishes a completion
// channel before the goroutine starts. Server shutdown can therefore wait for
// every refresh associated with its rules before clearing routing state.
func (runtime *routingRuntime) startLazyRevalidate(parent context.Context, rule *config.Rule) {
	if rule == nil || len(rule.Targets) < 2 {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := runtime.ctx.Err(); err != nil {
		return
	}
	key := boostRuleKey(rule)
	job := &boostRevalidation{done: make(chan struct{})}
	if _, loaded := runtime.boost.revalidating.LoadOrStore(key, job); loaded {
		return
	}
	jobCtx, cancelJob := context.WithCancel(parent)
	stopRuntimeCancel := context.AfterFunc(runtime.ctx, cancelJob)
	go func() {
		defer cancelJob()
		defer stopRuntimeCancel()
		defer close(job.done)
		defer runtime.boost.revalidating.Delete(key)
		runtime.lazyRevalidate(jobCtx, rule, key)
	}()
}

// lazyRevalidate runs one bounded background race without interrupting the
// current stream. Deduplication and lifecycle tracking live in the starter.
func (runtime *routingRuntime) lazyRevalidate(parent context.Context, rule *config.Rule, key string) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, boostRevalidateLimit)
	defer cancel()
	dial := boostDialFunc(DialFastContext)
	var prepare boostPrepareFunc
	if rule.ProxyProtocol != nil && rule.ProxyProtocol.Send != "" {
		prepare = func(prepareCtx context.Context, connection net.Conn, _ string) error {
			return writeActiveHealthProxyProtocolContext(prepareCtx, connection, rule.ProxyProtocol.Send)
		}
	}
	winner, err := runtime.raceBoostTargetsPreparedWithAdmission(
		ctx,
		rule,
		dial,
		prepare,
		runtime.acquireBoostMaintenanceDial,
	)
	if err != nil {
		return
	}
	defer winner.conn.Close()
	runtime.storeBoostWinner(key, winner.addr)
	utils.Logger.Debug("懒惰刷新winner",
		zap.String("ruleName", rule.Name),
		zap.String("targetAddr", winner.addr))
}

func (runtime *routingRuntime) waitBoostRevalidations(rules []*config.Rule) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if value, ok := runtime.boost.revalidating.Load(boostRuleKey(rule)); ok {
			if job, ok := value.(*boostRevalidation); ok {
				<-job.done
			}
		}
	}
}

func boostDecisionTimeout(rule *config.Rule) time.Duration {
	if rule == nil || rule.Timeout == 0 {
		return dialTimeout
	}
	return time.Duration(rule.Timeout) * time.Millisecond
}

// HandleBoost races fresh dials, picks the first successful route, and relays
// until either side finishes or ctx is cancelled.
func HandleBoost(ctx context.Context, conn net.Conn, rule *config.Rule) {
	defaultRoutingRuntime.handleBoost(ctx, conn, rule)
}

func (runtime *routingRuntime) handleBoost(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil {
		return
	}
	defer conn.Close()
	defer failPendingSOCKS5(conn)
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return
	}

	decisionBegin := time.Now()
	decisionFinished := false
	finishDecision := func() {
		if decisionFinished {
			return
		}
		decisionFinished = true
		metricBoostDecisionDuration(rule.Name, time.Since(decisionBegin))
	}
	defer finishDecision()
	decisionCtx, cancelDecision := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	defer cancelDecision()
	key := boostRuleKey(rule)
	var prepare boostPrepareFunc
	if rule.ProxyProtocol != nil && rule.ProxyProtocol.Send != "" {
		prepare = func(prepareCtx context.Context, candidate net.Conn, _ string) error {
			return writeOutboundProxyProtocolContext(prepareCtx, candidate, conn, rule)
		}
	}

	if cached, ok := runtime.loadUsableBoostWinnerToken(key, rule, time.Now()); ok {
		cachedToken := boostWinnerToken{key: key, addr: cached.addr, generation: cached.generation}
		triggerLazy := rule.Protocol != config.ProtocolSOCKS5 && time.Until(cached.expires) < boostRevalidateAfter
		outcome, err := runtime.raceCachedBoostTarget(decisionCtx, rule, cached.addr, prepare)
		if err == nil {
			cacheHit, winnerToken := runtime.reconcileCachedBoostWinner(key, cachedToken, outcome, true)
			if cacheHit {
				metricBoostCache(rule.Name, true)
			} else {
				metricBoostCache(rule.Name, false)
			}
			defer outcome.winner.conn.Close()
			if err := markSOCKS5Connected(conn); err != nil {
				return
			}
			// A true cache hit deliberately does not extend expires. Otherwise
			// steady traffic would postpone lazy revalidation forever. A fallback or
			// hedge win is fresh route evidence and replaces the cached winner, except
			// when a destination-specific CONNECT response preserved the old winner.
			fields := []zap.Field{
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)),
				zap.String("targetAddr", connAddr(outcome.winner.conn)),
				zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
				zap.Bool("boostCacheHit", cacheHit),
				zap.Bool("boostFallbackStarted", outcome.fallbackStarted),
				zap.Bool("boostHedged", outcome.hedged),
				zap.Bool("boostWinnerPreserved", outcome.cachedFailureNeutral),
			}
			if cacheHit && triggerLazy {
				fields = append(fields, zap.Bool("boostLazyRefresh", true))
				runtime.startLazyRevalidate(ctx, rule)
			}
			utils.Logger.Debug("建立连接", fields...)
			cancelDecision()
			finishDecision()
			result := relayBidirectional(ctx, conn, outcome.winner.conn)
			logRelayResult(rule, conn, outcome.winner.conn, result)
			runtime.finishBoostRelay(winnerToken, outcome.winner.attempt, result)
			return
		}
		runtime.reconcileCachedBoostWinner(key, cachedToken, outcome, false)
		if isDialBulkheadError(err) && !outcome.cachedFailed {
			// Local dial pressure says nothing about the cached route's health. Keep
			// the winner so a later connection can reuse it after capacity drains.
			utils.Logger.Debug("前台拨号容量暂时不可用，保留 Boost winner 并结束当前连接",
				zap.String("ruleName", rule.Name),
				zap.String("targetAddr", cached.addr),
				zap.Error(err))
			return
		}
		metricBoostCache(rule.Name, false)
		if ctx.Err() != nil {
			return
		}
		if rule.Protocol == config.ProtocolSOCKS5 {
			setPendingSOCKS5Failure(conn, err)
			logConnectProxyFailure(rule, cached.addr, err, "缓存原生代理线路及备选均不可用")
		} else {
			utils.Logger.Error("缓存线路及备选均不可用",
				zap.String("ruleName", rule.Name),
				zap.String("targetAddr", cached.addr),
				zap.Bool("boostFallbackStarted", outcome.fallbackStarted),
				zap.Bool("boostHedged", outcome.hedged),
				zap.Error(err))
		}
		return
	}
	metricBoostCache(rule.Name, false)

	dial := boostDialFunc(func(dialCtx context.Context, addr string) (net.Conn, error) {
		return runtime.dialRouteTarget(dialCtx, rule, addr)
	})
	winner, err := runtime.raceBoostTargetsPrepared(decisionCtx, rule, dial, prepare)
	if err != nil {
		if isDialBulkheadError(err) {
			utils.Logger.Debug("前台拨号容量暂时不可用，结束当前 Boost 连接",
				zap.String("ruleName", rule.Name), zap.Error(err))
			return
		}
		if rule.Protocol == config.ProtocolSOCKS5 {
			setPendingSOCKS5Failure(conn, err)
			logConnectProxyFailure(rule, "", err, "原生代理加速决策失败")
		} else {
			utils.Logger.Error("加速决策失败：所有线路均不可用",
				zap.String("ruleName", rule.Name), zap.Error(err))
		}
		return
	}
	defer winner.conn.Close()
	if err := markSOCKS5Connected(conn); err != nil {
		return
	}
	winnerToken := runtime.storeBoostWinner(key, winner.addr)
	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.String("targetAddr", connAddr(winner.conn)),
		zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
		zap.Bool("boostCacheHit", false))
	cancelDecision()
	finishDecision()
	result := relayBidirectional(ctx, conn, winner.conn)
	logRelayResult(rule, conn, winner.conn, result)
	runtime.finishBoostRelay(winnerToken, winner.attempt, result)
}
