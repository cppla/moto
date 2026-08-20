package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"moto/utils"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	boostWinnerTTL       = 30 * time.Second // 胜出线路缓存时长
	boostRevalidateAfter = boostWinnerTTL / 2
	boostRevalidateLimit = 2 * time.Second
	boostWinnerCacheMax  = 256
)

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
}

type boostDialFunc func(context.Context, string) (net.Conn, error)

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

// raceBoostTargets uses fresh connections and keeps at most two candidates in
// flight. A failed or concurrently claimed slot is immediately filled from a
// target not yet attempted by this inbound connection. This preserves the
// Top-2 concurrency bound without turning a healthy third target into an
// avoidable request failure.
func raceBoostTargets(ctx context.Context, rule *config.Rule, dial boostDialFunc) (dialResult, error) {
	return defaultRoutingRuntime.raceBoostTargets(ctx, rule, dial)
}

func (runtime *routingRuntime) raceBoostTargets(ctx context.Context, rule *config.Rule, dial boostDialFunc) (dialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return dialResult{}, errors.New("boost rule has no targets")
	}
	if dial == nil {
		dial = DialFastContext
	}
	if err := ctx.Err(); err != nil {
		return dialResult{}, err
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(rule.Targets))
	attempted := make(map[string]struct{}, len(rule.Targets))
	active := 0
	healthExcluded := false
	launchAvailable := func() bool {
		capacity := 2 - active
		if capacity <= 0 {
			return false
		}
		candidates := runtime.routes.selectTargetsExcluding(rule, len(rule.Targets), time.Now(), attempted)
		launched := 0
		for _, target := range candidates {
			if launched == capacity {
				break
			}
			addr := target.Address
			attempted[addr] = struct{}{}
			if runtime.health.unhealthy(rule, addr) {
				healthExcluded = true
				continue
			}
			active++
			launched++
			go func() {
				started := time.Now()
				attempt, err := runtime.routes.begin(rule, addr, started)
				if err != nil {
					results <- dialResult{addr: addr, err: err}
					return
				}
				conn, err := dial(raceCtx, addr)
				if err == nil && conn == nil {
					err = errors.New("dial returned a nil connection")
				}
				latency := time.Since(started)
				routeObserve(attempt, latency, err, time.Now())
				metricDial(rule.Name, addr, latency, err)
				results <- dialResult{conn: conn, addr: addr, attempt: attempt, err: err}
			}()
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
	launchAvailable()
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
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				dialErrors = append(dialErrors, fmt.Errorf("%s: %w", result.addr, result.err))
			}
			launchAvailable()
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
		if healthExcluded {
			return dialResult{}, fmt.Errorf("all boost targets unavailable: %w", ErrActiveHealthUnhealthy)
		}
		return dialResult{}, fmt.Errorf("all boost targets unavailable: %w", ErrCircuitOpen)
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
	if rule.ProxyProtocol != nil && rule.ProxyProtocol.Send != "" {
		dial = func(dialCtx context.Context, addr string) (net.Conn, error) {
			return dialActiveHealthTarget(dialCtx, "tcp", addr, rule.ProxyProtocol.Send)
		}
	}
	winner, err := runtime.raceBoostTargets(ctx, rule, dial)
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
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return
	}

	decisionBegin := time.Now()
	decisionCtx, cancelDecision := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	defer cancelDecision()
	key := boostRuleKey(rule)

	if cached, ok := runtime.loadBoostWinnerToken(key); ok {
		cachedToken := boostWinnerToken{key: key, addr: cached.addr, generation: cached.generation}
		triggerLazy := time.Until(cached.expires) < boostRevalidateAfter
		cachedConn, cachedAttempt, err := runtime.outboundDialRoute(decisionCtx, rule, cached.addr)
		if err == nil {
			if headerErr := writeOutboundProxyProtocol(cachedConn, conn, rule); headerErr != nil {
				routeReportFailure(cachedAttempt, headerErr, time.Now())
				_ = cachedConn.Close()
				err = headerErr
			} else {
				metricBoostCache(rule.Name, true)
				defer cachedConn.Close()
				// A cache hit deliberately does not extend expires. Otherwise steady
				// traffic would postpone lazy revalidation forever.
				fields := []zap.Field{
					zap.String("ruleName", rule.Name),
					zap.String("remoteAddr", connAddr(conn)),
					zap.String("targetAddr", connAddr(cachedConn)),
					zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
					zap.Bool("boostCacheHit", true),
				}
				if triggerLazy {
					fields = append(fields, zap.Bool("boostLazyRefresh", true))
					runtime.startLazyRevalidate(ctx, rule)
				}
				utils.Logger.Debug("建立连接", fields...)
				cancelDecision()
				result := relayBidirectional(ctx, conn, cachedConn)
				logRelayResult(rule, conn, cachedConn, result)
				reportRouteRelay(cachedAttempt, result)
				if upstreamRelayError(result) != nil {
					runtime.deleteBoostWinnerIfCurrent(cachedToken)
				}
				return
			}
		}
		runtime.deleteBoostWinnerIfCurrent(cachedToken)
		if ctx.Err() != nil {
			return
		}
	}
	metricBoostCache(rule.Name, false)

	dial := boostDialFunc(DialFastContext)
	if rule.ProxyProtocol != nil && rule.ProxyProtocol.Send != "" {
		dial = func(dialCtx context.Context, addr string) (net.Conn, error) {
			candidate, dialErr := DialFastContext(dialCtx, addr)
			if dialErr != nil {
				return candidate, dialErr
			}
			if headerErr := writeOutboundProxyProtocol(candidate, conn, rule); headerErr != nil {
				_ = candidate.Close()
				return nil, headerErr
			}
			return candidate, nil
		}
	}
	winner, err := runtime.raceBoostTargets(decisionCtx, rule, dial)
	if err != nil {
		utils.Logger.Error("加速决策失败：所有线路均不可用",
			zap.String("ruleName", rule.Name), zap.Error(err))
		return
	}
	defer winner.conn.Close()
	winnerToken := runtime.storeBoostWinner(key, winner.addr)
	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.String("targetAddr", connAddr(winner.conn)),
		zap.Int64("decisionTime(ms)", time.Since(decisionBegin).Milliseconds()),
		zap.Bool("boostCacheHit", false))
	cancelDecision()
	result := relayBidirectional(ctx, conn, winner.conn)
	logRelayResult(rule, conn, winner.conn, result)
	reportRouteRelay(winner.attempt, result)
	if upstreamRelayError(result) != nil {
		runtime.deleteBoostWinnerIfCurrent(winnerToken)
	}
}
