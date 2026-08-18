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
	addr    string
	expires time.Time
}

var boostWinnerCache = struct {
	sync.Mutex
	entries map[string]boostWinnerEntry
}{entries: make(map[string]boostWinnerEntry)}

type boostRevalidation struct {
	done chan struct{}
}

var boostRevalidating sync.Map // map[string]*boostRevalidation

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
	now := time.Now()
	boostWinnerCache.Lock()
	defer boostWinnerCache.Unlock()
	entry, ok := boostWinnerCache.entries[key]
	if !ok {
		return "", false, time.Time{}
	}
	if !now.Before(entry.expires) {
		delete(boostWinnerCache.entries, key)
		return "", false, time.Time{}
	}
	return entry.addr, true, entry.expires
}

func storeBoostWinner(key, addr string) {
	boostWinnerCache.Lock()
	defer boostWinnerCache.Unlock()
	if _, exists := boostWinnerCache.entries[key]; !exists && len(boostWinnerCache.entries) >= boostWinnerCacheMax {
		for oldKey := range boostWinnerCache.entries {
			delete(boostWinnerCache.entries, oldKey)
			break
		}
	}
	boostWinnerCache.entries[key] = boostWinnerEntry{addr: addr, expires: time.Now().Add(boostWinnerTTL)}
}

func deleteBoostWinner(key string) {
	boostWinnerCache.Lock()
	delete(boostWinnerCache.entries, key)
	boostWinnerCache.Unlock()
}

// raceBoostTargets uses fresh connections and keeps at most two candidates in
// flight. A failed or concurrently claimed slot is immediately filled from a
// target not yet attempted by this inbound connection. This preserves the
// Top-2 concurrency bound without turning a healthy third target into an
// avoidable request failure.
func raceBoostTargets(ctx context.Context, rule *config.Rule, dial boostDialFunc) (dialResult, error) {
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
	launchAvailable := func() bool {
		capacity := 2 - active
		if capacity <= 0 {
			return false
		}
		candidates := selectRouteTargetsExcluding(rule, capacity, time.Now(), attempted)
		for _, target := range candidates {
			addr := target.Address
			attempted[addr] = struct{}{}
			active++
			go func() {
				started := time.Now()
				attempt, err := routeBegin(rule, addr, started)
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
		return len(candidates) > 0
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
		return dialResult{}, fmt.Errorf("all boost targets unavailable: %w", ErrCircuitOpen)
	}
	return dialResult{}, fmt.Errorf("all boost targets failed: %w", errors.Join(dialErrors...))
}

// startLazyRevalidate deduplicates background races and publishes a completion
// channel before the goroutine starts. Server shutdown can therefore wait for
// every refresh associated with its rules before clearing routing state.
func startLazyRevalidate(parent context.Context, rule *config.Rule) {
	if rule == nil || len(rule.Targets) < 2 {
		return
	}
	key := boostRuleKey(rule)
	job := &boostRevalidation{done: make(chan struct{})}
	if _, loaded := boostRevalidating.LoadOrStore(key, job); loaded {
		return
	}
	go func() {
		defer close(job.done)
		defer boostRevalidating.Delete(key)
		lazyRevalidate(parent, rule, key)
	}()
}

// lazyRevalidate runs one bounded background race without interrupting the
// current stream. Deduplication and lifecycle tracking live in the starter.
func lazyRevalidate(parent context.Context, rule *config.Rule, key string) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, boostRevalidateLimit)
	defer cancel()
	winner, err := raceBoostTargets(ctx, rule, DialFastContext)
	if err != nil {
		return
	}
	defer winner.conn.Close()
	storeBoostWinner(key, winner.addr)
	utils.Logger.Debug("懒惰刷新winner",
		zap.String("ruleName", rule.Name),
		zap.String("targetAddr", winner.addr))
}

func waitBoostRevalidations(rules []*config.Rule) {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if value, ok := boostRevalidating.Load(boostRuleKey(rule)); ok {
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

	if addr, ok, expires := loadBoostWinner(key); ok {
		triggerLazy := time.Until(expires) < boostRevalidateAfter
		cachedConn, cachedAttempt, err := outboundDialRoute(decisionCtx, rule, addr)
		if err == nil {
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
				startLazyRevalidate(ctx, rule)
			}
			utils.Logger.Debug("建立连接", fields...)
			cancelDecision()
			result := relayBidirectional(ctx, conn, cachedConn)
			logRelayResult(rule, conn, cachedConn, result)
			reportRouteRelay(cachedAttempt, result)
			if upstreamRelayError(result) != nil {
				deleteBoostWinner(key)
			}
			return
		}
		deleteBoostWinner(key)
		if ctx.Err() != nil {
			return
		}
	}
	metricBoostCache(rule.Name, false)

	winner, err := raceBoostTargets(decisionCtx, rule, DialFastContext)
	if err != nil {
		utils.Logger.Error("加速决策失败：所有线路均不可用",
			zap.String("ruleName", rule.Name), zap.Error(err))
		return
	}
	defer winner.conn.Close()
	storeBoostWinner(key, winner.addr)
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
		deleteBoostWinner(key)
	}
}
