package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type relayDirection string

const (
	relayDirectionClientToTarget relayDirection = "client_to_target"
	relayDirectionTargetToClient relayDirection = "target_to_client"
)

type relayStopKind uint8

const (
	relayStopUnknown relayStopKind = iota
	relayStopCopyError
	relayStopContext
)

type relayStopCause struct {
	Kind      relayStopKind
	Direction relayDirection
}

type relayStopPhase uint32

const (
	relayStopPhaseOpen relayStopPhase = iota
	relayStopPhaseClaimed
	relayStopPhaseClosing
)

type relayStopArbiter struct {
	phase     atomic.Uint32
	cause     relayStopCause
	interrupt func()
}

func (arbiter *relayStopArbiter) claim(cause relayStopCause) bool {
	if arbiter == nil || !arbiter.phase.CompareAndSwap(
		uint32(relayStopPhaseOpen), uint32(relayStopPhaseClaimed),
	) {
		return false
	}
	// Publish the cause before announcing that close-induced errors may occur.
	// A contender that observed the intermediate claimed phase is concurrent,
	// not secondary, because endpoint shutdown has not started yet.
	arbiter.cause = cause
	arbiter.phase.Store(uint32(relayStopPhaseClosing))
	if arbiter.interrupt != nil {
		arbiter.interrupt()
	}
	return true
}

func (arbiter *relayStopArbiter) observeError(cause relayStopCause) relayErrorOrigin {
	observedPhase := relayStopPhase(arbiter.phase.Load())
	if arbiter.claim(cause) {
		return relayErrorOriginPrimary
	}
	if observedPhase == relayStopPhaseClosing {
		return relayErrorOriginSecondary
	}
	return relayErrorOriginConcurrent
}

type relayErrorOrigin uint8

const (
	relayErrorOriginUnknown relayErrorOrigin = iota
	relayErrorOriginPrimary
	relayErrorOriginConcurrent
	relayErrorOriginSecondary
)

type relayDirectionResult struct {
	Bytes  int64
	Err    error
	Origin relayErrorOrigin
}

type relayResult struct {
	ClientToTarget relayDirectionResult
	TargetToClient relayDirectionResult
	Duration       time.Duration
	StopCause      relayStopCause
}

type namedRelayResult struct {
	direction relayDirection
	result    relayDirectionResult
}

// relayBidirectional waits for both stream directions. A normal EOF only
// half-closes the destination write side, so a request-side EOF cannot truncate
// a response that is still in flight in the other direction.
func relayBidirectional(ctx context.Context, client, target net.Conn) relayResult {
	if ctx == nil {
		ctx = context.Background()
	}

	started := time.Now()
	results := make(chan namedRelayResult, 2)
	interrupt := func() {
		_ = client.Close()
		_ = target.Close()
	}
	stop := relayStopArbiter{interrupt: interrupt}

	var stopContextWatch func() bool
	var contextWatchDone chan struct{}
	if ctx.Done() != nil {
		// context.AfterFunc does not keep one watcher goroutine alive for every
		// established tunnel. Its callback runs only when cancellation wins; the
		// returned stop function lets a normally completed relay unregister it.
		contextWatchDone = make(chan struct{})
		stopContextWatch = context.AfterFunc(ctx, func() {
			stop.claim(relayStopCause{Kind: relayStopContext})
			close(contextWatchDone)
		})
	}

	copyDirection := func(dst, src net.Conn, direction relayDirection) {
		copied, err := copyConn(dst, src)
		origin := relayErrorOriginUnknown
		if err != nil {
			// An actual copy/half-close failure must unblock the other direction.
			// Normal EOF is represented by a nil io.Copy error and does not come
			// through this path. Closing both endpoints wakes the peer direction.
			origin = stop.observeError(relayStopCause{
				Kind: relayStopCopyError, Direction: direction,
			})
		} else if closeErr := closeWrite(dst); closeErr != nil {
			err = closeErr
			origin = stop.observeError(relayStopCause{
				Kind: relayStopCopyError, Direction: direction,
			})
		}
		results <- namedRelayResult{
			direction: direction,
			result: relayDirectionResult{
				Bytes:  copied,
				Err:    err,
				Origin: origin,
			},
		}
	}

	// The connection handler already owns a goroutine. Use it for one direction
	// and spawn only the peer direction, instead of parking the handler while two
	// additional copy goroutines do all relay work.
	go copyDirection(client, target, relayDirectionTargetToClient)
	copyDirection(target, client, relayDirectionClientToTarget)

	var relay relayResult
	for i := 0; i < 2; i++ {
		completed := <-results
		if completed.direction == relayDirectionClientToTarget {
			relay.ClientToTarget = completed.result
		} else {
			relay.TargetToClient = completed.result
		}
	}
	if stopContextWatch != nil {
		if stopContextWatch() {
			// A true return guarantees that the callback will not run, so this
			// goroutine owns completion notification. Otherwise the callback owns it.
			close(contextWatchDone)
		}
		<-contextWatchDone
	}
	relay.StopCause = stop.cause
	relay.Duration = time.Since(started)
	return relay
}

type relayCopyUnwrapper interface {
	unwrapForRelayCopy() net.Conn
}

// copyConn intentionally delegates to io.Copy. On Linux, Go's TCPConn fast
// paths use splice(2) for TCP-to-TCP transfer; other platforms and unsupported
// transports use the runtime's maintained fallback. Copy errors are not fed
// into route health because io.Copy cannot identify which endpoint caused one.
func copyConn(dst, src net.Conn) (int64, error) {
	return io.Copy(relayCopyEndpoint(dst), relayCopyEndpoint(src))
}

func relayCopyEndpoint(conn net.Conn) net.Conn {
	if unwrapper, ok := conn.(relayCopyUnwrapper); ok {
		if underlying := unwrapper.unwrapForRelayCopy(); underlying != nil {
			return underlying
		}
	}
	return conn
}

func closeWrite(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func connAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

// reportRouteRelay treats copied traffic as proof that a selected route was
// usable, but deliberately leaves ambiguous io.Copy errors to active health
// checks and future dials instead of risking a false circuit break.
func reportRouteRelay(attempt routeAttempt, result relayResult) {
	if !relayHasError(result) && result.ClientToTarget.Bytes+result.TargetToClient.Bytes > 0 {
		routeReportSuccess(attempt)
	}
}

func relayHasError(result relayResult) bool {
	return result.ClientToTarget.Err != nil || result.TargetToClient.Err != nil
}

// relayInvalidatesBoostWinner reports whether a relay failure is actionable
// evidence against the cached route. io.Copy errors are generally ambiguous,
// so this only exempts shutdown signatures that identify a client-side close;
// upstream and otherwise ambiguous failures still force the next connection to
// re-evaluate the cached winner.
func relayInvalidatesBoostWinner(result relayResult) bool {
	return relayDirectionInvalidatesBoostWinner(result, relayDirectionClientToTarget) ||
		relayDirectionInvalidatesBoostWinner(result, relayDirectionTargetToClient)
}

func relayDirectionInvalidatesBoostWinner(result relayResult, direction relayDirection) bool {
	directionResult := relayDirectionResultFor(result, direction)
	if directionResult.Err == nil || directionResult.Origin == relayErrorOriginSecondary {
		return false
	}
	if result.StopCause.Kind == relayStopContext &&
		directionResult.Origin != relayErrorOriginConcurrent {
		return false
	}
	if isClientRelayDisconnectError(direction, directionResult.Err) ||
		isExpectedRelayCloseError(direction, directionResult.Err) {
		return false
	}
	return true
}

func logRelayResult(rule *config.Rule, client, target net.Conn, result relayResult) {
	ruleName := ""
	if rule != nil {
		ruleName = rule.Name
	}
	metricRelay(ruleName, "client_to_target", result.ClientToTarget.Bytes, result.ClientToTarget.Err)
	metricRelay(ruleName, "target_to_client", result.TargetToClient.Bytes, result.TargetToClient.Err)
	metricRelayDuration(ruleName, result.Duration)
	debugEntry := utils.Logger.Check(zap.DebugLevel, "连接转发结束")
	if !relayHasError(result) && debugEntry == nil {
		return
	}
	fields := []zap.Field{
		zap.String("ruleName", ruleName),
		zap.String("remoteAddr", connAddr(client)),
		zap.String("targetAddr", connAddr(target)),
		zap.Int64("clientToTargetBytes", result.ClientToTarget.Bytes),
		zap.Int64("targetToClientBytes", result.TargetToClient.Bytes),
		zap.Int64("durationMs", result.Duration.Milliseconds()),
		zap.String("stopCause", relayStopCauseName(result.StopCause)),
	}
	if result.ClientToTarget.Err != nil {
		logRelayDirection(utils.Logger, "客户端到目标的转发异常", fields, result,
			relayDirectionClientToTarget, result.ClientToTarget.Err)
	}
	if result.TargetToClient.Err != nil {
		logRelayDirection(utils.Logger, "目标到客户端的转发异常", fields, result,
			relayDirectionTargetToClient, result.TargetToClient.Err)
	}
	if debugEntry != nil {
		debugEntry.Write(fields...)
	}
}

const (
	relayLogClassPrimary       = "primary_error"
	relayLogClassConcurrent    = "concurrent_error"
	relayLogClassSecondary     = "secondary_close"
	relayLogClassExpectedClose = "expected_close"
	relayLogClassContextClose  = "context_close"
)

type relayLogDecision struct {
	Level   zapcore.Level
	Class   string
	Primary bool
}

func classifyRelayError(result relayResult, direction relayDirection, err error) relayLogDecision {
	origin := relayDirectionResultFor(result, direction).Origin
	if origin == relayErrorOriginSecondary {
		class := relayLogClassSecondary
		if result.StopCause.Kind == relayStopContext {
			class = relayLogClassContextClose
		}
		return relayLogDecision{Level: zapcore.DebugLevel, Class: class}
	}
	if isExpectedRelayCloseError(direction, err) {
		return relayLogDecision{
			Level:   zapcore.DebugLevel,
			Class:   relayLogClassExpectedClose,
			Primary: origin != relayErrorOriginConcurrent,
		}
	}
	if isClientRelayDisconnectError(direction, err) {
		return relayLogDecision{
			Level:   zapcore.DebugLevel,
			Class:   relayLogClassExpectedClose,
			Primary: origin != relayErrorOriginConcurrent,
		}
	}
	if origin == relayErrorOriginConcurrent {
		return relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassConcurrent}
	}
	if result.StopCause.Kind == relayStopContext && origin == relayErrorOriginUnknown {
		return relayLogDecision{Level: zapcore.DebugLevel, Class: relayLogClassContextClose}
	}
	return relayLogDecision{Level: zapcore.WarnLevel, Class: relayLogClassPrimary, Primary: true}
}

func relayDirectionResultFor(result relayResult, direction relayDirection) relayDirectionResult {
	if direction == relayDirectionClientToTarget {
		return result.ClientToTarget
	}
	return result.TargetToClient
}

func isExpectedRelayCloseError(direction relayDirection, err error) bool {
	return isExpectedRelayCloseErrorForOS(runtime.GOOS, direction, err)
}

const (
	windowsErrorBrokenPipe syscall.Errno = 109
	windowsWSAENOTCONN     syscall.Errno = 10057
	windowsWSAESHUTDOWN    syscall.Errno = 10058
	windowsWSAECONNRESET   syscall.Errno = 10054
)

func isClientRelayDisconnectError(direction relayDirection, err error) bool {
	return isClientRelayDisconnectErrorForOS(runtime.GOOS, direction, err)
}

// A reset is attributable to the client only when it happened while reading
// the client-to-target source. The same errno while writing upstream, or while
// reading target-to-client traffic, remains an actionable route failure.
func isClientRelayDisconnectErrorForOS(goos string, direction relayDirection, err error) bool {
	if direction != relayDirectionClientToTarget ||
		(!errors.Is(err, syscall.ECONNRESET) &&
			!(goos == "windows" && errors.Is(err, windowsWSAECONNRESET))) {
		return false
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		if opErr, ok := current.(*net.OpError); ok && opErr.Op == "read" {
			return true
		}
	}
	return false
}

func isExpectedRelayCloseErrorForOS(goos string, direction relayDirection, err error) bool {
	if errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, syscall.ENOTCONN) {
		return true
	}
	if goos == "windows" && (errors.Is(err, windowsWSAENOTCONN) ||
		errors.Is(err, windowsWSAESHUTDOWN)) {
		return true
	}
	// A broken pipe while writing target data back to the client means the
	// client has already gone away. The same errno in the opposite direction
	// may indicate an upstream failure and remains actionable.
	return direction == relayDirectionTargetToClient && (errors.Is(err, syscall.EPIPE) ||
		goos == "windows" && errors.Is(err, windowsErrorBrokenPipe))
}

func relayStopCauseName(cause relayStopCause) string {
	switch cause.Kind {
	case relayStopContext:
		return "context"
	case relayStopCopyError:
		return string(cause.Direction)
	default:
		return "unknown"
	}
}

func logRelayDirection(
	logger *zap.Logger,
	message string,
	baseFields []zap.Field,
	result relayResult,
	direction relayDirection,
	err error,
) {
	if logger == nil || err == nil {
		return
	}
	decision := classifyRelayError(result, direction, err)
	fields := append(baseFields,
		zap.String("event", "relay_termination"),
		zap.String("direction", string(direction)),
		zap.String("origin", relayErrorOriginName(relayDirectionResultFor(result, direction).Origin)),
		zap.String("class", decision.Class),
		zap.Bool("primary", decision.Primary),
		zap.Error(err),
	)
	logger.Log(decision.Level, message, fields...)
}

func relayErrorOriginName(origin relayErrorOrigin) string {
	switch origin {
	case relayErrorOriginPrimary:
		return "primary"
	case relayErrorOriginConcurrent:
		return "concurrent"
	case relayErrorOriginSecondary:
		return "secondary"
	default:
		return "unknown"
	}
}
