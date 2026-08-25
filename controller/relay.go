package controller

import (
	"context"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type relayDirectionResult struct {
	Bytes int64
	Err   error
}

type relayResult struct {
	ClientToTarget relayDirectionResult
	TargetToClient relayDirectionResult
	Duration       time.Duration
}

type namedRelayResult struct {
	clientToTarget bool
	result         relayDirectionResult
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
	finished := make(chan struct{})
	var interruptOnce sync.Once
	interrupt := func() {
		_ = client.Close()
		_ = target.Close()
	}

	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				interruptOnce.Do(interrupt)
			case <-finished:
			}
		}()
	}

	copyDirection := func(dst, src net.Conn, clientToTarget bool) {
		copied, err := copyConn(dst, src)
		if closeErr := closeWrite(dst); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			// An actual copy/half-close failure must unblock the other direction.
			// Normal EOF is represented by a nil io.Copy error and does not come
			// through this path. Closing both endpoints wakes the peer direction.
			interruptOnce.Do(interrupt)
		}
		results <- namedRelayResult{
			clientToTarget: clientToTarget,
			result: relayDirectionResult{
				Bytes: copied,
				Err:   err,
			},
		}
	}

	go copyDirection(target, client, true)
	go copyDirection(client, target, false)

	var relay relayResult
	for i := 0; i < 2; i++ {
		completed := <-results
		if completed.clientToTarget {
			relay.ClientToTarget = completed.result
		} else {
			relay.TargetToClient = completed.result
		}
	}
	close(finished)
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

func logRelayResult(rule *config.Rule, client, target net.Conn, result relayResult) {
	ruleName := ""
	if rule != nil {
		ruleName = rule.Name
	}
	metricRelay(ruleName, "client_to_target", result.ClientToTarget.Bytes, result.ClientToTarget.Err)
	metricRelay(ruleName, "target_to_client", result.TargetToClient.Bytes, result.TargetToClient.Err)
	metricRelayDuration(ruleName, result.Duration)
	fields := []zap.Field{
		zap.String("ruleName", ruleName),
		zap.String("remoteAddr", connAddr(client)),
		zap.String("targetAddr", connAddr(target)),
		zap.Int64("clientToTargetBytes", result.ClientToTarget.Bytes),
		zap.Int64("targetToClientBytes", result.TargetToClient.Bytes),
		zap.Int64("durationMs", result.Duration.Milliseconds()),
	}
	if result.ClientToTarget.Err != nil {
		utils.Logger.Warn("客户端到目标的转发异常",
			append(fields, zap.Error(result.ClientToTarget.Err))...)
	}
	if result.TargetToClient.Err != nil {
		utils.Logger.Warn("目标到客户端的转发异常",
			append(fields, zap.Error(result.TargetToClient.Err))...)
	}
	utils.Logger.Debug("连接转发结束", fields...)
}
