package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type relayDirectionResult struct {
	Bytes           int64
	Err             error
	upstreamFailure bool
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
	var interruptCause atomic.Uint32
	interrupt := func() {
		_ = client.Close()
		_ = target.Close()
	}

	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				interruptCause.CompareAndSwap(relayInterruptNone, relayInterruptNeutral)
				interruptOnce.Do(interrupt)
			case <-finished:
			}
		}()
	}

	copyDirection := func(dst, src net.Conn, clientToTarget bool) {
		copied, failedOperation, err := copyConn(dst, src)
		upstreamFailure := (clientToTarget && failedOperation == relayFailureWrite) ||
			(!clientToTarget && failedOperation == relayFailureRead)
		if closeErr := closeWrite(dst); err == nil && closeErr != nil {
			err = closeErr
			// The destination is the upstream only for client -> target.
			upstreamFailure = clientToTarget
		}
		if err != nil {
			// An actual copy/half-close failure must unblock the other direction.
			// Normal EOF is represented by a nil io.Copy error and does not come
			// through this path. Only the first failing direction is causal; errors
			// produced in the peer direction by interrupt() must not be attributed
			// to the upstream circuit.
			cause := uint32(relayInterruptNeutral)
			if upstreamFailure {
				cause = relayInterruptUpstream
			}
			if !interruptCause.CompareAndSwap(relayInterruptNone, cause) {
				upstreamFailure = false
			}
			interruptOnce.Do(interrupt)
		}
		results <- namedRelayResult{
			clientToTarget: clientToTarget,
			result: relayDirectionResult{
				Bytes:           copied,
				Err:             err,
				upstreamFailure: upstreamFailure,
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

type relayFailureOperation uint8

const (
	relayFailureNone relayFailureOperation = iota
	relayFailureRead
	relayFailureWrite
)

const (
	relayInterruptNone uint32 = iota
	relayInterruptNeutral
	relayInterruptUpstream
)

// copyConn deliberately uses an explicit read/write loop. io.Copy selects
// TCPConn.WriteTo/ReadFrom fast paths whose nested net.OpError values do not
// reliably reveal whether the source read or destination write failed. Keeping
// the operations separate lets the circuit breaker ignore client faults while
// still reacting to faults attributable to the upstream connection.
func copyConn(dst, src net.Conn) (int64, relayFailureOperation, error) {
	// Each active stream owns two buffers. Keep them moderately sized so the
	// process-wide connection cap also places a practical bound on relay memory.
	buffer := make([]byte, 16*1024)
	var copied int64
	for {
		read, readErr := src.Read(buffer)
		if read > 0 {
			written := 0
			for written < read {
				count, writeErr := dst.Write(buffer[written:read])
				if count > 0 {
					written += count
					copied += int64(count)
				}
				if writeErr != nil {
					return copied, relayFailureWrite, writeErr
				}
				if count == 0 {
					return copied, relayFailureWrite, io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return copied, relayFailureNone, nil
			}
			return copied, relayFailureRead, readErr
		}
	}
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

// upstreamRelayError returns only errors whose network operation can be
// attributed to the upstream side. This deliberately ignores ambiguous and
// client-side failures so a client reset cannot trip an upstream circuit.
func upstreamRelayError(result relayResult) error {
	var upstream []error
	if result.ClientToTarget.Err != nil && result.ClientToTarget.upstreamFailure {
		upstream = append(upstream, result.ClientToTarget.Err)
	}
	if result.TargetToClient.Err != nil && result.TargetToClient.upstreamFailure {
		upstream = append(upstream, result.TargetToClient.Err)
	}
	return errors.Join(upstream...)
}

func reportRouteRelay(attempt routeAttempt, result relayResult) {
	if err := upstreamRelayError(result); err != nil {
		routeReportFailure(attempt, err, time.Now())
		return
	}
	if result.ClientToTarget.Bytes+result.TargetToClient.Bytes > 0 {
		routeReportSuccess(attempt)
	}
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
