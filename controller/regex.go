package controller

import (
	"bytes"
	"context"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

const regexpProbeLimit = 4096

// HandleRegexp 通过限长、增量的首包检测选出目标，然后完整转发已读数据和后续数据流。
func HandleRegexp(ctx context.Context, conn net.Conn, rule *config.Rule) {
	defaultRoutingRuntime.handleRegexp(ctx, conn, rule)
}

func (runtime *routingRuntime) handleRegexp(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil || rule == nil || len(rule.Targets) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer conn.Close()

	probeTimeout := time.Duration(rule.Timeout) * time.Millisecond
	if probeTimeout <= 0 {
		probeTimeout = 500 * time.Millisecond
	}
	probeDeadline := time.Now().Add(probeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(probeDeadline) {
		probeDeadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(probeDeadline); err != nil {
		utils.Logger.Error("无法处理连接，设置首包超时失败",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.Error(err))
		return
	}

	firstPacket := make([]byte, 0, regexpProbeLimit)
	readBuffer := make([]byte, 512)
	for len(firstPacket) < regexpProbeLimit {
		remaining := regexpProbeLimit - len(firstPacket)
		if remaining < len(readBuffer) {
			readBuffer = readBuffer[:remaining]
		}

		n, readErr := conn.Read(readBuffer)
		if n > 0 {
			firstPacket = append(firstPacket, readBuffer[:n]...)
			matched := matchingTargets(rule, firstPacket)
			if len(matched) > 0 {
				if err := conn.SetReadDeadline(time.Time{}); err != nil {
					utils.Logger.Warn("清除首包读取超时失败",
						zap.String("ruleName", rule.Name),
						zap.String("remoteAddr", connAddr(conn)),
						zap.Error(err))
				}
				runtime.handleRegexpMatch(ctx, conn, rule, matched, firstPacket)
				return
			}
		}

		if readErr != nil {
			utils.Logger.Error("无法处理连接，首包读取结束前未匹配到目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)),
				zap.Int("probeBytes", len(firstPacket)),
				zap.Error(readErr))
			return
		}
	}

	utils.Logger.Error("无法处理连接，首包达到检测上限仍未匹配到目标",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.Int("probeBytes", len(firstPacket)))
}

func matchingTargets(rule *config.Rule, packet []byte) []*config.Target {
	matched := make([]*config.Target, 0, len(rule.Targets))
	for _, target := range rule.Targets {
		if target.Re != nil && target.Re.Match(packet) {
			matched = append(matched, target)
		}
	}
	return matched
}

func (runtime *routingRuntime) handleRegexpMatch(ctx context.Context, conn net.Conn, rule *config.Rule, matched []*config.Target, firstPacket []byte) {
	dialCtx, cancelDial := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	defer cancelDial()

	var target net.Conn
	var targetAttempt routeAttempt
	for _, candidate := range matched {
		candidateConn, attempt, err := runtime.outboundDialRoute(dialCtx, rule, candidate.Address)
		if err != nil {
			utils.Logger.Error("无法建立连接，尝试下一个匹配目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)),
				zap.String("targetAddr", candidate.Address),
				zap.Error(err))
			continue
		}
		configureTCP(candidateConn)
		if err := writeOutboundProxyProtocol(candidateConn, conn, rule); err != nil {
			routeReportFailure(attempt, err, time.Now())
			_ = candidateConn.Close()
			utils.Logger.Error("写入 PROXY protocol 头失败，尝试下一个匹配目标",
				zap.String("ruleName", rule.Name),
				zap.String("targetAddr", candidate.Address),
				zap.Error(err))
			continue
		}
		target = candidateConn
		targetAttempt = attempt
		break
	}
	if target == nil {
		utils.Logger.Error("已匹配的目标均连接失败，无法处理连接",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.Int("probeBytes", len(firstPacket)))
		return
	}
	defer target.Close()

	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.String("targetAddr", connAddr(target)),
		zap.Int("probeBytes", len(firstPacket)))

	written, err := io.Copy(target, bytes.NewReader(firstPacket))
	if err != nil || written != int64(len(firstPacket)) {
		if err == nil {
			err = io.ErrShortWrite
		}
		utils.Logger.Error("无法处理连接，转发首包失败",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.String("targetAddr", connAddr(target)),
			zap.Int64("writtenBytes", written),
			zap.Int("probeBytes", len(firstPacket)),
			zap.Error(err))
		metricRelay(rule.Name, "client_to_target", written, err)
		routeReportFailure(targetAttempt, err, time.Now())
		return
	}

	result := relayBidirectional(ctx, conn, target)
	result.ClientToTarget.Bytes += written
	logRelayResult(rule, conn, target, result)
	reportRouteRelay(targetAttempt, result)
}
