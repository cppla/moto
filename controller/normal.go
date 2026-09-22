package controller

import (
	"context"
	"errors"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

// HandleNormal 会依次尝试各个目标，并在首个连接成功的目标上转发流量。
func HandleNormal(ctx context.Context, conn net.Conn, rule *config.Rule) {
	defaultRoutingRuntime.handleNormal(ctx, conn, rule)
}

func (runtime *routingRuntime) handleNormal(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil || rule == nil || len(rule.Targets) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer conn.Close()
	defer failPendingConnectClient(conn)
	dialCtx := ctx
	cancelDial := func() {}
	if rule.Timeout > 0 {
		dialCtx, cancelDial = context.WithTimeout(ctx, time.Duration(rule.Timeout)*time.Millisecond)
	}
	defer cancelDial()

	var target net.Conn
	var targetAttempt routeAttempt
	var dialFailures []error
	lastFailedTarget := ""
	if config.IsConnectProtocol(rule.Protocol) {
		var err error
		target, targetAttempt, lastFailedTarget, err = runtime.dialSequentialConnectProxyTargets(dialCtx, rule, 0)
		if err != nil {
			setPendingConnectClientFailure(conn, err)
			if connectProxySequentialFailureIsLocal(err) {
				utils.Logger.Debug("原生代理连接因本地准入或取消结束",
					zap.String("ruleName", rule.Name), zap.Error(err))
				return
			}
			dialFailures = append(dialFailures, err)
		}
	} else {
		targetAttempts := 0
		targetAttemptLimit := connectProxyTargetAttemptLimit(rule)
		tryCapacityFallback := false
		for _, candidate := range rule.Targets {
			if targetAttempts >= targetAttemptLimit {
				break
			}
			targetAttempts++
			candidateConn, attempt, err := runtime.outboundDialRouteWithOptions(
				dialCtx, rule, candidate.Address, tryCapacityFallback, nil,
			)
			if err != nil {
				dialFailures = append(dialFailures, err)
				lastFailedTarget = candidate.Address
				if isDialBulkheadError(err) {
					if isDialTargetBulkheadSaturation(err) {
						tryCapacityFallback = true
						utils.Logger.Debug("目标拨号容量已满，尝试其他目标",
							zap.String("ruleName", rule.Name),
							zap.String("targetAddr", candidate.Address))
						continue
					}
					utils.Logger.Debug("前台拨号容量暂时不可用，结束当前连接",
						zap.String("ruleName", rule.Name),
						zap.String("remoteAddr", connAddr(conn)),
						zap.String("targetAddr", candidate.Address),
						zap.Error(err))
					return
				}
				utils.Logger.Error("无法建立连接，尝试下一个目标",
					zap.String("ruleName", rule.Name),
					zap.String("remoteAddr", connAddr(conn)),
					zap.String("targetAddr", candidate.Address),
					zap.Error(err))
				continue
			}
			configureTCP(candidateConn)
			if err := writeOutboundProxyProtocolContext(dialCtx, candidateConn, conn, rule); err != nil {
				routeReportFailure(attempt, err, time.Now())
				_ = candidateConn.Close()
				utils.Logger.Error("写入 PROXY protocol 头失败，尝试下一个目标",
					zap.String("ruleName", rule.Name),
					zap.String("targetAddr", candidate.Address),
					zap.Error(err))
				continue
			}
			target = candidateConn
			targetAttempt = attempt
			break
		}
	}
	if target == nil {
		finalErr := errors.Join(dialFailures...)
		if config.IsConnectProtocol(rule.Protocol) {
			setPendingConnectClientFailure(conn, finalErr)
			logConnectProxyFailure(rule, lastFailedTarget, finalErr, "所有原生代理目标均连接失败")
		} else {
			utils.Logger.Error("所有目标均连接失败，无法处理连接",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)))
		}
		return
	}
	defer target.Close()
	if err := markConnectClientConnected(conn); err != nil {
		return
	}

	if entry := utils.Logger.Check(zap.DebugLevel, "建立连接"); entry != nil {
		entry.Write(
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.String("targetAddr", connAddr(target)))
	}

	result := relayBidirectional(ctx, conn, target)
	logRelayResult(rule, conn, target, result)
	reportRouteRelay(targetAttempt, result)
}
