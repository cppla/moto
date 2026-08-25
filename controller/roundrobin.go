package controller

import (
	"context"
	"moto/config"
	"moto/utils"
	"net"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

func nextRoundRobinIndex(rule *config.Rule) (int, bool) {
	return defaultRoutingRuntime.nextRoundRobinIndex(rule)
}

func (runtime *routingRuntime) nextRoundRobinIndex(rule *config.Rule) (int, bool) {
	if rule == nil || len(rule.Targets) == 0 {
		return 0, false
	}
	value, _ := runtime.roundRobin.LoadOrStore(rule, &atomic.Uint64{})
	sequence := value.(*atomic.Uint64).Add(1)
	return int((sequence - 1) % uint64(len(rule.Targets))), true
}

// HandleRoundrobin 顺序轮转目标，失败时回退到 boost 模式。
func HandleRoundrobin(ctx context.Context, conn net.Conn, rule *config.Rule) {
	defaultRoutingRuntime.handleRoundrobin(ctx, conn, rule)
}

func (runtime *routingRuntime) handleRoundrobin(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil {
		return
	}
	defer conn.Close()
	if ctx == nil {
		ctx = context.Background()
	}
	index, ok := runtime.nextRoundRobinIndex(rule)
	if !ok {
		return
	}

	v := rule.Targets[index]
	selectedAddr := v.Address

	roundrobinBegin := time.Now()
	dialCtx, cancelDial := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	defer cancelDial()
	target, targetAttempt, err := runtime.outboundDialRoute(dialCtx, rule, v.Address)
	if err != nil {
		if isDialBulkheadError(err) {
			if isDialTargetBulkheadSaturation(err) {
				utils.Logger.Debug("RoundRobin 目标拨号容量已满，立即尝试其他目标",
					zap.String("ruleName", rule.Name),
					zap.String("targetAddr", v.Address))
				for _, candidate := range rule.Targets {
					if candidate.Address == v.Address {
						continue
					}
					fallback, attempt, fallbackErr := runtime.outboundDialRouteWithOptions(
						dialCtx, rule, candidate.Address, true, nil,
					)
					if fallbackErr == nil {
						target = fallback
						targetAttempt = attempt
						selectedAddr = candidate.Address
						err = nil
						break
					}
					if isDialBulkheadError(fallbackErr) && !isDialTargetBulkheadSaturation(fallbackErr) {
						break
					}
				}
				if err != nil {
					return
				}
			} else {
				utils.Logger.Debug("前台拨号容量暂时不可用，结束当前 RoundRobin 连接",
					zap.String("ruleName", rule.Name),
					zap.String("remoteAddr", connAddr(conn)),
					zap.String("targetAddr", v.Address),
					zap.Error(err))
				return
			}
		} else {
			utils.Logger.Error("无法建立连接，切换到 boost 模式",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)),
				zap.String("targetAddr", v.Address),
				zap.Int64("failedTime(ms)", time.Since(roundrobinBegin).Milliseconds()),
				zap.Error(err))
			runtime.handleBoost(ctx, conn, rule)
			return
		}
	}
	configureTCP(target)
	if err := writeOutboundProxyProtocolContext(dialCtx, target, conn, rule); err != nil {
		routeReportFailure(targetAttempt, err, time.Now())
		_ = target.Close()
		utils.Logger.Error("写入 PROXY protocol 头失败，切换到 boost 模式",
			zap.String("ruleName", rule.Name),
			zap.String("targetAddr", selectedAddr),
			zap.Error(err))
		runtime.handleBoost(ctx, conn, rule)
		return
	}
	cancelDial()
	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.String("targetAddr", connAddr(target)),
		zap.Int64("roundrobinTime(ms)", time.Since(roundrobinBegin).Milliseconds()))

	defer target.Close()
	result := relayBidirectional(ctx, conn, target)
	logRelayResult(rule, conn, target, result)
	reportRouteRelay(targetAttempt, result)
}
