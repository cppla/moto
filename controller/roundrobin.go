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

	roundrobinBegin := time.Now()
	dialCtx, cancelDial := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	target, targetAttempt, err := runtime.outboundDialRoute(dialCtx, rule, v.Address)
	cancelDial()
	if err != nil {
		utils.Logger.Error("无法建立连接，切换到 boost 模式",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.String("targetAddr", v.Address),
			zap.Int64("failedTime(ms)", time.Since(roundrobinBegin).Milliseconds()))
		runtime.handleBoost(ctx, conn, rule)
		return
	}
	configureTCP(target)
	if err := writeOutboundProxyProtocol(target, conn, rule); err != nil {
		routeReportFailure(targetAttempt, err, time.Now())
		_ = target.Close()
		utils.Logger.Error("写入 PROXY protocol 头失败，切换到 boost 模式",
			zap.String("ruleName", rule.Name),
			zap.String("targetAddr", v.Address),
			zap.Error(err))
		runtime.handleBoost(ctx, conn, rule)
		return
	}
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
