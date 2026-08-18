package controller

import (
	"context"
	"moto/config"
	"moto/utils"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var roundRobinCounters sync.Map // map[*config.Rule]*atomic.Uint64

func nextRoundRobinIndex(rule *config.Rule) (int, bool) {
	if rule == nil || len(rule.Targets) == 0 {
		return 0, false
	}
	value, _ := roundRobinCounters.LoadOrStore(rule, &atomic.Uint64{})
	sequence := value.(*atomic.Uint64).Add(1)
	return int((sequence - 1) % uint64(len(rule.Targets))), true
}

// HandleRoundrobin 顺序轮转目标，失败时回退到 boost 模式。
func HandleRoundrobin(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil {
		return
	}
	defer conn.Close()
	if ctx == nil {
		ctx = context.Background()
	}
	index, ok := nextRoundRobinIndex(rule)
	if !ok {
		return
	}

	v := rule.Targets[index]

	roundrobinBegin := time.Now()
	dialCtx, cancelDial := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	target, targetAttempt, err := outboundDialRoute(dialCtx, rule, v.Address)
	cancelDial()
	if err != nil {
		utils.Logger.Error("无法建立连接，切换到 boost 模式",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)),
			zap.String("targetAddr", v.Address),
			zap.Int64("failedTime(ms)", time.Since(roundrobinBegin).Milliseconds()))
		HandleBoost(ctx, conn, rule)
		return
	}
	configureTCP(target)
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
