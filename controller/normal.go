package controller

import (
	"context"
	"moto/config"
	"moto/utils"
	"net"
	"time"

	"go.uber.org/zap"
)

// HandleNormal 会依次尝试各个目标，并在首个连接成功的目标上转发流量。
func HandleNormal(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil || rule == nil || len(rule.Targets) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer conn.Close()
	dialCtx := ctx
	cancelDial := func() {}
	if rule.Timeout > 0 {
		dialCtx, cancelDial = context.WithTimeout(ctx, time.Duration(rule.Timeout)*time.Millisecond)
	}
	defer cancelDial()

	var target net.Conn
	var targetAttempt routeAttempt
	for _, candidate := range rule.Targets {
		candidateConn, attempt, err := outboundDialRoute(dialCtx, rule, candidate.Address)
		if err != nil {
			utils.Logger.Error("无法建立连接，尝试下一个目标",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", connAddr(conn)),
				zap.String("targetAddr", candidate.Address),
				zap.Error(err))
			continue
		}
		configureTCP(candidateConn)
		target = candidateConn
		targetAttempt = attempt
		break
	}
	if target == nil {
		utils.Logger.Error("所有目标均连接失败，无法处理连接",
			zap.String("ruleName", rule.Name),
			zap.String("remoteAddr", connAddr(conn)))
		return
	}
	defer target.Close()

	utils.Logger.Debug("建立连接",
		zap.String("ruleName", rule.Name),
		zap.String("remoteAddr", connAddr(conn)),
		zap.String("targetAddr", connAddr(target)))

	result := relayBidirectional(ctx, conn, target)
	logRelayResult(rule, conn, target, result)
	reportRouteRelay(targetAttempt, result)
}
