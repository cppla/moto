package controller

import (
	"bytes"
	"context"
	"io"
	"moto/config"
	"moto/utils"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

const tlsClientHelloProbeLimit = 64 << 10

// HandleTLS selects targets from SNI and ALPN without terminating TLS. Every
// consumed ClientHello byte is replayed to the chosen target unchanged.
func HandleTLS(ctx context.Context, conn net.Conn, rule *config.Rule) {
	defaultRoutingRuntime.handleTLS(ctx, conn, rule)
}

func (runtime *routingRuntime) handleTLS(ctx context.Context, conn net.Conn, rule *config.Rule) {
	if conn == nil || rule == nil || len(rule.Targets) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer conn.Close()

	probeTimeout := boostDecisionTimeout(rule)
	deadline := time.Now().Add(probeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		utils.Logger.Error("无法设置 TLS ClientHello 检测超时",
			zap.String("ruleName", rule.Name), zap.Error(err))
		return
	}
	probe, probeErr := readTLSClientHello(conn, tlsClientHelloProbeLimit)
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		utils.Logger.Warn("清除 TLS ClientHello 检测超时失败",
			zap.String("ruleName", rule.Name), zap.Error(err))
	}
	matched := matchingTLSTargets(rule, probe)
	if len(matched) == 0 {
		utils.Logger.Error("TLS ClientHello 未匹配到目标",
			zap.String("ruleName", rule.Name),
			zap.String("serverName", probe.ServerName),
			zap.Strings("alpn", probe.ALPNProtocols),
			zap.Int("probeBytes", len(probe.Raw)),
			zap.Error(probeErr))
		return
	}
	if probeErr != nil {
		// A configured fallback is deliberately allowed to carry malformed or
		// incomplete handshakes transparently; explicit SNI/ALPN matchers never
		// match when parsing failed.
		utils.Logger.Warn("TLS ClientHello 解析失败，使用 fallback 目标",
			zap.String("ruleName", rule.Name),
			zap.Int("probeBytes", len(probe.Raw)),
			zap.Error(probeErr))
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, boostDecisionTimeout(rule))
	defer cancelDial()
	var target net.Conn
	var targetAttempt routeAttempt
	tryCapacityFallback := false
	for _, candidate := range matched {
		candidateConn, attempt, err := runtime.outboundDialRouteWithOptions(
			dialCtx, rule, candidate.Address, tryCapacityFallback, nil,
		)
		if err != nil {
			if isDialBulkheadError(err) {
				if isDialTargetBulkheadSaturation(err) {
					tryCapacityFallback = true
					utils.Logger.Debug("TLS 目标拨号容量已满，尝试其他匹配目标",
						zap.String("ruleName", rule.Name),
						zap.String("targetAddr", candidate.Address))
					continue
				}
				utils.Logger.Debug("前台拨号容量暂时不可用，结束当前 TLS 连接",
					zap.String("ruleName", rule.Name),
					zap.String("targetAddr", candidate.Address),
					zap.Error(err))
				return
			}
			utils.Logger.Error("无法建立连接，尝试下一个 TLS 匹配目标",
				zap.String("ruleName", rule.Name),
				zap.String("targetAddr", candidate.Address),
				zap.Error(err))
			continue
		}
		configureTCP(candidateConn)
		if err := writeOutboundProxyProtocolContext(dialCtx, candidateConn, conn, rule); err != nil {
			routeReportFailure(attempt, err, time.Now())
			_ = candidateConn.Close()
			utils.Logger.Error("写入 PROXY protocol 头失败，尝试下一个 TLS 目标",
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
		utils.Logger.Error("TLS 匹配目标均连接失败",
			zap.String("ruleName", rule.Name),
			zap.String("serverName", probe.ServerName))
		return
	}
	defer target.Close()

	written, err := io.Copy(target, bytes.NewReader(probe.Raw))
	if err != nil || written != int64(len(probe.Raw)) {
		if err == nil {
			err = io.ErrShortWrite
		}
		metricRelay(rule.Name, "client_to_target", written, err)
		routeReportFailure(targetAttempt, err, time.Now())
		utils.Logger.Error("转发 TLS ClientHello 失败",
			zap.String("ruleName", rule.Name),
			zap.String("targetAddr", connAddr(target)),
			zap.Int64("writtenBytes", written),
			zap.Error(err))
		return
	}

	if entry := utils.Logger.Check(zap.DebugLevel, "建立 TLS 透明连接"); entry != nil {
		entry.Write(
			zap.String("ruleName", rule.Name),
			zap.String("serverName", probe.ServerName),
			zap.Strings("alpn", probe.ALPNProtocols),
			zap.String("targetAddr", connAddr(target)))
	}
	result := relayBidirectional(ctx, conn, target)
	result.ClientToTarget.Bytes += written
	logRelayResult(rule, conn, target, result)
	reportRouteRelay(targetAttempt, result)
}

func matchingTLSTargets(rule *config.Rule, probe tlsClientHelloProbe) []*config.Target {
	if rule == nil {
		return nil
	}
	matched := make([]*config.Target, 0, len(rule.Targets))
	fallbacks := make([]*config.Target, 0, 1)
	serverName := strings.ToLower(probe.ServerName)
	offeredALPN := make(map[string]struct{}, len(probe.ALPNProtocols))
	for _, protocol := range probe.ALPNProtocols {
		offeredALPN[protocol] = struct{}{}
	}
	for _, target := range rule.Targets {
		if target == nil {
			continue
		}
		if len(target.ServerNames) == 0 && len(target.ALPN) == 0 {
			fallbacks = append(fallbacks, target)
			continue
		}
		if len(target.ServerNames) > 0 && !matchesTLSServerName(target.ServerNames, serverName) {
			continue
		}
		if len(target.ALPN) > 0 && !matchesTLSALPN(target.ALPN, offeredALPN) {
			continue
		}
		matched = append(matched, target)
	}
	return append(matched, fallbacks...)
}

func matchesTLSServerName(patterns []string, serverName string) bool {
	if serverName == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == serverName {
			return true
		}
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:]
		if !strings.HasSuffix(serverName, suffix) {
			continue
		}
		left := strings.TrimSuffix(serverName, suffix)
		if left != "" && !strings.Contains(left, ".") {
			return true
		}
	}
	return false
}

func matchesTLSALPN(wanted []string, offered map[string]struct{}) bool {
	for _, candidate := range wanted {
		if _, ok := offered[candidate]; ok {
			return true
		}
	}
	return false
}
