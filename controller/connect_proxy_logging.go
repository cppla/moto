package controller

import (
	"moto/config"
	"moto/utils"
	"net/http"

	"go.uber.org/zap"
)

var connectProxyFailureLogLimiter = newConnectProxyErrorLogLimiter()

// logConnectProxyFailure emits one bounded, sampled final decision log. Lower
// protocol attempts remain visible through metrics, avoiding one Error line per
// target plus another aggregate line for the same inbound SOCKS request.
func logConnectProxyFailure(rule *config.Rule, fallbackTarget string, err error, message string) {
	if rule == nil || err == nil {
		return
	}
	target, protocol, class := connectProxyErrorIdentity(err, fallbackTarget)
	if target == "" {
		target = "multiple"
	}
	if protocol == "" {
		protocol = configuredConnectProxyProtocol(rule)
	}
	if protocol == "" {
		protocol = "mixed"
	}
	if class == "" {
		class = connectProxyAttemptTransportError
	}
	allowed, suppressed := connectProxyFailureLogLimiter.allow(rule.Name, target, protocol, class)
	if !allowed {
		return
	}
	statusErr := connectProxyFinalStatusError(err)
	message = connectProxyStatusLogMessage(message, statusErr)
	fields := []zap.Field{
		zap.String("ruleName", rule.Name),
		zap.String("targetAddr", target),
		zap.String("protocol", protocol),
		zap.String("class", class),
		zap.Uint64("suppressed", suppressed),
	}
	if statusErr != nil {
		fields = append(fields, zap.Int("statusCode", statusErr.statusCode))
		if statusErr.hasRetryAfter {
			fields = append(fields, zap.Int64("retryAfterMs", statusErr.retryAfter.Milliseconds()))
		}
	} else {
		fields = append(fields, zap.Error(err))
	}

	switch class {
	case string(connectProxyFailureProxyAuth):
		utils.Logger.Error(message, fields...)
	case string(connectProxyFailureRateLimited), string(connectProxyFailureServiceUnavailable),
		connectProxyAttemptTransportError, connectProxyAttemptTimeout, string(connectProxyFailureStatusUnknown):
		utils.Logger.Warn(message, fields...)
	default:
		utils.Logger.Info(message, fields...)
	}
}

// connectProxyStatusLogMessage replaces route-selection summaries only when
// the final result is an explicit upstream CONNECT response. The bounded class
// and status fields retain machine-readable details; the message describes the
// actual proxy response instead of incorrectly claiming that every route was
// unavailable.
func connectProxyStatusLogMessage(fallback string, statusErr *connectProxyStatusError) string {
	if statusErr == nil {
		return fallback
	}
	switch statusErr.statusCode {
	case http.StatusForbidden:
		return "目标连接被上游策略拒绝"
	case http.StatusServiceUnavailable:
		return "上游暂时无法处理目标连接"
	default:
		return fallback
	}
}

// configuredConnectProxyProtocol provides a bounded protocol identity when a
// final generic transport error has no concrete HTTP response to identify the
// attempt. All targets must be protocol-homogeneous before the summary may be
// labeled h2 or h3; any ambiguity remains mixed.
func configuredConnectProxyProtocol(rule *config.Rule) string {
	if rule == nil || len(rule.Targets) == 0 {
		return ""
	}
	configured := ""
	for _, target := range rule.Targets {
		if target == nil || target.ConnectProxy == nil || len(target.ConnectProxy.Protocols) == 0 {
			return ""
		}
		for _, protocol := range target.ConnectProxy.Protocols {
			if protocol != config.ConnectProxyH2 && protocol != config.ConnectProxyH3 {
				return ""
			}
			if configured == "" {
				configured = protocol
				continue
			}
			if configured != protocol {
				return "mixed"
			}
		}
	}
	return configured
}
