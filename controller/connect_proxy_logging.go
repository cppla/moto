package controller

import (
	"moto/config"
	"moto/utils"

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
		protocol = "mixed"
	}
	if class == "" {
		class = connectProxyAttemptTransportError
	}
	allowed, suppressed := connectProxyFailureLogLimiter.allow(rule.Name, target, protocol, class)
	if !allowed {
		return
	}
	fields := []zap.Field{
		zap.String("ruleName", rule.Name),
		zap.String("targetAddr", target),
		zap.String("protocol", protocol),
		zap.String("class", class),
		zap.Uint64("suppressed", suppressed),
	}
	if statusErr := connectProxyFinalStatusError(err); statusErr != nil {
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
