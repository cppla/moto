package controller

import (
	"context"
	"errors"
	"moto/config"
)

const connectProxyMaxTargetAttempts = 2

// connectProxyTargetAttemptLimit bounds one inbound SOCKS CONNECT. H3 and H2
// attempts inside one target count as one target attempt; a Boost hedge counts
// as the second target. Raw TCP rules retain their existing all-target policy.
func connectProxyTargetAttemptLimit(rule *config.Rule) int {
	if rule == nil || len(rule.Targets) == 0 {
		return 0
	}
	if rule.Protocol != config.ProtocolSOCKS5 || len(rule.Targets) < connectProxyMaxTargetAttempts {
		return len(rule.Targets)
	}
	return connectProxyMaxTargetAttempts
}

// connectProxyFinalStatusError selects one deterministic concrete HTTP status
// from a possibly concurrent multi-target error. The precedence keeps client
// policy/authentication decisions ahead of transient service failures, and
// keeps a destination/service response ahead of an earlier protocol-capability
// response. Stable tie-breaking prevents Boost completion order from changing
// the SOCKS reply, log key, or severity.
func connectProxyFinalStatusError(err error) *connectProxyStatusError {
	if err == nil {
		return nil
	}
	var best *connectProxyStatusError
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if statusErr := connectProxyFinalStatusError(child); connectProxyStatusDecisionBetter(statusErr, best) {
				best = statusErr
			}
		}
		return best
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		return connectProxyFinalStatusError(unwrapped)
	}
	var statusErr *connectProxyStatusError
	if errors.As(err, &statusErr) {
		return statusErr
	}
	return nil
}

func connectProxyStatusDecisionBetter(candidate, current *connectProxyStatusError) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	candidatePriority := connectProxyStatusDecisionPriority(connectProxyStatusFailureClass(candidate))
	currentPriority := connectProxyStatusDecisionPriority(connectProxyStatusFailureClass(current))
	if candidatePriority != currentPriority {
		return candidatePriority > currentPriority
	}
	if candidate.statusCode != current.statusCode {
		return candidate.statusCode < current.statusCode
	}
	if candidate.target != current.target {
		return candidate.target < current.target
	}
	return candidate.protocol < current.protocol
}

func connectProxyStatusDecisionPriority(class connectProxyFailureClass) int {
	switch class {
	case connectProxyFailureProxyAuth:
		return 7
	case connectProxyFailurePolicyDenied:
		return 6
	case connectProxyFailureRateLimited:
		return 5
	case connectProxyFailureDestinationConnect:
		return 4
	case connectProxyFailureServiceUnavailable:
		return 3
	case connectProxyFailureProtocolUnsupported:
		return 2
	default:
		return 1
	}
}

func connectProxyStatusFailureClass(statusErr *connectProxyStatusError) connectProxyFailureClass {
	if statusErr == nil {
		return connectProxyFailureStatusUnknown
	}
	if statusErr.class != "" {
		return statusErr.class
	}
	return classifyConnectProxyStatus(statusErr.statusCode)
}

func connectProxyErrorIdentity(err error, fallbackTarget string) (target, protocol, class string) {
	if statusErr := connectProxyFinalStatusError(err); statusErr != nil {
		target = statusErr.target
		if target == "" {
			target = fallbackTarget
		}
		protocol = statusErr.protocol
		class = string(connectProxyStatusFailureClass(statusErr))
		return
	}
	target = fallbackTarget
	switch {
	case errors.Is(err, errConnectProxyProtocolCapacity):
		class = connectProxyAttemptCapacity
	case errors.Is(err, context.DeadlineExceeded):
		class = connectProxyAttemptTimeout
	case errors.Is(err, context.Canceled):
		class = connectProxyAttemptCanceled
	default:
		class = connectProxyAttemptTransportError
	}
	return
}
