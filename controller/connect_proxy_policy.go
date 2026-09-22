package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
)

const connectProxyMaxTargetAttempts = 2

// connectProxyTargetAttemptLimit bounds one inbound CONNECT. H3 and H2
// attempts inside one target count as one target attempt; a Boost hedge counts
// as the second target. Raw TCP rules retain their existing all-target policy.
func connectProxyTargetAttemptLimit(rule *config.Rule) int {
	if rule == nil || len(rule.Targets) == 0 {
		return 0
	}
	if !config.IsConnectProtocol(rule.Protocol) || len(rule.Targets) < connectProxyMaxTargetAttempts {
		return len(rule.Targets)
	}
	return connectProxyMaxTargetAttempts
}

// dialSequentialConnectProxyTargets bounds normal/round-robin CONNECT requests
// by distinct admitted target attempts, not by locally rejected candidates.
// The outbound start callback runs only after health, circuit, and dial-capacity
// admission. Both protocols inside one target still consume a single attempt.
func (runtime *routingRuntime) dialSequentialConnectProxyTargets(
	ctx context.Context,
	rule *config.Rule,
	start int,
) (net.Conn, routeAttempt, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rule == nil || len(rule.Targets) == 0 {
		return nil, routeAttempt{}, "", errors.New("CONNECT proxy has no targets")
	}
	var failures []error
	lastAddress := ""
	started := 0
	limit := connectProxyTargetAttemptLimit(rule)
	visited := make(map[string]struct{}, len(rule.Targets))
	tryOnly := false
	start %= len(rule.Targets)
	if start < 0 {
		start += len(rule.Targets)
	}
	for offset := 0; offset < len(rule.Targets) && started < limit; offset++ {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		candidate := rule.Targets[(start+offset)%len(rule.Targets)]
		if candidate == nil || candidate.Address == "" {
			continue
		}
		if _, seen := visited[candidate.Address]; seen {
			continue
		}
		visited[candidate.Address] = struct{}{}
		lastAddress = candidate.Address
		connection, attempt, err := runtime.outboundDialRouteWithOptions(
			ctx, rule, candidate.Address, tryOnly, func() { started++ },
		)
		if err == nil {
			return connection, attempt, candidate.Address, nil
		}
		failures = append(failures, err)
		if isDialBulkheadError(err) {
			if !isDialTargetBulkheadSaturation(err) {
				break
			}
			// After one target exhausts the foreground wait budget, remaining
			// candidates are opportunistic rather than starting another queue.
			tryOnly = true
		}
	}
	if len(failures) == 0 {
		failures = append(failures, errors.New("CONNECT proxy has no usable targets"))
	}
	return nil, routeAttempt{}, lastAddress, errors.Join(failures...)
}

// Local admission/cancellation is not an upstream outage. Every component
// must be local before lowering the final log level, so a later CONNECT HTTP
// response retains its normal status-specific message and severity.
func connectProxySequentialFailureIsLocal(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !connectProxySequentialFailureIsLocal(child) {
				return false
			}
		}
		return true
	}
	if _, local := err.(*dialBulkheadError); local {
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return connectProxySequentialFailureIsLocal(wrapped)
	}
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrCircuitOpen) || errors.Is(err, ErrActiveHealthUnhealthy)
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
