package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	connectProxyRetryAfterMaxBytes = 128
	connectProxyRetryAfterMax      = time.Minute
)

// connectProxyFailureClass is deliberately bounded. Values may be used by
// routing, metrics, and log sampling without allowing an upstream response to
// create unbounded label or key cardinality.
type connectProxyFailureClass string

const (
	connectProxyFailurePolicyDenied        connectProxyFailureClass = "policy_denied"
	connectProxyFailureProxyAuth           connectProxyFailureClass = "proxy_auth"
	connectProxyFailureRateLimited         connectProxyFailureClass = "rate_limited"
	connectProxyFailureDestinationConnect  connectProxyFailureClass = "destination_connect"
	connectProxyFailureServiceUnavailable  connectProxyFailureClass = "service_unavailable"
	connectProxyFailureProtocolUnsupported connectProxyFailureClass = "protocol_unsupported"
	connectProxyFailureStatusUnknown       connectProxyFailureClass = "status_unknown"
)

// connectProxyStatusError retains only bounded, classified response metadata.
// It intentionally does not keep the response, arbitrary headers, or error
// body. protocol and statusCode remain unchanged for existing callers/tests.
type connectProxyStatusError struct {
	protocol      string
	target        string
	statusCode    int
	class         connectProxyFailureClass
	retryAfter    time.Duration
	hasRetryAfter bool
}

func (err *connectProxyStatusError) Error() string {
	return fmt.Sprintf("%s CONNECT proxy returned HTTP status %d", err.protocol, err.statusCode)
}

func newConnectProxyStatusError(protocol, target string, response *http.Response) *connectProxyStatusError {
	return newConnectProxyStatusErrorAt(protocol, target, response, time.Now())
}

func newConnectProxyStatusErrorAt(protocol, target string, response *http.Response, now time.Time) *connectProxyStatusError {
	err := &connectProxyStatusError{
		protocol:   protocol,
		target:     target,
		statusCode: http.StatusInternalServerError,
		class:      connectProxyFailureStatusUnknown,
	}
	if response == nil {
		return err
	}

	err.statusCode = response.StatusCode
	err.class = classifyConnectProxyStatus(response.StatusCode)
	err.retryAfter, err.hasRetryAfter = parseConnectProxyRetryAfter(response.Header.Get("Retry-After"), now)
	return err
}

func classifyConnectProxyStatus(statusCode int) connectProxyFailureClass {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusProxyAuthRequired:
		return connectProxyFailureProxyAuth
	case http.StatusTooManyRequests:
		return connectProxyFailureRateLimited
	case http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported:
		return connectProxyFailureProtocolUnsupported
	case http.StatusForbidden:
		return connectProxyFailurePolicyDenied
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return connectProxyFailureDestinationConnect
	case http.StatusServiceUnavailable:
		return connectProxyFailureServiceUnavailable
	default:
		return connectProxyFailureStatusUnknown
	}
}

func parseConnectProxyRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > connectProxyRetryAfterMaxBytes {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		maximumSeconds := uint64(connectProxyRetryAfterMax / time.Second)
		if seconds > maximumSeconds {
			seconds = maximumSeconds
		}
		return time.Duration(seconds) * time.Second, true
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := retryAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	if delay > connectProxyRetryAfterMax {
		delay = connectProxyRetryAfterMax
	}
	return delay, true
}
