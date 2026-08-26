package controller

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestConnectProxyStatusErrorClassification(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		statusCode     int
		retryAfter     string
		wantClass      connectProxyFailureClass
		wantRetryAfter time.Duration
		wantHasRetry   bool
	}{
		{
			name:       "policy denied",
			statusCode: http.StatusForbidden,
			wantClass:  connectProxyFailurePolicyDenied,
		},
		{
			name:       "proxy authentication required",
			statusCode: http.StatusProxyAuthRequired,
			wantClass:  connectProxyFailureProxyAuth,
		},
		{
			name:       "unauthorized proxy front end",
			statusCode: http.StatusUnauthorized,
			wantClass:  connectProxyFailureProxyAuth,
		},
		{
			name:           "rate limited with bounded delay",
			statusCode:     http.StatusTooManyRequests,
			retryAfter:     "3600",
			wantClass:      connectProxyFailureRateLimited,
			wantRetryAfter: connectProxyRetryAfterMax,
			wantHasRetry:   true,
		},
		{
			name:       "bad gateway is destination connect",
			statusCode: http.StatusBadGateway,
			wantClass:  connectProxyFailureDestinationConnect,
		},
		{
			name:       "gateway timeout is destination connect",
			statusCode: http.StatusGatewayTimeout,
			wantClass:  connectProxyFailureDestinationConnect,
		},
		{
			name:       "service unavailable",
			statusCode: http.StatusServiceUnavailable,
			wantClass:  connectProxyFailureServiceUnavailable,
		},
		{
			name:       "method not allowed",
			statusCode: http.StatusMethodNotAllowed,
			wantClass:  connectProxyFailureProtocolUnsupported,
		},
		{
			name:       "not implemented",
			statusCode: http.StatusNotImplemented,
			wantClass:  connectProxyFailureProtocolUnsupported,
		},
		{
			name:       "http version unsupported",
			statusCode: http.StatusHTTPVersionNotSupported,
			wantClass:  connectProxyFailureProtocolUnsupported,
		},
		{
			name:       "unknown status",
			statusCode: http.StatusTeapot,
			wantClass:  connectProxyFailureStatusUnknown,
		},
		{
			name:           "http date retry after",
			statusCode:     http.StatusServiceUnavailable,
			retryAfter:     now.Add(30 * time.Second).Format(http.TimeFormat),
			wantClass:      connectProxyFailureServiceUnavailable,
			wantRetryAfter: 30 * time.Second,
			wantHasRetry:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{StatusCode: test.statusCode, Header: make(http.Header)}
			if test.retryAfter != "" {
				response.Header.Set("Retry-After", test.retryAfter)
			}
			err := newConnectProxyStatusErrorAt("h3", "proxy.example:443", response, now)
			if err.protocol != "h3" || err.statusCode != test.statusCode {
				t.Fatalf("protocol/status = %q/%d, want h3/%d", err.protocol, err.statusCode, test.statusCode)
			}
			if err.target != "proxy.example:443" {
				t.Fatalf("target = %q, want proxy.example:443", err.target)
			}
			if err.class != test.wantClass {
				t.Fatalf("class = %q, want %q", err.class, test.wantClass)
			}
			if err.retryAfter != test.wantRetryAfter || err.hasRetryAfter != test.wantHasRetry {
				t.Fatalf("Retry-After = %s/%t, want %s/%t", err.retryAfter, err.hasRetryAfter, test.wantRetryAfter, test.wantHasRetry)
			}
		})
	}
}

func TestConnectProxyStatusErrorIgnoresVendorHeaders(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header)}
	response.Header.Set("X-Vendor-Error", "destination-specific")
	err := newConnectProxyStatusErrorAt("h2", "proxy.example:443", response, time.Now())
	if err.class != connectProxyFailureServiceUnavailable {
		t.Fatalf("vendor header changed class to %q", err.class)
	}
}

func TestConnectProxyStatusErrorRejectsUnboundedRetryAfter(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	response := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header)}
	response.Header.Set("Retry-After", strings.Repeat("9", connectProxyRetryAfterMaxBytes+1))

	err := newConnectProxyStatusErrorAt("h2", "proxy.example:443", response, now)
	if err.hasRetryAfter || err.retryAfter != 0 {
		t.Fatalf("oversized Retry-After retained as %s/%t", err.retryAfter, err.hasRetryAfter)
	}
	if err.class != connectProxyFailureServiceUnavailable {
		t.Fatalf("class = %q, want %q", err.class, connectProxyFailureServiceUnavailable)
	}
}

func TestConnectProxyRetryAfterPastAndInvalidValues(t *testing.T) {
	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	if delay, ok := parseConnectProxyRetryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now); !ok || delay != 0 {
		t.Fatalf("past HTTP date = %s/%t, want 0/true", delay, ok)
	}
	for _, value := range []string{"-1", "+1", "1.5", "tomorrow"} {
		if delay, ok := parseConnectProxyRetryAfter(value, now); ok || delay != 0 {
			t.Fatalf("invalid Retry-After %q = %s/%t", value, delay, ok)
		}
	}
}

func TestConnectProxyStatusErrorCompatibility(t *testing.T) {
	err := newConnectProxyStatusErrorAt("h2", "proxy.example:443", nil, time.Time{})
	if err.statusCode != http.StatusInternalServerError || err.class != connectProxyFailureStatusUnknown {
		t.Fatalf("nil response error = %+v", err)
	}
	if got, want := err.Error(), "h2 CONNECT proxy returned HTTP status 500"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
