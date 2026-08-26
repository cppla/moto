package controller

import (
	"context"
	"math/rand/v2"
)

type connectProxyUserAgentContextKey struct{}

// withRandomConnectProxyUserAgent selects one identity for the complete
// inbound SOCKS CONNECT. Context descendants used by target hedging and
// H3-to-H2 fallback inherit the same value, while the shared transports remain
// reusable because User-Agent is request metadata rather than a pool key.
func withRandomConnectProxyUserAgent(ctx context.Context, userAgents []string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(userAgents) == 0 {
		return ctx
	}
	return context.WithValue(ctx, connectProxyUserAgentContextKey{}, userAgents[rand.IntN(len(userAgents))])
}

func connectProxyUserAgentFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	userAgent, ok := ctx.Value(connectProxyUserAgentContextKey{}).(string)
	return userAgent, ok && userAgent != ""
}
