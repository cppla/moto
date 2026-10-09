package controller

import (
	"context"
	"math/rand/v2"

	"moto/config"
)

type connectProxyUserAgentContextKey struct{}

const connectProxyChromeUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// An explicit browser profile supplies a matching default header, but never
// silently overwrites a user-configured identity.
func connectProxyProfileUserAgent(ctx context.Context, target *config.Target) (string, bool) {
	if userAgent, ok := connectProxyUserAgentFromContext(ctx); ok {
		return userAgent, true
	}
	if target != nil && target.ConnectProxy != nil && target.ConnectProxy.BrowserProfile == config.BrowserProfileChrome {
		return connectProxyChromeUserAgent, true
	}
	return "", false
}

// selectConnectProxyUserAgent chooses a process-lifetime identity for one
// CONNECT rule. A preferred identity survives a successful reload while it is
// still present in the rule's candidate list.
func selectConnectProxyUserAgent(userAgents []string, preferred string) string {
	if preferred != "" {
		for _, userAgent := range userAgents {
			if userAgent == preferred {
				return preferred
			}
		}
	}
	if len(userAgents) == 0 {
		return ""
	}
	return userAgents[rand.IntN(len(userAgents))]
}

// withConnectProxyUserAgent attaches the rule's process-lifetime identity to
// one inbound CONNECT. Context descendants used by target hedging and
// H3-to-H2 fallback inherit the same value.
func withConnectProxyUserAgent(ctx context.Context, userAgent string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if userAgent == "" {
		return ctx
	}
	return context.WithValue(ctx, connectProxyUserAgentContextKey{}, userAgent)
}

func connectProxyUserAgentFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	userAgent, ok := ctx.Value(connectProxyUserAgentContextKey{}).(string)
	return userAgent, ok && userAgent != ""
}

// preserveConnectProxyUserAgentSelections keeps each named CONNECT rule's
// selected identity across a successful reload whenever the new candidate list
// still contains it. The next generation is private until commit, so preparing
// or rejecting a reload cannot mutate the active generation's selection.
func preserveConnectProxyUserAgentSelections(previous, next *routingGeneration) {
	if previous == nil || next == nil {
		return
	}
	previousByName := make(map[string]string, len(previous.bindings))
	for _, binding := range previous.bindings {
		if binding == nil || binding.rule == nil || !config.IsConnectProtocol(binding.rule.Protocol) {
			continue
		}
		previousByName[binding.rule.Name] = binding.connectProxyUserAgent
	}
	for _, binding := range next.bindings {
		if binding == nil || binding.rule == nil || !config.IsConnectProtocol(binding.rule.Protocol) {
			continue
		}
		preferred := previousByName[binding.rule.Name]
		binding.connectProxyUserAgent = selectConnectProxyUserAgent(binding.rule.UserAgent, preferred)
	}
}
