package controller

import (
	"context"
	"math/rand/v2"

	"moto/config"
)

type connectProxyUserAgentContextKey struct{}

// selectConnectProxyUserAgent chooses a process-lifetime identity for one
// SOCKS5 rule. A preferred identity survives a successful reload while it is
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
// one inbound SOCKS CONNECT. Context descendants used by target hedging and
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

// preserveConnectProxyUserAgentSelections keeps each named SOCKS5 rule's
// selected identity across a successful reload whenever the new candidate list
// still contains it. The next generation is private until commit, so preparing
// or rejecting a reload cannot mutate the active generation's selection.
func preserveConnectProxyUserAgentSelections(previous, next *routingGeneration) {
	if previous == nil || next == nil {
		return
	}
	previousByName := make(map[string]string, len(previous.bindings))
	for _, binding := range previous.bindings {
		if binding == nil || binding.rule == nil || binding.rule.Protocol != config.ProtocolSOCKS5 {
			continue
		}
		previousByName[binding.rule.Name] = binding.connectProxyUserAgent
	}
	for _, binding := range next.bindings {
		if binding == nil || binding.rule == nil || binding.rule.Protocol != config.ProtocolSOCKS5 {
			continue
		}
		preferred := previousByName[binding.rule.Name]
		binding.connectProxyUserAgent = selectConnectProxyUserAgent(binding.rule.UserAgent, preferred)
	}
}
