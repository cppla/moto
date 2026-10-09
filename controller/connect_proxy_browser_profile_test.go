package controller

import (
	"context"
	"moto/config"
	"testing"
)

func TestBrowserProfileUserAgentDefaultsAndExplicitIdentity(t *testing.T) {
	native := &config.Target{ConnectProxy: &config.ConnectProxyConfig{}}
	chrome := &config.Target{ConnectProxy: &config.ConnectProxyConfig{BrowserProfile: config.BrowserProfileChrome}}
	for _, target := range []*config.Target{nil, native} {
		if _, ok := connectProxyProfileUserAgent(context.Background(), target); ok {
			t.Fatal("legacy or nil target gained an unsolicited User-Agent")
		}
	}
	if ua, ok := connectProxyProfileUserAgent(context.Background(), chrome); !ok || ua != connectProxyChromeUserAgent {
		t.Fatal("explicit profile lost its default identity")
	}
	const custom = "test-configured-identity"
	ctx := withConnectProxyUserAgent(context.Background(), custom)
	if ua, ok := connectProxyProfileUserAgent(ctx, chrome); !ok || ua != custom {
		t.Fatal("profile overwrote explicit User-Agent")
	}
}
