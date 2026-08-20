package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTLSRuleValidationNormalizesMatchers(t *testing.T) {
	rule := &Rule{
		Name:   "tls-routing",
		Listen: "127.0.0.1:8443",
		Mode:   ModeTLS,
		Targets: []*Target{
			{Address: "127.0.0.1:9443", ServerNames: []string{"API.Example.COM", "*.edge.example.com"}, ALPN: []string{"h2", "http/1.1"}},
			{Address: "127.0.0.1:9444"},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := strings.Join(rule.Targets[0].ServerNames, ","); got != "api.example.com,*.edge.example.com" {
		t.Fatalf("normalized serverNames = %q", got)
	}
}

func TestTLSRuleValidationRejectsAmbiguousOrUnsafeMatchers(t *testing.T) {
	base := func() *Rule {
		return &Rule{
			Name:    "tls-invalid",
			Listen:  "127.0.0.1:8443",
			Mode:    ModeTLS,
			Targets: []*Target{{Address: "127.0.0.1:9443", ServerNames: []string{"example.com"}}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{name: "embedded wildcard", mutate: func(rule *Rule) { rule.Targets[0].ServerNames = []string{"api.*.example.com"} }},
		{name: "unicode hostname", mutate: func(rule *Rule) { rule.Targets[0].ServerNames = []string{"例子.example"} }},
		{name: "invalid alpn", mutate: func(rule *Rule) { rule.Targets[0].ALPN = []string{"bad protocol"} }},
		{name: "multiple fallbacks", mutate: func(rule *Rule) {
			rule.Targets = []*Target{{Address: "127.0.0.1:9443"}, {Address: "127.0.0.1:9444"}}
		}},
		{name: "regexp in tls", mutate: func(rule *Rule) { rule.Targets[0].Regexp = "^TLS" }},
		{name: "tls fields in normal", mutate: func(rule *Rule) { rule.Mode = ModeNormal }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := base()
			test.mutate(rule)
			if err := rule.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}

func TestProxyProtocolValidationAndTrustBoundary(t *testing.T) {
	configuration := &ProxyProtocolConfig{
		Accept:       true,
		TrustedCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"},
		Send:         "V2",
	}
	if err := configuration.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if configuration.Send != ProxyProtocolV2 {
		t.Fatalf("normalized send = %q", configuration.Send)
	}
	for _, address := range []string{"192.0.2.5", "2001:db8::5"} {
		if !configuration.Trusts(netip.MustParseAddr(address)) {
			t.Fatalf("trusted address %s was rejected", address)
		}
	}
	if configuration.Trusts(netip.MustParseAddr("198.51.100.5")) {
		t.Fatal("untrusted address was accepted")
	}
}

func TestProxyProtocolNormalizesIPv4MappedTrustedCIDR(t *testing.T) {
	configuration := &ProxyProtocolConfig{
		Accept:       true,
		TrustedCIDRs: []string{"::ffff:192.0.2.0/120"},
	}
	if err := configuration.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !configuration.Trusts(netip.MustParseAddr("192.0.2.9")) ||
		!configuration.Trusts(netip.MustParseAddr("::ffff:192.0.2.9")) {
		t.Fatal("normalized mapped IPv4 CIDR did not trust equivalent addresses")
	}
	if configuration.Trusts(netip.MustParseAddr("192.0.3.9")) {
		t.Fatal("normalized mapped IPv4 CIDR trusted an address outside the prefix")
	}
}

func TestProxyProtocolValidationRejectsUnsafeConfiguration(t *testing.T) {
	tests := []ProxyProtocolConfig{
		{Accept: true},
		{TrustedCIDRs: []string{"127.0.0.0/8"}},
		{Accept: true, TrustedCIDRs: []string{"not-a-cidr"}},
		{Send: "v3"},
	}
	for _, configuration := range tests {
		configuration := configuration
		if err := configuration.Validate(); err == nil {
			t.Fatalf("Validate(%+v) succeeded", configuration)
		}
	}
}

func TestRuleValidationRejectsPrewarmWithOutboundProxyProtocol(t *testing.T) {
	for _, version := range []string{ProxyProtocolV1, ProxyProtocolV2} {
		t.Run(version, func(t *testing.T) {
			rule := &Rule{
				Name:           "proxy-prewarm",
				Listen:         "127.0.0.1:8443",
				Mode:           ModeNormal,
				Prewarm:        true,
				ProxyProtocol:  &ProxyProtocolConfig{Send: version},
				Targets:        []*Target{{Address: "127.0.0.1:9443"}},
				MaxConnections: 8,
				Blacklist:      map[string]bool{},
			}
			if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "prewarm cannot be combined") {
				t.Fatalf("Validate error = %v, want prewarm/outbound PROXY rejection", err)
			}
		})
	}
}
