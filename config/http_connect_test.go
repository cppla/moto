package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func newConnectProtocolTestRule(protocol string) *Rule {
	return &Rule{
		Name:     "connect",
		Listen:   "127.0.0.1:9007",
		Mode:     ModeNormal,
		Protocol: protocol,
		Targets: []*Target{{
			Address:      "proxy.example.com:443",
			ConnectProxy: &ConnectProxyConfig{Protocols: []string{ConnectProxyH3, ConnectProxyH2}},
		}},
	}
}

func TestIsConnectProtocol(t *testing.T) {
	for _, protocol := range []string{ProtocolSOCKS5, ProtocolHTTP} {
		if !IsConnectProtocol(protocol) {
			t.Errorf("IsConnectProtocol(%q) = false", protocol)
		}
	}
	for _, protocol := range []string{"", ProtocolTCP, "https", "h2", "h3", "HTTP", " http", "socks4"} {
		if IsConnectProtocol(protocol) {
			t.Errorf("IsConnectProtocol(%q) = true", protocol)
		}
	}
}

func TestLoadHTTPConnectConfiguration(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{
		"log":{"level":"info","path":""},
		"rules":[{
			"name":"http-connect",
			"listen":"127.0.0.1:9007",
			"mode":"boost",
			"protocol":"http",
			"allowlist":["127.0.0.0/8","::1/128"],
			"userAgent":["Browser/1.0"],
			"healthCheck":{"type":"tcp"},
			"targets":[{
				"address":"proxy.example.com:443",
				"connectProxy":{
					"protocols":["h3","h2"],
					"serverName":"proxy.example.com",
					"basicAuth":{"username":"proxy-user","password":"test-password"}
				}
			}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	rule := cfg.Rules[0]
	if rule.Protocol != ProtocolHTTP || rule.HealthCheck.Type != HealthCheckTCP {
		t.Fatalf("protocol/health = %q/%q, want http/tcp", rule.Protocol, rule.HealthCheck.Type)
	}
	if !slices.Equal(rule.UserAgent, []string{"Browser/1.0"}) {
		t.Fatalf("userAgent = %q", rule.UserAgent)
	}
	proxy := rule.Targets[0].ConnectProxy
	if !slices.Equal(proxy.Protocols, []string{ConnectProxyH3, ConnectProxyH2}) {
		t.Fatalf("protocols = %q, want h3,h2", proxy.Protocols)
	}
	if proxy.BasicAuth == nil || proxy.BasicAuth.Username != "proxy-user" || proxy.BasicAuth.Password != "test-password" {
		t.Fatal("upstream Basic Auth was not decoded")
	}
	if !rule.Allows(netip.MustParseAddr("127.0.0.2")) || !rule.Allows(netip.MustParseAddr("::1")) || rule.Allows(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("HTTP source allowlist was not applied")
	}
}

func TestConnectProtocolCompatibleModesAndTransports(t *testing.T) {
	for _, protocol := range []string{ProtocolSOCKS5, ProtocolHTTP} {
		for _, mode := range []string{ModeNormal, ModeBoost, ModeRoundRobin} {
			for _, transports := range [][]string{nil, {ConnectProxyH2}, {ConnectProxyH3}, {ConnectProxyH3, ConnectProxyH2}, {ConnectProxyH2, ConnectProxyH3}} {
				t.Run(protocol+"/"+mode+"/"+strings.Join(transports, ","), func(t *testing.T) {
					rule := newConnectProtocolTestRule(protocol)
					rule.Mode = mode
					rule.HealthCheck = &HealthCheckConfig{Type: HealthCheckTCP}
					rule.UserAgent = []string{"Browser/1.0"}
					rule.Targets[0].ConnectProxy.Protocols = slices.Clone(transports)
					if err := rule.Validate(); err != nil {
						t.Fatalf("Validate() error = %v", err)
					}
					want := transports
					if len(want) == 0 {
						want = []string{ConnectProxyH2}
					}
					if got := rule.Targets[0].ConnectProxy.Protocols; !slices.Equal(got, want) {
						t.Fatalf("protocols = %q, want %q", got, want)
					}
				})
			}
		}
	}
}

func TestHTTPConnectValidation(t *testing.T) {
	tests := map[string]struct {
		mutate func(*Rule)
		want   string
	}{
		"missing connect proxy": {func(r *Rule) { r.Targets[0].ConnectProxy = nil }, "connectProxy is required for protocol http"},
		"regex mode":            {func(r *Rule) { r.Mode = ModeRegex }, `protocol "http" is not compatible with mode "regex"`},
		"TLS mode":              {func(r *Rule) { r.Mode = ModeTLS }, `protocol "http" is not compatible with mode "tls"`},
		"prewarm":               {func(r *Rule) { r.Prewarm = true }, "protocol http cannot use prewarm"},
		"HTTP health check":     {func(r *Rule) { r.HealthCheck = &HealthCheckConfig{Type: " HTTP "} }, "protocol http cannot use HTTP healthCheck"},
		"proxy protocol":        {func(r *Rule) { r.ProxyProtocol = &ProxyProtocolConfig{} }, "protocol http cannot use proxyProtocol"},
		"duplicate target":      {func(r *Rule) { r.Targets = append(r.Targets, r.Targets[0]) }, "protocol http requires unique target addresses"},
		"unknown inbound":       {func(r *Rule) { r.Protocol = "https" }, `invalid protocol "https"`},
		"unknown upstream":      {func(r *Rule) { r.Targets[0].ConnectProxy.Protocols = []string{"http"} }, `invalid protocol "http"`},
		"duplicate upstream":    {func(r *Rule) { r.Targets[0].ConnectProxy.Protocols = []string{ConnectProxyH2, ConnectProxyH2} }, "duplicate protocol"},
		"invalid user agent":    {func(r *Rule) { r.UserAgent = []string{"Browser\r\nInjected"} }, "only printable ASCII"},
		"empty user agent":      {func(r *Rule) { r.UserAgent = []string{""} }, "length must be between"},
		"invalid server name":   {func(r *Rule) { r.Targets[0].ConnectProxy.ServerName = "https://proxy.example.com" }, "invalid serverName"},
		"invalid upstream auth": {func(r *Rule) { r.Targets[0].ConnectProxy.BasicAuth = &BasicAuthConfig{Username: "bad:user"} }, "must not contain ':'"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rule := newConnectProtocolTestRule(ProtocolHTTP)
			test.mutate(rule)
			if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestConnectProtocolListenerSafeguards(t *testing.T) {
	for _, protocol := range []string{ProtocolSOCKS5, ProtocolHTTP} {
		for _, listen := range []string{"127.0.0.1:9007", "127.0.0.2:9007", "[::1]:9007", "[::ffff:127.0.0.1]:9007", "0.0.0.0:9007", "[::]:9007", "192.0.2.1:9007", "localhost:9007", ":9007"} {
			for _, allowlist := range [][]string{nil, {"192.0.2.0/24"}, {"invalid-cidr"}} {
				t.Run(protocol+"/"+listen+"/"+strings.Join(allowlist, ","), func(t *testing.T) {
					rule := newConnectProtocolTestRule(protocol)
					rule.Listen = listen
					rule.Allowlist = allowlist
					loopback := strings.HasPrefix(listen, "127.") || listen == "[::1]:9007" || listen == "[::ffff:127.0.0.1]:9007"
					err := rule.Validate()
					switch {
					case len(allowlist) != 0 && allowlist[0] == "invalid-cidr":
						if err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
							t.Fatalf("Validate() error = %v, want invalid allowlist", err)
						}
					case !loopback && len(allowlist) == 0:
						if err == nil || !strings.Contains(err.Error(), "requires an explicit non-empty allowlist") {
							t.Fatalf("Validate() error = %v, want non-loopback guard", err)
						}
					default:
						if err != nil {
							t.Fatalf("Validate() error = %v", err)
						}
					}
				})
			}
		}
	}
}
