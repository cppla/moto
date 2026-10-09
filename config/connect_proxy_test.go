package config

import (
	"strings"
	"testing"
)

func TestLoadSOCKS5ConnectProxyConfiguration(t *testing.T) {
	path := writeConfig(t, `{
		"log":{"level":"info","path":""},
		"rules":[{
			"name":"huojian",
			"listen":"127.0.0.1:83",
			"mode":"boost",
			"protocol":"socks5",
			"healthCheck":{"type":"tcp"},
			"targets":[{
				"address":"proxy.example.com:443",
				"connectProxy":{
					"protocols":["h3","h2"],
					"serverName":"proxy.example.com",
					"basicAuth":{"username":"moto","password":"secret"}
				}
			},{
				"address":"backup.example.com:443",
				"connectProxy":{"protocols":["h2"]}
			}]
		}]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	rule := cfg.Rules[0]
	if rule.Protocol != ProtocolSOCKS5 || rule.HealthCheck.Type != HealthCheckTCP {
		t.Fatalf("protocol/health = %q/%q, want socks5/tcp", rule.Protocol, rule.HealthCheck.Type)
	}
	proxy := rule.Targets[0].ConnectProxy
	if proxy == nil || strings.Join(proxy.Protocols, ",") != "h3,h2" {
		t.Fatalf("connect proxy protocols = %+v, want h3,h2", proxy)
	}
	if proxy.BasicAuth == nil || proxy.BasicAuth.Username != "moto" || proxy.BasicAuth.Password != "secret" {
		t.Fatalf("basic auth was not decoded: %+v", proxy.BasicAuth)
	}
}

func TestStrictJSONRejectsRemovedUserAgentFields(t *testing.T) {
	for _, protocol := range []string{ProtocolSOCKS5, ProtocolHTTP, ProtocolTCP} {
		for _, field := range []string{"userAgent", "UserAgent", "useragent", "USERAGENT"} {
			for name, value := range map[string]string{
				"null": "null", "empty": "[]", "configured": `["Browser/1.0"]`,
			} {
				t.Run(protocol+"/"+field+"/"+name, func(t *testing.T) {
					proxy := `,"connectProxy":{"protocols":["h3","h2"]}`
					if protocol == ProtocolTCP {
						proxy = ""
					}
					body := `{"log":{"level":"info","path":""},"rules":[{"name":"removed-ua","listen":"127.0.0.1:1080","mode":"normal","protocol":"` + protocol + `","targets":[{"address":"proxy.example:443"` + proxy + `}],"` + field + `":` + value + `}]}`
					_, err := Load(writeConfig(t, body))
					if err == nil || !strings.Contains(err.Error(), "unknown or non-canonical field") || !strings.Contains(err.Error(), `"`+field+`"`) {
						t.Fatalf("Load() error = %v, want explicit rejection of removed field %q", err, field)
					}
				})
			}
		}
	}
}

func TestSOCKS5ConnectProxyValidation(t *testing.T) {
	validTarget := func(address string) *Target {
		return &Target{Address: address, ConnectProxy: &ConnectProxyConfig{Protocols: []string{ConnectProxyH2}}}
	}
	tests := map[string]struct {
		mutate func(*Rule)
		want   string
	}{
		"missing connect proxy": {
			mutate: func(rule *Rule) { rule.Targets[0].ConnectProxy = nil },
			want:   "connectProxy is required",
		},
		"connect proxy on TCP listener": {
			mutate: func(rule *Rule) { rule.Protocol = ProtocolTCP },
			want:   "only valid for protocol socks5",
		},
		"regex mode": {
			mutate: func(rule *Rule) { rule.Mode = ModeRegex },
			want:   "not compatible",
		},
		"TLS mode": {
			mutate: func(rule *Rule) { rule.Mode = ModeTLS },
			want:   "not compatible",
		},
		"prewarm": {
			mutate: func(rule *Rule) { rule.Prewarm = true },
			want:   "cannot use prewarm",
		},
		"HTTP health check": {
			mutate: func(rule *Rule) { rule.HealthCheck = &HealthCheckConfig{Type: HealthCheckHTTP} },
			want:   "cannot use HTTP healthCheck",
		},
		"proxy protocol": {
			mutate: func(rule *Rule) {
				rule.ProxyProtocol = &ProxyProtocolConfig{Accept: true, TrustedCIDRs: []string{"127.0.0.0/8"}}
			},
			want: "cannot use proxyProtocol",
		},
		"duplicate endpoint": {
			mutate: func(rule *Rule) { rule.Targets = append(rule.Targets, validTarget(rule.Targets[0].Address)) },
			want:   "requires unique target addresses",
		},
		"unknown CONNECT protocol": {
			mutate: func(rule *Rule) { rule.Targets[0].ConnectProxy.Protocols = []string{"h4"} },
			want:   "invalid protocol",
		},
		"duplicate CONNECT protocol": {
			mutate: func(rule *Rule) { rule.Targets[0].ConnectProxy.Protocols = []string{ConnectProxyH2, ConnectProxyH2} },
			want:   "duplicate protocol",
		},
		"invalid server name": {
			mutate: func(rule *Rule) { rule.Targets[0].ConnectProxy.ServerName = "https://proxy.example" },
			want:   "invalid serverName",
		},
		"wildcard server name": {
			mutate: func(rule *Rule) { rule.Targets[0].ConnectProxy.ServerName = "*.proxy.example" },
			want:   "must not contain a wildcard",
		},
		"Basic username colon": {
			mutate: func(rule *Rule) {
				rule.Targets[0].ConnectProxy.BasicAuth = &BasicAuthConfig{Username: "bad:user", Password: "secret"}
			},
			want: "must not contain ':'",
		},
		"Basic password newline": {
			mutate: func(rule *Rule) {
				rule.Targets[0].ConnectProxy.BasicAuth = &BasicAuthConfig{Username: "user", Password: "bad\nsecret"}
			},
			want: "must not contain NUL",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rule := &Rule{
				Name:      "socks",
				Listen:    "127.0.0.1:1080",
				Mode:      ModeNormal,
				Protocol:  ProtocolSOCKS5,
				Targets:   []*Target{validTarget("proxy.example.com:443")},
				Allowlist: []string{"127.0.0.0/8"},
			}
			test.mutate(rule)
			err := rule.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSOCKS5ConnectProxyDefaultsAndCompatibleModes(t *testing.T) {
	for _, mode := range []string{ModeNormal, ModeBoost, ModeRoundRobin} {
		t.Run(mode, func(t *testing.T) {
			rule := &Rule{
				Name:        "socks",
				Listen:      "127.0.0.1:1080",
				Mode:        mode,
				Protocol:    ProtocolSOCKS5,
				HealthCheck: &HealthCheckConfig{Type: HealthCheckTCP},
				Targets: []*Target{{
					Address:      "127.0.0.1:443",
					ConnectProxy: &ConnectProxyConfig{ServerName: "127.0.0.1"},
				}},
			}
			if err := rule.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if got := strings.Join(rule.Targets[0].ConnectProxy.Protocols, ","); got != ConnectProxyH2 {
				t.Fatalf("default protocols = %q, want h2", got)
			}
		})
	}
}

func TestSOCKS5ExternalListenerRequiresExplicitAllowlist(t *testing.T) {
	newRule := func() *Rule {
		return &Rule{
			Name:     "external-socks",
			Listen:   "0.0.0.0:1080",
			Mode:     ModeNormal,
			Protocol: ProtocolSOCKS5,
			Targets: []*Target{{
				Address:      "proxy.example.com:443",
				ConnectProxy: &ConnectProxyConfig{Protocols: []string{ConnectProxyH2}},
			}},
		}
	}

	rule := newRule()
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "requires an explicit non-empty allowlist") {
		t.Fatalf("Validate() error = %v, want external-listener allowlist rejection", err)
	}

	rule = newRule()
	rule.Allowlist = []string{"192.0.2.0/24"}
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate() rejected explicit external allowlist: %v", err)
	}
}

func TestStrictJSONRejectsUnknownConnectProxyFields(t *testing.T) {
	tests := []string{
		`"connectProxy":{"protocols":["h2"],"unknown":true}`,
		`"connectProxy":{"protocols":["h2"],"basicAuth":{"username":"u","password":"p","unknown":true}}`,
		`"connectProxy":{"protocols":["h3"],"h3Degradation":{"mode":"rotate"}}`,
	}
	for _, connectProxy := range tests {
		body := `{"log":{"level":"info","path":""},"rules":[{"name":"s","listen":"127.0.0.1:1080","mode":"normal","protocol":"socks5","targets":[{"address":"proxy.example:443",` + connectProxy + `}]}]}`
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Fatalf("Load() accepted non-strict connectProxy: %s", connectProxy)
		}
	}
}
