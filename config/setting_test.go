package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadStrictJSONAndApplyDefaults(t *testing.T) {
	path := writeConfig(t, `{
		"log": {"level": "INFO", "path": ""},
		"rules": [{
			"name": "http",
			"listen": "127.0.0.1:8080",
			"mode": "regex",
			"allowlist": ["10.0.0.0/8"],
			"targets": [{"regexp": "^GET", "address": "example.com:80"}]
		}]
	}
	`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("normalized log level = %q, want info", cfg.Log.Level)
	}
	rule := cfg.Rules[0]
	if rule.MaxConnections != DefaultMaxConnections {
		t.Fatalf("MaxConnections = %d, want %d", rule.MaxConnections, DefaultMaxConnections)
	}
	if rule.MaxConnectionsPerIP != DefaultMaxConnectionsPerIP {
		t.Fatalf("MaxConnectionsPerIP = %d, want %d", rule.MaxConnectionsPerIP, DefaultMaxConnectionsPerIP)
	}
	if rule.Timeout != 500 {
		t.Fatalf("regex Timeout = %d, want 500", rule.Timeout)
	}
	if rule.Targets[0].Re == nil || !rule.Targets[0].Re.MatchString("GET / HTTP/1.1") {
		t.Fatal("regex target was not compiled")
	}
	if !rule.Allows(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("address inside allowlist was rejected")
	}
	if rule.Allows(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("address outside allowlist was accepted")
	}
}

func TestMetricsConfigDefaultsToLoopback(t *testing.T) {
	path := writeConfig(t, `{
		"log": {"level": "info", "path": ""},
		"metrics": {"enabled": true},
		"rules": [{
			"name": "http",
			"listen": "127.0.0.1:8080",
			"mode": "normal",
			"targets": [{"address": "example.com:80"}]
		}]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Metrics.Enabled {
		t.Fatal("Metrics.Enabled = false, want true")
	}
	if got := cfg.Metrics.Listen; got != DefaultMetricsListen {
		t.Fatalf("Metrics.Listen = %q, want %q", got, DefaultMetricsListen)
	}
}

func TestMetricsConfigRejectsPublicAndConflictingListeners(t *testing.T) {
	tests := map[string]struct {
		metrics MetricsConfig
		listen  string
		want    string
	}{
		"public IPv4": {
			metrics: MetricsConfig{Enabled: true, Listen: "0.0.0.0:9090"},
			listen:  "127.0.0.1:8080",
			want:    "numeric loopback address",
		},
		"public IPv6": {
			metrics: MetricsConfig{Enabled: false, Listen: "[::]:9090"},
			listen:  "127.0.0.1:8080",
			want:    "numeric loopback address",
		},
		"hostname": {
			metrics: MetricsConfig{Enabled: true, Listen: "localhost:9090"},
			listen:  "127.0.0.1:8080",
			want:    "numeric loopback address",
		},
		"same address": {
			metrics: MetricsConfig{Enabled: true, Listen: "127.0.0.1:9090"},
			listen:  "127.0.0.1:9090",
			want:    "conflicts with",
		},
		"wildcard rule": {
			metrics: MetricsConfig{Enabled: true, Listen: "127.0.0.1:9090"},
			listen:  ":9090",
			want:    "conflicts with",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Metrics = tc.metrics
			cfg.Rules[0].Listen = tc.listen
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoadCamelCaseConnectionLimits(t *testing.T) {
	path := writeConfig(t, `{
		"log": {"level": "info", "path": ""},
		"rules": [{
			"name": "limited",
			"listen": ":8080",
			"mode": "normal",
			"maxConnections": 100,
			"maxConnectionsPerIP": 10,
			"targets": [{"address": "example.com:80"}]
		}]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Rules[0].MaxConnections; got != 100 {
		t.Fatalf("MaxConnections = %d, want 100", got)
	}
	if got := cfg.Rules[0].MaxConnectionsPerIP; got != 10 {
		t.Fatalf("MaxConnectionsPerIP = %d, want 10", got)
	}
	if got := cfg.Rules[0].Timeout; got != 3000 {
		t.Fatalf("normal Timeout = %d, want 3000", got)
	}
}

func TestLoadRejectsNonStrictJSON(t *testing.T) {
	validRule := `"log":{"level":"info","path":""},"rules":[{"name":"one","listen":":8000","mode":"normal","targets":[{"address":"example.com:80"}]}]`
	tests := map[string]string{
		"unknown top-level field": `{` + validRule + `,"unknown":true}`,
		"unknown nested field":    `{"log":{"level":"info","path":"","unknown":true},"rules":[{"name":"one","listen":":8000","mode":"normal","targets":[{"address":"example.com:80"}]}]}`,
		"unknown metrics field":   `{"log":{"level":"info","path":""},"metrics":{"enabled":true,"unknown":true},"rules":[{"name":"one","listen":":8000","mode":"normal","targets":[{"address":"example.com:80"}]}]}`,
		"legacy snake-case limit": `{"log":{"level":"info","path":""},"rules":[{"name":"one","listen":":8000","mode":"normal","max_connections":100,"targets":[{"address":"example.com:80"}]}]}`,
		"second JSON value":       `{` + validRule + `} {}`,
		"trailing junk":           `{` + validRule + `} nope`,
		"null config":             `null`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load() succeeded, want error")
			}
		})
	}
}

func TestValidateRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"empty rules": {
			mutate: func(c *Config) { c.Rules = nil },
			want:   "rules must not be empty",
		},
		"invalid log level": {
			mutate: func(c *Config) { c.Log.Level = "verbose" },
			want:   "invalid level",
		},
		"unknown mode": {
			mutate: func(c *Config) { c.Rules[0].Mode = "random" },
			want:   "invalid mode",
		},
		"empty targets": {
			mutate: func(c *Config) { c.Rules[0].Targets = nil },
			want:   "targets must not be empty",
		},
		"invalid target": {
			mutate: func(c *Config) { c.Rules[0].Targets[0].Address = "missing-port" },
			want:   "invalid address",
		},
		"invalid regexp": {
			mutate: func(c *Config) {
				c.Rules[0].Mode = ModeRegex
				c.Rules[0].Targets[0].Regexp = "["
			},
			want: "invalid regexp",
		},
		"invalid CIDR": {
			mutate: func(c *Config) { c.Rules[0].Allowlist = []string{"127.0.0.1"} },
			want:   "invalid CIDR",
		},
		"invalid blacklist IP": {
			mutate: func(c *Config) { c.Rules[0].Blacklist = map[string]bool{"not-an-ip": true} },
			want:   "invalid IP",
		},
		"per-IP limit exceeds total": {
			mutate: func(c *Config) {
				c.Rules[0].MaxConnections = 10
				c.Rules[0].MaxConnectionsPerIP = 11
			},
			want: "exceeds maxConnections",
		},
		"timeout too large": {
			mutate: func(c *Config) { c.Rules[0].Timeout = uint64(maxRuleTimeout/time.Millisecond) + 1 },
			want:   "timeout must not exceed",
		},
		"too many targets": {
			mutate: func(c *Config) {
				c.Rules[0].Targets = make([]*Target, maxTargets+1)
			},
			want: "targets must not contain more than",
		},
		"connection limit too large": {
			mutate: func(c *Config) { c.Rules[0].MaxConnections = maxConnections + 1 },
			want:   "maxConnections must not exceed",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsDuplicateNameAndListen(t *testing.T) {
	for _, field := range []string{"name", "listen"} {
		t.Run(field, func(t *testing.T) {
			cfg := validConfig()
			second := &Rule{
				Name:    "two",
				Listen:  ":8001",
				Mode:    ModeNormal,
				Targets: []*Target{{Address: "example.net:80"}},
			}
			if field == "name" {
				second.Name = cfg.Rules[0].Name
			} else {
				second.Listen = cfg.Rules[0].Listen
			}
			cfg.Rules = append(cfg.Rules, second)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate "+field) {
				t.Fatalf("Validate() error = %v, want duplicate %s", err, field)
			}
		})
	}
}

func TestValidateRejectsEquivalentListenerConflicts(t *testing.T) {
	tests := []struct {
		first  string
		second string
	}{
		{first: ":8080", second: "127.0.0.1:8080"},
		{first: "0.0.0.0:8080", second: "127.0.0.1:8080"},
		{first: "127.0.0.1:09090", second: "127.0.0.1:9090"},
		{first: "[::]:8080", second: "[::1]:8080"},
	}
	for _, test := range tests {
		t.Run(test.first+"/"+test.second, func(t *testing.T) {
			cfg := validConfig()
			cfg.Rules[0].Listen = test.first
			cfg.Rules = append(cfg.Rules, &Rule{
				Name:    "two",
				Listen:  test.second,
				Mode:    ModeNormal,
				Targets: []*Target{{Address: "example.net:80"}},
			})
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate listen") {
				t.Fatalf("Validate() error = %v, want equivalent-listener conflict", err)
			}
		})
	}
}

func TestDisabledMetricsAddressDoesNotReservePort(t *testing.T) {
	cfg := validConfig()
	cfg.Rules[0].Listen = "127.0.0.1:9090"
	cfg.Metrics = MetricsConfig{Enabled: false, Listen: "127.0.0.1:9090"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled metrics address rejected: %v", err)
	}
}

func TestValidateCapsUniquePrewarmTargets(t *testing.T) {
	cfg := &Config{Log: LogConfig{Level: "info"}}
	remaining := maxPrewarmTargets + 1
	port := 10000
	for ruleIndex := 0; remaining > 0; ruleIndex++ {
		count := maxTargets
		if count > remaining {
			count = remaining
		}
		targets := make([]*Target, 0, count)
		for i := 0; i < count; i++ {
			targets = append(targets, &Target{Address: fmt.Sprintf("127.0.0.1:%d", port)})
			port++
		}
		cfg.Rules = append(cfg.Rules, &Rule{
			Name:    fmt.Sprintf("prewarm-%d", ruleIndex),
			Listen:  fmt.Sprintf("127.0.0.1:%d", 20000+ruleIndex),
			Mode:    ModeNormal,
			Prewarm: true,
			Targets: targets,
		})
		remaining -= count
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "prewarm targets") {
		t.Fatalf("Validate() error = %v, want prewarm target cap", err)
	}
}

func TestPrepareRuntimeRulesAllowsEphemeralPortsAndKeepsCrossRuleLimits(t *testing.T) {
	rules := []*Rule{
		{Name: "one", Listen: "127.0.0.1:0", Mode: ModeNormal, Targets: []*Target{{Address: "127.0.0.1:9"}}},
		{Name: "two", Listen: "127.0.0.1:0", Mode: ModeNormal, Targets: []*Target{{Address: "127.0.0.1:10"}}},
	}
	if err := PrepareRuntimeRules(rules); err != nil {
		t.Fatalf("PrepareRuntimeRules() rejected independent ephemeral listeners: %v", err)
	}
	if rules[0].MaxConnections != DefaultMaxConnections || rules[0].MaxConnectionsPerIP != DefaultMaxConnectionsPerIP {
		t.Fatal("PrepareRuntimeRules() did not apply rule defaults")
	}

	rules[1].Name = rules[0].Name
	if err := PrepareRuntimeRules(rules); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("PrepareRuntimeRules() error = %v, want duplicate-name rejection", err)
	}

	tooMany := make([]*Rule, maxRules+1)
	for index := range tooMany {
		tooMany[index] = &Rule{
			Name:    fmt.Sprintf("runtime-%d", index),
			Listen:  "127.0.0.1:0",
			Mode:    ModeNormal,
			Targets: []*Target{{Address: "127.0.0.1:9"}},
		}
	}
	if err := PrepareRuntimeRules(tooMany); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("PrepareRuntimeRules() error = %v, want rule-count cap", err)
	}
}

func TestRuleAccessPolicy(t *testing.T) {
	rule := validConfig().Rules[0]
	rule.Allowlist = []string{"192.0.2.0/24", "2001:db8::/32"}
	rule.Blacklist = map[string]bool{
		"192.0.2.10": true,
		"192.0.2.11": false,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if !rule.Allows(netip.MustParseAddr("192.0.2.10")) || !rule.Allows(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("allowlist rejected an included address")
	}
	if rule.Allows(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("allowlist accepted an excluded address")
	}
	if !rule.Blocked(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("enabled blacklist entry was not blocked")
	}
	if rule.Blocked(netip.MustParseAddr("192.0.2.11")) {
		t.Fatal("disabled blacklist entry was blocked")
	}
}

func TestReloadKeepsPreviousGlobalOnFailure(t *testing.T) {
	previous := GlobalCfg
	t.Cleanup(func() { GlobalCfg = previous })

	good := validConfig()
	if err := SetGlobal(good); err != nil {
		t.Fatalf("SetGlobal() error = %v", err)
	}
	if err := Reload(writeConfig(t, `{}`)); err == nil {
		t.Fatal("Reload() succeeded, want error")
	}
	if GlobalCfg != good {
		t.Fatal("failed Reload() replaced GlobalCfg")
	}
}

func TestLogConfigRejectsDirectoryPath(t *testing.T) {
	cfg := LogConfig{Level: "info", Path: t.TempDir()}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("Validate() error = %v, want directory error", err)
	}
}

func validConfig() *Config {
	return &Config{
		Log: LogConfig{Level: "info"},
		Rules: []*Rule{{
			Name:    "one",
			Listen:  ":8000",
			Mode:    ModeNormal,
			Targets: []*Target{{Address: "example.com:80"}},
		}},
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "setting.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
