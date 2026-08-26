package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPath is the configuration file used when no path is supplied by
	// the caller.
	DefaultPath = "config/setting.json"

	// These limits are intentionally conservative defaults. A rule may opt in
	// to larger limits explicitly, while a missing value never means unlimited.
	DefaultMaxConnections       = 4096
	DefaultMaxConnectionsPerIP  = 256
	DefaultMetricsListen        = "127.0.0.1:9090"
	DefaultHealthCheckInterval  = 10_000
	DefaultHealthCheckTimeout   = 2_000
	DefaultHealthCheckFailures  = 3
	DefaultHealthCheckSuccesses = 2
	DefaultHedgeMinDelay        = 25
	DefaultHedgeMaxDelay        = 250

	ModeNormal          = "normal"
	ModeRegex           = "regex"
	ModeBoost           = "boost"
	ModeRoundRobin      = "roundrobin"
	ModeTLS             = "tls"
	ProtocolTCP         = "tcp"
	ProtocolSOCKS5      = "socks5"
	ConnectProxyH2      = "h2"
	ConnectProxyH3      = "h3"
	HealthCheckTCP      = "tcp"
	HealthCheckHTTP     = "http"
	ProxyProtocolV1     = "v1"
	ProxyProtocolV2     = "v2"
	maxRuleTimeout      = 5 * time.Minute
	minHealthInterval   = 250 * time.Millisecond
	maxHealthInterval   = 10 * time.Minute
	minHealthTimeout    = 50 * time.Millisecond
	maxHealthTimeout    = 30 * time.Second
	maxHealthThreshold  = 20
	minHedgeDelay       = 10
	maxHedgeDelay       = 5_000
	maxHealthPath       = 2 << 10
	maxRules            = 256
	maxTargets          = 128
	maxPrewarmTargets   = 256
	maxActiveHealthJobs = 1024
	maxConnections      = 1_000_000
	maxAccessItems      = 4096
	maxTLSMatchers      = 64
	maxConfigFileBytes  = 16 << 20
	maxBasicCredential  = 4 << 10
	maxUserAgents       = 64
	maxUserAgentBytes   = 1024
)

var validLogLevels = map[string]struct{}{
	"debug":  {},
	"info":   {},
	"warn":   {},
	"error":  {},
	"dpanic": {},
	"panic":  {},
	"fatal":  {},
}

var validModes = map[string]struct{}{
	ModeNormal:     {},
	ModeRegex:      {},
	ModeBoost:      {},
	ModeRoundRobin: {},
	ModeTLS:        {},
}

var validProtocols = map[string]struct{}{
	ProtocolTCP:    {},
	ProtocolSOCKS5: {},
}

// Config is the complete Moto configuration.
type Config struct {
	Log     LogConfig     `json:"log"`
	Metrics MetricsConfig `json:"metrics,omitempty"`
	Rules   []*Rule       `json:"rules"`
}

// MetricsConfig controls the optional local-only observability listener.
// Listen must remain on a numeric loopback address so metrics and health
// endpoints cannot be exposed accidentally.
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
}

// LogConfig controls the minimum log level and the optional rolling log file.
// Logs are always written to stdout; Path adds a second, rolling destination.
type LogConfig struct {
	Level string `json:"level"`
	Path  string `json:"path"`
}

// Target is one upstream endpoint. Regexp is used by regex-mode rules and Re
// holds its validated, compiled form.
type Target struct {
	Regexp       string              `json:"regexp"`
	Re           *regexp.Regexp      `json:"-"`
	Address      string              `json:"address"`
	ServerNames  []string            `json:"serverNames,omitempty"`
	ALPN         []string            `json:"alpn,omitempty"`
	ConnectProxy *ConnectProxyConfig `json:"connectProxy,omitempty"`
}

// ConnectProxyConfig describes an ordered set of HTTP CONNECT transports for
// one forward-proxy endpoint. HTTP/3 may be listed ahead of HTTP/2 so a runtime
// with H3 support can fall back without changing the routing configuration.
type ConnectProxyConfig struct {
	Protocols  []string         `json:"protocols"`
	ServerName string           `json:"serverName,omitempty"`
	BasicAuth  *BasicAuthConfig `json:"basicAuth,omitempty"`
}

// BasicAuthConfig is sent only as an outbound Proxy-Authorization header. It
// is never used for inbound SOCKS authentication.
type BasicAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ProxyProtocolConfig enables trusted inbound PROXY v1/v2 metadata and/or a
// canonical outbound header. Inbound parsing is restricted to explicit CIDRs;
// untrusted peers are rejected before client-controlled addresses are used.
type ProxyProtocolConfig struct {
	Accept       bool     `json:"accept"`
	TrustedCIDRs []string `json:"trustedCIDRs,omitempty"`
	Send         string   `json:"send,omitempty"`

	trustedPrefixes []netip.Prefix
}

// HealthCheckConfig enables active probes for every target in one rule. The
// duration fields are milliseconds, matching Rule.Timeout. A nil HealthCheck
// leaves active checking disabled and preserves passive-only routing.
type HealthCheckConfig struct {
	Type             string `json:"type"`
	Interval         uint64 `json:"interval"`
	Timeout          uint64 `json:"timeout"`
	FailureThreshold int    `json:"failureThreshold"`
	SuccessThreshold int    `json:"successThreshold"`
	Path             string `json:"path,omitempty"`
	StatusMin        int    `json:"statusMin,omitempty"`
	StatusMax        int    `json:"statusMax,omitempty"`
}

// HedgeConfig enables delayed fallback dialing for a Boost rule. Durations are
// milliseconds. A nil Rule.Hedge preserves the historical cache-hit behavior;
// a non-nil object opts the rule into hedged scheduling.
type HedgeConfig struct {
	MinDelay uint64 `json:"minDelay"`
	MaxDelay uint64 `json:"maxDelay"`
}

// Rule describes one listener and its routing policy.
type Rule struct {
	Name                string               `json:"name"`
	Listen              string               `json:"listen"`
	Mode                string               `json:"mode"`
	Protocol            string               `json:"protocol,omitempty"`
	Prewarm             bool                 `json:"prewarm"`
	Targets             []*Target            `json:"targets"`
	Timeout             uint64               `json:"timeout"`
	Blacklist           map[string]bool      `json:"blacklist"`
	Allowlist           []string             `json:"allowlist,omitempty"`
	MaxConnections      int                  `json:"maxConnections,omitempty"`
	MaxConnectionsPerIP int                  `json:"maxConnectionsPerIP,omitempty"`
	HealthCheck         *HealthCheckConfig   `json:"healthCheck,omitempty"`
	Hedge               *HedgeConfig         `json:"hedge,omitempty"`
	ProxyProtocol       *ProxyProtocolConfig `json:"proxyProtocol,omitempty"`
	UserAgent           []string             `json:"userAgent,omitempty"`

	allowPrefixes []netip.Prefix
	blockedIPs    map[netip.Addr]struct{}
}

// GlobalCfg is retained for callers that use the process-wide configuration.
// It is deliberately nil until SetGlobal or Reload succeeds.
var GlobalCfg *Config

// Load decodes and validates a configuration file. Unknown JSON fields,
// multiple JSON values, and any other trailing non-whitespace content are
// rejected.
func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config path is empty")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if len(raw) > maxConfigFileBytes {
		return nil, fmt.Errorf("read config %q: file exceeds %d bytes", path, maxConfigFileBytes)
	}
	if err := validateStrictConfigJSON(raw); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var cfg *Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("decode config %q: top-level value must be an object", path)
	}

	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode config %q: trailing JSON value", path)
		}
		return nil, fmt.Errorf("decode config %q: trailing content: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	return cfg, nil
}

// Validate applies defaults, compiles matchers, and verifies the complete
// configuration. It is also useful for configurations constructed in code.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if err := c.Log.Validate(); err != nil {
		return fmt.Errorf("log: %w", err)
	}
	if err := c.Metrics.Validate(); err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	if err := validateRules(c.Rules, false); err != nil {
		return err
	}
	if c.Metrics.Enabled && c.Metrics.Listen != "" {
		for i, rule := range c.Rules {
			if endpointsConflict(c.Metrics.Listen, rule.Listen) {
				return fmt.Errorf("metrics: listen address %q conflicts with rules[%d].listen %q", c.Metrics.Listen, i, rule.Listen)
			}
		}
	}
	return nil
}

// PrepareRuntimeRules applies the same schema, cross-rule, and resource-bound
// validation used for file configuration while permitting port 0 listeners.
// It is intended for servers embedded in tests or other Go programs that need
// the kernel to assign an ephemeral port. Like Validate, it compiles access
// policies and regex matchers in place before the rules can serve traffic.
func PrepareRuntimeRules(rules []*Rule) error {
	return validateRules(rules, true)
}

func validateRules(rules []*Rule, allowEphemeralListen bool) error {
	if len(rules) == 0 {
		return errors.New("rules must not be empty")
	}
	if len(rules) > maxRules {
		return fmt.Errorf("rules must not contain more than %d entries", maxRules)
	}

	names := make(map[string]int, len(rules))
	type listenerUse struct {
		address string
		index   int
	}
	listeners := make([]listenerUse, 0, len(rules))
	prewarmTargets := make(map[string]struct{})
	activeHealthJobs := 0
	for i, rule := range rules {
		if rule == nil {
			return fmt.Errorf("rules[%d]: rule is null", i)
		}
		if err := rule.validate(allowEphemeralListen); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}

		if previous, ok := names[rule.Name]; ok {
			return fmt.Errorf("rules[%d]: duplicate name %q (already used by rules[%d])", i, rule.Name, previous)
		}
		names[rule.Name] = i

		for _, previous := range listeners {
			// Each port 0 listener receives an independent kernel-assigned port and
			// therefore cannot conflict with a fixed or another ephemeral listener.
			if !endpointUsesPortZero(rule.Listen) && !endpointUsesPortZero(previous.address) &&
				endpointsConflict(rule.Listen, previous.address) {
				return fmt.Errorf("rules[%d]: duplicate listen address %q conflicts with rules[%d].listen %q", i, rule.Listen, previous.index, previous.address)
			}
		}
		listeners = append(listeners, listenerUse{address: rule.Listen, index: i})
		if rule.Prewarm {
			for _, target := range rule.Targets {
				prewarmTargets[target.Address] = struct{}{}
			}
			if len(prewarmTargets) > maxPrewarmTargets {
				return fmt.Errorf("prewarm targets must not contain more than %d unique addresses", maxPrewarmTargets)
			}
		}
		if rule.HealthCheck != nil {
			uniqueTargets := make(map[string]struct{}, len(rule.Targets))
			for _, target := range rule.Targets {
				uniqueTargets[target.Address] = struct{}{}
			}
			activeHealthJobs += len(uniqueTargets)
			if activeHealthJobs > maxActiveHealthJobs {
				return fmt.Errorf("active health checks must not contain more than %d unique rule-target jobs", maxActiveHealthJobs)
			}
		}
	}
	return nil
}

// Validate validates a Config. It mirrors (*Config).Validate for callers that
// prefer a package-level function.
func Validate(cfg *Config) error {
	return cfg.Validate()
}

// Validate checks an independent logging configuration.
func (c *LogConfig) Validate() error {
	if c == nil {
		return errors.New("log config is nil")
	}

	level := strings.ToLower(strings.TrimSpace(c.Level))
	if _, ok := validLogLevels[level]; !ok {
		return fmt.Errorf("invalid level %q", c.Level)
	}
	c.Level = level

	if strings.IndexByte(c.Path, 0) >= 0 {
		return errors.New("path contains a NUL byte")
	}
	if c.Path == "" {
		return nil
	}
	if strings.TrimSpace(c.Path) == "" {
		return errors.New("path must not be blank")
	}
	c.Path = filepath.Clean(c.Path)
	if info, err := os.Stat(c.Path); err == nil && info.IsDir() {
		return fmt.Errorf("path %q is a directory", c.Path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect path %q: %w", c.Path, err)
	}
	return nil
}

// Validate applies the default metrics address when enabled and ensures any
// configured listener is a numeric IPv4 or IPv6 loopback endpoint. A disabled
// listener may be left empty, but a supplied address is still validated so
// enabling it later cannot expose an unsafe value.
func (c *MetricsConfig) Validate() error {
	if c == nil {
		return errors.New("metrics config is nil")
	}
	if c.Listen == "" {
		if c.Enabled {
			c.Listen = DefaultMetricsListen
		}
		return nil
	}
	if err := validateEndpoint("listen", c.Listen); err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen %q: %w", c.Listen, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Unmap().IsLoopback() {
		return fmt.Errorf("listen %q must use a numeric loopback address", c.Listen)
	}
	return nil
}

// Validate applies per-rule defaults and compiles any regex and allowlist
// entries. Cross-rule uniqueness is checked by Config.Validate.
func (r *Rule) Validate() error {
	return r.validate(false)
}

func (r *Rule) validate(allowEphemeralListen bool) error {
	if r == nil {
		return errors.New("rule is nil")
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name must not be empty")
	}
	if r.Name != strings.TrimSpace(r.Name) {
		return errors.New("name must not have leading or trailing whitespace")
	}
	if err := validateEndpointPort("listen", r.Listen, allowEphemeralListen); err != nil {
		return err
	}
	if _, ok := validModes[r.Mode]; !ok {
		return fmt.Errorf("invalid mode %q", r.Mode)
	}
	if r.Protocol == "" {
		r.Protocol = ProtocolTCP
	}
	if _, ok := validProtocols[r.Protocol]; !ok {
		return fmt.Errorf("invalid protocol %q", r.Protocol)
	}
	if len(r.UserAgent) != 0 {
		if r.Protocol != ProtocolSOCKS5 {
			return errors.New("userAgent is only valid for protocol socks5")
		}
		if err := validateUserAgents(r.UserAgent); err != nil {
			return err
		}
	}
	if r.Protocol == ProtocolSOCKS5 {
		if r.Mode == ModeRegex || r.Mode == ModeTLS {
			return fmt.Errorf("protocol %q is not compatible with mode %q", r.Protocol, r.Mode)
		}
		if len(r.Allowlist) == 0 {
			host, _, splitErr := net.SplitHostPort(r.Listen)
			listenAddr, parseErr := netip.ParseAddr(host)
			if splitErr != nil || parseErr != nil || !listenAddr.Unmap().IsLoopback() {
				return errors.New("protocol socks5 on a non-loopback listener requires an explicit non-empty allowlist")
			}
		}
		if r.Prewarm {
			return errors.New("protocol socks5 cannot use prewarm")
		}
		if r.HealthCheck != nil && strings.ToLower(strings.TrimSpace(r.HealthCheck.Type)) == HealthCheckHTTP {
			return errors.New("protocol socks5 cannot use HTTP healthCheck; use a TCP endpoint check")
		}
		if r.ProxyProtocol != nil {
			return errors.New("protocol socks5 cannot use proxyProtocol")
		}
	}
	if len(r.Targets) == 0 {
		return errors.New("targets must not be empty")
	}
	if len(r.Targets) > maxTargets {
		return fmt.Errorf("targets must not contain more than %d entries", maxTargets)
	}

	if r.MaxConnections < 0 {
		return errors.New("maxConnections must not be negative")
	}
	if r.MaxConnections == 0 {
		r.MaxConnections = DefaultMaxConnections
	}
	if r.MaxConnections > maxConnections {
		return fmt.Errorf("maxConnections must not exceed %d", maxConnections)
	}
	if r.MaxConnectionsPerIP < 0 {
		return errors.New("maxConnectionsPerIP must not be negative")
	}
	if r.MaxConnectionsPerIP == 0 {
		r.MaxConnectionsPerIP = DefaultMaxConnectionsPerIP
		if r.MaxConnectionsPerIP > r.MaxConnections {
			r.MaxConnectionsPerIP = r.MaxConnections
		}
	}
	if r.MaxConnectionsPerIP > r.MaxConnections {
		return fmt.Errorf("maxConnectionsPerIP (%d) exceeds maxConnections (%d)", r.MaxConnectionsPerIP, r.MaxConnections)
	}

	if r.Timeout == 0 {
		if r.Mode == ModeRegex {
			r.Timeout = 500
		} else {
			r.Timeout = uint64((3 * time.Second) / time.Millisecond)
		}
	}
	if r.Timeout > uint64(maxRuleTimeout/time.Millisecond) {
		return fmt.Errorf("timeout must not exceed %s", maxRuleTimeout)
	}
	if r.Hedge != nil {
		if r.Mode != ModeBoost {
			return errors.New("hedge is only valid in boost mode")
		}
		if err := r.Hedge.Validate(r.Timeout); err != nil {
			return fmt.Errorf("hedge: %w", err)
		}
	}
	if r.HealthCheck != nil {
		if err := r.HealthCheck.Validate(); err != nil {
			return fmt.Errorf("healthCheck: %w", err)
		}
	}
	if r.ProxyProtocol != nil {
		if err := r.ProxyProtocol.Validate(); err != nil {
			return fmt.Errorf("proxyProtocol: %w", err)
		}
		if r.Prewarm && r.ProxyProtocol.Send != "" {
			return errors.New("prewarm cannot be combined with outbound PROXY protocol because the client address is not known when pooled connections are created")
		}
	}
	tlsFallbacks := 0
	uniqueTargets := make(map[string]struct{}, len(r.Targets))
	for i, target := range r.Targets {
		if target == nil {
			return fmt.Errorf("targets[%d]: target is null", i)
		}
		if err := validateEndpoint("address", target.Address); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		_, duplicateTarget := uniqueTargets[target.Address]
		uniqueTargets[target.Address] = struct{}{}
		if r.Protocol == ProtocolSOCKS5 {
			if duplicateTarget {
				return fmt.Errorf("targets[%d]: protocol socks5 requires unique target addresses", i)
			}
			if target.ConnectProxy == nil {
				return fmt.Errorf("targets[%d]: connectProxy is required for protocol socks5", i)
			}
			if err := target.ConnectProxy.Validate(); err != nil {
				return fmt.Errorf("targets[%d].connectProxy: %w", i, err)
			}
		} else if target.ConnectProxy != nil {
			return fmt.Errorf("targets[%d]: connectProxy is only valid for protocol socks5", i)
		}
		target.Re = nil
		if r.Mode == ModeRegex {
			compiled, err := regexp.Compile(target.Regexp)
			if err != nil {
				return fmt.Errorf("targets[%d]: invalid regexp %q: %w", i, target.Regexp, err)
			}
			target.Re = compiled
		}
		if r.Mode == ModeTLS {
			if target.Regexp != "" {
				return fmt.Errorf("targets[%d]: regexp is not valid in tls mode", i)
			}
			if err := target.validateTLSMatchers(); err != nil {
				return fmt.Errorf("targets[%d]: %w", i, err)
			}
			if len(target.ServerNames) == 0 && len(target.ALPN) == 0 {
				tlsFallbacks++
				if tlsFallbacks > 1 {
					return errors.New("tls mode permits at most one fallback target without serverNames or alpn")
				}
			}
		} else if len(target.ServerNames) != 0 || len(target.ALPN) != 0 {
			return fmt.Errorf("targets[%d]: serverNames and alpn are only valid in tls mode", i)
		}
	}
	if r.Hedge != nil && len(uniqueTargets) < 2 {
		return errors.New("hedge requires at least two unique target addresses")
	}

	if len(r.Allowlist) > maxAccessItems {
		return fmt.Errorf("allowlist must not contain more than %d entries", maxAccessItems)
	}
	if len(r.Blacklist) > maxAccessItems {
		return fmt.Errorf("blacklist must not contain more than %d entries", maxAccessItems)
	}
	prefixes := make([]netip.Prefix, 0, len(r.Allowlist))
	for i, item := range r.Allowlist {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return fmt.Errorf("allowlist[%d]: invalid CIDR %q: %w", i, item, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	r.allowPrefixes = prefixes

	blocked := make(map[netip.Addr]struct{}, len(r.Blacklist))
	for item, enabled := range r.Blacklist {
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return fmt.Errorf("blacklist: invalid IP %q: %w", item, err)
		}
		if enabled {
			blocked[addr.Unmap()] = struct{}{}
		}
	}
	r.blockedIPs = blocked
	return nil
}

func validateUserAgents(userAgents []string) error {
	if len(userAgents) > maxUserAgents {
		return fmt.Errorf("userAgent must not contain more than %d entries", maxUserAgents)
	}
	seen := make(map[string]struct{}, len(userAgents))
	for index, userAgent := range userAgents {
		if len(userAgent) == 0 || len(userAgent) > maxUserAgentBytes {
			return fmt.Errorf("userAgent[%d] length must be between 1 and %d bytes", index, maxUserAgentBytes)
		}
		if userAgent != strings.TrimSpace(userAgent) {
			return fmt.Errorf("userAgent[%d] must not have leading or trailing whitespace", index)
		}
		for _, value := range []byte(userAgent) {
			if value < 0x20 || value > 0x7e {
				return fmt.Errorf("userAgent[%d] must contain only printable ASCII", index)
			}
		}
		if _, duplicate := seen[userAgent]; duplicate {
			return fmt.Errorf("userAgent[%d]: duplicate value", index)
		}
		seen[userAgent] = struct{}{}
	}
	return nil
}

// Validate normalizes and checks an ordered CONNECT transport preference.
func (c *ConnectProxyConfig) Validate() error {
	if c == nil {
		return errors.New("connect proxy config is nil")
	}
	if len(c.Protocols) == 0 {
		c.Protocols = []string{ConnectProxyH2}
	}
	if len(c.Protocols) > 2 {
		return errors.New("protocols must not contain more than h3 and h2")
	}
	seen := make(map[string]struct{}, len(c.Protocols))
	for i, protocol := range c.Protocols {
		if protocol != ConnectProxyH2 && protocol != ConnectProxyH3 {
			return fmt.Errorf("protocols[%d]: invalid protocol %q", i, protocol)
		}
		if _, duplicate := seen[protocol]; duplicate {
			return fmt.Errorf("protocols[%d]: duplicate protocol %q", i, protocol)
		}
		seen[protocol] = struct{}{}
	}
	if strings.TrimSpace(c.ServerName) != c.ServerName {
		return errors.New("serverName must not contain leading or trailing whitespace")
	}
	if c.ServerName != "" && net.ParseIP(c.ServerName) == nil {
		c.ServerName = strings.ToLower(c.ServerName)
		if strings.Contains(c.ServerName, "*") {
			return errors.New("serverName must not contain a wildcard")
		}
		if err := validateTLSServerNamePattern(c.ServerName); err != nil {
			return fmt.Errorf("invalid serverName: %w", err)
		}
	}
	if c.BasicAuth != nil {
		if err := c.BasicAuth.Validate(); err != nil {
			return fmt.Errorf("basicAuth: %w", err)
		}
	}
	return nil
}

// Validate rejects credentials that could produce ambiguous Basic auth data or
// unbounded request headers.
func (c *BasicAuthConfig) Validate() error {
	if c == nil {
		return errors.New("basic auth config is nil")
	}
	if c.Username == "" {
		return errors.New("username must not be empty")
	}
	if strings.Contains(c.Username, ":") {
		return errors.New("username must not contain ':'")
	}
	if strings.ContainsAny(c.Username+c.Password, "\x00\r\n") {
		return errors.New("credentials must not contain NUL, CR, or LF")
	}
	if len(c.Username)+len(c.Password) > maxBasicCredential {
		return fmt.Errorf("credentials must not exceed %d bytes", maxBasicCredential)
	}
	return nil
}

// Validate applies hedge defaults and checks the rule decision budget. The
// caller verifies mode and unique-target requirements because those belong to
// the enclosing rule.
func (c *HedgeConfig) Validate(ruleTimeout uint64) error {
	if c == nil {
		return errors.New("hedge config is nil")
	}
	if c.MinDelay == 0 {
		c.MinDelay = DefaultHedgeMinDelay
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = DefaultHedgeMaxDelay
	}
	if c.MinDelay < minHedgeDelay || c.MinDelay > maxHedgeDelay {
		return fmt.Errorf("minDelay must be between %d and %d milliseconds", minHedgeDelay, maxHedgeDelay)
	}
	if c.MaxDelay < minHedgeDelay || c.MaxDelay > maxHedgeDelay {
		return fmt.Errorf("maxDelay must be between %d and %d milliseconds", minHedgeDelay, maxHedgeDelay)
	}
	if c.MinDelay > c.MaxDelay {
		return errors.New("minDelay must not exceed maxDelay")
	}
	if c.MaxDelay >= ruleTimeout {
		return errors.New("maxDelay must be less than rule timeout")
	}
	return nil
}

func (target *Target) validateTLSMatchers() error {
	if len(target.ServerNames) > maxTLSMatchers {
		return fmt.Errorf("serverNames must not contain more than %d entries", maxTLSMatchers)
	}
	if len(target.ALPN) > maxTLSMatchers {
		return fmt.Errorf("alpn must not contain more than %d entries", maxTLSMatchers)
	}
	seenNames := make(map[string]struct{}, len(target.ServerNames))
	for index, value := range target.ServerNames {
		if value != strings.TrimSpace(value) {
			return fmt.Errorf("serverNames[%d] must not have leading or trailing whitespace", index)
		}
		value = strings.ToLower(value)
		if err := validateTLSServerNamePattern(value); err != nil {
			return fmt.Errorf("serverNames[%d]: %w", index, err)
		}
		if _, duplicate := seenNames[value]; duplicate {
			return fmt.Errorf("serverNames[%d]: duplicate value %q", index, value)
		}
		seenNames[value] = struct{}{}
		target.ServerNames[index] = value
	}
	seenALPN := make(map[string]struct{}, len(target.ALPN))
	for index, protocol := range target.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 {
			return fmt.Errorf("alpn[%d] length must be between 1 and 255 bytes", index)
		}
		for _, b := range []byte(protocol) {
			if b < 0x21 || b > 0x7e {
				return fmt.Errorf("alpn[%d] must contain printable ASCII without spaces", index)
			}
		}
		if _, duplicate := seenALPN[protocol]; duplicate {
			return fmt.Errorf("alpn[%d]: duplicate value %q", index, protocol)
		}
		seenALPN[protocol] = struct{}{}
	}
	return nil
}

func validateTLSServerNamePattern(value string) error {
	if value == "" || len(value) > 253 {
		return errors.New("must be a non-empty DNS name no longer than 253 bytes")
	}
	if strings.HasPrefix(value, "*.") {
		value = value[2:]
		if value == "" {
			return errors.New("wildcard must have a DNS suffix")
		}
	} else if strings.Contains(value, "*") {
		return errors.New("wildcard is only allowed as the complete left-most label")
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return errors.New("must not begin or end with a dot")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS label %q", label)
		}
		for _, b := range []byte(label) {
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return fmt.Errorf("invalid DNS label %q", label)
			}
		}
	}
	return nil
}

func (c *ProxyProtocolConfig) Validate() error {
	if c == nil {
		return errors.New("proxy protocol config is nil")
	}
	c.Send = strings.ToLower(strings.TrimSpace(c.Send))
	if c.Send != "" && c.Send != ProxyProtocolV1 && c.Send != ProxyProtocolV2 {
		return fmt.Errorf("send must be empty, %q, or %q", ProxyProtocolV1, ProxyProtocolV2)
	}
	if !c.Accept && len(c.TrustedCIDRs) != 0 {
		return errors.New("trustedCIDRs requires accept=true")
	}
	if c.Accept && len(c.TrustedCIDRs) == 0 {
		return errors.New("accept=true requires at least one trustedCIDR")
	}
	if len(c.TrustedCIDRs) > maxAccessItems {
		return fmt.Errorf("trustedCIDRs must not contain more than %d entries", maxAccessItems)
	}
	prefixes := make([]netip.Prefix, 0, len(c.TrustedCIDRs))
	for index, value := range c.TrustedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("trustedCIDRs[%d]: invalid CIDR %q: %w", index, value, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return fmt.Errorf("trustedCIDRs[%d]: IPv4-mapped CIDR %q must use a prefix length of at least 96", index, value)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	c.trustedPrefixes = prefixes
	return nil
}

func (c *ProxyProtocolConfig) Trusts(addr netip.Addr) bool {
	if c == nil || !c.Accept || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range c.trustedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Validate applies conservative active-check defaults and rejects settings
// that could create tight retry loops or turn an HTTP path into another
// network destination.
func (c *HealthCheckConfig) Validate() error {
	if c == nil {
		return errors.New("health check config is nil")
	}
	if c.Type == "" {
		c.Type = HealthCheckTCP
	}
	if c.Type != strings.TrimSpace(c.Type) {
		return errors.New("type must not have leading or trailing whitespace")
	}
	c.Type = strings.ToLower(c.Type)
	if c.Type != HealthCheckTCP && c.Type != HealthCheckHTTP {
		return fmt.Errorf("invalid type %q", c.Type)
	}

	if c.Interval == 0 {
		c.Interval = DefaultHealthCheckInterval
	}
	if c.Interval < uint64(minHealthInterval/time.Millisecond) || c.Interval > uint64(maxHealthInterval/time.Millisecond) {
		return fmt.Errorf("interval must be between %s and %s", minHealthInterval, maxHealthInterval)
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultHealthCheckTimeout
		if c.Timeout > c.Interval {
			c.Timeout = c.Interval
		}
	}
	if c.Timeout < uint64(minHealthTimeout/time.Millisecond) || c.Timeout > uint64(maxHealthTimeout/time.Millisecond) {
		return fmt.Errorf("timeout must be between %s and %s", minHealthTimeout, maxHealthTimeout)
	}
	if c.Timeout > c.Interval {
		return errors.New("timeout must not exceed interval")
	}

	if c.FailureThreshold == 0 {
		c.FailureThreshold = DefaultHealthCheckFailures
	}
	if c.FailureThreshold < 1 || c.FailureThreshold > maxHealthThreshold {
		return fmt.Errorf("failureThreshold must be between 1 and %d", maxHealthThreshold)
	}
	if c.SuccessThreshold == 0 {
		c.SuccessThreshold = DefaultHealthCheckSuccesses
	}
	if c.SuccessThreshold < 1 || c.SuccessThreshold > maxHealthThreshold {
		return fmt.Errorf("successThreshold must be between 1 and %d", maxHealthThreshold)
	}

	if c.Type == HealthCheckTCP {
		if c.Path != "" || c.StatusMin != 0 || c.StatusMax != 0 {
			return errors.New("path and status range are only valid for http checks")
		}
		return nil
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if len(c.Path) > maxHealthPath {
		return fmt.Errorf("path must not exceed %d bytes", maxHealthPath)
	}
	parsed, err := url.ParseRequestURI(c.Path)
	if err != nil || !strings.HasPrefix(c.Path, "/") || strings.HasPrefix(c.Path, "//") ||
		parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return fmt.Errorf("path %q must be an HTTP origin-form request target", c.Path)
	}
	if c.StatusMin == 0 {
		c.StatusMin = 200
	}
	if c.StatusMax == 0 {
		c.StatusMax = 399
	}
	if c.StatusMin < 100 || c.StatusMin > 599 || c.StatusMax < 100 || c.StatusMax > 599 {
		return errors.New("status range must be between 100 and 599")
	}
	if c.StatusMin > c.StatusMax {
		return errors.New("statusMin must not exceed statusMax")
	}
	return nil
}

// Allows reports whether addr is permitted by the rule's CIDR allowlist. An
// empty allowlist permits every valid address.
func (r *Rule) Allows(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() {
		return false
	}
	if len(r.Allowlist) == 0 {
		return true
	}

	addr = addr.Unmap()
	for _, prefix := range r.allowPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Blocked reports whether addr is enabled in the legacy exact-IP blacklist.
func (r *Rule) Blocked(addr netip.Addr) bool {
	if r == nil || !addr.IsValid() || len(r.blockedIPs) == 0 {
		return false
	}
	_, blocked := r.blockedIPs[addr.Unmap()]
	return blocked
}

// SetGlobal validates cfg before publishing it as the process-wide config.
func SetGlobal(cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	GlobalCfg = cfg
	return nil
}

// Reload atomically replaces GlobalCfg only after the new file has loaded and
// validated successfully.
func Reload(path string) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	GlobalCfg = cfg
	return nil
}

func validateEndpoint(field, value string) error {
	return validateEndpointPort(field, value, false)
}

func validateEndpointPort(field, value string, allowZero bool) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have leading or trailing whitespace", field)
	}

	_, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	port, err := strconv.Atoi(portText)
	minimum := 1
	if allowZero {
		minimum = 0
	}
	if err != nil || port < minimum || port > 65535 {
		if allowZero {
			return fmt.Errorf("invalid %s %q: port must be between 0 and 65535", field, value)
		}
		return fmt.Errorf("invalid %s %q: port must be between 1 and 65535", field, value)
	}
	return nil
}

func endpointUsesPortZero(value string) bool {
	_, portText, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port == 0
}

func endpointsConflict(first, second string) bool {
	firstHost, firstPortText, firstErr := net.SplitHostPort(first)
	secondHost, secondPortText, secondErr := net.SplitHostPort(second)
	if firstErr != nil || secondErr != nil {
		return false
	}
	firstPort, firstPortErr := strconv.Atoi(firstPortText)
	secondPort, secondPortErr := strconv.Atoi(secondPortText)
	if firstPortErr != nil || secondPortErr != nil || firstPort != secondPort {
		return false
	}

	firstAddr, firstAddrErr := netip.ParseAddr(firstHost)
	secondAddr, secondAddrErr := netip.ParseAddr(secondHost)
	if firstHost == "" || secondHost == "" ||
		(firstAddrErr == nil && firstAddr.IsUnspecified()) ||
		(secondAddrErr == nil && secondAddr.IsUnspecified()) {
		return true
	}
	if firstAddrErr == nil && secondAddrErr == nil {
		return firstAddr.Unmap() == secondAddr.Unmap()
	}
	if strings.EqualFold(firstHost, secondHost) {
		return true
	}
	if strings.EqualFold(firstHost, "localhost") && firstAddrErr != nil && secondAddrErr == nil {
		return secondAddr.Unmap().IsLoopback()
	}
	if strings.EqualFold(secondHost, "localhost") && secondAddrErr != nil && firstAddrErr == nil {
		return firstAddr.Unmap().IsLoopback()
	}
	return false
}
