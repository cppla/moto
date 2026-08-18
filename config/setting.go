package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	DefaultMaxConnections      = 4096
	DefaultMaxConnectionsPerIP = 256
	DefaultMetricsListen       = "127.0.0.1:9090"

	ModeNormal        = "normal"
	ModeRegex         = "regex"
	ModeBoost         = "boost"
	ModeRoundRobin    = "roundrobin"
	maxRuleTimeout    = 5 * time.Minute
	maxRules          = 256
	maxTargets        = 128
	maxPrewarmTargets = 256
	maxConnections    = 1_000_000
	maxAccessItems    = 4096
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
	Level   string `json:"level"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Date    string `json:"date"`
}

// Target is one upstream endpoint. Regexp is used by regex-mode rules and Re
// holds its validated, compiled form.
type Target struct {
	Regexp  string         `json:"regexp"`
	Re      *regexp.Regexp `json:"-"`
	Address string         `json:"address"`
}

// Rule describes one listener and its routing policy.
type Rule struct {
	Name                string          `json:"name"`
	Listen              string          `json:"listen"`
	Mode                string          `json:"mode"`
	Prewarm             bool            `json:"prewarm"`
	Targets             []*Target       `json:"targets"`
	Timeout             uint64          `json:"timeout"`
	Blacklist           map[string]bool `json:"blacklist"`
	Allowlist           []string        `json:"allowlist,omitempty"`
	MaxConnections      int             `json:"maxConnections,omitempty"`
	MaxConnectionsPerIP int             `json:"maxConnectionsPerIP,omitempty"`

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

	dec := json.NewDecoder(f)
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
	for i, target := range r.Targets {
		if target == nil {
			return fmt.Errorf("targets[%d]: target is null", i)
		}
		if err := validateEndpoint("address", target.Address); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		target.Re = nil
		if r.Mode == ModeRegex {
			compiled, err := regexp.Compile(target.Regexp)
			if err != nil {
				return fmt.Errorf("targets[%d]: invalid regexp %q: %w", i, target.Regexp, err)
			}
			target.Re = compiled
		}
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
