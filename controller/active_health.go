package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"moto/config"
)

var ErrActiveHealthUnhealthy = errors.New("target marked unhealthy by active health checks")

const (
	activeHealthMaxConcurrentProbes = 32
	activeHealthJitterPercent       = 10
	activeHealthMaxResponseHeaders  = 32 << 10
)

// The slot pool is process-wide rather than per server generation. This keeps
// simultaneous reload generations and multiple embedded servers from
// multiplying the number of background network operations.
var activeHealthProbeSlots = make(chan struct{}, activeHealthMaxConcurrentProbes)

type activeHealthKey struct {
	rule    *config.Rule
	address string
}

type activeHealthState struct {
	unhealthy            bool
	consecutiveFailures  int
	consecutiveSuccesses int
}

type activeHealthJob struct {
	key           activeHealthKey
	target        string
	check         config.HealthCheckConfig
	proxyProtocol string
}

type activeHealthProbeFunc func(context.Context, string, config.HealthCheckConfig, string) error
type activeHealthDelayFunc func(time.Duration) time.Duration

// activeHealthManager owns the active state for one routing generation. It is
// intentionally independent from passive route health: a later integration can
// exclude actively unhealthy targets without letting background probes distort
// EWMA latency or half-open ownership.
type activeHealthManager struct {
	mu     sync.RWMutex
	states map[activeHealthKey]*activeHealthState

	lifecycleMu sync.Mutex
	started     bool
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	probe        activeHealthProbeFunc
	initialDelay activeHealthDelayFunc
	nextDelay    activeHealthDelayFunc
}

func newActiveHealthManager() *activeHealthManager {
	return &activeHealthManager{
		states:       make(map[activeHealthKey]*activeHealthState),
		probe:        probeActiveHealthTarget,
		initialDelay: activeHealthInitialDelay,
		nextDelay:    activeHealthIntervalDelay,
	}
}

// start launches at most one checker for each rule/target address. Configuration
// validation happens before server construction, so this lifecycle method only
// ignores nil or disabled entries defensively.
func (manager *activeHealthManager) start(parent context.Context, rules []*config.Rule) {
	if manager == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	manager.lifecycleMu.Lock()
	if manager.started {
		manager.lifecycleMu.Unlock()
		return
	}
	manager.started = true
	ctx, cancel := context.WithCancel(parent)
	manager.cancel = cancel

	jobs := make([]activeHealthJob, 0)
	seen := make(map[activeHealthKey]struct{})
	for _, rule := range rules {
		if rule == nil || rule.HealthCheck == nil {
			continue
		}
		for _, target := range rule.Targets {
			if target == nil || target.Address == "" {
				continue
			}
			key := activeHealthKey{rule: rule, address: target.Address}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			proxyProtocol := ""
			if rule.ProxyProtocol != nil {
				proxyProtocol = rule.ProxyProtocol.Send
			}
			jobs = append(jobs, activeHealthJob{
				key:           key,
				target:        target.Address,
				check:         *rule.HealthCheck,
				proxyProtocol: proxyProtocol,
			})
		}
	}
	manager.mu.Lock()
	for _, job := range jobs {
		if manager.states[job.key] == nil {
			manager.states[job.key] = &activeHealthState{}
		}
	}
	manager.mu.Unlock()
	manager.wg.Add(len(jobs))
	for _, job := range jobs {
		go manager.runChecker(ctx, job)
	}
	manager.lifecycleMu.Unlock()
}

// stop cancels timer waits, semaphore waits, dials, and HTTP requests, then
// waits until every checker has exited. It is safe to call repeatedly.
func (manager *activeHealthManager) stop() {
	if manager == nil {
		return
	}
	manager.lifecycleMu.Lock()
	cancel := manager.cancel
	manager.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	manager.wg.Wait()
}

// unhealthy reports only a threshold-confirmed active failure. Missing,
// disabled, and not-yet-checked targets remain usable, preserving legacy
// passive routing during startup and when active checking is omitted.
func (manager *activeHealthManager) unhealthy(rule *config.Rule, address string) bool {
	if manager == nil || rule == nil || address == "" {
		return false
	}
	manager.mu.RLock()
	state := manager.states[activeHealthKey{rule: rule, address: address}]
	unhealthy := state != nil && state.unhealthy
	manager.mu.RUnlock()
	return unhealthy
}

func (manager *activeHealthManager) runChecker(ctx context.Context, job activeHealthJob) {
	defer manager.wg.Done()
	interval := time.Duration(job.check.Interval) * time.Millisecond
	delay := manager.initialDelay(interval)
	for {
		if !waitActiveHealthDelay(ctx, delay) {
			return
		}
		if !manager.runProbe(ctx, job) {
			return
		}
		delay = manager.nextDelay(interval)
	}
}

func waitActiveHealthDelay(ctx context.Context, delay time.Duration) bool {
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (manager *activeHealthManager) runProbe(ctx context.Context, job activeHealthJob) bool {
	select {
	case activeHealthProbeSlots <- struct{}{}:
	case <-ctx.Done():
		return false
	}

	timeout := time.Duration(job.check.Timeout) * time.Millisecond
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	err := manager.probe(probeCtx, job.target, job.check, job.proxyProtocol)
	parentCanceled := ctx.Err() != nil
	cancel()
	<-activeHealthProbeSlots
	if parentCanceled {
		return false
	}
	manager.observe(job.key, job.check, err == nil)
	return true
}

func (manager *activeHealthManager) observe(key activeHealthKey, check config.HealthCheckConfig, success bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state := manager.states[key]
	if state == nil {
		state = &activeHealthState{}
		manager.states[key] = state
	}
	if success {
		state.consecutiveFailures = 0
		if !state.unhealthy {
			state.consecutiveSuccesses = 0
			return
		}
		state.consecutiveSuccesses++
		if state.consecutiveSuccesses >= check.SuccessThreshold {
			state.unhealthy = false
			state.consecutiveSuccesses = 0
		}
		return
	}

	state.consecutiveSuccesses = 0
	if state.unhealthy {
		return
	}
	state.consecutiveFailures++
	if state.consecutiveFailures >= check.FailureThreshold {
		state.unhealthy = true
		state.consecutiveFailures = 0
	}
}

func activeHealthInitialDelay(interval time.Duration) time.Duration {
	maximum := interval * activeHealthJitterPercent / 100
	return activeHealthRandomDuration(maximum)
}

func activeHealthIntervalDelay(interval time.Duration) time.Duration {
	spread := interval * activeHealthJitterPercent / 100
	if spread <= 0 {
		return interval
	}
	return interval - spread + activeHealthRandomDuration(2*spread)
}

func activeHealthRandomDuration(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(maximum) + 1))
}

func probeActiveHealthTarget(ctx context.Context, address string, check config.HealthCheckConfig, proxyProtocol string) error {
	switch check.Type {
	case config.HealthCheckTCP:
		connection, err := dialActiveHealthTarget(ctx, "tcp", address, proxyProtocol)
		if err != nil {
			return err
		}
		_ = connection.Close()
		return nil
	case config.HealthCheckHTTP:
		return probeActiveHealthHTTP(ctx, address, check, proxyProtocol)
	default:
		return fmt.Errorf("unsupported active health check type %q", check.Type)
	}
}

func dialActiveHealthTarget(ctx context.Context, network, address, proxyProtocol string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	configureTCP(connection)
	if proxyProtocol == "" {
		return connection, nil
	}
	if err := writeActiveHealthProxyProtocolContext(ctx, connection, proxyProtocol); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func writeActiveHealthProxyProtocolContext(ctx context.Context, connection net.Conn, version string) error {
	return writeProxyProtocolWithContext(ctx, connection, "active health", func() error {
		return writeActiveHealthProxyProtocol(connection, version)
	})
}

func writeActiveHealthProxyProtocol(connection net.Conn, version string) error {
	if version == "" {
		return nil
	}
	if connection == nil {
		return errors.New("write active health PROXY protocol header: nil connection")
	}

	header := proxyProtocolHeader{Command: proxyProtocolCommandLocal}
	switch version {
	case config.ProxyProtocolV1:
		source, err := addrPortFromNetAddr(connection.LocalAddr())
		if err != nil {
			return fmt.Errorf("active health PROXY protocol source: %w", err)
		}
		destination, err := addrPortFromNetAddr(connection.RemoteAddr())
		if err != nil {
			return fmt.Errorf("active health PROXY protocol destination: %w", err)
		}
		header.Version = proxyProtocolVersion1
		header.Command = proxyProtocolCommandProxy
		header.Source = source
		header.Destination = destination
	case config.ProxyProtocolV2:
		header.Version = proxyProtocolVersion2
	default:
		return fmt.Errorf("unsupported active health PROXY protocol version %q", version)
	}
	if err := writeProxyProtocolHeader(connection, header); err != nil {
		return fmt.Errorf("write active health PROXY protocol header: %w", err)
	}
	return nil
}

func probeActiveHealthHTTP(ctx context.Context, address string, check config.HealthCheckConfig, proxyProtocol string) error {
	requestTarget, err := url.ParseRequestURI(check.Path)
	if err != nil {
		return fmt.Errorf("parse health check path: %w", err)
	}
	endpoint := &url.URL{
		Scheme:   "http",
		Host:     address,
		Path:     requestTarget.Path,
		RawPath:  requestTarget.RawPath,
		RawQuery: requestTarget.RawQuery,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			return dialActiveHealthTarget(dialCtx, network, target, proxyProtocol)
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: activeHealthMaxResponseHeaders,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < check.StatusMin || response.StatusCode > check.StatusMax {
		return fmt.Errorf("unexpected HTTP status %d (want %d-%d)", response.StatusCode, check.StatusMin, check.StatusMax)
	}
	return nil
}
