package controller

import (
	"context"
	"errors"
	"fmt"
	"moto/config"
	"moto/utils"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	gracefulDrainTimeout        = 10 * time.Second
	metricsHandlerDrainTimeout  = 5 * time.Second
	serverGlobalConnectionLimit = 4_096
	serverErrorBufferSize       = 257
	acceptRetryInitialDelay     = 5 * time.Millisecond
	acceptRetryMaximumDelay     = time.Second
)

type listenerState struct {
	key       string
	listener  net.Listener
	admission *listenerAdmission
}

// listenerAdmission outlives an individual listening socket. Keeping quota
// accounting separate prevents remove/re-add reloads from resetting limits
// while connections accepted by the previous socket are still active.
type listenerAdmission struct {
	mu     sync.Mutex
	perIP  map[netip.Addr]int
	active int
}

// Server owns every listener and active client connection. NewServer binds all
// configured addresses before any traffic is accepted, so startup is atomic.
type Server struct {
	current         atomic.Pointer[routingGeneration]
	listeners       []*listenerState
	listenersByKey  map[string]*listenerState
	admissionsByKey map[string]*listenerAdmission
	metricsListener net.Listener
	metricsServer   *http.Server
	metricsHandler  http.Handler
	ready           atomic.Bool
	stopCh          chan struct{}
	globalLimit     chan struct{}
	forceCtx        context.Context
	forceCancel     context.CancelFunc
	prewarmDialSem  chan struct{}
	trafficDials    *dialBulkhead
	serveCtx        context.Context
	errCh           chan error

	reloadMu             sync.Mutex
	lifecycleMu          sync.Mutex
	serveStarted         bool
	closed               bool
	closeOnce            sync.Once
	metricsHandlerMu     sync.Mutex
	metricsHandlerClosed bool
	metricsHandlerWG     sync.WaitGroup
	wg                   sync.WaitGroup
	active               sync.Map // net.Conn -> context.CancelFunc
	retiredMu            sync.Mutex
	retired              map[uint64]*routingGeneration
	retiredWatcherWG     sync.WaitGroup
}

// NewServer binds all rules. If one bind fails, every listener opened so far is
// closed and the caller receives an error.
func NewServer(rules []*config.Rule) (*Server, error) {
	return NewServerWithMetrics(rules, "")
}

// NewServerWithMetrics atomically binds every forwarding listener and, when
// requested, the loopback-only observability listener.
func NewServerWithMetrics(rules []*config.Rule, metricsListen string) (*Server, error) {
	if err := config.PrepareRuntimeRules(rules); err != nil {
		return nil, fmt.Errorf("validate server rules: %w", err)
	}
	if metricsListen != "" {
		if err := validateMetricsListen(metricsListen); err != nil {
			return nil, err
		}
	}
	forceCtx, forceCancel := context.WithCancel(context.Background())
	s := &Server{
		stopCh:          make(chan struct{}),
		globalLimit:     make(chan struct{}, serverGlobalConnectionLimit),
		forceCtx:        forceCtx,
		forceCancel:     forceCancel,
		prewarmDialSem:  make(chan struct{}, prewarmGlobalDialLimit),
		trafficDials:    newTrafficDialBulkhead(),
		listenersByKey:  make(map[string]*listenerState, len(rules)),
		admissionsByKey: make(map[string]*listenerAdmission, len(rules)),
		retired:         make(map[uint64]*routingGeneration),
	}
	listenerKeys := make([]string, 0, len(rules))
	for _, rule := range rules {
		listener, err := net.Listen("tcp", rule.Listen)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("listen rule %q at %s: %w", rule.Name, rule.Listen, err)
		}

		admission := &listenerAdmission{perIP: make(map[netip.Addr]int)}
		state := &listenerState{
			key:       runtimeListenerKey(rule.Listen, listener.Addr().String()),
			listener:  listener,
			admission: admission,
		}
		if _, duplicate := s.listenersByKey[state.key]; duplicate {
			_ = listener.Close()
			s.Close()
			return nil, fmt.Errorf("duplicate runtime listener key %q", state.key)
		}
		s.listeners = append(s.listeners, state)
		s.listenersByKey[state.key] = state
		s.admissionsByKey[state.key] = admission
		listenerKeys = append(listenerKeys, state.key)
	}
	generation, err := newRoutingGeneration(1, rules, listenerKeys, s.prewarmDialSem, s.trafficDials)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("prepare routing generation: %w", err)
	}
	s.current.Store(generation)
	if metricsListen != "" {
		listener, err := net.Listen("tcp", metricsListen)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("listen metrics at %s: %w", metricsListen, err)
		}
		s.metricsListener = listener
		s.metricsHandler = newObservabilityHandler(s.Ready, s.renderOperationalGauges)
		s.metricsServer = &http.Server{
			Handler:           http.HandlerFunc(s.serveObservability),
			ReadHeaderTimeout: 2 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
	}
	return s, nil
}

func validateMetricsListen(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid metrics listen %q: %w", value, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Unmap().IsLoopback() {
		return fmt.Errorf("metrics listen %q must use a numeric loopback address", value)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("invalid metrics listen %q: port must be between 0 and 65535", value)
	}
	return nil
}

// Serve starts accepting traffic and blocks until ctx is cancelled or a
// listener fails. Active connections receive a short drain window on shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		s.waitForRetiredGenerations()
		return nil
	}
	if s.serveStarted {
		s.lifecycleMu.Unlock()
		return errors.New("server Serve may only be called once")
	}
	s.serveStarted = true
	s.serveCtx = ctx
	s.errCh = make(chan error, max(len(s.listeners)+1, serverErrorBufferSize))
	if ctx.Err() != nil {
		s.lifecycleMu.Unlock()
		s.Close()
		s.waitForRetiredGenerations()
		return nil
	}

	// Listener goroutines and readiness are published while lifecycleMu is held.
	// Close therefore either wins before startup and prevents it entirely, or
	// waits until every startup goroutine has been registered before closing the
	// listeners. In particular, Close can never return before a later Ready=true
	// store or a newly launched accept/prewarm goroutine.
	if s.metricsListener != nil {
		utils.Logger.Info("开始监听观测端点",
			zap.String("listen", s.metricsListener.Addr().String()))
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.metricsServer.Serve(s.metricsListener); err != nil &&
				!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				select {
				case s.errCh <- fmt.Errorf("serve metrics: %w", err):
				default:
				}
			}
		}()
	}
	generation := s.current.Load()
	if generation != nil {
		generation.startBackground()
	}
	for _, state := range s.listeners {
		binding := generation.bindings[state.key]
		if binding == nil {
			continue
		}
		utils.Logger.Info("开始监听",
			zap.String("ruleName", binding.rule.Name),
			zap.String("listen", state.listener.Addr().String()),
			zap.String("mode", binding.rule.Mode))
		s.startListenerLocked(state)
	}
	s.ready.Store(true)
	s.lifecycleMu.Unlock()

	var serveErr error
	select {
	case <-ctx.Done():
	case <-s.stopCh:
	case serveErr = <-s.errCh:
	}

	s.ready.Store(false)
	s.Close()
	if generation := s.current.Load(); generation != nil {
		generation.retire()
	}

	drained := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(gracefulDrainTimeout):
		utils.Logger.Warn("等待连接退出超时，关闭剩余连接")
		s.closeActiveConnections()
		<-drained
	}
	// Release any cancellation callbacks left on the server context. When the
	// graceful path wins there are no live handlers; on the forced path this is
	// an idempotent second cancellation.
	if s.forceCancel != nil {
		s.forceCancel()
	}
	if !s.waitForMetricsHandlers(metricsHandlerDrainTimeout) {
		utils.Logger.Warn("等待观测请求退出超时")
	}
	s.waitForRetiredGenerations()

	return serveErr
}

func (s *Server) acceptLoop(ctx context.Context, state *listenerState) error {
	var retryDelay time.Duration
	for {
		conn, err := state.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if isRetryableAcceptError(err) {
				if retryDelay == 0 {
					retryDelay = acceptRetryInitialDelay
				} else {
					retryDelay *= 2
					if retryDelay > acceptRetryMaximumDelay {
						retryDelay = acceptRetryMaximumDelay
					}
				}
				utils.Logger.Warn("接收连接暂时失败，稍后重试",
					zap.String("listen", state.key),
					zap.Duration("retryAfter", retryDelay),
					zap.Error(err))
				timer := time.NewTimer(retryDelay)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return nil
				case <-timer.C:
				}
				continue
			}
			return fmt.Errorf("accept listener %q: %w", state.key, err)
		}
		retryDelay = 0
		generation, binding := s.acquireBinding(state.key)
		if generation == nil || binding == nil {
			_ = conn.Close()
			continue
		}
		rule := binding.rule

		clientIP, err := remoteIP(conn.RemoteAddr())
		if err != nil {
			metricConnectionRejected(rule.Name, rule.Mode, "invalid_remote_address")
			generation.release()
			utils.Logger.Warn("拒绝无法识别来源地址的连接",
				zap.String("ruleName", rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.Error(err))
			_ = conn.Close()
			continue
		}
		if rule.ProxyProtocol != nil && rule.ProxyProtocol.Accept && !rule.ProxyProtocol.Trusts(clientIP) {
			metricConnectionRejected(rule.Name, rule.Mode, "proxy_protocol")
			generation.release()
			utils.Logger.Warn("拒绝不可信的 PROXY protocol 上游",
				zap.String("ruleName", rule.Name),
				zap.String("peerIP", clientIP.String()))
			_ = conn.Close()
			continue
		}
		if !s.admitGlobal() {
			metricConnectionRejected(rule.Name, rule.Mode, "global_connection_limit")
			generation.release()
			utils.Logger.Warn("拒绝超过进程连接上限的连接",
				zap.String("ruleName", rule.Name),
				zap.String("clientIP", clientIP.String()))
			_ = conn.Close()
			continue
		}
		if !state.admission.reserveRule(rule) {
			s.releaseGlobal()
			metricConnectionRejected(rule.Name, rule.Mode, "connection_limit")
			generation.release()
			utils.Logger.Warn("拒绝超过连接上限的连接",
				zap.String("ruleName", rule.Name),
				zap.String("clientIP", clientIP.String()))
			_ = conn.Close()
			continue
		}

		// Listener shutdown leaves established streams alone during the graceful
		// window. Keep an independent cancellation handle so the forced-shutdown
		// path can also interrupt target selection and outbound dialing, not only
		// reads and writes on the inbound socket.
		rawConn := conn
		connectionCtx, cancelConnection, stopForcedClose := s.newConnectionContext(ctx, rawConn)
		s.active.Store(rawConn, context.CancelFunc(cancelConnection))
		s.wg.Add(1)
		go func(peerIP netip.Addr) {
			defer s.wg.Done()
			defer generation.release()
			defer stopForcedClose()
			defer cancelConnection()
			defer s.releaseGlobal()
			defer s.active.Delete(rawConn)
			defer rawConn.Close()
			assigned := false
			clientIP := peerIP
			defer func() {
				if assigned {
					state.admission.releaseRule(clientIP)
				} else {
					state.admission.releasePending()
				}
				s.maybeCleanupAdmission(state.key, state.admission)
			}()

			preparedConn, effectiveIP, proxyErr := prepareInboundProxyProtocol(rawConn, rule, peerIP)
			if proxyErr != nil {
				metricConnectionRejected(rule.Name, rule.Mode, "proxy_protocol")
				utils.Logger.Warn("拒绝无效的 PROXY protocol 连接",
					zap.String("ruleName", rule.Name),
					zap.String("peerIP", peerIP.String()),
					zap.Error(proxyErr))
				return
			}
			clientIP = effectiveIP
			if rule.Blocked(clientIP) || !rule.Allows(clientIP) {
				metricConnectionRejected(rule.Name, rule.Mode, "access_policy")
				utils.Logger.Info("拒绝访问策略命中的连接",
					zap.String("ruleName", rule.Name),
					zap.String("clientIP", clientIP.String()))
				return
			}
			if !state.admission.assignReservedIP(rule, clientIP) {
				metricConnectionRejected(rule.Name, rule.Mode, "connection_limit")
				utils.Logger.Warn("拒绝超过单 IP 连接上限的连接",
					zap.String("ruleName", rule.Name),
					zap.String("clientIP", clientIP.String()))
				return
			}
			assigned = true
			metricConnectionAccepted(rule.Name, rule.Mode)
			metricConnectionActive(rule.Name, rule.Mode, 1)
			defer metricConnectionActive(rule.Name, rule.Mode, -1)
			generation.runtime.dispatch(connectionCtx, preparedConn, rule)
		}(clientIP)
	}
}

func isRetryableAcceptError(err error) bool {
	if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func (s *Server) startListenerLocked(state *listenerState) {
	if s == nil || state == nil || s.serveCtx == nil || s.errCh == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.acceptLoop(s.serveCtx, state); err != nil {
			select {
			case s.errCh <- err:
			default:
			}
		}
	}()
}

func (s *Server) acquireBinding(key string) (*routingGeneration, *ruleBinding) {
	for {
		generation := s.current.Load()
		if generation == nil {
			return nil, nil
		}
		binding := generation.bindings[key]
		if binding == nil {
			return nil, nil
		}
		if !generation.tryAcquire() {
			if s.current.Load() == generation {
				return nil, nil
			}
			continue
		}
		if s.current.Load() == generation {
			return generation, binding
		}
		generation.release()
	}
}

func (s *Server) renderOperationalGauges(output *strings.Builder) {
	if s == nil {
		return
	}
	// Take a generation lease while lifecycleMu prevents the reload commit
	// point from moving. Keep that lock through the bounded gauge snapshot so
	// retirement cannot stop/clear the selected runtime halfway through it.
	s.lifecycleMu.Lock()
	generation := s.current.Load()
	acquired := !s.closed && generation != nil && generation.tryAcquire()
	retired := s.retiredCount()
	if acquired {
		generation.runtime.renderOperationalGauges(output)
		writeMetricHeader(output, "moto_routing_generation", "Currently published routing configuration generation.", "gauge")
		writeMetricSample(output, "moto_routing_generation", nil, strconv.FormatUint(generation.id, 10))
		generation.release()
	}
	s.lifecycleMu.Unlock()
	writeMetricHeader(output, "moto_routing_retired_generations", "Routing generations still draining established connections.", "gauge")
	writeMetricSample(output, "moto_routing_retired_generations", nil, strconv.Itoa(retired))
}

func (s *Server) trackRetired(generation *routingGeneration) {
	if s == nil || generation == nil {
		return
	}
	s.retiredMu.Lock()
	s.retired[generation.id] = generation
	s.retiredMu.Unlock()
	s.retiredWatcherWG.Add(1)
	go func() {
		defer s.retiredWatcherWG.Done()
		<-generation.done
		s.retiredMu.Lock()
		delete(s.retired, generation.id)
		s.retiredMu.Unlock()
		s.pruneAdmissions()
	}()
}

func (s *Server) retiredCount() int {
	if s == nil {
		return 0
	}
	s.retiredMu.Lock()
	s.pruneCompletedRetiredLocked()
	count := len(s.retired)
	s.retiredMu.Unlock()
	return count
}

func (s *Server) waitForRetiredGenerations() {
	if s == nil {
		return
	}
	for {
		s.retiredMu.Lock()
		s.pruneCompletedRetiredLocked()
		generations := make([]*routingGeneration, 0, len(s.retired))
		for _, generation := range s.retired {
			generations = append(generations, generation)
		}
		s.retiredMu.Unlock()
		if len(generations) == 0 {
			break
		}
		for _, generation := range generations {
			<-generation.done
		}
	}
	if generation := s.current.Load(); generation != nil {
		<-generation.done
	}
	s.retiredWatcherWG.Wait()
}

func (s *Server) admitGlobal() bool {
	if s == nil || s.globalLimit == nil {
		return true
	}
	select {
	case s.globalLimit <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseGlobal() {
	if s != nil && s.globalLimit != nil {
		<-s.globalLimit
	}
}

func (runtime *routingRuntime) dispatch(ctx context.Context, conn net.Conn, rule *config.Rule) {
	switch rule.Mode {
	case "normal":
		runtime.handleNormal(ctx, conn, rule)
	case "regex":
		runtime.handleRegexp(ctx, conn, rule)
	case "boost":
		runtime.handleBoost(ctx, conn, rule)
	case "roundrobin":
		runtime.handleRoundrobin(ctx, conn, rule)
	case "tls":
		runtime.handleTLS(ctx, conn, rule)
	default:
		utils.Logger.Error("拒绝未知运行模式",
			zap.String("ruleName", rule.Name),
			zap.String("mode", rule.Mode))
	}
}

// Close stops accepting new connections. In-flight connections are drained by
// Serve and force-closed only after gracefulDrainTimeout.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.lifecycleMu.Lock()
	var generation *routingGeneration
	s.closeOnce.Do(func() {
		s.closed = true
		s.ready.Store(false)
		s.closeMetricsHandlers()
		if s.stopCh != nil {
			close(s.stopCh)
		}
		for _, state := range s.listeners {
			_ = state.listener.Close()
		}
		if s.metricsServer != nil {
			_ = s.metricsServer.Close()
		}
		// http.Server.Close only knows listeners after Serve has registered
		// them. Always close our listener explicitly so Close-before-Serve does
		// not leak the bound port.
		if s.metricsListener != nil {
			_ = s.metricsListener.Close()
		}
		generation = s.current.Load()
	})
	s.lifecycleMu.Unlock()
	if generation != nil {
		generation.retire()
	}
}

func (s *Server) serveObservability(writer http.ResponseWriter, request *http.Request) {
	s.metricsHandlerMu.Lock()
	if s.metricsHandlerClosed || s.metricsHandler == nil {
		s.metricsHandlerMu.Unlock()
		http.Error(writer, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	handler := s.metricsHandler
	s.metricsHandlerWG.Add(1)
	s.metricsHandlerMu.Unlock()
	defer s.metricsHandlerWG.Done()
	handler.ServeHTTP(writer, request)
}

func (s *Server) closeMetricsHandlers() {
	s.metricsHandlerMu.Lock()
	s.metricsHandlerClosed = true
	s.metricsHandlerMu.Unlock()
}

func (s *Server) waitForMetricsHandlers(timeout time.Duration) bool {
	if s.metricsHandler == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		s.metricsHandlerWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Ready reports whether all configured listeners have started and shutdown has
// not begun. It backs the readiness endpoint and is safe for concurrent use.
func (s *Server) Ready() bool {
	return s != nil && s.ready.Load()
}

func (s *Server) closeActiveConnections() {
	// Cancel the broadcast first. A connection accepted just before listener
	// shutdown but registered after the Range below will observe the already
	// cancelled context in newConnectionContext and close itself immediately.
	if s.forceCancel != nil {
		s.forceCancel()
	}
	s.active.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok && cancel != nil {
			cancel()
		}
		_ = key.(net.Conn).Close()
		return true
	})
}

func (s *Server) newConnectionContext(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc, func() bool) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stopForcedClose := func() bool { return false }
	if s != nil && s.forceCtx != nil {
		forceClose := func() {
			cancel()
			if conn != nil {
				_ = conn.Close()
			}
		}
		stopForcedClose = context.AfterFunc(s.forceCtx, forceClose)
		// AfterFunc runs asynchronously for an already-cancelled context. Close
		// synchronously as well so a late registration cannot start useful work.
		if s.forceCtx.Err() != nil {
			forceClose()
		}
	}
	return ctx, cancel, stopForcedClose
}

func (s *listenerAdmission) reserveRule(rule *config.Rule) bool {
	if s == nil || rule == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rule.MaxConnections > 0 && s.active >= rule.MaxConnections {
		return false
	}
	s.active++
	return true
}

func (s *listenerAdmission) assignReservedIP(rule *config.Rule, ip netip.Addr) bool {
	if s == nil || rule == nil || !ip.IsValid() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if max := rule.MaxConnectionsPerIP; max > 0 && s.perIP[ip] >= max {
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *listenerAdmission) releasePending() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.active > 0 {
		s.active--
	}
	s.mu.Unlock()
}

func (s *listenerAdmission) releaseRule(ip netip.Addr) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.active > 0 {
		s.active--
	}
	if s.perIP[ip] <= 1 {
		delete(s.perIP, ip)
	} else {
		s.perIP[ip]--
	}
	s.mu.Unlock()
}

func (s *listenerAdmission) idle() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	idle := s.active == 0
	s.mu.Unlock()
	return idle
}

func (s *Server) maybeCleanupAdmission(key string, admission *listenerAdmission) {
	if s == nil || admission == nil {
		return
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.admissionsByKey[key] != admission || !admission.idle() {
		return
	}
	if current := s.current.Load(); current != nil {
		if _, used := current.bindings[key]; used {
			return
		}
	}
	s.retiredMu.Lock()
	defer s.retiredMu.Unlock()
	for _, generation := range s.retired {
		select {
		case <-generation.done:
			continue
		default:
		}
		if _, used := generation.bindings[key]; used {
			return
		}
	}
	delete(s.admissionsByKey, key)
}

func (s *Server) pruneAdmissions() {
	if s == nil {
		return
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	used := make(map[string]struct{})
	if current := s.current.Load(); current != nil {
		for key := range current.bindings {
			used[key] = struct{}{}
		}
	}
	s.retiredMu.Lock()
	for _, generation := range s.retired {
		select {
		case <-generation.done:
			continue
		default:
		}
		for key := range generation.bindings {
			used[key] = struct{}{}
		}
	}
	s.retiredMu.Unlock()
	for key, admission := range s.admissionsByKey {
		if _, keep := used[key]; !keep && admission.idle() {
			delete(s.admissionsByKey, key)
		}
	}
}

func (s *Server) pruneCompletedRetiredLocked() {
	for id, generation := range s.retired {
		select {
		case <-generation.done:
			delete(s.retired, id)
		default:
		}
	}
}

func runtimeListenerKey(configured, actual string) string {
	_, portText, err := net.SplitHostPort(configured)
	if err != nil {
		return configured
	}
	port, err := strconv.Atoi(portText)
	if err == nil && port == 0 {
		return actual
	}
	return configured
}

func remoteIP(addr net.Addr) (netip.Addr, error) {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip, ok := netip.AddrFromSlice(tcpAddr.IP)
		if !ok {
			return netip.Addr{}, fmt.Errorf("invalid TCP IP %q", tcpAddr.IP)
		}
		return ip.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ip.Unmap(), nil
}
