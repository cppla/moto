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
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	gracefulDrainTimeout        = 10 * time.Second
	metricsHandlerDrainTimeout  = 5 * time.Second
	serverGlobalConnectionLimit = 4_096
)

type listenerState struct {
	rule     *config.Rule
	listener net.Listener
	limit    chan struct{}

	mu    sync.Mutex
	perIP map[netip.Addr]int
}

// Server owns every listener and active client connection. NewServer binds all
// configured addresses before any traffic is accepted, so startup is atomic.
type Server struct {
	listeners       []*listenerState
	metricsListener net.Listener
	metricsServer   *http.Server
	metricsHandler  http.Handler
	ready           atomic.Bool
	stopCh          chan struct{}
	globalLimit     chan struct{}
	forceCtx        context.Context
	forceCancel     context.CancelFunc

	lifecycleMu          sync.Mutex
	serveStarted         bool
	closed               bool
	closeOnce            sync.Once
	metricsHandlerMu     sync.Mutex
	metricsHandlerClosed bool
	metricsHandlerWG     sync.WaitGroup
	wg                   sync.WaitGroup
	active               sync.Map // net.Conn -> context.CancelFunc
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
		stopCh:      make(chan struct{}),
		globalLimit: make(chan struct{}, serverGlobalConnectionLimit),
		forceCtx:    forceCtx,
		forceCancel: forceCancel,
	}
	for _, rule := range rules {
		listener, err := net.Listen("tcp", rule.Listen)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("listen rule %q at %s: %w", rule.Name, rule.Listen, err)
		}

		state := &listenerState{
			rule:     rule,
			listener: listener,
			perIP:    make(map[netip.Addr]int),
		}
		if rule.MaxConnections > 0 {
			state.limit = make(chan struct{}, min(rule.MaxConnections, serverGlobalConnectionLimit))
		}
		s.listeners = append(s.listeners, state)
	}
	if metricsListen != "" {
		listener, err := net.Listen("tcp", metricsListen)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("listen metrics at %s: %w", metricsListen, err)
		}
		setMetricsGaugeRenderer(renderOperationalGauges)
		s.metricsListener = listener
		s.metricsHandler = newObservabilityHandler(s.Ready)
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

	errCh := make(chan error, len(s.listeners)+1)
	s.lifecycleMu.Lock()
	if s.closed {
		s.lifecycleMu.Unlock()
		return nil
	}
	if s.serveStarted {
		s.lifecycleMu.Unlock()
		return errors.New("server Serve may only be called once")
	}
	s.serveStarted = true
	if ctx.Err() != nil {
		s.lifecycleMu.Unlock()
		s.Close()
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
				case errCh <- fmt.Errorf("serve metrics: %w", err):
				default:
				}
			}
		}()
	}
	for _, state := range s.listeners {
		if state.rule.Prewarm {
			initPrewarm(state.rule)
		}
		utils.Logger.Info("开始监听",
			zap.String("ruleName", state.rule.Name),
			zap.String("listen", state.listener.Addr().String()),
			zap.String("mode", state.rule.Mode))
		s.wg.Add(1)
		go func(st *listenerState) {
			defer s.wg.Done()
			if err := s.acceptLoop(ctx, st); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}(state)
	}
	s.ready.Store(true)
	s.lifecycleMu.Unlock()

	var serveErr error
	select {
	case <-ctx.Done():
	case <-s.stopCh:
	case serveErr = <-errCh:
	}

	s.ready.Store(false)
	s.Close()
	shutdownPrewarm()

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
	clearRuntimeRoutingState(s.rules())

	return serveErr
}

func (s *Server) acceptLoop(ctx context.Context, state *listenerState) error {
	for {
		conn, err := state.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept rule %q: %w", state.rule.Name, err)
		}

		clientIP, err := remoteIP(conn.RemoteAddr())
		if err != nil {
			metricConnectionRejected(state.rule.Name, state.rule.Mode, "invalid_remote_address")
			utils.Logger.Warn("拒绝无法识别来源地址的连接",
				zap.String("ruleName", state.rule.Name),
				zap.String("remoteAddr", conn.RemoteAddr().String()),
				zap.Error(err))
			_ = conn.Close()
			continue
		}
		if state.rule.Blocked(clientIP) || !state.rule.Allows(clientIP) {
			metricConnectionRejected(state.rule.Name, state.rule.Mode, "access_policy")
			utils.Logger.Info("拒绝访问策略命中的连接",
				zap.String("ruleName", state.rule.Name),
				zap.String("clientIP", clientIP.String()))
			_ = conn.Close()
			continue
		}
		if !s.admitGlobal() {
			metricConnectionRejected(state.rule.Name, state.rule.Mode, "global_connection_limit")
			utils.Logger.Warn("拒绝超过进程连接上限的连接",
				zap.String("ruleName", state.rule.Name),
				zap.String("clientIP", clientIP.String()))
			_ = conn.Close()
			continue
		}
		if !state.admit(clientIP) {
			s.releaseGlobal()
			metricConnectionRejected(state.rule.Name, state.rule.Mode, "connection_limit")
			utils.Logger.Warn("拒绝超过连接上限的连接",
				zap.String("ruleName", state.rule.Name),
				zap.String("clientIP", clientIP.String()))
			_ = conn.Close()
			continue
		}

		metricConnectionAccepted(state.rule.Name, state.rule.Mode)
		metricConnectionActive(state.rule.Name, state.rule.Mode, 1)
		// Listener shutdown leaves established streams alone during the graceful
		// window. Keep an independent cancellation handle so the forced-shutdown
		// path can also interrupt target selection and outbound dialing, not only
		// reads and writes on the inbound socket.
		connectionCtx, cancelConnection, stopForcedClose := s.newConnectionContext(ctx, conn)
		s.active.Store(conn, context.CancelFunc(cancelConnection))
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer stopForcedClose()
			defer cancelConnection()
			defer s.releaseGlobal()
			defer metricConnectionActive(state.rule.Name, state.rule.Mode, -1)
			defer s.active.Delete(conn)
			defer state.release(clientIP)
			defer conn.Close()
			dispatch(connectionCtx, conn, state.rule)
		}()
	}
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

func dispatch(ctx context.Context, conn net.Conn, rule *config.Rule) {
	switch rule.Mode {
	case "normal":
		HandleNormal(ctx, conn, rule)
	case "regex":
		HandleRegexp(ctx, conn, rule)
	case "boost":
		HandleBoost(ctx, conn, rule)
	case "roundrobin":
		HandleRoundrobin(ctx, conn, rule)
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
	defer s.lifecycleMu.Unlock()
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
	})
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

func (s *Server) rules() []*config.Rule {
	rules := make([]*config.Rule, 0, len(s.listeners))
	for _, state := range s.listeners {
		if state != nil && state.rule != nil {
			rules = append(rules, state.rule)
		}
	}
	return rules
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

func (s *listenerState) admit(ip netip.Addr) bool {
	if s.limit != nil {
		select {
		case s.limit <- struct{}{}:
		default:
			return false
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if max := s.rule.MaxConnectionsPerIP; max > 0 && s.perIP[ip] >= max {
		if s.limit != nil {
			<-s.limit
		}
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *listenerState) release(ip netip.Addr) {
	s.mu.Lock()
	if s.perIP[ip] <= 1 {
		delete(s.perIP, ip)
	} else {
		s.perIP[ip]--
	}
	s.mu.Unlock()
	if s.limit != nil {
		<-s.limit
	}
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
