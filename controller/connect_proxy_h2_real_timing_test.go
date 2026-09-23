package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"moto/config"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
)

// TestHTTP2RealRoutePingTiming is opt-in and never changes the production
// defaults. Fault injection is restricted to a disposable network namespace
// owned by a Docker container. Neither errors nor results include credentials,
// endpoint names, or payload contents.
func TestHTTP2RealRoutePingTiming(t *testing.T) {
	privatePath := os.Getenv("MOTO_H2_REAL_CONFIG")
	if privatePath == "" {
		t.Skip("set MOTO_H2_REAL_CONFIG to run the private-route timing experiment")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	result := h2RealTimingResult{Profile: os.Getenv("MOTO_H2_REAL_PROFILE"), Streams: make([]h2RealStreamResult, 2)}
	result.Direction = "none"
	result.OuterNetwork = "tcp4"
	if result.Profile == "" {
		result.Profile = "normal"
	}
	defer func() {
		result.TotalSeconds = time.Since(started).Seconds()
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Error("result_encode_failed")
			return
		}
		fmt.Printf("MOTO_H2_REAL_RESULT %s\n", encoded)
	}()
	fail := func(class string) {
		result.Error = class
		t.Fatal(class)
	}
	var err error
	result.OutageAfterSeconds, err = h2RealParseOutageAfter(os.Getenv("MOTO_H2_REAL_OUTAGE_AFTER_SECONDS"))
	if err != nil {
		fail("invalid_outage_after_seconds")
	}
	result.TargetIndex, err = strconv.Atoi(os.Getenv("MOTO_H2_REAL_TARGET"))
	if err != nil || result.TargetIndex < 0 {
		fail("invalid_target_index")
	}
	result.IdleSeconds, err = strconv.Atoi(os.Getenv("MOTO_H2_REAL_IDLE"))
	if err != nil || (result.IdleSeconds != 10 && result.IdleSeconds != 15) {
		fail("invalid_idle_seconds")
	}
	result.PingSeconds, err = strconv.Atoi(os.Getenv("MOTO_H2_REAL_PING"))
	if err != nil || (result.PingSeconds != 5 && result.PingSeconds != 10) {
		fail("invalid_ping_seconds")
	}
	outage := time.Duration(0)
	switch result.Profile {
	case "normal", "blackhole", "weak":
	case "outage4", "outage8", "outage14", "outage18":
		seconds, _ := strconv.Atoi(strings.TrimPrefix(result.Profile, "outage"))
		outage = time.Duration(seconds) * time.Second
	default:
		fail("invalid_profile")
	}
	var injector *h2RealNetem
	if result.Profile != "normal" {
		result.Direction = "egress_only"
		if result.Profile == "blackhole" || outage > 0 {
			result.Direction = "bidirectional"
		}
		injector, err = h2RealNewNetem(ctx)
		if err != nil {
			fail("unsafe_or_unavailable_injection_environment")
		}
		defer func() {
			if err := injector.clear(); err != nil {
				result.Error = "injection_cleanup_failed"
				t.Error(result.Error)
			}
		}()
	}
	settings, err := config.Load(privatePath)
	if err != nil {
		fail("private_config_invalid")
	}
	var selected *config.Rule
	for _, rule := range settings.Rules {
		if config.IsConnectProtocol(rule.Protocol) {
			selected = rule
			break
		}
	}
	if selected == nil || result.TargetIndex >= len(selected.Targets) {
		fail("private_target_not_found")
	}
	target := selected.Targets[result.TargetIndex]
	if target.ConnectProxy == nil {
		fail("private_target_not_connect_proxy")
	}
	destination := os.Getenv("MOTO_H2_REAL_DESTINATION")
	originHost, originPort, err := net.SplitHostPort(destination)
	if err != nil || net.ParseIP(originHost) == nil || originPort != "443" {
		fail("origin_must_be_numeric_ip_port_443")
	}
	pem, err := os.ReadFile(os.Getenv("MOTO_H2_REAL_ORIGIN_CA"))
	if err != nil {
		fail("origin_ca_unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fail("origin_ca_invalid")
	}
	var stats h2RealWireStats
	stats.started = started
	var dialAttempts, handshakes, lostPing, payload atomic.Int64
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.ReadIdleTimeout = time.Duration(result.IdleSeconds) * time.Second
		transport.PingTimeout = time.Duration(result.PingSeconds) * time.Second
		dial := transport.DialTLSContext
		transport.DialTLSContext = func(ctx context.Context, _ string, address string, cfg *tls.Config) (net.Conn, error) {
			dialAttempts.Add(1)
			// Keep every comparison on IPv4 so the explicitly installed IPv4
			// INPUT rule blocks the complete return path. The original hostname
			// and TLS configuration still drive certificate verification.
			conn, err := dial(ctx, "tcp4", address, cfg)
			if err != nil {
				return nil, err
			}
			id := handshakes.Add(1)
			stats.remote(conn.RemoteAddr())
			return &h2RealWireConn{Conn: conn, stats: &stats, physical: id, outgoing: h2RealFrameParser{preface: len(xhttp2.ClientPreface)}}, nil
		}
		countError := transport.CountError
		transport.CountError = func(class string) {
			if class == "conn_close_lost_ping" {
				lostPing.Add(1)
				stats.event("lost_ping", 0)
			}
			if countError != nil {
				countError(class)
			}
		}
		return transport
	})
	defer manager.closeIdle()
	defer func() {
		result.PhysicalDialAttempts = dialAttempts.Load()
		result.PhysicalHandshakes = handshakes.Load()
		result.LostPing = lostPing.Load()
		result.PayloadBytes = payload.Load()
		result.Wire = stats.snapshot()
	}()
	// A fixed configured UA makes profile comparisons use the same TLS style.
	if len(selected.UserAgent) > 0 {
		ctx = withConnectProxyUserAgent(ctx, selected.UserAgent[0])
	}
	open := func() (net.Conn, *tls.Conn, error) {
		setup, stop := context.WithTimeout(ctx, 12*time.Second)
		defer stop()
		raw, err := manager.dial(setup, target, destination)
		if err != nil {
			return nil, nil, err
		}
		secured := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: originHost, RootCAs: roots})
		if err := secured.HandshakeContext(setup); err != nil {
			_ = raw.Close()
			return nil, nil, err
		}
		return raw, secured, nil
	}
	raw := make([]net.Conn, 2)
	secured := make([]*tls.Conn, 2)
	for i := range raw {
		raw[i], secured[i], err = open()
		if err != nil {
			fail("initial_connect_" + h2RealErrorClass(err))
		}
		defer raw[i].Close()
		if err := h2RealEcho(ctx, secured[i], raw[i], 1024, &payload); err != nil {
			fail("initial_echo_" + h2RealErrorClass(err))
		}
	}
	result.InitialSharedPhysical = handshakes.Load() == 1
	if !result.InitialSharedPhysical {
		fail("initial_tunnels_not_one_physical_connection")
	}
	// Unlike business data, successful PING ACKs do not invalidate the idle
	// period: x/net is expected to continue periodic probes while tunnels idle.
	lastBusiness := time.Now()
	result.LastBusinessSeconds = lastBusiness.Sub(started).Seconds()
	if result.Profile == "weak" {
		if err := injector.set(ctx, "delay", "200ms", "loss", "2%", "rate", "256kbit"); err != nil {
			fail("injection_failed")
		}
		result.FaultStartSeconds = time.Since(started).Seconds()
		for i := range raw {
			if err := h2RealEcho(ctx, secured[i], raw[i], 4096, &payload); err != nil {
				fail("weak_echo_" + h2RealErrorClass(err))
			}
		}
		lastBusiness = time.Now()
		result.LastBusinessSeconds = lastBusiness.Sub(started).Seconds()
	}
	quietBaseline := stats.snapshot()
	reads := make([]chan h2RealReadResult, len(raw))
	for i := range raw {
		reads[i] = make(chan h2RealReadResult, 1)
		go func(i int) {
			var one [1]byte
			_, err := io.ReadFull(secured[i], one[:])
			reads[i] <- h2RealReadResult{err: err, value: one[0], at: time.Since(started).Seconds()}
		}(i)
	}
	if result.Profile == "blackhole" || outage > 0 {
		if outage > 0 && !h2RealWaitUntil(ctx, lastBusiness.Add(time.Duration(result.OutageAfterSeconds*float64(time.Second)))) {
			fail("experiment_deadline")
		}
		if err := injector.set(ctx, "loss", "100%"); err != nil {
			fail("injection_failed")
		}
		if err := injector.blockInbound(ctx); err != nil {
			fail("inbound_injection_failed")
		}
		result.FaultStartSeconds = time.Since(started).Seconds()
		result.LastInboundAtFault = stats.snapshot().LastInboundSecond
	}
	quietUntil := lastBusiness.Add(time.Duration(result.IdleSeconds+result.PingSeconds+2) * time.Second)
	if result.Profile == "normal" || result.Profile == "weak" {
		// Equal observation windows make healthy-path comparisons fair. This
		// exceeds the slowest 15+10 pair and observes its first automatic ACK.
		quietUntil = lastBusiness.Add(32 * time.Second)
	}
	if outage > 0 {
		if !h2RealWaitUntil(ctx, started.Add(time.Duration(result.FaultStartSeconds*float64(time.Second))).Add(outage)) {
			fail("experiment_deadline")
		}
		if err := injector.clear(); err != nil {
			fail("injection_cleanup_failed")
		}
		result.FaultEndSeconds = time.Since(started).Seconds()
		// Leave room for TCP retransmissions after restoring the path. A
		// recovered link need not deliver the already-lost PING immediately.
		if after := time.Now().Add(4 * time.Second); after.After(quietUntil) {
			quietUntil = after
		}
	}
	if !h2RealWaitUntil(ctx, quietUntil) {
		fail("experiment_deadline")
	}
	// Freeze the idle evidence before any echo probe, RST_STREAM, cleanup,
	// or recovery CONNECT can create unrelated PING/ACK activity.
	result.QuietWindowEndSeconds = time.Since(started).Seconds()
	result.QuietWire = stats.snapshot()
	result.QuietWire.Pings -= quietBaseline.Pings
	result.QuietWire.PingACKs -= quietBaseline.PingACKs
	quietEvents := result.QuietWire.Events[:0]
	for _, event := range result.QuietWire.Events {
		if event.Seconds >= result.LastBusinessSeconds {
			quietEvents = append(quietEvents, event)
		}
	}
	result.QuietWire.Events = quietEvents
	if result.Profile == "normal" && (result.QuietWire.Pings < 1 || result.QuietWire.PingACKs < 1) {
		fail("normal_quiet_window_no_automatic_ping_ack")
	}
	for i := range raw {
		select {
		case read := <-reads[i]:
			result.Streams[i] = h2RealStreamResult{State: "closed", ClosedSeconds: read.at, Error: h2RealErrorClass(read.err)}
			if read.err == nil {
				fail("unexpected_unsolicited_origin_payload")
			}
		default:
			result.Streams[i].State = "pending"
		}
	}
	if result.Profile == "blackhole" {
		if result.Streams[0].State != "closed" || result.Streams[1].State != "closed" || lostPing.Load() != 1 {
			fail("blackhole_not_closed_once_by_lost_ping")
		}
		if err := injector.clear(); err != nil {
			fail("injection_cleanup_failed")
		}
		result.FaultEndSeconds = time.Since(started).Seconds()
	}
	// Existing streams are probed before new CONNECTs. A new response on the
	// same H2 physical connection would otherwise mask a lost idle PING.
	for i := range raw {
		if result.Streams[i].State != "pending" {
			continue
		}
		probeCtx, stop := context.WithTimeout(ctx, 8*time.Second)
		write := make(chan error, 1)
		go func(i int) { _, err := secured[i].Write([]byte{0xa5}); write <- err }(i)
		select {
		case err := <-write:
			if err == nil {
				payload.Add(1)
			}
		case <-probeCtx.Done():
			// Closing the raw stream causes the pending reader to return an
			// error. That error is our probe timeout, not an independently
			// observed H2/PING closure, so never reclassify it below.
			result.Streams[i] = h2RealStreamResult{State: "probe_timeout", Error: "deadline"}
			_ = raw[i].Close()
			stop()
			continue
		}
		select {
		case read := <-reads[i]:
			if read.err == nil && read.value == 0xa5 {
				payload.Add(1)
				result.Streams[i] = h2RealStreamResult{State: "survived", EchoSeconds: read.at}
			} else {
				result.Streams[i] = h2RealStreamResult{State: "closed", ClosedSeconds: read.at, Error: h2RealErrorClass(read.err)}
			}
		case <-probeCtx.Done():
			_ = raw[i].Close()
			result.Streams[i] = h2RealStreamResult{State: "probe_timeout", Error: "deadline"}
		}
		stop()
	}
	if result.Profile == "weak" {
		if err := injector.clear(); err != nil {
			fail("injection_cleanup_failed")
		}
		result.FaultEndSeconds = time.Since(started).Seconds()
	}
	for _, conn := range raw {
		_ = conn.Close()
	}
	recoveryStart := time.Now()
	recoveredRaw, recoveredTLS, err := open()
	if err != nil {
		fail("recovery_connect_" + h2RealErrorClass(err))
	}
	defer recoveredRaw.Close()
	if err := h2RealEcho(ctx, recoveredTLS, recoveredRaw, 1024, &payload); err != nil {
		fail("recovery_echo_" + h2RealErrorClass(err))
	}
	result.RecoverySeconds = time.Since(recoveryStart).Seconds()
	result.RecoveryOK = true
	if lostPing.Load() > 0 {
		before := lostPing.Load()
		if !h2RealWaitUntil(ctx, time.Now().Add(time.Duration(result.IdleSeconds+1)*time.Second)) {
			fail("late_callback_observation_deadline")
		}
		result.LateCallbackChecked = true
		if lostPing.Load() != before {
			fail("duplicate_or_replacement_lost_ping")
		}
	}
	if payload.Load() > 1<<20 {
		fail("payload_budget_exceeded")
	}
	// Temporary loss, and even the weak profile, may legitimately retire a
	// shared connection. Report the outcome, not a predetermined recommendation.
	if result.Profile == "normal" && (result.Streams[0].State != "survived" || result.Streams[1].State != "survived") {
		fail("normal_path_did_not_survive")
	}
	if result.Profile == "normal" && handshakes.Load() != 1 {
		fail("normal_recovery_did_not_reuse_physical_connection")
	}
}

type h2RealTimingResult struct {
	TargetIndex           int                  `json:"target_index"`
	IdleSeconds           int                  `json:"idle_seconds"`
	PingSeconds           int                  `json:"ping_seconds"`
	Profile               string               `json:"profile"`
	OutageAfterSeconds    float64              `json:"outage_after_seconds"`
	Direction             string               `json:"fault_direction"`
	OuterNetwork          string               `json:"outer_network"`
	InitialSharedPhysical bool                 `json:"initial_shared_physical"`
	PhysicalDialAttempts  int64                `json:"physical_dial_attempts"`
	PhysicalHandshakes    int64                `json:"physical_handshakes"`
	LostPing              int64                `json:"lost_ping"`
	PayloadBytes          int64                `json:"payload_bytes"`
	LastBusinessSeconds   float64              `json:"last_business_seconds"`
	QuietWindowEndSeconds float64              `json:"quiet_window_end_seconds"`
	FaultStartSeconds     float64              `json:"fault_start_seconds,omitempty"`
	LastInboundAtFault    float64              `json:"last_inbound_at_fault_seconds,omitempty"`
	FaultEndSeconds       float64              `json:"fault_end_seconds,omitempty"`
	RecoveryOK            bool                 `json:"recovery_ok"`
	LateCallbackChecked   bool                 `json:"late_callback_checked"`
	RecoverySeconds       float64              `json:"recovery_seconds"`
	TotalSeconds          float64              `json:"total_seconds"`
	Streams               []h2RealStreamResult `json:"streams"`
	Wire                  h2RealWireSnapshot   `json:"wire"`
	QuietWire             h2RealWireSnapshot   `json:"quiet_wire"`
	Error                 string               `json:"error,omitempty"`
}

type h2RealStreamResult struct {
	State         string  `json:"state"`
	ClosedSeconds float64 `json:"closed_seconds,omitempty"`
	EchoSeconds   float64 `json:"echo_seconds,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type h2RealReadResult struct {
	err   error
	value byte
	at    float64
}

func h2RealParseOutageAfter(value string) (float64, error) {
	if value == "" {
		return 9.5, nil
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 20 {
		return 0, errors.New("invalid outage start offset")
	}
	return seconds, nil
}

func h2RealErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	var status *connectProxyStatusError
	if errors.As(err, &status) {
		return "upstream_status"
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return "certificate"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout"
	}
	return "transport"
}

func h2RealWaitUntil(ctx context.Context, until time.Time) bool {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func h2RealEcho(ctx context.Context, secured *tls.Conn, raw net.Conn, size int, total *atomic.Int64) error {
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		payload := bytes.Repeat([]byte{0x4d}, size)
		n, err := secured.Write(payload)
		total.Add(int64(n))
		if err == nil {
			response := make([]byte, size)
			n, err = io.ReadFull(secured, response)
			total.Add(int64(n))
			if err == nil && !bytes.Equal(response, payload) {
				err = errors.New("echo integrity failure")
			}
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-probe.Done():
		_ = raw.Close()
		return probe.Err()
	}
}

type h2RealNetem struct {
	installed bool
	chain     bool
	attached  bool
}

func h2RealNewNetem(ctx context.Context) (*h2RealNetem, error) {
	if os.Getenv("MOTO_H2_REAL_ISOLATED") != "1" {
		return nil, errors.New("isolation not acknowledged")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return nil, errors.New("not a Docker container")
	}
	output, err := exec.CommandContext(ctx, "tc", "-json", "qdisc", "show", "dev", "eth0").Output()
	if err != nil {
		return nil, err
	}
	var disciplines []struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(output, &disciplines); err != nil {
		return nil, err
	}
	for _, discipline := range disciplines {
		if discipline.Kind != "noqueue" {
			return nil, errors.New("preexisting nondefault discipline")
		}
	}
	return &h2RealNetem{}, nil
}

func (n *h2RealNetem) set(ctx context.Context, profile ...string) error {
	op := "add"
	if n.installed {
		op = "replace"
	}
	args := []string{"qdisc", op, "dev", "eth0", "root", "handle", "7331:", "netem"}
	args = append(args, profile...)
	command, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(command, "tc", args...).Run(); err != nil {
		return err
	}
	n.installed = true
	return nil
}

func (n *h2RealNetem) clear() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if n.attached {
		if err := exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-j", "MOTO_H2_TIMING").Run(); err != nil {
			return err
		}
		n.attached = false
	}
	if n.chain {
		if err := exec.CommandContext(ctx, "iptables", "-F", "MOTO_H2_TIMING").Run(); err != nil {
			return err
		}
		if err := exec.CommandContext(ctx, "iptables", "-X", "MOTO_H2_TIMING").Run(); err != nil {
			return err
		}
		n.chain = false
	}
	if !n.installed {
		return nil
	}
	if err := exec.CommandContext(ctx, "tc", "qdisc", "del", "dev", "eth0", "root", "handle", "7331:").Run(); err != nil {
		return err
	}
	n.installed = false
	return nil
}

func (n *h2RealNetem) blockInbound(ctx context.Context) error {
	// A new named chain must be created successfully; never borrow or modify
	// a preexisting rule. The caller has already checked Docker isolation.
	if err := exec.CommandContext(ctx, "iptables", "-N", "MOTO_H2_TIMING").Run(); err != nil {
		return err
	}
	n.chain = true
	if err := exec.CommandContext(ctx, "iptables", "-A", "MOTO_H2_TIMING", "-j", "DROP").Run(); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "1", "-j", "MOTO_H2_TIMING").Run(); err != nil {
		return err
	}
	n.attached = true
	return nil
}

type h2RealFrameEvent struct {
	Kind     string  `json:"kind"`
	Physical int64   `json:"physical"`
	Seconds  float64 `json:"seconds"`
}

type h2RealWireSnapshot struct {
	Pings             int                `json:"pings"`
	PingACKs          int                `json:"ping_acks"`
	LastInboundSecond float64            `json:"last_inbound_seconds"`
	RemoteFamilies    []string           `json:"remote_ip_families"`
	Events            []h2RealFrameEvent `json:"events"`
}

type h2RealWireStats struct {
	mu      sync.Mutex
	started time.Time
	data    h2RealWireSnapshot
}

func (s *h2RealWireStats) event(kind string, physical int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Since(s.started).Seconds()
	if kind == "inbound" {
		s.data.LastInboundSecond = now
		return
	}
	if kind == "ping" {
		s.data.Pings++
	}
	if kind == "ping_ack" {
		s.data.PingACKs++
	}
	if len(s.data.Events) < 64 {
		s.data.Events = append(s.data.Events, h2RealFrameEvent{Kind: kind, Physical: physical, Seconds: now})
	}
}

func (s *h2RealWireStats) snapshot() h2RealWireSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := s.data
	copy.Events = append([]h2RealFrameEvent(nil), s.data.Events...)
	copy.RemoteFamilies = append([]string(nil), s.data.RemoteFamilies...)
	return copy
}

func (s *h2RealWireStats) remote(address net.Addr) {
	family := "unknown"
	if tcp, ok := address.(*net.TCPAddr); ok {
		family = "ipv6"
		if tcp.IP.To4() != nil {
			family = "ipv4"
		}
	}
	s.mu.Lock()
	s.data.RemoteFamilies = append(s.data.RemoteFamilies, family)
	s.mu.Unlock()
}

// The adapter sits above the verified TLS layer and retains only H2 frame
// headers. Neither DATA nor HPACK payload is buffered or emitted.
type h2RealWireConn struct {
	net.Conn
	stats              *h2RealWireStats
	physical           int64
	readMu, writeMu    sync.Mutex
	incoming, outgoing h2RealFrameParser
	closed             sync.Once
}

func (c *h2RealWireConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.readMu.Lock()
		c.incoming.feed(buffer[:n], func(kind, flags byte) {
			c.stats.event("inbound", c.physical)
			if kind == 6 && flags&1 != 0 {
				c.stats.event("ping_ack", c.physical)
			}
		})
		c.readMu.Unlock()
	}
	return n, err
}

func (c *h2RealWireConn) Write(buffer []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.Conn.Write(buffer)
	c.outgoing.feed(buffer[:n], func(kind, flags byte) {
		if kind == 6 && flags&1 == 0 {
			c.stats.event("ping", c.physical)
		}
	})
	return n, err
}

func (c *h2RealWireConn) Close() error {
	c.closed.Do(func() { c.stats.event("physical_close", c.physical) })
	return c.Conn.Close()
}

type h2RealFrameParser struct {
	preface   int
	header    [9]byte
	headerLen int
	remaining int
}

func (p *h2RealFrameParser) feed(data []byte, complete func(byte, byte)) {
	if p.preface > 0 {
		n := min(len(data), p.preface)
		p.preface -= n
		data = data[n:]
	}
	for len(data) > 0 {
		if p.headerLen < len(p.header) {
			n := copy(p.header[p.headerLen:], data)
			p.headerLen += n
			data = data[n:]
			if p.headerLen != len(p.header) {
				return
			}
			p.remaining = int(p.header[0])<<16 | int(p.header[1])<<8 | int(p.header[2])
		}
		n := min(p.remaining, len(data))
		p.remaining -= n
		data = data[n:]
		if p.remaining == 0 {
			complete(p.header[3], p.header[4])
			p.headerLen = 0
		}
	}
}

func TestHTTP2RealFrameParserFragmented(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString(xhttp2.ClientPreface)
	framer := xhttp2.NewFramer(&wire, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	if err := framer.WritePing(false, [8]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := framer.WriteData(1, false, bytes.Repeat([]byte{0xaa}, 16384)); err != nil {
		t.Fatal(err)
	}
	if err := framer.WritePing(true, [8]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []int{1, 3, 8, 9, 17, 4096, wire.Len()} {
		t.Run(strconv.Itoa(chunk), func(t *testing.T) {
			parser := h2RealFrameParser{preface: len(xhttp2.ClientPreface)}
			var frames [][2]byte
			data := wire.Bytes()
			for len(data) > 0 {
				n := min(chunk, len(data))
				parser.feed(data[:n], func(kind, flags byte) { frames = append(frames, [2]byte{kind, flags}) })
				data = data[n:]
			}
			want := [][2]byte{{4, 0}, {6, 0}, {0, 0}, {6, 1}}
			if fmt.Sprint(frames) != fmt.Sprint(want) || parser.headerLen != 0 || parser.remaining != 0 {
				t.Fatalf("parsed frames %v, want %v, parser residue header=%d payload=%d", frames, want, parser.headerLen, parser.remaining)
			}
		})
	}
}

func TestHTTP2RealOutageAfterParser(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  float64
		valid bool
	}{
		{name: "default", want: 9.5, valid: true},
		{name: "zero", input: "0", valid: true},
		{name: "fractional", input: "0.125", want: 0.125, valid: true},
		{name: "existing_phase", input: "9.5", want: 9.5, valid: true},
		{name: "maximum", input: "20", want: 20, valid: true},
		{name: "negative", input: "-0.001"},
		{name: "above_maximum", input: "20.001"},
		{name: "nan", input: "NaN"},
		{name: "positive_infinity", input: "+Inf"},
		{name: "negative_infinity", input: "-Inf"},
		{name: "overflow", input: "1e309"},
		{name: "nonnumeric", input: "tomorrow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := h2RealParseOutageAfter(test.input)
			if (err == nil) != test.valid {
				t.Fatalf("valid = %v, want %v", err == nil, test.valid)
			}
			if got != test.want {
				t.Fatalf("offset = %v, want %v", got, test.want)
			}
		})
	}
}
