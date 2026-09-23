// The connection reservation and dial-coalescing behavior below is adapted
// from golang.org/x/net/http2/client_conn_pool.go (Copyright 2015 The Go Authors).
// The Go Authors' BSD license follows:
//
// Copyright 2009 The Go Authors.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of Google LLC nor the names of its contributors may
//     be used to endorse or promote products derived from this software
//     without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"sync"

	xhttp2 "golang.org/x/net/http2"
)

// http2ConnectConnPool gives each physical connection its own error callback
// while retaining HTTP/2 stream reservations and shared connection reuse.
// The template is configured before its first request and is never copied as
// a struct: an in-use Transport contains synchronization and pool state.
// This pool serves Moto's reusable CONNECT requests, which do not request
// Connection: close or cross-authority certificate coalescing.
type http2ConnectConnPool struct {
	template *xhttp2.Transport

	mu            sync.Mutex
	conns         map[string][]*xhttp2.ClientConn
	keys          map[*xhttp2.ClientConn]string
	reservations  map[*xhttp2.ClientConn]uint64
	idleChecks    map[*xhttp2.ClientConn]*http2ConnectIdleCheck
	dialing       map[string]*http2ConnectDialCall
	deadBeforeAdd map[*xhttp2.ClientConn]struct{}
}

type http2ConnectDialCall struct {
	ctx  context.Context
	done chan struct{}
	conn *xhttp2.ClientConn
	err  error
}

// http2SetupError identifies a failed physical DNS/TCP/TLS setup, not an
// individual CONNECT stream. Every waiter on one dial receives the same group
// so route health counts the failure once per route and routing generation.
type http2SetupError struct {
	cause error
	group *routeFailureGroup
}

func (err *http2SetupError) Error() string { return err.cause.Error() }
func (err *http2SetupError) Unwrap() error { return err.cause }

type http2ConnectIdleCheck struct {
	again bool // guarded by the pool mutex
}

var _ xhttp2.ClientConnPool = (*http2ConnectConnPool)(nil)

func newHTTP2ConnectConnPool(template *xhttp2.Transport) *http2ConnectConnPool {
	return &http2ConnectConnPool{
		template:     template,
		conns:        make(map[string][]*xhttp2.ClientConn),
		keys:         make(map[*xhttp2.ClientConn]string),
		reservations: make(map[*xhttp2.ClientConn]uint64),
		idleChecks:   make(map[*xhttp2.ClientConn]*http2ConnectIdleCheck),
		dialing:      make(map[string]*http2ConnectDialCall),
	}
}

func (pool *http2ConnectConnPool) GetClientConn(request *http.Request, address string) (*xhttp2.ClientConn, error) {
	ctx := request.Context()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pool.mu.Lock()
		for _, connection := range pool.conns[address] {
			if connection.ReserveNewRequest() {
				pool.reservations[connection]++
				traceHTTP2ConnectGetConn(ctx, address)
				pool.mu.Unlock()
				return connection, nil
			}
		}
		traceHTTP2ConnectGetConn(ctx, address)
		call := pool.dialing[address]
		if call == nil {
			call = &http2ConnectDialCall{ctx: ctx, done: make(chan struct{})}
			pool.dialing[address] = call
			go pool.dial(call, address)
		}
		pool.mu.Unlock()

		// The CONNECT manager returns to canceled callers immediately but
		// retains its cleanup lease until this shared physical dial settles.
		// Keep x/net's waiting behavior so retirement cannot orphan a dial.
		<-call.done
		if call.err != nil {
			// An independent request may retry a shared dial canceled by its
			// initiating request. Ordinary dial errors remain errors for every
			// waiter, and an initiating request never retries its own cancel.
			if call.ctx != ctx && call.ctx.Err() != nil &&
				(errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) {
				continue
			}
			return nil, call.err
		}

		pool.mu.Lock()
		// Idle closing or GOAWAY may have removed this freshly dialed
		// connection before a waiter was scheduled. Reserve under the same
		// lock that removes idle connections to avoid closing a reservation.
		if key, present := pool.keys[call.conn]; present && key == address && call.conn.ReserveNewRequest() {
			pool.reservations[call.conn]++
			pool.mu.Unlock()
			return call.conn, nil
		}
		pool.mu.Unlock()
	}
}

func traceHTTP2ConnectGetConn(ctx context.Context, address string) {
	if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.GetConn != nil {
		trace.GetConn(address)
	}
}

func (pool *http2ConnectConnPool) dial(call *http2ConnectDialCall, address string) {
	call.conn, call.err = pool.newClientConn(call.ctx, address)
	pool.mu.Lock()
	if call.err == nil {
		_, dead := pool.deadBeforeAdd[call.conn]
		if dead {
			// NewClientConn starts its reader before returning. Report an
			// immediate peer failure to callers instead of retaining a dead
			// connection or retrying the failed dial indefinitely.
			call.err = errors.New("HTTP/2 CONNECT connection closed before use")
		} else {
			pool.conns[address] = append(pool.conns[address], call.conn)
			pool.keys[call.conn] = address
		}
	}
	delete(pool.deadBeforeAdd, call.conn)
	delete(pool.dialing, address)
	if len(pool.dialing) == 0 {
		// Duplicate MarkDead callbacks for previously retired connections
		// need not be retained once every possible new connection is known.
		clear(pool.deadBeforeAdd)
	}
	pool.mu.Unlock()
	if call.err != nil && call.conn != nil {
		_ = call.conn.Close()
	}
	if call.err != nil {
		call.err = &http2SetupError{cause: call.err, group: newRouteFailureGroup()}
	}
	close(call.done)
}

func (pool *http2ConnectConnPool) newClientConn(ctx context.Context, address string) (*xhttp2.ClientConn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{}
	if pool.template.TLSClientConfig != nil {
		config = pool.template.TLSClientConfig.Clone()
	}
	if config.ServerName == "" {
		config.ServerName = host
	}
	if !slices.Contains(config.NextProtos, xhttp2.NextProtoTLS) {
		config.NextProtos = append([]string{xhttp2.NextProtoTLS}, config.NextProtos...)
	}

	var raw net.Conn
	switch {
	case pool.template.DialTLSContext != nil:
		raw, err = pool.template.DialTLSContext(ctx, "tcp", address, config)
	default:
		dialer := tls.Dialer{Config: config}
		raw, err = dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			state := raw.(*tls.Conn).ConnectionState()
			if state.NegotiatedProtocol != xhttp2.NextProtoTLS {
				_ = raw.Close()
				return nil, fmt.Errorf("HTTP/2 TLS handshake negotiated ALPN %q; want %q", state.NegotiatedProtocol, xhttp2.NextProtoTLS)
			}
		}
	}
	if err != nil {
		return nil, err
	}

	connection, countError := wrapHTTP2PingMetricConnection(raw, pool.template.CountError)
	physical := pool.physicalTransport(config, countError)
	client, err := physical.NewClientConn(connection)
	if err != nil {
		_ = connection.Close()
	}
	return client, err
}

func (pool *http2ConnectConnPool) physicalTransport(config *tls.Config, countError func(string)) *xhttp2.Transport {
	template := pool.template
	// Only public configuration is copied. The dedicated transport creates
	// exactly one ClientConn; its callback and all internal state are private
	// to that physical connection. MarkDead still returns to the shared pool.
	return &xhttp2.Transport{
		DialTLSContext:             template.DialTLSContext,
		TLSClientConfig:            config,
		ConnPool:                   pool,
		DisableCompression:         template.DisableCompression,
		AllowHTTP:                  template.AllowHTTP,
		MaxHeaderListSize:          template.MaxHeaderListSize,
		MaxReadFrameSize:           template.MaxReadFrameSize,
		MaxDecoderHeaderTableSize:  template.MaxDecoderHeaderTableSize,
		MaxEncoderHeaderTableSize:  template.MaxEncoderHeaderTableSize,
		StrictMaxConcurrentStreams: template.StrictMaxConcurrentStreams,
		IdleConnTimeout:            template.IdleConnTimeout,
		ReadIdleTimeout:            template.ReadIdleTimeout,
		PingTimeout:                template.PingTimeout,
		WriteByteTimeout:           template.WriteByteTimeout,
		CountError:                 countError,
	}
}

func (pool *http2ConnectConnPool) MarkDead(connection *xhttp2.ClientConn) {
	pool.mu.Lock()
	if _, present := pool.keys[connection]; !present && len(pool.dialing) != 0 {
		// GOAWAY calls MarkDead before setting ClientConn's Closing state;
		// retain that early notification until the in-flight dials register.
		if pool.deadBeforeAdd == nil {
			pool.deadBeforeAdd = make(map[*xhttp2.ClientConn]struct{})
		}
		pool.deadBeforeAdd[connection] = struct{}{}
	}
	pool.removeLocked(connection)
	pool.mu.Unlock()
}

func (pool *http2ConnectConnPool) removeLocked(connection *xhttp2.ClientConn) {
	address, present := pool.keys[connection]
	if !present {
		return
	}
	connections := pool.conns[address]
	for index, candidate := range connections {
		if candidate == connection {
			connections = slices.Delete(connections, index, index+1)
			break
		}
	}
	if len(connections) == 0 {
		delete(pool.conns, address)
	} else {
		pool.conns[address] = connections
	}
	delete(pool.keys, connection)
	delete(pool.reservations, connection)
}

// closeIdleConnections must be called explicitly by the CONNECT manager:
// x/net's idle-closing pool interface contains a package-private method.
// State can wait behind a blocked HTTP/2 write, so checks run asynchronously,
// with at most one worker per physical connection. Repeated requests are
// coalesced, but request another pass if a check is already in progress.
func (pool *http2ConnectConnPool) closeIdleConnections() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for connection := range pool.keys {
		if check := pool.idleChecks[connection]; check != nil {
			check.again = true
			continue
		}
		check := &http2ConnectIdleCheck{}
		pool.idleChecks[connection] = check
		go pool.closeIfIdle(connection, check)
	}
}

func (pool *http2ConnectConnPool) closeIfIdle(connection *xhttp2.ClientConn, check *http2ConnectIdleCheck) {
	for {
		pool.mu.Lock()
		if _, present := pool.keys[connection]; !present {
			delete(pool.idleChecks, connection)
			pool.mu.Unlock()
			return
		}
		reservation := pool.reservations[connection]
		check.again = false
		pool.mu.Unlock()

		state := connection.State()
		idle := state.StreamsActive == 0 && state.StreamsReserved == 0 && state.StreamsPending == 0
		pool.mu.Lock()
		_, present := pool.keys[connection]
		if present && idle && pool.reservations[connection] == reservation {
			pool.removeLocked(connection)
			delete(pool.idleChecks, connection)
			pool.mu.Unlock()
			_ = connection.Close()
			return
		}
		if !present || !check.again {
			delete(pool.idleChecks, connection)
			pool.mu.Unlock()
			return
		}
		pool.mu.Unlock()
	}
}
