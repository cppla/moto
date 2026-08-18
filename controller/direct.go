package controller

import (
	"context"
	"net"
	"time"
)

const dialTimeout = 3 * time.Second

// configureTCP applies the transport settings used by every outbound TCP
// connection. DialFastContext deliberately returns the real *net.TCPConn so
// callers do not lose access to TCP-specific operations behind a wrapper.
func configureTCP(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetNoDelay(true)
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
}

// DialFastContext dials addr with the supplied cancellation context. Go's
// net.Dialer already implements IPv4/IPv6 fallback, avoiding resolver and
// fallback goroutine leaks from a hand-rolled race.
func DialFastContext(ctx context.Context, addr string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	configureTCP(conn)
	return conn, nil
}

// DialFast preserves the original API for callers that do not yet carry a
// context. The wrapper remains bounded and delegates to DialFastContext.
func DialFast(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	return DialFastContext(ctx, addr)
}
