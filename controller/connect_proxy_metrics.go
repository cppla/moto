package controller

import (
	"net"
	"sync"
	"time"
)

// observedConnectProxyConn gives H2 and H3 tunnels the same bounded
// observability without adding a registry lock to each relay Read or Write.
// The underlying protocol connection remains responsible for transport
// lifecycle, deadlines, and half-close behavior.
type observedConnectProxyConn struct {
	net.Conn
	metrics   *connectProxyTunnelMetrics
	closeOnce sync.Once
	closeErr  error
}

func observeConnectProxyTunnel(connection net.Conn, rule, target, protocol string) net.Conn {
	if connection == nil {
		return nil
	}
	metrics := metricConnectProxyTunnelOpened(rule, target, protocol, time.Now())
	if metrics == nil {
		return connection
	}
	return &observedConnectProxyConn{Conn: connection, metrics: metrics}
}

func (connection *observedConnectProxyConn) Read(buffer []byte) (int, error) {
	read, err := connection.Conn.Read(buffer)
	if read > 0 {
		connection.metrics.targetToClientBytes.Add(uint64(read))
	}
	return read, err
}

func (connection *observedConnectProxyConn) Write(buffer []byte) (int, error) {
	written, err := connection.Conn.Write(buffer)
	if written > 0 {
		connection.metrics.clientToTargetBytes.Add(uint64(written))
	}
	return written, err
}

func (connection *observedConnectProxyConn) CloseWrite() error {
	if connection == nil || connection.Conn == nil {
		return nil
	}
	if closeWriter, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (connection *observedConnectProxyConn) Close() error {
	if connection == nil || connection.Conn == nil {
		return nil
	}
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.metrics.active.Add(-1)
	})
	return connection.closeErr
}
