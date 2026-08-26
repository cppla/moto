package controller

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	http2ConnectMaxIdleConnectionsPerProxy = 8
	http2ConnectIdleTimeout                = 90 * time.Second
	http2ConnectMaxResponseHeaders         = 16 << 10
)

type http2ConnectTransportKey struct {
	address    string
	serverName string
}

type http2ConnectManager struct {
	mu           sync.Mutex
	transports   map[http2ConnectTransportKey]*http.Transport
	active       map[http2ConnectTransportKey]int
	retired      bool
	newTransport func(http2ConnectTransportKey) *http.Transport
}

func newHTTP2ConnectManager(factory func(http2ConnectTransportKey) *http.Transport) *http2ConnectManager {
	if factory == nil {
		factory = newHTTP2ConnectTransport
	}
	return &http2ConnectManager{
		transports:   make(map[http2ConnectTransportKey]*http.Transport),
		active:       make(map[http2ConnectTransportKey]int),
		newTransport: factory,
	}
}

func newHTTP2ConnectTransport(key http2ConnectTransportKey) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: key.serverName,
		},
		TLSHandshakeTimeout:    3 * time.Second,
		DisableCompression:     true,
		MaxIdleConns:           http2ConnectMaxIdleConnectionsPerProxy,
		MaxIdleConnsPerHost:    http2ConnectMaxIdleConnectionsPerProxy,
		IdleConnTimeout:        http2ConnectIdleTimeout,
		MaxResponseHeaderBytes: http2ConnectMaxResponseHeaders,
		Protocols:              protocols,
	}
}

func (manager *http2ConnectManager) acquireTransport(key http2ConnectTransportKey) (*http.Transport, func()) {
	manager.mu.Lock()
	transport := manager.transports[key]
	if transport == nil {
		transport = manager.newTransport(key)
		manager.transports[key] = transport
	}
	manager.active[key]++
	manager.mu.Unlock()

	var releaseOnce sync.Once
	return transport, func() {
		releaseOnce.Do(func() {
			manager.releaseTransport(key)
		})
	}

}

func (manager *http2ConnectManager) releaseTransport(key http2ConnectTransportKey) {
	if manager == nil {
		return
	}
	var closeTransport *http.Transport
	manager.mu.Lock()
	if active := manager.active[key]; active > 1 {
		manager.active[key] = active - 1
	} else {
		delete(manager.active, key)
		if manager.retired {
			closeTransport = manager.transports[key]
			delete(manager.transports, key)
		}
	}
	manager.mu.Unlock()
	if closeTransport != nil {
		closeTransport.CloseIdleConnections()
	}
}

func (manager *http2ConnectManager) dial(ctx context.Context, target *config.Target, destination string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target == nil || target.ConnectProxy == nil {
		return nil, errors.New("HTTP/2 CONNECT target is not configured")
	}
	key := http2ConnectTransportKey{address: target.Address, serverName: target.ConnectProxy.ServerName}
	transport, releaseTransport := manager.acquireTransport(key)

	requestReader, requestWriter := io.Pipe()
	streamCtx, cancelStream := context.WithCancel(context.Background())
	setupDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-setupDone:
			return
		case <-ctx.Done():
			// A completed setup wins if setupDone and ctx.Done become ready
			// together. The caller owns the stream after dial returns.
			select {
			case <-setupDone:
				return
			default:
				cancelStream()
			}
		}
	}()
	request := &http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: target.Address},
		Host:          destination,
		Header:        make(http.Header),
		Body:          requestReader,
		ContentLength: -1,
	}
	request = request.WithContext(streamCtx)
	if auth := target.ConnectProxy.BasicAuth; auth != nil {
		token := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		request.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if userAgent, ok := connectProxyUserAgentFromContext(ctx); ok {
		request.Header.Set("User-Agent", userAgent)
	}

	response, err := transport.RoundTrip(request)
	close(setupDone)
	<-watcherDone
	if err != nil {
		setupErr := err
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The detached stream context is canceled by the setup watcher.
			// Preserve the caller's deadline/cancellation cause for route health
			// and protocol metrics instead of returning context.Canceled blindly.
			setupErr = ctxErr
		}
		cancelStream()
		_ = requestWriter.CloseWithError(setupErr)
		_ = requestReader.CloseWithError(setupErr)
		releaseTransport()
		return nil, setupErr
	}
	if ctx.Err() != nil {
		cancelStream()
		_ = response.Body.Close()
		setupErr := ctx.Err()
		if setupErr == nil {
			setupErr = context.Canceled
		}
		_ = requestWriter.CloseWithError(setupErr)
		releaseTransport()
		return nil, setupErr
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		statusErr := newConnectProxyStatusError(config.ConnectProxyH2, target.Address, response)
		cancelStream()
		_ = response.Body.Close()
		_ = requestWriter.CloseWithError(errors.New("CONNECT proxy rejected stream"))
		releaseTransport()
		return nil, statusErr
	}
	return &http2TunnelConn{
		reader:     response.Body,
		writer:     requestWriter,
		cancel:     cancelStream,
		release:    releaseTransport,
		remoteAddr: tunnelAddr{network: config.ConnectProxyH2, value: target.Address},
	}, nil
}

// retire closes every currently idle TLS connection without interrupting an
// established CONNECT stream. A transport that becomes idle later is removed
// by releaseTransport, so an unrelated old-generation TCP connection cannot
// retain this rule's H2 pool until the whole generation drains.
func (manager *http2ConnectManager) retire() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	manager.retired = true
	transports := make([]*http.Transport, 0, len(manager.transports))
	for key, transport := range manager.transports {
		if manager.active[key] != 0 {
			continue
		}
		delete(manager.transports, key)
		transports = append(transports, transport)
	}
	manager.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func (manager *http2ConnectManager) closeIdle() {
	manager.mu.Lock()
	transports := make([]*http.Transport, 0, len(manager.transports))
	for _, transport := range manager.transports {
		transports = append(transports, transport)
	}
	manager.mu.Unlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

type tunnelAddr struct {
	network string
	value   string
}

func (addr tunnelAddr) Network() string { return addr.network }
func (addr tunnelAddr) String() string  { return addr.value }

type http2TunnelConn struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	release    func()
	remoteAddr net.Addr
	closeOnce  sync.Once
}

func (conn *http2TunnelConn) Read(buffer []byte) (int, error)  { return conn.reader.Read(buffer) }
func (conn *http2TunnelConn) Write(buffer []byte) (int, error) { return conn.writer.Write(buffer) }

func (conn *http2TunnelConn) CloseWrite() error {
	if conn.writer == nil {
		return nil
	}
	return conn.writer.Close()
}

func (conn *http2TunnelConn) Close() error {
	var closeErr error
	conn.closeOnce.Do(func() {
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.writer != nil {
			closeErr = conn.writer.Close()
		}
		if conn.reader != nil {
			if err := conn.reader.Close(); closeErr == nil {
				closeErr = err
			}
		}
		if conn.release != nil {
			conn.release()
		}
	})
	return closeErr
}

func (conn *http2TunnelConn) LocalAddr() net.Addr {
	return tunnelAddr{network: config.ConnectProxyH2, value: "local"}
}

func (conn *http2TunnelConn) RemoteAddr() net.Addr { return conn.remoteAddr }

func (conn *http2TunnelConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (conn *http2TunnelConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (conn *http2TunnelConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }
