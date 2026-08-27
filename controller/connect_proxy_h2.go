package controller

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	xhttp2 "golang.org/x/net/http2"
)

const (
	http2ConnectIdleTimeout         = 90 * time.Second
	http2ConnectTLSHandshakeTimeout = 3 * time.Second
	http2ConnectMaxResponseHeaders  = 16 << 10
)

type http2ConnectTransportKey struct {
	address    string
	serverName string
	userAgent  string
	tlsProfile http2TLSClientHelloProfile
}

type http2TLSClientHelloProfile uint8

const (
	http2TLSProfileChrome133 http2TLSClientHelloProfile = iota
	http2TLSProfileFirefox120
	http2TLSProfileSafari160
	http2TLSProfileIOS14
)

func http2TLSProfileForUserAgent(userAgent string) http2TLSClientHelloProfile {
	normalized := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case strings.Contains(normalized, "iphone"),
		strings.Contains(normalized, "ipad"),
		strings.Contains(normalized, "crios/"),
		strings.Contains(normalized, "fxios/"),
		strings.Contains(normalized, "edgios/"):
		return http2TLSProfileIOS14
	case strings.Contains(normalized, "edg/"),
		strings.Contains(normalized, "edga/"):
		// Chromium-based Edge uses the current Chrome profile. The Edge
		// markers must be checked before Chrome because its UA contains both.
		return http2TLSProfileChrome133
	case strings.Contains(normalized, "firefox/"):
		return http2TLSProfileFirefox120
	case strings.Contains(normalized, "chrome/"),
		strings.Contains(normalized, "chromium/"):
		return http2TLSProfileChrome133
	case strings.Contains(normalized, "macintosh") &&
		strings.Contains(normalized, "version/") &&
		strings.Contains(normalized, "safari/") &&
		!strings.Contains(normalized, "chrome/") &&
		!strings.Contains(normalized, "chromium/") &&
		!strings.Contains(normalized, "edg/") &&
		!strings.Contains(normalized, "opr/"):
		return http2TLSProfileSafari160
	default:
		return http2TLSProfileChrome133
	}
}

func (profile http2TLSClientHelloProfile) clientHelloID() utls.ClientHelloID {
	switch profile {
	case http2TLSProfileFirefox120:
		return utls.HelloFirefox_120
	case http2TLSProfileSafari160:
		return utls.HelloSafari_16_0
	case http2TLSProfileIOS14:
		return utls.HelloIOS_14
	default:
		return utls.HelloChrome_133
	}
}

type http2ConnectManager struct {
	mu           sync.Mutex
	transports   map[http2ConnectTransportKey]*xhttp2.Transport
	active       map[http2ConnectTransportKey]int
	retired      bool
	newTransport func(http2ConnectTransportKey) *xhttp2.Transport
}

func newHTTP2ConnectManager(factory func(http2ConnectTransportKey) *xhttp2.Transport) *http2ConnectManager {
	if factory == nil {
		factory = newHTTP2ConnectTransport
	}
	return &http2ConnectManager{
		transports:   make(map[http2ConnectTransportKey]*xhttp2.Transport),
		active:       make(map[http2ConnectTransportKey]int),
		newTransport: factory,
	}
}

func newHTTP2ConnectTransport(key http2ConnectTransportKey) *xhttp2.Transport {
	profile := key.tlsProfile
	return &xhttp2.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: key.serverName,
		},
		DialTLSContext: func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
			return dialHTTP2TLS(ctx, network, address, config, profile)
		},
		DisableCompression: true,
		IdleConnTimeout:    http2ConnectIdleTimeout,
		MaxHeaderListSize:  http2ConnectMaxResponseHeaders,
	}
}

// dialHTTP2TLS changes only the outer TLS ClientHello. HTTP/2 framing,
// CONNECT headers, pooling, and stream behavior remain owned by x/net/http2.
// Certificate-chain and hostname verification stay enabled through uTLS.
func dialHTTP2TLS(
	ctx context.Context,
	network string,
	address string,
	config *tls.Config,
	profile http2TLSClientHelloProfile,
) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	utlsConfig, err := newHTTP2UTLSConfig(config)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	rawConnection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, http2ConnectTLSHandshakeTimeout)
	defer cancelHandshake()

	connection := utls.UClient(rawConnection, utlsConfig, profile.clientHelloID())
	if err := connection.HandshakeContext(handshakeCtx); err != nil {
		_ = rawConnection.Close()
		return nil, err
	}
	return &http2UTLSConn{UConn: connection, rawConnection: rawConnection}, nil
}

func newHTTP2UTLSConfig(config *tls.Config) (*utls.Config, error) {
	if config == nil {
		config = &tls.Config{}
	}
	if config.InsecureSkipVerify {
		return nil, errors.New("HTTP/2 TLS certificate verification cannot be disabled")
	}
	if config.VerifyConnection != nil {
		return nil, errors.New("HTTP/2 TLS crypto/tls VerifyConnection callback is unsupported")
	}
	return &utls.Config{
		Rand:                        config.Rand,
		Time:                        config.Time,
		RootCAs:                     config.RootCAs,
		ServerName:                  config.ServerName,
		VerifyPeerCertificate:       config.VerifyPeerCertificate,
		VerifyConnection:            verifyHTTP2UTLSConnection,
		SessionTicketsDisabled:      config.SessionTicketsDisabled,
		MinVersion:                  config.MinVersion,
		MaxVersion:                  config.MaxVersion,
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
		KeyLogWriter:                config.KeyLogWriter,
	}, nil
}

func verifyHTTP2UTLSConnection(state utls.ConnectionState) error {
	if state.NegotiatedProtocol != xhttp2.NextProtoTLS {
		return fmt.Errorf("HTTP/2 TLS handshake negotiated ALPN %q; want %q", state.NegotiatedProtocol, xhttp2.NextProtoTLS)
	}
	return nil
}

// http2UTLSConn closes the socket directly. uTLS otherwise waits up to five
// seconds while sending close_notify, which can stall H2 pool retirement when
// a peer is no longer responsive.
type http2UTLSConn struct {
	*utls.UConn
	rawConnection net.Conn
	closeOnce     sync.Once
	closeErr      error
}

func (connection *http2UTLSConn) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.rawConnection.Close()
	})
	return connection.closeErr
}

func (manager *http2ConnectManager) acquireTransport(key http2ConnectTransportKey) (*xhttp2.Transport, func()) {
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
	var closeTransport *xhttp2.Transport
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
	userAgent, hasUserAgent := connectProxyUserAgentFromContext(ctx)
	key := http2ConnectTransportKey{
		address:    target.Address,
		serverName: target.ConnectProxy.ServerName,
		userAgent:  userAgent,
		tlsProfile: http2TLSProfileForUserAgent(userAgent),
	}
	transport, releaseTransport := manager.acquireTransport(key)

	requestReader, requestWriter := io.Pipe()
	streamCtx, cancelStream := context.WithCancel(context.Background())
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
	if hasUserAgent {
		request.Header.Set("User-Agent", userAgent)
	}

	type roundTripResult struct {
		response *http.Response
		err      error
	}
	resultReady := make(chan roundTripResult, 1)
	go func() {
		response, err := transport.RoundTrip(request)
		resultReady <- roundTripResult{response: response, err: err}
	}()

	var response *http.Response
	var err error
	select {
	case result := <-resultReady:
		response, err = result.response, result.err
	case <-ctx.Done():
		// x/net/http2 coalesces dials per authority. A request that joins an
		// existing dial must still honor its own shorter setup deadline.
		select {
		case result := <-resultReady:
			response, err = result.response, result.err
		default:
			setupErr := ctx.Err()
			cancelStream()
			_ = requestWriter.CloseWithError(setupErr)
			_ = requestReader.CloseWithError(setupErr)
			go func() {
				result := <-resultReady
				if result.response != nil {
					_ = result.response.Body.Close()
				}
				releaseTransport()
			}()
			return nil, setupErr
		}
	}
	if err != nil {
		setupErr := err
		if ctxErr := ctx.Err(); ctxErr != nil {
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
	transports := make([]*xhttp2.Transport, 0, len(manager.transports))
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
	transports := make([]*xhttp2.Transport, 0, len(manager.transports))
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
