package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version          = 0x05
	socks5MethodNoAuth     = 0x00
	socks5MethodRejected   = 0xff
	socks5CommandConnect   = 0x01
	socks5AddressIPv4      = 0x01
	socks5AddressDomain    = 0x03
	socks5AddressIPv6      = 0x04
	socks5ReplySuccess     = 0x00
	socks5ReplyGeneral     = 0x01
	socks5ReplyNotAllowed  = 0x02
	socks5ReplyHost        = 0x04
	socks5ReplyCommand     = 0x07
	socks5ReplyAddressType = 0x08
	socks5HandshakeMaxWait = 10 * time.Second
)

type connectDestinationContextKey struct{}

// socks5ClientConn tracks whether the final CONNECT reply was sent. Mode
// handlers call markSOCKS5Connected only after an upstream tunnel is ready;
// their deferred failure path therefore cannot acknowledge a half-built route.
type socks5ClientConn struct {
	net.Conn
	destination  string
	replied      bool
	failureReply byte
}

// CloseWrite preserves TCP half-close semantics through the SOCKS metadata
// wrapper. relayBidirectional relies on this after the proxy-to-client stream
// reaches EOF; without it, protocols that wait for the client's final bytes
// can deadlock instead of observing a FIN.
func (conn *socks5ClientConn) CloseWrite() error {
	if conn == nil || conn.Conn == nil {
		return nil
	}
	if closer, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (conn *socks5ClientConn) unwrapForRelayCopy() net.Conn {
	if conn == nil {
		return nil
	}
	return conn.Conn
}

func withConnectDestination(ctx context.Context, destination string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, connectDestinationContextKey{}, destination)
}

func connectDestinationFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	destination, ok := ctx.Value(connectDestinationContextKey{}).(string)
	return destination, ok && destination != ""
}

func prepareSOCKS5Client(conn net.Conn, rule *config.Rule) (*socks5ClientConn, error) {
	if conn == nil {
		return nil, errors.New("nil SOCKS5 connection")
	}
	timeout := socks5HandshakeTimeout(rule)
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set SOCKS5 handshake deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{}) // best effort; a failed clear closes shortly

	destination, err := readSOCKS5Handshake(conn)
	if err != nil {
		return nil, err
	}
	return &socks5ClientConn{Conn: conn, destination: destination}, nil
}

func socks5HandshakeTimeout(rule *config.Rule) time.Duration {
	timeout := 3 * time.Second
	if rule != nil && rule.Timeout > 0 {
		timeout = time.Duration(rule.Timeout) * time.Millisecond
	}
	if timeout > socks5HandshakeMaxWait {
		return socks5HandshakeMaxWait
	}
	return timeout
}

func readSOCKS5Handshake(conn net.Conn) (string, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if greeting[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version %d", greeting[0])
	}
	if greeting[1] == 0 {
		_ = writeSOCKS5Method(conn, socks5MethodRejected)
		return "", errors.New("SOCKS5 greeting contains no authentication methods")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read SOCKS5 methods: %w", err)
	}
	supportsNoAuth := false
	for _, method := range methods {
		if method == socks5MethodNoAuth {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_ = writeSOCKS5Method(conn, socks5MethodRejected)
		return "", errors.New("SOCKS5 client did not offer NO AUTH")
	}
	if err := writeSOCKS5Method(conn, socks5MethodNoAuth); err != nil {
		return "", fmt.Errorf("write SOCKS5 method selection: %w", err)
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", fmt.Errorf("read SOCKS5 CONNECT header: %w", err)
	}
	if request[0] != socks5Version || request[2] != 0 {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneral)
		return "", errors.New("malformed SOCKS5 request header")
	}
	if request[1] != socks5CommandConnect {
		_ = writeSOCKS5Reply(conn, socks5ReplyCommand)
		return "", fmt.Errorf("unsupported SOCKS5 command %d", request[1])
	}

	host, reply, err := readSOCKS5Host(conn, request[3])
	if err != nil {
		_ = writeSOCKS5Reply(conn, reply)
		return "", err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneral)
		return "", fmt.Errorf("read SOCKS5 destination port: %w", err)
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	if port == 0 {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneral)
		return "", errors.New("SOCKS5 destination port must not be zero")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readSOCKS5Host(conn net.Conn, addressType byte) (string, byte, error) {
	switch addressType {
	case socks5AddressIPv4:
		var address [net.IPv4len]byte
		if _, err := io.ReadFull(conn, address[:]); err != nil {
			return "", socks5ReplyGeneral, fmt.Errorf("read SOCKS5 IPv4 address: %w", err)
		}
		return net.IP(address[:]).String(), socks5ReplySuccess, nil
	case socks5AddressIPv6:
		var address [net.IPv6len]byte
		if _, err := io.ReadFull(conn, address[:]); err != nil {
			return "", socks5ReplyGeneral, fmt.Errorf("read SOCKS5 IPv6 address: %w", err)
		}
		return net.IP(address[:]).String(), socks5ReplySuccess, nil
	case socks5AddressDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", socks5ReplyGeneral, fmt.Errorf("read SOCKS5 domain length: %w", err)
		}
		if length[0] == 0 {
			return "", socks5ReplyAddressType, errors.New("SOCKS5 domain must not be empty")
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", socks5ReplyGeneral, fmt.Errorf("read SOCKS5 domain: %w", err)
		}
		if !validSOCKS5DomainName(domain) {
			return "", socks5ReplyAddressType, errors.New("SOCKS5 domain is not a valid ASCII hostname")
		}
		return string(domain), socks5ReplySuccess, nil
	default:
		return "", socks5ReplyAddressType, fmt.Errorf("unsupported SOCKS5 address type %d", addressType)
	}
}

func validSOCKS5DomainName(domain []byte) bool {
	if len(domain) == 0 || len(domain) > 253 || domain[0] == '.' {
		return false
	}
	end := len(domain)
	if domain[end-1] == '.' {
		end--
		if end == 0 {
			return false
		}
	}
	labelStart := 0
	for index := 0; index <= end; index++ {
		if index < end && domain[index] != '.' {
			value := domain[index]
			if (value < 'a' || value > 'z') && (value < 'A' || value > 'Z') &&
				(value < '0' || value > '9') && value != '-' && value != '_' {
				return false
			}
			continue
		}
		labelLength := index - labelStart
		if labelLength == 0 || labelLength > 63 || domain[labelStart] == '-' || domain[index-1] == '-' {
			return false
		}
		labelStart = index + 1
	}
	return true
}

func writeSOCKS5Method(conn net.Conn, method byte) error {
	return writeSOCKS5Bytes(conn, []byte{socks5Version, method})
}

func writeSOCKS5Reply(conn net.Conn, reply byte) error {
	// An HTTP CONNECT stream has no meaningful TCP BND endpoint to expose. A
	// zero IPv4 endpoint is interoperable and avoids leaking proxy internals.
	return writeSOCKS5Bytes(conn, []byte{socks5Version, reply, 0, socks5AddressIPv4, 0, 0, 0, 0, 0, 0})
}

func writeSOCKS5Bytes(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func markSOCKS5Connected(conn net.Conn) error {
	client, ok := conn.(*socks5ClientConn)
	if !ok || client.replied {
		return nil
	}
	client.replied = true
	return writeSOCKS5Reply(client.Conn, socks5ReplySuccess)
}

func failPendingSOCKS5(conn net.Conn) {
	client, ok := conn.(*socks5ClientConn)
	if !ok || client.replied {
		return
	}
	client.replied = true
	reply := client.failureReply
	if reply == socks5ReplySuccess {
		reply = socks5ReplyGeneral
	}
	_ = writeSOCKS5Reply(client.Conn, reply)
}

// setPendingSOCKS5Failure preserves a useful RFC 1928 failure code until the
// mode handler's deferred failure reply runs. Only standard HTTP status and
// transport information is used; Moto does not inspect vendor-specific proxy
// headers or error bodies.
func setPendingSOCKS5Failure(conn net.Conn, err error) {
	client, ok := conn.(*socks5ClientConn)
	if !ok || client.replied {
		return
	}
	client.failureReply = connectProxySOCKS5Reply(err)
}

func connectProxySOCKS5Reply(err error) byte {
	statusErr := connectProxyFinalStatusError(err)
	switch connectProxyStatusFailureClass(statusErr) {
	case connectProxyFailurePolicyDenied:
		return socks5ReplyNotAllowed
	case connectProxyFailureDestinationConnect:
		return socks5ReplyHost
	default:
		// A generic 503 cannot safely be called a DNS or network failure without
		// relying on a vendor-specific response. Report a server failure instead.
		return socks5ReplyGeneral
	}
}
