package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"moto/config"
	"net"
	"net/netip"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

func http3ConnectKey(target *config.Target) http3ConnectTransportKey {
	return http3ConnectTransportKey{
		address:        target.Address,
		serverName:     target.ConnectProxy.ServerName,
		browserProfile: target.ConnectProxy.BrowserProfile,
	}
}

// A zero-length source connection ID permits exactly one live QUIC connection
// on its UDP socket. Own resources per physical connection, not per pool slot:
// an HTTP/3 cache eviction can leave older sibling streams draining in a slot
// while a later dial has already opened another physical connection.
type http3ChromeSocket struct {
	transport *quic.Transport
	packet    net.PacketConn
	closeOnce sync.Once
}

func (socket *http3ChromeSocket) close() {
	socket.closeOnce.Do(func() {
		_ = socket.transport.Close()
		// Transport does not own a PacketConn supplied by its caller.
		_ = socket.packet.Close()
	})
}

func dialHTTP3Chrome(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	// The existing resolver has already applied the physical setup deadline.
	// Parse its numeric result without allowing a second DNS lookup here.
	remote, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP/3 resolved address: %w", err)
	}
	network, localAddress := "udp6", "[::]:0"
	if remote.Addr().Is4() {
		network, localAddress = "udp4", "0.0.0.0:0"
	}
	var listenConfig net.ListenConfig
	packet, err := listenConfig.ListenPacket(ctx, network, localAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for HTTP/3 connection: %w", err)
	}
	return dialHTTP3ChromeOnSocket(ctx, net.UDPAddrFromAddrPort(remote), tlsConfig, quicConfig, packet)
}

// dialHTTP3ChromeOnSocket takes ownership of packet on both success and error.
// The detached physical setup context controls only the handshake; after that,
// the slot owns the connection and its normal close releases these resources.
func dialHTTP3ChromeOnSocket(ctx context.Context, remote *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config, packet net.PacketConn) (*quic.Conn, error) {
	socket := &http3ChromeSocket{
		transport: &quic.Transport{
			Conn:                  packet,
			ConnectionIDGenerator: quic.ZeroLengthConnectionIDGenerator{},
		},
		packet: packet,
	}
	connection, err := socket.transport.Dial(ctx, remote, tlsConfig, quicConfig)
	if err != nil {
		socket.close()
		return nil, err
	}
	// A late dial completing after slot retirement is immediately closed by
	// ownPhysicalConnection. Register this first, including for an already
	// closed connection, so that race cannot orphan the UDP descriptor.
	context.AfterFunc(connection.Context(), socket.close)
	// The Chrome transport parameters permit server-created bidirectional
	// streams. Moto negotiates no HTTP/3 extension that uses them, and the
	// ordinary HTTP/3 Transport only accepts unidirectional streams. Enforce
	// RFC 9114 section 6.1 at receipt, without reading peer-controlled data.
	// Use the connection context: the setup context ends when Dial returns.
	go func() {
		if _, err := connection.AcceptStream(connection.Context()); err == nil {
			_ = connection.CloseWithError(
				quic.ApplicationErrorCode(http3.ErrCodeStreamCreationError),
				"server-initiated bidirectional stream",
			)
		}
	}()
	return connection, nil
}
