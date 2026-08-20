package controller

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/netip"
	"time"
)

var ErrUntrustedProxyProtocolPeer = errors.New("untrusted PROXY protocol peer")

const proxyProtocolHeaderTimeout = 5 * time.Second

type proxyMetadataConn struct {
	net.Conn
	reader io.Reader
	remote net.Addr
	local  net.Addr
}

func (conn *proxyMetadataConn) Read(buffer []byte) (int, error) {
	return conn.reader.Read(buffer)
}

func (conn *proxyMetadataConn) RemoteAddr() net.Addr {
	if conn.remote != nil {
		return conn.remote
	}
	return conn.Conn.RemoteAddr()
}

func (conn *proxyMetadataConn) LocalAddr() net.Addr {
	if conn.local != nil {
		return conn.local
	}
	return conn.Conn.LocalAddr()
}

// prepareInboundProxyProtocol authenticates the immediate peer before using a
// client-supplied source address. When accept is enabled, a trusted peer must
// send one complete v1 or v2 header before any application bytes.
func prepareInboundProxyProtocol(conn net.Conn, rule *config.Rule, peerIP netip.Addr) (net.Conn, netip.Addr, error) {
	if conn == nil || rule == nil || rule.ProxyProtocol == nil || !rule.ProxyProtocol.Accept {
		return conn, peerIP, nil
	}
	if !rule.ProxyProtocol.Trusts(peerIP) {
		return conn, peerIP, ErrUntrustedProxyProtocolPeer
	}
	if err := conn.SetReadDeadline(time.Now().Add(proxyProtocolHeaderTimeout)); err != nil {
		return conn, peerIP, fmt.Errorf("set PROXY protocol read deadline: %w", err)
	}
	result, err := readProxyProtocolHeader(conn)
	clearErr := conn.SetReadDeadline(time.Time{})
	if err != nil {
		return conn, peerIP, fmt.Errorf("read PROXY protocol header: %w", err)
	}
	if result.Header == nil {
		return conn, peerIP, errors.New("PROXY protocol header is required")
	}
	if clearErr != nil {
		return conn, peerIP, fmt.Errorf("clear PROXY protocol read deadline: %w", clearErr)
	}
	wrapped := &proxyMetadataConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(result.Replay), conn),
	}
	if result.Header.Command == proxyProtocolCommandProxy {
		wrapped.remote = net.TCPAddrFromAddrPort(result.Header.Source)
		wrapped.local = net.TCPAddrFromAddrPort(result.Header.Destination)
		return wrapped, result.Header.Source.Addr().Unmap(), nil
	}
	return wrapped, peerIP, nil
}

func writeOutboundProxyProtocol(target net.Conn, inbound net.Conn, rule *config.Rule) error {
	if rule == nil || rule.ProxyProtocol == nil || rule.ProxyProtocol.Send == "" {
		return nil
	}
	if target == nil || inbound == nil {
		return errors.New("write PROXY protocol header: nil connection")
	}
	source, err := addrPortFromNetAddr(inbound.RemoteAddr())
	if err != nil {
		return fmt.Errorf("PROXY protocol source: %w", err)
	}
	destination, err := addrPortFromNetAddr(inbound.LocalAddr())
	if err != nil {
		return fmt.Errorf("PROXY protocol destination: %w", err)
	}
	version := proxyProtocolVersion1
	if rule.ProxyProtocol.Send == config.ProxyProtocolV2 {
		version = proxyProtocolVersion2
	}
	return writeProxyProtocolHeader(target, proxyProtocolHeader{
		Version:     version,
		Command:     proxyProtocolCommandProxy,
		Source:      source,
		Destination: destination,
	})
}

func addrPortFromNetAddr(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, errors.New("address is nil")
	}
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		addr, ok := netip.AddrFromSlice(tcpAddress.IP)
		if !ok || tcpAddress.Port < 0 || tcpAddress.Port > 65535 {
			return netip.AddrPort{}, fmt.Errorf("invalid TCP address %q", address)
		}
		return netip.AddrPortFrom(addr.Unmap(), uint16(tcpAddress.Port)), nil
	}
	value, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse %q: %w", address, err)
	}
	return netip.AddrPortFrom(value.Addr().Unmap(), value.Port()), nil
}
