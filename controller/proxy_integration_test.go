package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPrepareInboundProxyProtocolRequiresHeader(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	rule := &config.Rule{
		Timeout: 500,
		ProxyProtocol: &config.ProxyProtocolConfig{
			Accept:       true,
			TrustedCIDRs: []string{"127.0.0.0/8"},
		},
	}
	if err := rule.ProxyProtocol.Validate(); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientSide.Write([]byte("h"))
		writeDone <- err
	}()
	prepared, effective, err := prepareInboundProxyProtocol(serverSide, rule, netip.MustParseAddr("127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "header is required") {
		t.Fatalf("error = %v, want required-header rejection", err)
	}
	if prepared != serverSide {
		t.Fatal("required-header rejection replaced the physical connection")
	}
	if effective.String() != "127.0.0.1" {
		t.Fatalf("effective client = %s", effective)
	}
	select {
	case writeErr := <-writeDone:
		if writeErr != nil {
			t.Fatal(writeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary-byte writer did not finish")
	}
}

func TestPrepareInboundProxyProtocolRejectsUntrustedPeerWithoutReading(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	rule := &config.Rule{ProxyProtocol: &config.ProxyProtocolConfig{
		Accept:       true,
		TrustedCIDRs: []string{"127.0.0.0/8"},
	}}
	if err := rule.ProxyProtocol.Validate(); err != nil {
		t.Fatal(err)
	}
	_, _, err := prepareInboundProxyProtocol(serverSide, rule, netip.MustParseAddr("192.0.2.10"))
	if !errors.Is(err, ErrUntrustedProxyProtocolPeer) {
		t.Fatalf("error = %v", err)
	}
}

func TestProxyProtocolTrustedInboundAndOutboundEndToEnd(t *testing.T) {
	type backendResult struct {
		header  proxyProtocolHeader
		payload string
		err     error
	}
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()
	backendDone := make(chan backendResult, 1)
	go func() {
		conn, acceptErr := backendListener.Accept()
		if acceptErr != nil {
			backendDone <- backendResult{err: acceptErr}
			return
		}
		defer conn.Close()
		result, readErr := readProxyProtocolHeader(conn)
		if readErr != nil || result.Header == nil {
			backendDone <- backendResult{err: readErr}
			return
		}
		payload := make([]byte, 4)
		_, readErr = io.ReadFull(conn, payload)
		if readErr == nil {
			_, readErr = conn.Write([]byte("ok"))
		}
		backendDone <- backendResult{header: *result.Header, payload: string(payload), err: readErr}
	}()

	rule := &config.Rule{
		Name:                "proxy-e2e",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeNormal,
		Timeout:             1000,
		Allowlist:           []string{"192.0.2.0/24"},
		MaxConnections:      4,
		MaxConnectionsPerIP: 4,
		ProxyProtocol: &config.ProxyProtocolConfig{
			Accept:       true,
			TrustedCIDRs: []string{"127.0.0.0/8"},
			Send:         config.ProxyProtocolV2,
		},
		Targets: []*config.Target{{Address: backendListener.Addr().String()}},
	}
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	waitReloadServerReady(t, server)

	client, err := net.Dial("tcp", server.listeners[0].listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	if err := writeProxyProtocolHeader(&input, proxyProtocolHeader{
		Version:     proxyProtocolVersion1,
		Command:     proxyProtocolCommandProxy,
		Source:      netip.MustParseAddrPort("192.0.2.10:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
	}); err != nil {
		t.Fatal(err)
	}
	input.WriteString("ping")
	if _, err := client.Write(input.Bytes()); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = client.Close()
	if string(response) != "ok" {
		t.Fatalf("response = %q", response)
	}
	select {
	case result := <-backendDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.header.Version != proxyProtocolVersion2 || result.header.Source != netip.MustParseAddrPort("192.0.2.10:12345") ||
			result.header.Destination != netip.MustParseAddrPort("198.51.100.20:443") || result.payload != "ping" {
			t.Fatalf("backend result = %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive PROXY header and payload")
	}

	cancel()
	select {
	case serveErr := <-serveDone:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}
