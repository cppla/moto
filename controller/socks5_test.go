package controller

import (
	"encoding/binary"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSOCKS5HandshakeTimeoutIsIndependentAndBounded(t *testing.T) {
	if got := socks5HandshakeTimeout(nil); got != 3*time.Second {
		t.Fatalf("default handshake timeout = %s, want 3s", got)
	}
	if got := socks5HandshakeTimeout(&config.Rule{Timeout: 750}); got != 750*time.Millisecond {
		t.Fatalf("short handshake timeout = %s, want 750ms", got)
	}
	if got := socks5HandshakeTimeout(&config.Rule{Timeout: uint64((5 * time.Minute) / time.Millisecond)}); got != socks5HandshakeMaxWait {
		t.Fatalf("long handshake timeout = %s, want cap %s", got, socks5HandshakeMaxWait)
	}
}

func TestReadSOCKS5HandshakeDestinations(t *testing.T) {
	tests := map[string]struct {
		addressType byte
		address     []byte
		want        string
	}{
		"domain": {
			addressType: socks5AddressDomain,
			address:     append([]byte{11}, []byte("example.com")...),
			want:        "example.com:443",
		},
		"IPv4": {
			addressType: socks5AddressIPv4,
			address:     []byte{192, 0, 2, 10},
			want:        "192.0.2.10:443",
		},
		"IPv6": {
			addressType: socks5AddressIPv6,
			address:     net.ParseIP("2001:db8::1").To16(),
			want:        "[2001:db8::1]:443",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			result := make(chan struct {
				destination string
				err         error
			}, 1)
			go func() {
				destination, err := readSOCKS5Handshake(server)
				result <- struct {
					destination string
					err         error
				}{destination, err}
			}()

			if _, err := client.Write([]byte{socks5Version, 2, 2, socks5MethodNoAuth}); err != nil {
				t.Fatal(err)
			}
			method := make([]byte, 2)
			if _, err := io.ReadFull(client, method); err != nil {
				t.Fatal(err)
			}
			if method[1] != socks5MethodNoAuth {
				t.Fatalf("selected method = %d, want NO AUTH", method[1])
			}
			request := []byte{socks5Version, socks5CommandConnect, 0, test.addressType}
			request = append(request, test.address...)
			request = binary.BigEndian.AppendUint16(request, 443)
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			got := <-result
			if got.err != nil || got.destination != test.want {
				t.Fatalf("readSOCKS5Handshake() = %q, %v; want %q, nil", got.destination, got.err, test.want)
			}
		})
	}
}

func TestReadSOCKS5HandshakeRejectsUnsupportedMethodAndCommands(t *testing.T) {
	t.Run("authentication", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		errCh := make(chan error, 1)
		go func() {
			_, err := readSOCKS5Handshake(server)
			errCh <- err
		}()
		_, _ = client.Write([]byte{socks5Version, 1, 2})
		reply := make([]byte, 2)
		_, _ = io.ReadFull(client, reply)
		if reply[1] != socks5MethodRejected {
			t.Fatalf("method reply = %v, want rejected", reply)
		}
		if err := <-errCh; err == nil {
			t.Fatal("readSOCKS5Handshake() succeeded")
		}
	})

	for name, test := range map[string]struct {
		command     byte
		addressType byte
		wantReply   byte
	}{
		"UDP ASSOCIATE": {3, socks5AddressIPv4, socks5ReplyCommand},
		"address type":  {socks5CommandConnect, 9, socks5ReplyAddressType},
	} {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			errCh := make(chan error, 1)
			go func() {
				_, err := readSOCKS5Handshake(server)
				errCh <- err
			}()
			_, _ = client.Write([]byte{socks5Version, 1, socks5MethodNoAuth})
			method := make([]byte, 2)
			_, _ = io.ReadFull(client, method)
			_, _ = client.Write([]byte{socks5Version, test.command, 0, test.addressType})
			reply := make([]byte, 10)
			_, _ = io.ReadFull(client, reply)
			if reply[1] != test.wantReply {
				t.Fatalf("reply = %v, want code %d", reply, test.wantReply)
			}
			if err := <-errCh; err == nil {
				t.Fatal("readSOCKS5Handshake() succeeded")
			}
		})
	}
}

func TestReadSOCKS5HandshakeRejectsInvalidHTTPAuthorityDomain(t *testing.T) {
	for _, domain := range []string{"bad?host", "bad#host", "user@host", "bad..host", "-bad.example"} {
		t.Run(domain, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			errCh := make(chan error, 1)
			go func() {
				_, err := readSOCKS5Handshake(server)
				errCh <- err
			}()
			_, _ = client.Write([]byte{socks5Version, 1, socks5MethodNoAuth})
			method := make([]byte, 2)
			_, _ = io.ReadFull(client, method)
			request := []byte{socks5Version, socks5CommandConnect, 0, socks5AddressDomain, byte(len(domain))}
			request = append(request, domain...)
			_, _ = client.Write(request)
			reply := make([]byte, 10)
			_, _ = io.ReadFull(client, reply)
			if reply[1] != socks5ReplyAddressType {
				t.Fatalf("reply = %v, want address-type rejection", reply)
			}
			if err := <-errCh; err == nil {
				t.Fatal("invalid domain was accepted")
			}
		})
	}
}

func TestSOCKS5SuccessReplyWaitsForUpstream(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	wrapped := &socks5ClientConn{Conn: server, destination: "example.com:443"}

	if err := client.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 10)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("SOCKS5 success arrived before upstream was ready")
	}
	_ = client.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { done <- markSOCKS5Connected(wrapped) }()
	if _, err := io.ReadFull(client, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if buffer[1] != socks5ReplySuccess {
		t.Fatalf("success reply = %v", buffer)
	}
}

func TestSOCKS5ClientConnPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	wrapper := &socks5ClientConn{Conn: server}
	if got := relayCopyEndpoint(wrapper); got != server {
		t.Fatal("relay copy endpoint did not unwrap the SOCKS5 metadata connection")
	}
	if err := closeWrite(wrapper); err != nil {
		t.Fatalf("close wrapped TCP write side: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if read, err := client.Read(make([]byte, 1)); read != 0 || err != io.EOF {
		t.Fatalf("read after wrapped CloseWrite = %d, %v; want 0, EOF", read, err)
	}
}

func TestConnectProxySOCKS5ReplyUsesOnlyStandardStatus(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantReply byte
	}{
		{
			name: "403 is not allowed",
			err: &connectProxyStatusError{
				protocol: config.ConnectProxyH3, statusCode: http.StatusForbidden,
			},
			wantReply: socks5ReplyNotAllowed,
		},
		{
			name: "502 is host unreachable",
			err: &connectProxyStatusError{
				protocol: config.ConnectProxyH2, statusCode: http.StatusBadGateway,
			},
			wantReply: socks5ReplyHost,
		},
		{
			name: "504 is host unreachable",
			err: &connectProxyStatusError{
				protocol: config.ConnectProxyH2, statusCode: http.StatusGatewayTimeout,
			},
			wantReply: socks5ReplyHost,
		},
		{
			name: "503 stays generic",
			err: &connectProxyStatusError{
				protocol: config.ConnectProxyH2, statusCode: http.StatusServiceUnavailable,
			},
			wantReply: socks5ReplyGeneral,
		},
		{name: "transport failure stays generic", err: errors.New("proxy endpoint lookup failed"), wantReply: socks5ReplyGeneral},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := connectProxySOCKS5Reply(test.err); got != test.wantReply {
				t.Fatalf("SOCKS5 reply = %#x, want %#x", got, test.wantReply)
			}
		})
	}
}
