package controller

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPConnectParseAuthorities(t *testing.T) {
	for _, test := range []struct{ authority, host, want string }{
		{"example.com:443", "example.com:443", "example.com:443"},
		{"EXAMPLE.com:0443", "example.COM:443", "example.com:443"},
		{"example.com.:443", "EXAMPLE.COM.:443", "example.com.:443"},
		{"192.0.2.10:8443", "192.0.2.10:8443", "192.0.2.10:8443"},
		{"[2001:db8::1]:443", "[2001:0db8::1]:443", "[2001:db8::1]:443"},
		{"[::ffff:192.0.2.10]:443", "192.0.2.10:443", "192.0.2.10:443"},
	} {
		t.Run(test.authority, func(t *testing.T) {
			request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", test.authority, test.host)
			destination, status, err := parseHTTPConnectHeader([]byte(request))
			if err != nil || status != 0 || destination != test.want {
				t.Fatalf("parse = %q, %d, %v; want %q", destination, status, err, test.want)
			}
		})
	}
}

func TestHTTPConnectRejectMalformedRequests(t *testing.T) {
	const valid = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
	tests := []struct {
		name, request string
		status        int
	}{
		{"empty", "", 400},
		{"missing terminator", valid, 400},
		{"missing host", "CONNECT example.com:443 HTTP/1.1\r\n\r\n", 400},
		{"mismatched host", valid + "Host: other.example:443\r\n\r\n", 400},
		{"duplicate host", valid + "Host: example.com:443\r\n\r\n", 400},
		{"different single host", "CONNECT example.com:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n", 400},
		{"space before colon", "CONNECT example.com:443 HTTP/1.1\r\nHost : example.com:443\r\n\r\n", 400},
		{"obs fold", valid + " continuation: ignored\r\n\r\n", 400},
		{"nul header", valid + "X-Test: a\x00b\r\n\r\n", 400},
		{"injected CR", valid + "X-Test: a\rb\r\n\r\n", 400},
		{"body", valid + "Content-Length: 1\r\n\r\n", 400},
		{"conflicting body length", valid + "Content-Length: 0\r\nContent-Length: 4\r\n\r\n", 400},
		{"chunked", valid + "Transfer-Encoding: chunked\r\n\r\n", 400},
		{"identity framing", valid + "Transfer-Encoding: identity\r\n\r\n", 400},
		{"expect", valid + "Expect: 100-continue\r\n\r\n", 400},
		{"get", "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n", 405},
		{"HTTP1.0", "CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n", 505},
		{"HTTP2", "CONNECT example.com:443 HTTP/2.0\r\nHost: example.com:443\r\n\r\n", 505},
		{"too many headers", valid + strings.Repeat("X-Test: a\r\n", httpConnectMaxHeaders) + "\r\n", 431},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination, status, err := parseHTTPConnectHeader([]byte(test.request))
			if destination != "" || err == nil || status != test.status {
				t.Fatalf("parse = %q, %d, %v; want error %d", destination, status, err, test.status)
			}
		})
	}
	for _, authority := range []string{
		"example.com", "example.com:", "example.com:0", "example.com:65536", "example.com:+443",
		"example.com:443/path", "https://example.com:443", "user@host:443", "bad?host:443", "bad#host:443",
		"bad..host:443", "-bad.host:443", "[example.com]:443", "[192.0.2.1]:443", "[fe80::1%en0]:443",
		"2001:db8::1:443", ":443", "*.example.com:443", "host:99999999999999999999999999999",
	} {
		t.Run(authority, func(t *testing.T) {
			request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
			if _, status, err := parseHTTPConnectHeader([]byte(request)); err == nil || status != 400 {
				t.Fatalf("accepted invalid authority: status %d error %v", status, err)
			}
		})
	}
}

func TestHTTPConnectHeaderReadBoundedAndPreservesPayload(t *testing.T) {
	const prefix = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Padding: "
	const suffix = "\r\n\r\n"
	for _, size := range []int{128, 8192, httpConnectMaxHeaderBytes, httpConnectMaxHeaderBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			header := prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
			payload := []byte{0x16, 0x03, 0x01, 0, 5, 0xff, 0, '\r', '\n'}
			reader := bufio.NewReader(bytes.NewReader(append([]byte(header), payload...)))
			got, status, err := readHTTPConnectHeader(reader)
			if size > httpConnectMaxHeaderBytes {
				if err == nil || status != 431 {
					t.Fatalf("oversize header: %d %v", status, err)
				}
				return
			}
			if err != nil || string(got) != header || status != 0 {
				t.Fatalf("read header: %d %v, bytes %d", status, err, len(got))
			}
			rest, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(rest, payload) {
				t.Fatalf("read-ahead payload changed: %x %v", rest, err)
			}
		})
	}
	for _, malformed := range []string{"CONNECT x:443 HTTP/1.1\nHost: x:443\n\n", "CONNECT x:443 HTTP/1.1\r\nHost: x:443\n\r\n"} {
		if _, status, err := readHTTPConnectHeader(bufio.NewReader(strings.NewReader(malformed))); err == nil || status != 400 {
			t.Fatalf("accepted bare LF: %d %v", status, err)
		}
	}
}

func TestHTTPConnectHeaderErrorsAreRedacted(t *testing.T) {
	const secret = "DO_NOT_LOG_THIS_CREDENTIAL"
	requests := []string{
		"CONNECT " + secret + ":0 HTTP/1.1\r\nHost: " + secret + ":0\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nAuthorization: " + secret + "\x00\r\n\r\n",
	}
	for _, request := range requests {
		_, _, err := parseHTTPConnectHeader([]byte(request))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("error should be present and redacted: %v", err)
		}
	}
}

func TestHTTPConnectHandshakeDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, err := prepareHTTPConnectClient(server, &config.Rule{Timeout: 40})
		done <- err
	}()
	if _, err := io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("slow headers: response %v error %v", response, err)
	}
	if err := <-done; err == nil {
		t.Fatal("slow header handshake succeeded")
	}
}

func TestHTTPConnectReplyOnce(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		conn := &httpConnectClientConn{Conn: server}
		err := markConnectClientConnected(conn)
		if err == nil {
			err = markConnectClientConnected(conn)
		}
		setPendingConnectClientFailure(conn, context.DeadlineExceeded)
		failPendingConnectClient(conn)
		done <- err
	}()
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("reply not singular/framing-free: %q %v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPConnectFailureStatusMapping(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{
		{context.DeadlineExceeded, 504},
		{&net.OpError{Op: "dial", Err: context.DeadlineExceeded}, 504},
		{ErrCircuitOpen, 503},
		{ErrActiveHealthUnhealthy, 503},
		{&dialBulkheadError{saturated: true}, 503},
		{errors.New("transport failed"), 502},
		{&connectProxyStatusError{statusCode: 407}, 502},
		{&connectProxyStatusError{statusCode: 401}, 502},
		{&connectProxyStatusError{statusCode: 403}, 403},
		{&connectProxyStatusError{statusCode: 429}, 429},
		{&connectProxyStatusError{statusCode: 503}, 503},
		{&connectProxyStatusError{statusCode: 504}, 504},
	} {
		if got := connectProxyHTTPReply(test.err); got != test.status {
			t.Errorf("reply(%v) = %d, want %d", test.err, got, test.status)
		}
	}
}

func FuzzHTTPConnectHeader(f *testing.F) {
	f.Add([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	f.Add([]byte("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*httpConnectMaxHeaderBytes {
			return
		}
		header, _, err := readHTTPConnectHeader(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		destination, status, err := parseHTTPConnectHeader(header)
		if err == nil {
			if status != 0 || destination == "" {
				t.Fatalf("invalid success: %q %d", destination, status)
			}
			if _, err := normalizeHTTPConnectAuthority(destination); err != nil {
				t.Fatalf("invalid successful authority: %v", err)
			}
		} else if status < 400 || status > 599 || destination != "" {
			t.Fatalf("invalid failure: %q %d", destination, status)
		}
	})
}
