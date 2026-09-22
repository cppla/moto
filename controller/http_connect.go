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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	httpConnectMaxHeaderBytes = 32 << 10
	httpConnectMaxHeaders     = 100
	httpConnectReplyTimeout   = 3 * time.Second
)

type httpConnectClientConn struct {
	net.Conn
	reader        *bufio.Reader
	destination   string
	replied       bool
	failureStatus int
}

func (conn *httpConnectClientConn) Read(buffer []byte) (int, error) {
	// Read-ahead can contain the first TLS record. Never discard it when the
	// CONNECT headers and application payload arrived in the same TCP write.
	if conn.reader != nil {
		if conn.reader.Buffered() > 0 {
			return conn.reader.Read(buffer)
		}
		conn.reader = nil
	}
	return conn.Conn.Read(buffer)
}

func (conn *httpConnectClientConn) CloseWrite() error {
	if closer, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func prepareHTTPConnectClient(conn net.Conn, rule *config.Rule) (*httpConnectClientConn, error) {
	if conn == nil {
		return nil, errors.New("nil HTTP CONNECT connection")
	}
	if err := conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout(rule))); err != nil {
		return nil, fmt.Errorf("set HTTP CONNECT handshake deadline: %w", err)
	}
	reader := bufio.NewReader(conn)
	header, status, err := readHTTPConnectHeader(reader)
	var destination string
	if err == nil {
		destination, status, err = parseHTTPConnectHeader(header)
	}
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			status = http.StatusRequestTimeout
		}
		_ = writeHTTPConnectReply(conn, status)
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear HTTP CONNECT handshake deadline: %w", err)
	}
	return &httpConnectClientConn{Conn: conn, reader: reader, destination: destination}, nil
}

func readHTTPConnectHeader(reader *bufio.Reader) ([]byte, int, error) {
	header := make([]byte, 0, 1024)
	lineStart := 0
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(header)+len(fragment) > httpConnectMaxHeaderBytes {
			return nil, http.StatusRequestHeaderFieldsTooLarge, errors.New("HTTP CONNECT headers exceed size limit")
		}
		header = append(header, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("read HTTP CONNECT headers: %w", err)
		}
		if !bytes.HasSuffix(header, []byte("\r\n")) {
			return nil, http.StatusBadRequest, errors.New("HTTP CONNECT requires CRLF line endings")
		}
		if len(header)-lineStart == 2 {
			return header, 0, nil
		}
		lineStart = len(header)
	}
}

// Parse only a bounded CONNECT header, not an arbitrary forward-proxy request.
// No incoming headers (especially credentials) are passed to the upstream.
// Error strings deliberately exclude request lines and header values.
func parseHTTPConnectHeader(header []byte) (string, int, error) {
	badRequest := func() (string, int, error) {
		return "", http.StatusBadRequest, errors.New("malformed HTTP CONNECT request")
	}
	if !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		return badRequest()
	}
	lines := strings.Split(string(header[:len(header)-4]), "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return badRequest()
	}
	if parts[2] != "HTTP/1.1" {
		return "", http.StatusHTTPVersionNotSupported, errors.New("HTTP CONNECT requires HTTP/1.1")
	}
	if len(lines)-1 > httpConnectMaxHeaders {
		return "", http.StatusRequestHeaderFieldsTooLarge, errors.New("too many HTTP CONNECT headers")
	}
	host := ""
	hostCount := 0
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return badRequest()
		}
		value = strings.Trim(value, " \t")
		switch {
		case strings.EqualFold(name, "Host"):
			host, hostCount = value, hostCount+1
		case strings.EqualFold(name, "Transfer-Encoding"), strings.EqualFold(name, "Expect"):
			return badRequest()
		case strings.EqualFold(name, "Content-Length"):
			if value != "0" {
				return badRequest()
			}
		}
	}
	if parts[0] != http.MethodConnect {
		return "", http.StatusMethodNotAllowed, errors.New("HTTP proxy supports CONNECT only")
	}
	destination, err := normalizeHTTPConnectAuthority(parts[1])
	if err != nil || hostCount != 1 {
		return badRequest()
	}
	hostDestination, err := normalizeHTTPConnectAuthority(host)
	if err != nil || hostDestination != destination {
		return badRequest()
	}
	return destination, 0, nil
}

func normalizeHTTPConnectAuthority(authority string) (string, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || portText == "" {
		return "", errors.New("invalid CONNECT authority")
	}
	for _, digit := range portText {
		if digit < '0' || digit > '9' {
			return "", errors.New("invalid CONNECT port")
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("invalid CONNECT port")
	}
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") != strings.HasPrefix(authority, "[") {
			return "", errors.New("invalid CONNECT IP literal")
		}
		host = ip.String()
	} else if strings.HasPrefix(authority, "[") || !validSOCKS5DomainName([]byte(host)) {
		return "", errors.New("invalid CONNECT hostname")
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port)), nil
}

func (conn *httpConnectClientConn) replyConnected() error {
	if conn.replied {
		return nil
	}
	conn.replied = true
	return writeHTTPConnectReply(conn.Conn, http.StatusOK)
}

func (conn *httpConnectClientConn) replyFailure() {
	if conn.replied {
		return
	}
	conn.replied = true
	status := conn.failureStatus
	if status == 0 {
		status = http.StatusBadGateway
	}
	_ = writeHTTPConnectReply(conn.Conn, status)
}

func writeHTTPConnectReply(conn net.Conn, status int) error {
	if err := conn.SetWriteDeadline(time.Now().Add(httpConnectReplyTimeout)); err != nil {
		return err
	}
	var response string
	if status == http.StatusOK {
		// RFC 9110 forbids Content-Length / Transfer-Encoding on CONNECT 2xx.
		response = "HTTP/1.1 200 Connection Established\r\n\r\n"
	} else {
		response = fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n", status, http.StatusText(status))
		if status == http.StatusMethodNotAllowed {
			response += "Allow: CONNECT\r\n"
		}
		response += "\r\n"
	}
	_, err := io.Copy(conn, strings.NewReader(response))
	clearErr := conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func connectProxyHTTPReply(err error) int {
	if statusErr := connectProxyFinalStatusError(err); statusErr != nil {
		switch statusErr.statusCode {
		case http.StatusForbidden, http.StatusTooManyRequests, http.StatusBadGateway,
			http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return statusErr.statusCode
		}
		// Upstream authentication belongs to Moto configuration, not the local
		// client. In particular, never forward a 407 challenge or private body.
		return http.StatusBadGateway
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return http.StatusGatewayTimeout
	}
	if errors.Is(err, ErrCircuitOpen) || errors.Is(err, ErrActiveHealthUnhealthy) || isDialBulkheadError(err) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}
