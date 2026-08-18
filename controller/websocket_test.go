package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

const webSocketMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type webSocketFrame struct {
	opcode  byte
	payload []byte
}

// TestWebSocketEndToEndAcrossModes exercises WebSocket as an opaque TCP
// protocol. In particular, rule.Timeout is allowed to bound routing decisions
// and the regex probe, but must not become a lifetime limit after HTTP Upgrade.
func TestWebSocketEndToEndAcrossModes(t *testing.T) {
	const ruleTimeout = 250 * time.Millisecond
	tests := []struct {
		name              string
		mode              string
		fragmentHandshake bool
	}{
		{name: "normal", mode: config.ModeNormal},
		{name: "regex", mode: config.ModeRegex, fragmentHandshake: true},
		{name: "boost", mode: config.ModeBoost},
		{name: "roundrobin", mode: config.ModeRoundRobin},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newWebSocketEchoFixture(t, test.name)
			targets := []*config.Target{{Address: backend.addr()}}
			if test.mode == config.ModeRegex {
				targets = []*config.Target{
					{Address: "127.0.0.1:9", Regexp: `^SSH-`},
					{
						Address: backend.addr(),
						Regexp:  `(?im)^Upgrade:[ \t]*websocket[ \t]*\r?$`,
					},
				}
			}

			rule := &config.Rule{
				Name:                "websocket-" + test.name,
				Listen:              "127.0.0.1:0",
				Mode:                test.mode,
				Prewarm:             false,
				Targets:             targets,
				Timeout:             uint64(ruleTimeout / time.Millisecond),
				MaxConnections:      4,
				MaxConnectionsPerIP: 4,
			}
			proxy := newWebSocketProxyFixture(t, rule)

			conn, err := net.DialTimeout("tcp", proxy.addr(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			clientClosed := false
			t.Cleanup(func() {
				if !clientClosed {
					_ = conn.Close()
				}
			})
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			performWebSocketClientHandshake(t, conn, reader, backend, test.fragmentHandshake)

			assertWebSocketTextEcho(t, conn, reader, "before-timeout-"+test.name)
			time.Sleep(ruleTimeout + 100*time.Millisecond)
			assertWebSocketTextEcho(t, conn, reader, "after-timeout-"+test.name)
			assertWebSocketPingPong(t, conn, reader, "ping-"+test.name)

			closePayload := []byte{0x03, 0xe8} // RFC 6455 normal closure (1000).
			if err := writeWebSocketFrame(conn, 0x8, closePayload, true); err != nil {
				t.Fatalf("write close frame: %v", err)
			}
			frame, err := readWebSocketFrame(reader, false)
			if err != nil {
				t.Fatalf("read close frame: %v", err)
			}
			if frame.opcode != 0x8 || !bytes.Equal(frame.payload, closePayload) {
				t.Fatalf("close frame = opcode %#x payload %x", frame.opcode, frame.payload)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("close client: %v", err)
			}
			clientClosed = true

			if err, ok := backend.wait(2 * time.Second); !ok {
				t.Fatal("WebSocket backend did not exit")
			} else if err != nil {
				t.Fatalf("WebSocket backend: %v", err)
			}
			if err, ok := proxy.stop(2 * time.Second); !ok {
				t.Fatal("proxy server did not exit")
			} else if err != nil {
				t.Fatalf("proxy server: %v", err)
			}
		})
	}
}

func assertWebSocketTextEcho(t *testing.T, conn net.Conn, reader *bufio.Reader, message string) {
	t.Helper()
	if err := writeWebSocketFrame(conn, 0x1, []byte(message), true); err != nil {
		t.Fatalf("write masked text frame: %v", err)
	}
	frame, err := readWebSocketFrame(reader, false)
	if err != nil {
		t.Fatalf("read text echo: %v", err)
	}
	if frame.opcode != 0x1 || string(frame.payload) != message {
		t.Fatalf("text echo = opcode %#x payload %q, want %q", frame.opcode, frame.payload, message)
	}
}

func assertWebSocketPingPong(t *testing.T, conn net.Conn, reader *bufio.Reader, message string) {
	t.Helper()
	if err := writeWebSocketFrame(conn, 0x9, []byte(message), true); err != nil {
		t.Fatalf("write masked ping: %v", err)
	}
	frame, err := readWebSocketFrame(reader, false)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if frame.opcode != 0xa || string(frame.payload) != message {
		t.Fatalf("pong = opcode %#x payload %q, want %q", frame.opcode, frame.payload, message)
	}
}

func performWebSocketClientHandshake(
	t *testing.T,
	conn net.Conn,
	reader *bufio.Reader,
	backend *webSocketEchoFixture,
	fragmented bool,
) {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("generate WebSocket nonce: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])
	first := "GET /echo HTTP/1.1\r\n" +
		"Host: websocket.test\r\n" +
		"Connection: keep-alive, Upgrade\r\n" +
		"Upgr"
	second := "ade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n\r\n"
	if fragmented {
		if err := writeAll(conn, []byte(first)); err != nil {
			t.Fatalf("write first Upgrade fragment: %v", err)
		}
		select {
		case <-backend.accepted:
			t.Fatal("Upgrade-specific regex routed before the Upgrade header was complete")
		case <-time.After(30 * time.Millisecond):
		}
		if err := writeAll(conn, []byte(second)); err != nil {
			t.Fatalf("write second Upgrade fragment: %v", err)
		}
	} else if err := writeAll(conn, []byte(first+second)); err != nil {
		t.Fatalf("write Upgrade request: %v", err)
	}

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read Upgrade status: %v", err)
	}
	if got := strings.TrimRight(statusLine, "\r\n"); got != "HTTP/1.1 101 Switching Protocols" {
		t.Fatalf("Upgrade status = %q", got)
	}
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		t.Fatalf("read Upgrade headers: %v", err)
	}
	if !webSocketHeaderHasToken(headers.Get("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(headers.Get("Upgrade")), "websocket") {
		t.Fatalf("invalid Upgrade response headers: %v", headers)
	}
	if got, want := headers.Get("Sec-WebSocket-Accept"), webSocketAccept(key); got != want {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, want)
	}
	if got := headers.Get("X-WebSocket-Backend"); got != backend.id {
		t.Fatalf("backend ID = %q, want %q", got, backend.id)
	}
}

type webSocketProxyFixture struct {
	server   *Server
	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
	err      error
}

func newWebSocketProxyFixture(t *testing.T, rule *config.Rule) *webSocketProxyFixture {
	t.Helper()
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fixture := &webSocketProxyFixture{server: server, cancel: cancel, done: make(chan struct{})}
	go func() {
		fixture.err = server.Serve(ctx)
		close(fixture.done)
	}()
	t.Cleanup(func() {
		if err, ok := fixture.stop(3 * time.Second); !ok {
			t.Errorf("proxy cleanup timed out")
		} else if err != nil {
			t.Errorf("proxy cleanup: %v", err)
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for !server.Ready() && time.Now().Before(deadline) {
		select {
		case <-fixture.done:
			t.Fatalf("proxy exited before readiness: %v", fixture.err)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !server.Ready() {
		t.Fatal("proxy did not become ready")
	}
	return fixture
}

func (f *webSocketProxyFixture) addr() string {
	return f.server.listeners[0].listener.Addr().String()
}

func (f *webSocketProxyFixture) stop(timeout time.Duration) (error, bool) {
	f.stopOnce.Do(func() {
		f.cancel()
		f.server.Close()
	})
	select {
	case <-f.done:
		return f.err, true
	case <-time.After(timeout):
		return nil, false
	}
}

type webSocketEchoFixture struct {
	id       string
	listener net.Listener
	accepted chan struct{}
	done     chan struct{}

	mu        sync.Mutex
	conn      net.Conn
	closing   bool
	err       error
	closeOnce sync.Once
}

func newWebSocketEchoFixture(t *testing.T, id string) *webSocketEchoFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen WebSocket backend: %v", err)
	}
	fixture := &webSocketEchoFixture{
		id:       id,
		listener: listener,
		accepted: make(chan struct{}),
		done:     make(chan struct{}),
	}
	go fixture.run()
	t.Cleanup(func() {
		fixture.forceClose()
		if err, ok := fixture.wait(3 * time.Second); !ok {
			t.Errorf("WebSocket backend cleanup timed out")
		} else if err != nil && !benignWebSocketFixtureError(err) {
			t.Errorf("WebSocket backend cleanup: %v", err)
		}
	})
	return fixture
}

func (f *webSocketEchoFixture) addr() string {
	return f.listener.Addr().String()
}

func (f *webSocketEchoFixture) run() {
	conn, err := f.listener.Accept()
	if err != nil {
		f.finish(err)
		return
	}
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		_ = conn.Close()
		f.finish(net.ErrClosed)
		return
	}
	f.conn = conn
	f.mu.Unlock()
	close(f.accepted)

	err = serveWebSocketEcho(conn, f.id)
	_ = conn.Close()
	f.mu.Lock()
	f.conn = nil
	f.mu.Unlock()
	f.finish(err)
}

func (f *webSocketEchoFixture) finish(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
	close(f.done)
}

func (f *webSocketEchoFixture) wait(timeout time.Duration) (error, bool) {
	select {
	case <-f.done:
		f.mu.Lock()
		err := f.err
		f.mu.Unlock()
		return err, true
	case <-time.After(timeout):
		return nil, false
	}
}

func (f *webSocketEchoFixture) forceClose() {
	f.closeOnce.Do(func() {
		_ = f.listener.Close()
		f.mu.Lock()
		f.closing = true
		conn := f.conn
		f.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	})
}

func benignWebSocketFixtureError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func serveWebSocketEcho(conn net.Conn, id string) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read Upgrade request: %w", err)
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.URL.Path != "/echo" ||
		!strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") ||
		!webSocketHeaderHasToken(request.Header.Get("Connection"), "upgrade") ||
		request.Header.Get("Sec-WebSocket-Version") != "13" {
		return fmt.Errorf("invalid Upgrade request: method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	nonce, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(nonce) != 16 {
		return fmt.Errorf("invalid Sec-WebSocket-Key %q", key)
	}

	writer := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(writer,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"X-WebSocket-Backend: %s\r\n\r\n",
		webSocketAccept(key), id); err != nil {
		return fmt.Errorf("write Upgrade response: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush Upgrade response: %w", err)
	}

	for {
		frame, err := readWebSocketFrame(reader, true)
		if err != nil {
			return fmt.Errorf("read client frame: %w", err)
		}
		switch frame.opcode {
		case 0x1:
			if err := writeWebSocketFrame(conn, 0x1, frame.payload, false); err != nil {
				return fmt.Errorf("write text echo: %w", err)
			}
		case 0x8:
			if err := writeWebSocketFrame(conn, 0x8, frame.payload, false); err != nil {
				return fmt.Errorf("write close frame: %w", err)
			}
			return nil
		case 0x9:
			if err := writeWebSocketFrame(conn, 0xa, frame.payload, false); err != nil {
				return fmt.Errorf("write pong: %w", err)
			}
		default:
			return fmt.Errorf("unexpected client opcode %#x", frame.opcode)
		}
	}
}

func webSocketAccept(key string) string {
	// SHA-1 is mandated by RFC 6455 for this handshake; it is not used as a
	// general-purpose password or signature hash.
	digest := sha1.Sum([]byte(key + webSocketMagicGUID))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func webSocketHeaderHasToken(value, token string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(candidate), token) {
			return true
		}
	}
	return false
}

func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte, masked bool) error {
	if opcode >= 0x8 && len(payload) > 125 {
		return errors.New("control frame payload exceeds 125 bytes")
	}
	frame := make([]byte, 0, len(payload)+14)
	frame = append(frame, 0x80|(opcode&0x0f))
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) <= 125:
		frame = append(frame, maskBit|byte(len(payload)))
	case len(payload) <= 65535:
		frame = append(frame, maskBit|126, 0, 0)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(payload)))
	default:
		frame = append(frame, maskBit|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(frame[len(frame)-8:], uint64(len(payload)))
	}
	if !masked {
		frame = append(frame, payload...)
		return writeAll(writer, frame)
	}
	var maskingKey [4]byte
	if _, err := rand.Read(maskingKey[:]); err != nil {
		return err
	}
	frame = append(frame, maskingKey[:]...)
	for index, value := range payload {
		frame = append(frame, value^maskingKey[index%len(maskingKey)])
	}
	return writeAll(writer, frame)
}

func readWebSocketFrame(reader io.Reader, wantMasked bool) (webSocketFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return webSocketFrame{}, err
	}
	if header[0]&0x80 == 0 || header[0]&0x70 != 0 {
		return webSocketFrame{}, fmt.Errorf("invalid FIN/RSV byte %#x", header[0])
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	if masked != wantMasked {
		return webSocketFrame{}, fmt.Errorf("masked=%v, want %v", masked, wantMasked)
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return webSocketFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return webSocketFrame{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
		if length>>63 != 0 {
			return webSocketFrame{}, errors.New("invalid 64-bit WebSocket payload length")
		}
	}
	if opcode >= 0x8 && length > 125 {
		return webSocketFrame{}, errors.New("oversized WebSocket control frame")
	}
	if length > 1<<20 {
		return webSocketFrame{}, fmt.Errorf("WebSocket payload length %d exceeds test limit", length)
	}
	var maskingKey [4]byte
	if masked {
		if _, err := io.ReadFull(reader, maskingKey[:]); err != nil {
			return webSocketFrame{}, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return webSocketFrame{}, err
	}
	if masked {
		for index := range payload {
			payload[index] ^= maskingKey[index%len(maskingKey)]
		}
	}
	return webSocketFrame{opcode: opcode, payload: payload}, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
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
