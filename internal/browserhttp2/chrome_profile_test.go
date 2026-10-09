package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func TestChromeProfileWireSettingsHeadersAndReceiveCredit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	serverResult := make(chan error, 1)
	go func() { serverResult <- serveChromeWireFixture(listener, done) }()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	transport := &Transport{ChromeProfile: true, DisableCompression: true, MaxHeaderListSize: 65536}
	connection, err := transport.NewClientConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	request := &http.Request{
		Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: "proxy.example:443"},
		Host: "target.example:443", Header: http.Header{
			"Proxy-Authorization": {"Basic dGVzdDp0ZXN0"}, "User-Agent": {"Chrome fixture"},
		}, Body: reader, ContentLength: -1,
	}
	response, err := connection.RoundTrip(request.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if len(response.Header.Get("X-Large")) != 20000 {
		t.Fatal("decoder did not accept a header list within the advertised 256 KiB capacity")
	}
	// The peer sends 5 MiB before this application reads anything. This exceeds
	// the upstream 4 MiB stream window and proves the advertised 6 MiB window
	// was also applied to actual inbound flow accounting.
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("server could not send advertised stream credit before application read")
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 5<<20 {
		t.Fatalf("payload length = %d", len(payload))
	}
}

func serveChromeWireFixture(listener net.Listener, done <-chan struct{}) error {
	peer, err := listener.Accept()
	if err != nil {
		return err
	}
	// Keep the socket open until the test consumes the response. Closing with
	// an unread client SETTINGS ACK can produce TCP RST and discard buffered
	// response DATA on macOS, which is a fixture failure rather than flow error.
	go func() { <-done; _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
	preface := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(peer, preface); err != nil {
		return err
	}
	if string(preface) != ClientPreface {
		return fmt.Errorf("invalid client preface")
	}
	framer := NewFramer(peer, peer)
	frame, err := framer.ReadFrame()
	if err != nil {
		return err
	}
	settings, ok := frame.(*SettingsFrame)
	if !ok {
		return fmt.Errorf("first frame is %T", frame)
	}
	var got []Setting
	if err := settings.ForeachSetting(func(s Setting) error { got = append(got, s); return nil }); err != nil {
		return err
	}
	want := []Setting{{ID: SettingHeaderTableSize, Val: 65536}, {ID: SettingEnablePush, Val: 0}, {ID: SettingInitialWindowSize, Val: 6291456}, {ID: SettingMaxHeaderListSize, Val: 262144}}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("wire SETTINGS = %v, want %v", got, want)
	}
	frame, err = framer.ReadFrame()
	if err != nil {
		return err
	}
	window, ok := frame.(*WindowUpdateFrame)
	if !ok || window.StreamID != 0 || window.Increment != 15663105 {
		return fmt.Errorf("initial WINDOW_UPDATE = %#v", frame)
	}
	if err := framer.WriteSettings(Setting{ID: SettingMaxConcurrentStreams, Val: 100}); err != nil {
		return err
	}
	framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	var headers *MetaHeadersFrame
	for headers == nil {
		frame, err = framer.ReadFrame()
		if err != nil {
			return err
		}
		headers, _ = frame.(*MetaHeadersFrame)
	}
	var names []string
	for _, field := range headers.Fields {
		names = append(names, field.Name)
	}
	if !reflect.DeepEqual(names, []string{":method", ":authority", "user-agent", "proxy-authorization"}) {
		return fmt.Errorf("CONNECT header order = %v", names)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	encoder.SetMaxDynamicTableSizeLimit(65536)
	encoder.SetMaxDynamicTableSize(65536)
	_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encoder.WriteField(hpack.HeaderField{Name: "x-large", Value: strings.Repeat("x", 20000)})
	firstFragment := block.Bytes()
	if len(firstFragment) > 16384 {
		firstFragment = firstFragment[:16384]
	}
	if err := framer.WriteHeaders(HeadersFrameParam{StreamID: headers.StreamID, BlockFragment: firstFragment, EndHeaders: len(firstFragment) == block.Len()}); err != nil {
		return err
	}
	if len(firstFragment) < block.Len() {
		if err := framer.WriteContinuation(headers.StreamID, true, block.Bytes()[len(firstFragment):]); err != nil {
			return err
		}
	}
	data := bytes.Repeat([]byte("x"), 16384)
	for index := 0; index < 320; index++ {
		if err := framer.WriteData(headers.StreamID, index == 319, data); err != nil {
			return err
		}
	}
	return nil
}

func TestChromeProfileValidatesHeadersBeforeEmitting(t *testing.T) {
	request := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: "proxy.example"}, Host: "target.example:443", Header: http.Header{"X-Bad": {"value\r\ninjected: true"}}}
	count := 0
	_, err := encodeChromeRequestHeaders(request, false, 0, func(string, string) { count++ })
	if err == nil || count != 0 {
		t.Fatalf("invalid header result err=%v emitted=%d", err, count)
	}
}
