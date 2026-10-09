package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"moto/config"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

type chromeLifecyclePacketConn struct {
	*net.UDPConn
	closed chan struct{}
	once   sync.Once
	closes atomic.Int64
}

func (packet *chromeLifecyclePacketConn) Close() error {
	packet.closes.Add(1)
	err := packet.UDPConn.Close()
	packet.once.Do(func() { close(packet.closed) })
	return err
}

func newChromeLifecyclePacket(t *testing.T) *chromeLifecyclePacketConn {
	t.Helper()
	packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return &chromeLifecyclePacketConn{UDPConn: packet, closed: make(chan struct{})}
}

func waitChromeLifecyclePacketClosed(t *testing.T, packet *chromeLifecyclePacketConn) {
	t.Helper()
	select {
	case <-packet.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("physical QUIC connection ended without releasing its UDP socket")
	}
	if got := packet.closes.Load(); got != 1 {
		t.Fatalf("owned socket closed %d times, want exactly once", got)
	}
}

func TestHTTP3ChromeHandshakeCancellationClosesSocket(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	packet := newChromeLifecyclePacket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	connection, err := dialHTTP3ChromeOnSocket(ctx, blackhole.LocalAddr().(*net.UDPAddr),
		&tls.Config{ServerName: "blackhole.example", NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{ChromeParrot: true, Versions: []quic.Version{quic.Version1}}, packet)
	if connection != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blackhole dial = (%v, %v), want deadline failure", connection, err)
	}
	waitChromeLifecyclePacketClosed(t, packet)
}

func TestHTTP3ChromePhysicalSocketLifecycle(t *testing.T) {
	for _, closeMode := range []string{"local", "remote", "late_retired_slot"} {
		t.Run(closeMode, func(t *testing.T) {
			endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, http.HandlerFunc(echoHTTP3OwnershipTunnel))
			var closeServerOnce sync.Once
			stopServer := func() { closeServerOnce.Do(closeServer) }
			t.Cleanup(stopServer)
			remote, err := net.ResolveUDPAddr("udp", endpoint)
			if err != nil {
				t.Fatal(err)
			}
			packet := newChromeLifecyclePacket(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			connection, err := dialHTTP3ChromeOnSocket(ctx, remote,
				&tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}},
				&quic.Config{ChromeParrot: true, Versions: []quic.Version{quic.Version1}}, packet)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.CloseWithError(0, "test cleanup") })
			cancel()
			// Setup completion detaches a successfully established QUIC from the
			// dial deadline, exactly as the existing native path does.
			if err := connection.Context().Err(); err != nil {
				t.Fatalf("canceling completed setup closed the connection: %v", err)
			}
			switch closeMode {
			case "local":
				_ = connection.CloseWithError(0, "")
			case "remote":
				stopServer()
			case "late_retired_slot":
				slot := &http3ConnectTransportSlot{}
				slot.closeRequested.Store(true)
				if slot.ownPhysicalConnection(connection) {
					t.Fatal("a retired slot accepted a late physical connection")
				}
			}
			waitChromeLifecyclePacketClosed(t, packet)
		})
	}
}

func TestHTTP3ChromeSlotOwnsIndependentSockets(t *testing.T) {
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, http.HandlerFunc(echoHTTP3OwnershipTunnel))
	defer closeServer()
	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	slot := &http3ConnectTransportSlot{}
	defer slot.close()
	var packets []*chromeLifecyclePacketConn
	var connections []*quic.Conn
	for range 2 {
		packet := newChromeLifecyclePacket(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		connection, err := dialHTTP3ChromeOnSocket(ctx, remote,
			&tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{ChromeParrot: true, Versions: []quic.Version{quic.Version1}}, packet)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if !slot.ownPhysicalConnection(connection) {
			t.Fatal("serving slot rejected a physical connection")
		}
		packets = append(packets, packet)
		connections = append(connections, connection)
	}
	if connections[0].LocalAddr().String() == connections[1].LocalAddr().String() {
		t.Fatal("zero-CID physical connections shared a local UDP endpoint")
	}
	_ = connections[0].CloseWithError(0, "")
	waitChromeLifecyclePacketClosed(t, packets[0])
	if err := connections[1].Context().Err(); err != nil {
		t.Fatalf("closing the old physical connection closed its successor: %v", err)
	}
	select {
	case <-packets[1].closed:
		t.Fatal("closing the old physical connection released the successor's socket")
	default:
	}
	slot.close()
	waitChromeLifecyclePacketClosed(t, packets[1])
}

func TestHTTP3ChromeServerNamesKeepDistinctPoolsAndSiblingTunnels(t *testing.T) {
	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServer(t, http.HandlerFunc(echoHTTP3OwnershipTunnel))
	defer closeServer()
	var capturedMu sync.Mutex
	var physical []*quic.Conn
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		dial := transport.Dial
		transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			connection, err := dial(ctx, address, tlsConfig, quicConfig)
			if err == nil {
				capturedMu.Lock()
				physical = append(physical, connection)
				capturedMu.Unlock()
			}
			return connection, err
		}
		return transport
	})
	defer manager.close()
	defaultName := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}}
	explicitName := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3}, ServerName: "example.com",
	}}
	var tunnels []net.Conn
	for _, target := range []*config.Target{defaultName, explicitName, explicitName} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		tunnel, err := manager.dial(ctx, target, "destination.example:443")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Close() })
		tunnels = append(tunnels, tunnel)
	}
	if got := connectionCount.Load(); got != 2 {
		t.Fatalf("physical connections = %d, want distinct server-name pools with reuse", got)
	}
	manager.mu.Lock()
	defaultSlots, explicitSlots := len(manager.transports[http3ConnectKey(defaultName)]), len(manager.transports[http3ConnectKey(explicitName)])
	manager.mu.Unlock()
	if defaultSlots != 1 || explicitSlots != 1 {
		t.Fatalf("pool slots = default name %d explicit name %d, want one each", defaultSlots, explicitSlots)
	}
	_ = tunnels[1].Close()
	for _, tunnel := range []net.Conn{tunnels[0], tunnels[2]} {
		done := make(chan error, 1)
		go func() {
			if _, err := tunnel.Write([]byte("sibling")); err != nil {
				done <- err
				return
			}
			payload := make([]byte, len("sibling"))
			if _, err := io.ReadFull(tunnel, payload); err != nil || string(payload) != "sibling" {
				done <- fmt.Errorf("sibling echo = %q, %v", payload, err)
				return
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("sibling CONNECT failed to make progress")
		}
	}
	manager.close()
	capturedMu.Lock()
	connections := append([]*quic.Conn(nil), physical...)
	capturedMu.Unlock()
	for _, connection := range connections {
		waitHTTP3PhysicalClosed(t, connection)
	}
}

func TestChromeH3IdleTunnelSurvivesAdvertisedTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("requires 35 seconds of real idle time to exceed the advertised 30s timeout")
	}
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, http.HandlerFunc(echoHTTP3OwnershipTunnel))
	defer closeServer()
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer manager.close()
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	tunnel, err := manager.dial(ctx, target, "idle.example:443")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	manager.mu.Lock()
	slot := manager.transports[http3ConnectKey(target)][0]
	connection := slot.connection
	keepalive := slot.transport.QUICConfig.KeepAlivePeriod
	manager.mu.Unlock()
	if keepalive != 10*time.Second {
		t.Fatalf("Chrome tunnel keepalive = %s, want Moto's 10s", keepalive)
	}
	before := connection.ConnectionStats()
	started := time.Now()
	for _, checkpoint := range []time.Duration{25 * time.Second, 35 * time.Second} {
		timer := time.NewTimer(time.Until(started.Add(checkpoint)))
		select {
		case <-timer.C:
		case <-connection.Context().Done():
			timer.Stop()
			t.Fatalf("quiet Chrome tunnel closed before %s: %v", checkpoint, context.Cause(connection.Context()))
		}
	}
	if after := connection.ConnectionStats(); after.PacketsReceived <= before.PacketsReceived {
		t.Fatal("quiet connection did not receive keepalive acknowledgements")
	}
	done := make(chan error, 1)
	go func() {
		const want = "still-usable-after-35s"
		if _, err := tunnel.Write([]byte(want)); err != nil {
			done <- err
			return
		}
		payload := make([]byte, len(want))
		if _, err := io.ReadFull(tunnel, payload); err != nil || string(payload) != want {
			done <- fmt.Errorf("post-idle echo = %q, %v", payload, err)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("existing CONNECT stopped making progress after the advertised idle timeout")
	}
}

func TestHTTP3ChromeConcurrentSlotAndPeerClose(t *testing.T) {
	endpoint, roots, closeServer, _ := startHTTP3ConnectTestServer(t, http.HandlerFunc(echoHTTP3OwnershipTunnel))
	var stopOnce sync.Once
	stopServer := func() { stopOnce.Do(closeServer) }
	defer stopServer()
	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	slot := &http3ConnectTransportSlot{}
	defer slot.close()
	var packets []*chromeLifecyclePacketConn
	var connections []*quic.Conn
	for range 2 {
		packet := newChromeLifecyclePacket(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		connection, err := dialHTTP3ChromeOnSocket(ctx, remote,
			&tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{ChromeParrot: true, Versions: []quic.Version{quic.Version1}}, packet)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if !slot.ownPhysicalConnection(connection) {
			t.Fatal("serving slot rejected a physical connection")
		}
		packets = append(packets, packet)
		connections = append(connections, connection)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for _, operation := range []func(){
		slot.close, slot.close, stopServer,
		func() { _ = connections[0].CloseWithError(0, "") },
		func() { _ = connections[1].CloseWithError(0, "") },
	} {
		workers.Go(func() {
			<-start
			operation()
		})
	}
	close(start)
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent slot, connection and remote closure did not finish")
	}
	for _, packet := range packets {
		waitChromeLifecyclePacketClosed(t, packet)
	}
}

func TestHTTP3ChromeCooldownAndHalfOpenUseServerNameIdentity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	recoveringAvailable := false
	h3Calls := make(map[string]int)
	managedProbeSeen := false
	manager := &connectProxyManager{
		now:          func() time.Time { return now },
		cooldownBase: 10 * time.Second,
		cooldownMax:  time.Minute,
		dialers: map[string]connectProxyDialFunc{
			config.ConnectProxyH3: func(ctx context.Context, target *config.Target, _ string) (net.Conn, error) {
				serverName := target.ConnectProxy.ServerName
				h3Calls[serverName]++
				if serverName == "recovering.example" {
					managedProbeSeen = http3ManagedProbeFromContext(ctx)
					if !recoveringAvailable {
						return nil, errors.New("QUIC setup unavailable")
					}
				}
				return newHTTP3CooldownTestConnection(t), nil
			},
			config.ConnectProxyH2: func(context.Context, *config.Target, string) (net.Conn, error) {
				return newHTTP3CooldownTestConnection(t), nil
			},
		},
	}
	healthy := &config.Target{Address: "proxy.example:443", ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}, ServerName: "healthy.example",
	}}
	recovering := &config.Target{Address: healthy.Address, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3, config.ConnectProxyH2}, ServerName: "recovering.example",
	}}
	for _, target := range []*config.Target{recovering, healthy, recovering} {
		connection, err := manager.dial(context.Background(), target, "destination.example:443")
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}
	if h3Calls["recovering.example"] != 1 || h3Calls["healthy.example"] != 1 {
		t.Fatalf("H3 attempts = %v, want only the failed server name cooled down", h3Calls)
	}
	now = now.Add(10 * time.Second)
	recoveringAvailable = true
	connection, err := manager.dial(context.Background(), recovering, "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if !managedProbeSeen || h3Calls["recovering.example"] != 2 {
		t.Fatalf("server-name recovery did not use its own half-open probe: managed=%v calls=%v", managedProbeSeen, h3Calls)
	}
	_, managed, allowed := manager.beginHTTP3Attempt(context.Background(), recovering)
	if !allowed || managed {
		t.Fatalf("recovered server name = allowed %v managed %v, want normal admission", allowed, managed)
	}
}

func TestHTTP3ChromeLargeConcurrentPayloadCrossesReceiveWindows(t *testing.T) {
	// Each stream exceeds the profile's 6 MiB initial receive window, while
	// the two streams together exceed the 15 MiB connection receive window.
	// Writers and readers run independently so the echo cannot deadlock from
	// application-side backpressure before QUIC can extend either window.
	const payloadSize = 8 << 20
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		flusher := writer.(http.Flusher)
		flusher.Flush()
		buffer := make([]byte, 32<<10)
		for {
			n, err := request.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	})
	endpoint, roots, closeServer, connectionCount := startHTTP3ConnectTestServer(t, handler)
	defer closeServer()
	manager := newHTTP3ConnectManager(func(key http3ConnectTransportKey, owner context.Context) *http3.Transport {
		transport := newHTTP3ConnectTransportWithOwner(key, owner)
		transport.TLSClientConfig.RootCAs = roots
		return transport
	})
	defer manager.close()
	target := &config.Target{Address: endpoint, ConnectProxy: &config.ConnectProxyConfig{
		Protocols: []string{config.ConnectProxyH3},
	}}
	var tunnels []net.Conn
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		tunnel, err := manager.dial(ctx, target, "large.example:443")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Close()
		tunnels = append(tunnels, tunnel)
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("large transfers use %d physical connections, want one shared connection", got)
	}
	start := make(chan struct{})
	done := make(chan error, 4)
	for index, tunnel := range tunnels {
		payload := make([]byte, payloadSize)
		for offset := range payload {
			payload[offset] = byte(offset*31 + offset/251 + index*97)
		}
		wantDigest := sha256.Sum256(payload)
		go func() {
			<-start
			written, err := io.Copy(tunnel, bytes.NewReader(payload))
			if err != nil || written != payloadSize {
				done <- fmt.Errorf("stream %d upload = %d bytes, %v", index, written, err)
				return
			}
			done <- closeWrite(tunnel)
		}()
		go func() {
			<-start
			digest := sha256.New()
			read, err := io.CopyN(digest, tunnel, payloadSize)
			if err != nil || read != payloadSize {
				done <- fmt.Errorf("stream %d download = %d bytes, %v", index, read, err)
				return
			}
			if !bytes.Equal(digest.Sum(nil), wantDigest[:]) {
				done <- fmt.Errorf("stream %d echoed payload digest differs", index)
				return
			}
			var extra [1]byte
			if n, err := tunnel.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
				done <- fmt.Errorf("stream %d trailing read = %d bytes, %v; want EOF", index, n, err)
				return
			}
			done <- nil
		}()
	}
	close(start)
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for range 4 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline.C:
			t.Fatal("concurrent large Chrome payloads stopped progressing across flow-control windows")
		}
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("large transfers replaced the shared connection: physical count %d", got)
	}
}

func TestHTTP3ChromeRejectsServerInitiatedBidirectionalStream(t *testing.T) {
	endpoint, roots, serverConnections, _ := startHTTP3CloseObservationServer(t, "", 0)
	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	packet := newChromeLifecyclePacket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	connection, err := dialHTTP3ChromeOnSocket(ctx, remote,
		&tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{ChromeParrot: true, Versions: []quic.Version{quic.Version1}}, packet)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseWithError(0, "test cleanup")
	var serverConnection *quic.Conn
	select {
	case serverConnection = <-serverConnections:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not observe the Chrome connection")
	}
	// Establish an ordinary request exchange first. Before confirmation QUIC
	// may carry a close in a Handshake packet as generic APPLICATION_ERROR;
	// after this 1-RTT exchange the peer can observe the exact HTTP/3 code.
	client := (&http3.Transport{}).NewClientConn(connection)
	readyCtx, cancelReady := context.WithTimeout(context.Background(), 3*time.Second)
	readyStream, err := client.OpenRequestStream(readyCtx)
	cancelReady()
	if err != nil {
		t.Fatal(err)
	}
	defer readyStream.Close()
	if err := readyStream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := &http.Request{
		Method: http.MethodConnect, Host: "guard.example:443",
		URL: &url.URL{Scheme: "https", Host: "guard.example:443"}, Header: make(http.Header),
	}
	if err := readyStream.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	response, err := readyStream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("legitimate CONNECT returned status %d", response.StatusCode)
	}
	if _, err := readyStream.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, len("ready"))
	if _, err := io.ReadFull(readyStream, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("legitimate CONNECT echo = %q, %v", ready, err)
	}
	openCtx, cancelOpen := context.WithTimeout(context.Background(), 3*time.Second)
	stream, err := serverConnection.OpenStreamSync(openCtx)
	cancelOpen()
	if err != nil {
		t.Fatalf("open server bidirectional stream allowed by Chrome transport parameters: %v", err)
	}
	// Opening a QUIC stream alone sends no frame. Write data so the client
	// actually receives a forbidden server-initiated stream on the wire.
	if _, err := stream.Write([]byte{0x00}); err != nil {
		t.Fatalf("send server bidirectional stream: %v", err)
	}
	for _, peer := range []struct {
		name       string
		connection *quic.Conn
		remote     bool
	}{
		{name: "client", connection: connection},
		{name: "server", connection: serverConnection, remote: true},
	} {
		select {
		case <-peer.connection.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("%s did not close after the forbidden server-initiated stream", peer.name)
		}
		var applicationError *quic.ApplicationError
		cause := context.Cause(peer.connection.Context())
		if !errors.As(cause, &applicationError) || applicationError.Remote != peer.remote ||
			applicationError.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeStreamCreationError) {
			t.Fatalf("%s close cause = %v, want H3_STREAM_CREATION_ERROR remote=%v", peer.name, cause, peer.remote)
		}
	}
	waitChromeLifecyclePacketClosed(t, packet)
}
