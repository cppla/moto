package controller

import (
	"context"
	"io"
	"moto/config"
	"net"
	"testing"
	"time"
)

func TestMatchingTLSTargetsUsesSNIAndALPNBeforeFallback(t *testing.T) {
	rule := &config.Rule{
		Targets: []*config.Target{
			{Address: "exact:443", ServerNames: []string{"api.example.com"}, ALPN: []string{"h2"}},
			{Address: "wildcard:443", ServerNames: []string{"*.example.com"}},
			{Address: "fallback:443"},
		},
	}
	matched := matchingTLSTargets(rule, tlsClientHelloProbe{
		ServerName:    "API.EXAMPLE.COM",
		ALPNProtocols: []string{"h2", "http/1.1"},
	})
	if len(matched) != 3 || matched[0].Address != "exact:443" || matched[1].Address != "wildcard:443" || matched[2].Address != "fallback:443" {
		t.Fatalf("matching targets = %+v", matched)
	}
	if matchesTLSServerName([]string{"*.example.com"}, "deep.api.example.com") {
		t.Fatal("single-label wildcard matched multiple labels")
	}
}

func TestMatchingTLSTargetsUsesBoundedOfferedALPNSet(t *testing.T) {
	offered := make([]string, tlsClientHelloMaxALPN)
	for index := range offered {
		offered[index] = "noise"
	}
	offered[len(offered)-1] = "mqtt"
	rule := &config.Rule{Targets: []*config.Target{
		{Address: "match:443", ALPN: []string{"missing", "mqtt"}},
		{Address: "case-sensitive-miss:443", ALPN: []string{"MQTT"}},
		{Address: "fallback:443"},
	}}

	matched := matchingTLSTargets(rule, tlsClientHelloProbe{ALPNProtocols: offered})
	if len(matched) != 2 || matched[0].Address != "match:443" || matched[1].Address != "fallback:443" {
		t.Fatalf("matching targets = %+v", matched)
	}
}

func TestTLSModeRoutesAndReplaysClientHello(t *testing.T) {
	backend := startTLSProbeBackend(t, "selected")
	fallback := startTLSProbeBackend(t, "fallback")
	rule := &config.Rule{
		Name:                "tls-e2e",
		Listen:              "127.0.0.1:0",
		Mode:                config.ModeTLS,
		Timeout:             1000,
		MaxConnections:      8,
		MaxConnectionsPerIP: 8,
		Targets: []*config.Target{
			{Address: backend, ServerNames: []string{"api.example.com"}, ALPN: []string{"h2"}},
			{Address: fallback},
		},
	}
	server, err := NewServer([]*config.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	waitReloadServerReady(t, server)

	conn, err := net.Dial("tcp", server.listeners[0].listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wire := testTLSHandshakeRecords(testTLSClientHelloHandshake("api.example.com", []string{"h2", "http/1.1"}), 1, 2, 3, 5)
	for offset := 0; offset < len(wire); {
		end := min(offset+7, len(wire))
		if _, err := conn.Write(wire[offset:end]); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	response := make([]byte, len("selected"))
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read selected backend response: %v", err)
	}
	if string(response) != "selected" {
		t.Fatalf("backend response = %q", response)
	}
	_ = conn.Close()

	cancel()
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS server did not stop")
	}
}

func startTLSProbeBackend(t *testing.T, response string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, parseErr := readTLSClientHello(conn, tlsClientHelloProbeLimit); parseErr == nil {
					_, _ = io.WriteString(conn, response)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("TLS probe backend did not stop")
		}
	})
	return listener.Addr().String()
}
