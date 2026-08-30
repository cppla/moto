package controller

import (
	"moto/config"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type closeWriteCountingConn struct {
	net.Conn
	closeWrites atomic.Int32
}

func (connection *closeWriteCountingConn) CloseWrite() error {
	connection.closeWrites.Add(1)
	return nil
}

func TestObservedConnectProxyTunnelMetrics(t *testing.T) {
	resetProcessMetricsForTest()
	t.Cleanup(resetProcessMetricsForTest)
	rules := []*config.Rule{{
		Name: "route-watch",
		Targets: []*config.Target{{
			Address: "proxy.example:443",
			ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{
				config.ConnectProxyH3,
				config.ConnectProxyH2,
			}},
		}},
	}}
	processMetrics.registerRules(rules)
	t.Cleanup(func() { processMetrics.unregisterRules(rules) })

	underlying, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	closeWriter := &closeWriteCountingConn{Conn: underlying}
	connection := observeConnectProxyTunnel(
		closeWriter,
		"route-watch",
		"proxy.example:443",
		config.ConnectProxyH2,
	)
	observed, ok := connection.(*observedConnectProxyConn)
	if !ok {
		t.Fatalf("observed connection type = %T, want *observedConnectProxyConn", connection)
	}

	key := connectProxyMetricKey{
		rule: "route-watch", target: "proxy.example:443", protocol: config.ConnectProxyH2,
	}
	snapshot := processMetrics.snapshot()
	if snapshot.connectProxyActive[key] != 1 {
		t.Fatalf("active tunnels = %d, want 1", snapshot.connectProxyActive[key])
	}
	if snapshot.connectProxyLastSuccess[key] <= 0 {
		t.Fatalf("last success timestamp = %d, want positive Unix timestamp", snapshot.connectProxyLastSuccess[key])
	}

	peerRead := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 3)
		_, _ = peer.Read(buffer)
		peerRead <- buffer
	}()
	if written, err := connection.Write([]byte("up!")); err != nil || written != 3 {
		t.Fatalf("Write() = %d, %v; want 3, nil", written, err)
	}
	if got := string(<-peerRead); got != "up!" {
		t.Fatalf("peer received %q, want %q", got, "up!")
	}

	peerWrite := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("down!"))
		peerWrite <- err
	}()
	buffer := make([]byte, 5)
	if read, err := connection.Read(buffer); err != nil || read != 5 {
		t.Fatalf("Read() = %d, %v; want 5, nil", read, err)
	}
	if err := <-peerWrite; err != nil {
		t.Fatalf("peer Write() error = %v", err)
	}

	if err := observed.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if closeWriter.closeWrites.Load() != 1 {
		t.Fatalf("underlying CloseWrite calls = %d, want 1", closeWriter.closeWrites.Load())
	}
	if active := processMetrics.snapshot().connectProxyActive[key]; active != 1 {
		t.Fatalf("active after CloseWrite = %d, want 1", active)
	}

	snapshot = processMetrics.snapshot()
	clientToTarget := connectProxyPayloadMetricKey{
		connectProxyMetricKey: key, direction: string(relayDirectionClientToTarget),
	}
	targetToClient := connectProxyPayloadMetricKey{
		connectProxyMetricKey: key, direction: string(relayDirectionTargetToClient),
	}
	if got := snapshot.connectProxyPayload[clientToTarget]; got != 3 {
		t.Fatalf("client-to-target payload = %d, want 3", got)
	}
	if got := snapshot.connectProxyPayload[targetToClient]; got != 5 {
		t.Fatalf("target-to-client payload = %d, want 5", got)
	}

	body := renderPrometheusMetrics()
	wants := []string{
		`moto_connect_proxy_active_tunnels{rule="route-watch",target="proxy.example:443",protocol="h2"} 1`,
		`moto_connect_proxy_payload_bytes_total{rule="route-watch",target="proxy.example:443",protocol="h2",direction="client_to_target"} 3`,
		`moto_connect_proxy_payload_bytes_total{rule="route-watch",target="proxy.example:443",protocol="h2",direction="target_to_client"} 5`,
	}
	for _, want := range wants {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("metrics output missing %q\noutput:\n%s", want, body)
		}
	}

	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	snapshot = processMetrics.snapshot()
	if snapshot.connectProxyActive[key] != 0 {
		t.Fatalf("active tunnels after repeated Close = %d, want 0", snapshot.connectProxyActive[key])
	}
	if snapshot.connectProxyPayload[clientToTarget] != 3 || snapshot.connectProxyPayload[targetToClient] != 5 {
		t.Fatal("payload counters changed when the tunnel closed")
	}
}

func TestObserveConnectProxyTunnelRejectsUnregisteredLabels(t *testing.T) {
	resetProcessMetricsForTest()
	t.Cleanup(resetProcessMetricsForTest)
	connection, peer := net.Pipe()
	t.Cleanup(func() { _ = connection.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	if observed := observeConnectProxyTunnel(connection, "unknown", "proxy.example:443", config.ConnectProxyH2); observed != connection {
		t.Fatalf("unregistered connection was wrapped as %T", observed)
	}
	if snapshot := processMetrics.snapshot(); len(snapshot.connectProxyActive) != 0 ||
		len(snapshot.connectProxyPayload) != 0 || len(snapshot.connectProxyLastSuccess) != 0 {
		t.Fatal("unregistered labels created CONNECT tunnel metric series")
	}
}

func TestConnectProxyLastSuccessTimestampDoesNotRegress(t *testing.T) {
	resetProcessMetricsForTest()
	t.Cleanup(resetProcessMetricsForTest)
	rules := []*config.Rule{{
		Name: "clock-step",
		Targets: []*config.Target{{
			Address:      "proxy.example:443",
			ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}},
		}},
	}}
	processMetrics.registerRules(rules)
	t.Cleanup(func() { processMetrics.unregisterRules(rules) })

	newer := metricConnectProxyTunnelOpened(
		"clock-step", "proxy.example:443", config.ConnectProxyH3, time.Unix(200, 0),
	)
	older := metricConnectProxyTunnelOpened(
		"clock-step", "proxy.example:443", config.ConnectProxyH3, time.Unix(100, 0),
	)
	if newer == nil || older != newer {
		t.Fatal("successful tunnel observations did not share their registered metric series")
	}
	key := connectProxyMetricKey{
		rule: "clock-step", target: "proxy.example:443", protocol: config.ConnectProxyH3,
	}
	snapshot := processMetrics.snapshot()
	if snapshot.connectProxyLastSuccess[key] != 200 {
		t.Fatalf("last-success timestamp regressed to %d, want 200", snapshot.connectProxyLastSuccess[key])
	}
	newer.active.Add(-2)
}
