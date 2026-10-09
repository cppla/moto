package controller

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"moto/config"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	xhttp2 "moto/internal/browserhttp2"
)

// This experiment changes actual TCP delivery, unlike the frame-level ACK
// tests. It is deliberately opt-in and always re-executes inside a new network
// namespace before touching lo. Run in a disposable Linux container with tc,
// ip, unshare, and permission to create a network namespace, for example:
//
//	MOTO_H2_PING_NETEM_TEST=1 go test ./controller \
//	  -run '^TestHTTP2ConnectPingTCPNetemRealClock$' -count=1 -v -timeout=7m
//
// Its real-clock observations are evidence about these particular profiles and
// kernel TCP retransmission behavior, not an Internet-wide reliability bound.
func TestHTTP2ConnectPingTCPNetemRealClock(t *testing.T) {
	if os.Getenv("MOTO_H2_PING_NETEM_TEST") != "1" {
		t.Skip("set MOTO_H2_PING_NETEM_TEST=1 in a disposable Linux container")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("TCP netem experiment requires Linux root inside a disposable container")
	}
	for _, binary := range []string{"tc", "ip", "unshare"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatalf("TCP netem experiment requires %s: %v", binary, err)
		}
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	const parentNamespaceEnv = "MOTO_H2_PING_NETEM_PARENT_NS"
	if parent := os.Getenv(parentNamespaceEnv); parent == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// Preserve the caller's subtest selector while constraining the child
		// to this suite; unrelated tests must not run in a networkless namespace.
		childRun := "^TestHTTP2ConnectPingTCPNetemRealClock$"
		if runFlag := flag.Lookup("test.run"); runFlag != nil {
			if _, subtests, found := strings.Cut(runFlag.Value.String(), "/"); found {
				childRun += "/" + subtests
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "unshare", "--net", "--", executable,
			"-test.run="+childRun, "-test.v", "-test.timeout=6m")
		command.Env = append(os.Environ(), parentNamespaceEnv+"="+namespace)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			t.Fatalf("isolated netem test: %v (container must permit unshare --net)", err)
		}
		return
	} else if parent == namespace {
		t.Fatal("refusing qdisc mutation: test did not enter a new network namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	// Some kernels automatically populate fresh namespaces with dormant tunnel
	// devices (tunl0, sit0, and similar). Permit those only while down and empty.
	foundLoopback := false
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			foundLoopback = true
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil || iface.Flags&net.FlagUp != 0 || len(addresses) != 0 {
			t.Fatalf("refusing qdisc mutation: non-loopback interface %s must be down without addresses; addresses=%v error=%v", iface.Name, addresses, err)
		}
	}
	if !foundLoopback {
		t.Fatal("refusing qdisc mutation: fresh network namespace has no lo")
	}
	for _, family := range []string{"-4", "-6"} {
		if output, err := exec.Command("ip", family, "route", "show", "default").CombinedOutput(); err != nil || len(bytes.TrimSpace(output)) != 0 {
			t.Fatalf("refusing qdisc mutation: isolated namespace has a default route or route check failed: %v: %s", err, output)
		}
	}
	if output, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v: %s", err, output)
	}
	t.Logf("isolation verified: network namespace %s differs from parent; no configured non-loopback interface or default route", namespace)
	if output, err := exec.Command("uname", "-sr").CombinedOutput(); err == nil {
		t.Logf("kernel: %s", strings.TrimSpace(string(output)))
	}

	for _, timing := range []struct{ readIdle, pingWait time.Duration }{
		{15 * time.Second, 5 * time.Second},
		{30 * time.Second, 5 * time.Second},
		{15 * time.Second, 10 * time.Second},
	} {
		readIdle, pingWait := timing.readIdle, timing.pingWait
		t.Run(fmt.Sprintf("blackhole_read_idle_%ds_ping_%ds", int(readIdle.Seconds()), int(pingWait.Seconds())), func(t *testing.T) {
			impairment := &http2PingNetemImpairment{}
			defer impairment.clear(t)
			proxy, manager, target, first, second := newHTTP2PingNetemPair(t, readIdle, pingWait)
			impairment.apply(t, "loss", "100%")
			started := time.Now()
			outcomes := startHTTP2PingNetemReads([]net.Conn{first, second}, 1, started)
			for range 2 {
				outcome := receiveHTTP2PingNetemRead(t, outcomes, started.Add(readIdle+pingWait+10*time.Second))
				if outcome.err == nil || !strings.Contains(outcome.err.Error(), "client connection lost") {
					t.Fatalf("stream %d blackhole read = %v, want HTTP/2 health-check connection loss", outcome.stream, outcome.err)
				}
				t.Logf("read_idle=%s ping_wait=%s: stream=%d closed=%s after actual TCP blackhole, error=%v", readIdle, pingWait, outcome.stream, outcome.elapsed, outcome.err)
				if outcome.elapsed < readIdle+pingWait-time.Second || outcome.elapsed > readIdle+pingWait+10*time.Second {
					t.Fatalf("blackhole close %s outside expected real-clock health-check interval", outcome.elapsed)
				}
			}
			impairment.stats(t)
			impairment.clear(t)
			recovered := dialHTTP2PingTestTunnel(t, manager, target)
			assertHTTP2PingTestEcho(t, recovered, "recovered-after-real-tcp-blackhole")
			if got := proxy.accepted.Load(); got != 2 {
				t.Fatalf("TLS connections after recovery = %d, want 2", got)
			}
			t.Log("restored TCP delivery: a fresh TLS/H2 connection carried a successful CONNECT echo")
		})
	}

	// The short-idle cases shorten only ReadIdleTimeout to position the outage
	// immediately before PING. The 5s/10s ACK waits and 4s/8s outages are real.
	// The real-idle cases additionally wait the full 30s or 15s interval to check
	// that the short-idle observations transfer to the actual parameter choices.
	for _, outage := range []time.Duration{4 * time.Second, 8 * time.Second} {
		for _, pingWait := range []time.Duration{5 * time.Second, 10 * time.Second} {
			readIdles := []time.Duration{2 * time.Second}
			if outage == 4*time.Second {
				if pingWait == 5*time.Second {
					readIdles = append(readIdles, 30*time.Second)
				} else {
					readIdles = append(readIdles, 15*time.Second)
				}
			}
			for _, readIdle := range readIdles {
				timingKind := "short"
				if readIdle != 2*time.Second {
					timingKind = "real"
				}
				t.Run(fmt.Sprintf("temporary_loss_%ds_ping_%ds_%s_idle_%ds", int(outage.Seconds()), int(pingWait.Seconds()), timingKind, int(readIdle.Seconds())), func(t *testing.T) {
					impairment := &http2PingNetemImpairment{}
					defer impairment.clear(t)
					proxy, manager, target, first, second := newHTTP2PingNetemPair(t, readIdle, pingWait)
					t.Logf("timing=%s read_idle=%s ping_wait=%s: waiting %s before starting %s TCP outage", timingKind, readIdle, pingWait, readIdle-250*time.Millisecond, outage)
					time.Sleep(readIdle - 250*time.Millisecond)
					impairment.apply(t, "loss", "100%")
					started := time.Now()
					const payload = "tcp-restored"
					tunnels := []net.Conn{first, second}
					outcomes := startHTTP2PingNetemReads(tunnels, len(payload), started)
					time.Sleep(outage)
					impairment.stats(t)
					impairment.clear(t)
					restoredAt := time.Since(started)
					// Real traffic resumes after connectivity returns. TCP may still
					// be waiting for its exponentially backed-off retransmission.
					for _, tunnel := range tunnels {
						go func() { _, _ = io.WriteString(tunnel, payload) }()
					}
					closed := 0
					for range 2 {
						outcome := receiveHTTP2PingNetemRead(t, outcomes, started.Add(pingWait+15*time.Second))
						if outcome.err != nil {
							if !strings.Contains(outcome.err.Error(), "client connection lost") {
								t.Fatalf("stream %d unexpected read failure: %v", outcome.stream, outcome.err)
							}
							closed++
						} else if string(outcome.data) != payload {
							t.Fatalf("stream %d echo = %q, want %q", outcome.stream, outcome.data, payload)
						}
						t.Logf("timing=%s read_idle=%s ping_wait=%s outage=%s restored_at=%s: stream=%d read_finished_at=%s error=%v", timingKind, readIdle, pingWait, outage, restoredAt, outcome.stream, outcome.elapsed, outcome.err)
					}
					if outage == 8*time.Second && pingWait == 5*time.Second && closed != 2 {
						t.Fatalf("8s TCP blackhole spanning 5s PING wait closed %d streams, want both", closed)
					}
					probe := dialHTTP2PingTestTunnel(t, manager, target)
					assertHTTP2PingTestEcho(t, probe, "verify-pool-after-temporary-tcp-loss")
					wantConnections := uint64(1)
					if closed > 0 {
						wantConnections = 2
					}
					if got := proxy.accepted.Load(); got != wantConnections {
						t.Fatalf("TLS connections = %d, want %d after %d stream failures", got, wantConnections, closed)
					}
					t.Logf("observed outcome: closed_streams=%d/2 TLS_connections=%d; temporary-outage survival is an observation, not a required 4s/8s recovery assumption", closed, proxy.accepted.Load())
				})
			}
		}
	}

	for _, pingWait := range []time.Duration{5 * time.Second, 10 * time.Second} {
		t.Run(fmt.Sprintf("healthy_400ms_rtt_2pct_loss_256kbit_read_idle_15s_ping_%ds", int(pingWait.Seconds())), func(t *testing.T) {
			impairment := &http2PingNetemImpairment{}
			defer impairment.clear(t)
			proxy, manager, target, first, second := newHTTP2PingNetemPair(t, 15*time.Second, pingWait)
			// Each direction crosses the loopback egress qdisc once, producing an
			// approximately 400ms RTT. Netem's random loss is intentionally real.
			impairment.apply(t, "limit", "1000", "delay", "200ms", "loss", "2%", "rate", "256kbit")
			started := time.Now()
			payload := bytes.Repeat([]byte("n"), 512)
			longest := time.Duration(0)
			count := 0
			for time.Since(started) < 8*time.Second && count < 40 {
				tunnel := first
				if count%2 != 0 {
					tunnel = second
				}
				requestStart := time.Now()
				assertHTTP2PingNetemEcho(t, tunnel, payload, 20*time.Second)
				if elapsed := time.Since(requestStart); elapsed > longest {
					longest = elapsed
				}
				count++
			}
			t.Logf("read_idle=15s ping_wait=%s: %d successful 512-byte echo exchanges across 2 shared streams in %s; maximum observed exchange latency=%s", pingWait, count, time.Since(started), longest)
			select {
			case id := <-proxy.pings:
				if id != 1 {
					t.Fatalf("healthy idle PING connection = %d, want 1", id)
				}
			case <-time.After(25 * time.Second):
				t.Fatal("no real 15s-idle PING reached the peer under the network profile")
			}
			assertHTTP2PingNetemEcho(t, first, []byte("warm-first-after-network-idle"), 20*time.Second)
			assertHTTP2PingNetemEcho(t, second, []byte("warm-second-after-network-idle"), 20*time.Second)
			impairment.stats(t)
			impairment.clear(t)
			third := dialHTTP2PingTestTunnel(t, manager, target)
			assertHTTP2PingTestEcho(t, third, "pooled-after-degraded-network")
			if got := proxy.accepted.Load(); got != 1 {
				t.Fatalf("TLS connections after sustained traffic and real idle PING = %d, want 1", got)
			}
			t.Log("both tunnels survived sustained traffic and an idle PING; another CONNECT reused the original TLS/H2 connection")
		})
	}
}

type http2PingNetemImpairment struct{ active bool }

func (impairment *http2PingNetemImpairment) apply(t *testing.T, profile ...string) {
	t.Helper()
	args := append([]string{"qdisc", "replace", "dev", "lo", "root", "netem"}, profile...)
	impairment.active = true
	if output, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
		t.Fatalf("apply isolated lo netem: %v: %s", err, output)
	}
	t.Logf("isolated lo netem: %s", strings.Join(profile, " "))
}

func (impairment *http2PingNetemImpairment) clear(t *testing.T) {
	t.Helper()
	if !impairment.active {
		return
	}
	if output, err := exec.Command("tc", "qdisc", "del", "dev", "lo", "root").CombinedOutput(); err != nil {
		t.Errorf("clear isolated lo netem: %v: %s", err, output)
		return
	}
	impairment.active = false
}

func (impairment *http2PingNetemImpairment) stats(t *testing.T) {
	t.Helper()
	if output, err := exec.Command("tc", "-s", "qdisc", "show", "dev", "lo").CombinedOutput(); err != nil {
		t.Errorf("read isolated netem counters: %v: %s", err, output)
	} else {
		t.Logf("actual qdisc counters:\n%s", strings.TrimSpace(string(output)))
	}
}

func newHTTP2PingNetemPair(t *testing.T, readIdle, pingWait time.Duration) (*http2PingTestProxy, *http2ConnectManager, *config.Target, net.Conn, net.Conn) {
	t.Helper()
	proxy := newHTTP2PingTestProxy(t, 0)
	manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
		transport := newHTTP2ConnectTransport(key)
		transport.TLSClientConfig.RootCAs = proxy.roots
		transport.ReadIdleTimeout = readIdle
		transport.PingTimeout = pingWait
		return transport
	})
	t.Cleanup(manager.closeIdle)
	target := &config.Target{
		Address: proxy.listener.Addr().String(),
		ConnectProxy: &config.ConnectProxyConfig{
			Protocols: []string{config.ConnectProxyH2}, ServerName: "127.0.0.1",
		},
	}
	first := dialHTTP2PingTestTunnel(t, manager, target)
	second := dialHTTP2PingTestTunnel(t, manager, target)
	assertHTTP2PingTestEcho(t, first, "first-before-network-fault")
	assertHTTP2PingTestEcho(t, second, "second-before-network-fault")
	if got := proxy.accepted.Load(); got != 1 {
		t.Fatalf("initial TLS connections = %d, want 1 shared by 2 CONNECT streams", got)
	}
	return proxy, manager, target, first, second
}

type http2PingNetemReadOutcome struct {
	stream  int
	data    []byte
	err     error
	elapsed time.Duration
}

func startHTTP2PingNetemReads(tunnels []net.Conn, length int, started time.Time) <-chan http2PingNetemReadOutcome {
	outcomes := make(chan http2PingNetemReadOutcome, len(tunnels))
	for index, tunnel := range tunnels {
		go func() {
			data := make([]byte, length)
			_, err := io.ReadFull(tunnel, data)
			outcomes <- http2PingNetemReadOutcome{stream: index + 1, data: data, err: err, elapsed: time.Since(started)}
		}()
	}
	return outcomes
}

func receiveHTTP2PingNetemRead(t *testing.T, outcomes <-chan http2PingNetemReadOutcome, deadline time.Time) http2PingNetemReadOutcome {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case outcome := <-outcomes:
		return outcome
	case <-timer.C:
		t.Fatal("TCP netem experiment exceeded its bounded stream-read observation window")
		return http2PingNetemReadOutcome{}
	}
}

func assertHTTP2PingNetemEcho(t *testing.T, tunnel net.Conn, payload []byte, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if _, err := tunnel.Write(payload); err != nil {
			done <- err
			return
		}
		response := make([]byte, len(payload))
		_, err := io.ReadFull(tunnel, response)
		if err == nil && !bytes.Equal(response, payload) {
			err = fmt.Errorf("echo payload mismatch")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("TCP netem echo: %v", err)
		}
	case <-time.After(timeout):
		t.Fatalf("TCP netem echo made no progress within %s", timeout)
	}
}
