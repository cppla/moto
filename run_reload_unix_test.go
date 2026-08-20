//go:build !windows

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"moto/config"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

type processReloadBackend struct {
	listener net.Listener
	id       string
	wg       sync.WaitGroup
	active   sync.Map
}

func newProcessReloadBackend(t *testing.T, id string) *processReloadBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &processReloadBackend{listener: listener, id: id}
	backend.wg.Add(1)
	go func() {
		defer backend.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			backend.active.Store(conn, struct{}{})
			backend.wg.Add(1)
			go func() {
				defer backend.wg.Done()
				defer backend.active.Delete(conn)
				defer conn.Close()
				_, _ = io.WriteString(conn, id+"\n")
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		backend.active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		backend.wg.Wait()
	})
	return backend
}

func TestProcessReloadsValidatedConfigurationOnSIGHUP(t *testing.T) {
	backendA := newProcessReloadBackend(t, "a")
	backendB := newProcessReloadBackend(t, "b")
	listenProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := listenProbe.Addr().String()
	_ = listenProbe.Close()

	temporary := t.TempDir()
	binary := filepath.Join(temporary, "moto")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build moto: %v\n%s", buildErr, output)
	}
	configPath := filepath.Join(temporary, "setting.json")
	writeProcessReloadConfig(t, configPath, listen, backendA.listener.Addr().String())
	logFile, err := os.Create(filepath.Join(temporary, "moto-process.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	command := exec.Command(binary, "--config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	defer func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-processDone:
		default:
		}
	}()

	oldConn := waitProcessReloadBackend(t, processDone, listen, "a")
	defer oldConn.Close()
	writeProcessReloadConfig(t, configPath, listen, backendB.listener.Addr().String())
	if err := command.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal SIGHUP: %v", err)
	}
	newConn := waitProcessReloadBackend(t, processDone, listen, "b")
	_ = newConn.Close()

	if _, err := io.WriteString(oldConn, "old\n"); err != nil {
		t.Fatalf("write old stream: %v", err)
	}
	oldReply := make([]byte, 4)
	if _, err := io.ReadFull(oldConn, oldReply); err != nil {
		t.Fatalf("read old stream: %v", err)
	}
	if string(oldReply) != "old\n" {
		t.Fatalf("old stream reply = %q", oldReply)
	}
	_ = oldConn.Close()

	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal SIGTERM: %v", err)
	}
	select {
	case waitErr := <-processDone:
		if waitErr != nil {
			t.Fatalf("moto exited with error: %v", waitErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("moto did not exit after SIGTERM")
	}
}

func writeProcessReloadConfig(t *testing.T, path, listen, target string) {
	t.Helper()
	cfg := config.Config{
		Log: config.LogConfig{Level: "error"},
		Rules: []*config.Rule{{
			Name:                "process-reload",
			Listen:              listen,
			Mode:                config.ModeNormal,
			Timeout:             1000,
			MaxConnections:      16,
			MaxConnectionsPerIP: 16,
			Targets:             []*config.Target{{Address: target}},
		}},
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitProcessReloadBackend(t *testing.T, processDone <-chan error, listen, want string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			t.Fatalf("moto exited before backend %q became active: %v", want, err)
		default:
		}
		conn, err := net.DialTimeout("tcp", listen, 100*time.Millisecond)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		id, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr == nil && id == want+"\n" {
			_ = conn.SetReadDeadline(time.Time{})
			return conn
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("backend %q did not become active", want)
	return nil
}
