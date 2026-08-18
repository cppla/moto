package controller

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialFastContextReturnsRealTCPConn(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialFastContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("DialFastContext() error = %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*net.TCPConn); !ok {
		t.Fatalf("DialFastContext() returned %T, want *net.TCPConn", conn)
	}

	select {
	case serverConn := <-accepted:
		_ = serverConn.Close()
	case <-time.After(time.Second):
		t.Fatal("listener did not accept the connection")
	}
}

func TestDialFastContextHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	conn, err := DialFastContext(ctx, "203.0.113.1:9")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("DialFastContext() returned a connection for a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialFastContext() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("cancelled dial took %s", elapsed)
	}
}
