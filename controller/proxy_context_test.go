package controller

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyProtocolContextCancellationInterruptsWriteAndClearsDeadline(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- writeProxyProtocolWithContext(ctx, connection, "test", func() error {
			close(started)
			_, err := connection.Write([]byte("blocked header"))
			return err
		})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("PROXY protocol write did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled PROXY protocol write error = %v, want context.Canceled", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("context cancellation did not interrupt blocked PROXY protocol write")
	}

	readDone := make(chan error, 1)
	go func() {
		var received [1]byte
		_, err := io.ReadFull(peer, received[:])
		if err == nil && received[0] != 'x' {
			err = errors.New("unexpected byte after canceled write")
		}
		readDone <- err
	}()
	if _, err := connection.Write([]byte{'x'}); err != nil {
		t.Fatalf("deadline remained poisoned after canceled PROXY protocol write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}
