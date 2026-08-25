//go:build linux

package controller

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestCopyConnTransfersLargeTCPPayload(t *testing.T) {
	sender, relaySource := newTCPPair(t)
	relayDestination, receiver := newTCPPair(t)
	defer sender.Close()
	defer relaySource.Close()
	defer relayDestination.Close()
	defer receiver.Close()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{sender, relaySource, relayDestination, receiver} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	payload := bytes.Repeat([]byte("moto-splice-"), 128*1024)
	receivedCh := make(chan []byte, 1)
	receiveErrCh := make(chan error, 1)
	go func() {
		received, err := io.ReadAll(receiver)
		if err != nil {
			receiveErrCh <- err
			return
		}
		receivedCh <- received
	}()

	type copyResult struct {
		copied int64
		err    error
	}
	resultCh := make(chan copyResult, 1)
	go func() {
		copied, err := copyConn(relayDestination, relaySource)
		resultCh <- copyResult{copied: copied, err: err}
	}()

	if _, err := sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := sender.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("io.Copy result = (%d, %v), want success", result.copied, result.err)
	}
	if result.copied != int64(len(payload)) {
		t.Fatalf("io.Copy bytes = %d, want %d", result.copied, len(payload))
	}
	if err := relayDestination.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-receiveErrCh:
		t.Fatal(err)
	case received := <-receivedCh:
		if !bytes.Equal(received, payload) {
			t.Fatalf("received %d bytes with mismatched payload", len(received))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out receiving spliced payload")
	}
}
