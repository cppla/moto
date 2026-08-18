package controller

import (
	"context"
	"io"
	"moto/config"
	"net"
	"regexp"
	"testing"
	"time"
)

func TestHandleRegexpRoutesShortInitialPacketImmediately(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		packet  string
	}{
		{name: "HTTP", pattern: `^GET`, packet: "GET / HTTP/1.0\r\n\r\n"},
		{name: "SSH", pattern: `^SSH`, packet: "SSH-2.0-test\r\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backendListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer backendListener.Close()

			backendDone := make(chan error, 1)
			backendReceived := make(chan string, 1)
			response := []byte("accepted " + test.name)
			go func() {
				conn, err := backendListener.Accept()
				if err != nil {
					backendDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

				packet := make([]byte, len(test.packet))
				if _, err := io.ReadFull(conn, packet); err != nil {
					backendDone <- err
					return
				}
				backendReceived <- string(packet)
				if _, err := conn.Write(response); err != nil {
					backendDone <- err
					return
				}
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					backendDone <- err
					return
				}
				_, err = io.Copy(io.Discard, conn)
				backendDone <- err
			}()

			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer proxyListener.Close()

			rule := &config.Rule{
				Name:    "short-" + test.name,
				Mode:    "regex",
				Timeout: 2000,
				Targets: []*config.Target{{
					Regexp:  test.pattern,
					Re:      regexp.MustCompile(test.pattern),
					Address: backendListener.Addr().String(),
				}},
			}
			proxyDone := make(chan struct{})
			go func() {
				conn, err := proxyListener.Accept()
				if err == nil {
					HandleRegexp(context.Background(), conn, rule)
				}
				close(proxyDone)
			}()

			clientConn, err := net.Dial("tcp", proxyListener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			client := clientConn.(*net.TCPConn)
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(750 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}

			// Keep the request write side open while waiting for the response. The
			// old CopyN(4096) implementation timed out here instead of routing.
			if _, err := client.Write([]byte(test.packet)); err != nil {
				t.Fatal(err)
			}
			gotResponse := make([]byte, len(response))
			if _, err := io.ReadFull(client, gotResponse); err != nil {
				t.Fatalf("short %s packet was not routed immediately: %v", test.name, err)
			}
			if string(gotResponse) != string(response) {
				t.Fatalf("response = %q, want %q", gotResponse, response)
			}
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, client); err != nil {
				t.Fatal(err)
			}

			select {
			case got := <-backendReceived:
				if got != test.packet {
					t.Fatalf("backend packet = %q, want %q", got, test.packet)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("backend did not receive buffered initial packet")
			}
			select {
			case err := <-backendDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("backend did not finish")
			}
			select {
			case <-proxyDone:
			case <-time.After(3 * time.Second):
				t.Fatal("regex handler did not finish")
			}
		})
	}
}
