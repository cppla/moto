package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"moto/config"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTP2BrowserProfileOversizeResponsePreservesSibling(t *testing.T) {
	var mu sync.Mutex
	addresses := make(map[string]bool)
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		addresses[r.RemoteAddr] = true
		mu.Unlock()
		if r.Host == "oversize.example:443" || r.Host == "trailer.example:443" {
			if r.Host == "trailer.example:443" {
				w.Header().Set("Trailer", "X-"+strings.Repeat("x", 20000))
			} else {
				w.Header().Set("X-Large", strings.Repeat("x", 20000))
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 4)
		for {
			if _, err := io.ReadFull(r.Body, buffer); err != nil {
				return
			}
			_, _ = w.Write(bytes.ToUpper(buffer))
			w.(http.Flusher).Flush()
		}
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")
	target.ConnectProxy.BrowserProfile = config.BrowserProfileChrome
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := manager.dial(ctx, target, "healthy.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for _, destination := range []string{"oversize.example:443", "trailer.example:443"} {
		if unexpected, err := manager.dial(ctx, target, destination); err == nil {
			_ = unexpected.Close()
			t.Fatalf("%s escaped local CONNECT header limit", destination)
		} else if !strings.Contains(err.Error(), "response header list exceeds local acceptance limit") {
			t.Fatalf("%s error = %v", destination, err)
		}
	}
	if _, err := first.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(first, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "PING" {
		t.Fatalf("sibling response = %q", response)
	}
	third, err := manager.dial(ctx, target, "next.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	mu.Lock()
	count := len(addresses)
	mu.Unlock()
	if count != 1 {
		t.Fatalf("oversize stream replaced physical connection: got %d", count)
	}
}

func TestHTTP2BrowserProfileIsExplicitAndCopiedToPhysicalTransport(t *testing.T) {
	defaultTransport := newHTTP2ConnectTransport(http2ConnectTransportKey{})
	if defaultTransport.ChromeProfile {
		t.Fatal("legacy default enabled browser HTTP/2 profile")
	}
	profileTransport := newHTTP2ConnectTransport(http2ConnectTransportKey{browserProfile: config.BrowserProfileChrome})
	pool := newHTTP2ConnectConnPool(profileTransport)
	physical := pool.physicalTransport(profileTransport.TLSClientConfig, nil)
	if !profileTransport.ChromeProfile || !physical.ChromeProfile {
		t.Fatal("explicit profile was lost in physical connection transport")
	}
}

func TestHTTP2BrowserProfileBidirectionalPayloadCrossesBothWindows(t *testing.T) {
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 64<<10)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	})
	manager := newHTTP2ConnectTestManager(proxy)
	defer manager.closeIdle()
	target := http2ConnectTestTarget(proxy, "", "")
	target.ConnectProxy.BrowserProfile = config.BrowserProfileChrome
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := manager.dial(ctx, target, "large.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	watchdog := time.AfterFunc(20*time.Second, func() { _ = connection.Close() })
	defer watchdog.Stop()
	// One tunnel exceeds both the 6 MiB stream and 15 MiB connection receive
	// windows in each direction, requiring real WINDOW_UPDATE processing.
	payload := make([]byte, (17<<20)+509)
	for index := range payload {
		payload[index] = byte((index*31 + index/257) % 251)
	}
	want := sha256.Sum256(payload)
	type uploadResult struct {
		bytes int64
		err   error
	}
	written := make(chan uploadResult, 1)
	go func() {
		n, err := io.Copy(connection, bytes.NewReader(payload))
		if err == nil {
			err = connection.(interface{ CloseWrite() error }).CloseWrite()
		}
		written <- uploadResult{n, err}
	}()
	digest := sha256.New()
	received, readErr := io.Copy(digest, connection)
	upload := <-written
	if upload.err != nil || readErr != nil {
		t.Fatalf("upload=%d/%v download=%d/%v", upload.bytes, upload.err, received, readErr)
	}
	if upload.bytes != int64(len(payload)) || received != int64(len(payload)) || !bytes.Equal(digest.Sum(nil), want[:]) {
		t.Fatalf("payload integrity failed: upload=%d download=%d expected=%d digest=%x", upload.bytes, received, len(payload), digest.Sum(nil))
	}
}
