package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"moto/config"
	xhttp2 "moto/internal/browserhttp2"
)

func TestHTTP2ConnectDebugRedactsCredentials(t *testing.T) {
	const (
		portEnv       = "MOTO_TEST_H2_DEBUG_PROXY_PORT"
		username      = "debug-fixture"
		password      = "synthetic-password"
		responseToken = "synthetic-response-token"
	)
	if port := os.Getenv(portEnv); port != "" {
		der, err := io.ReadAll(os.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		manager := newHTTP2ConnectManager(func(key http2ConnectTransportKey) *xhttp2.Transport {
			transport := newHTTP2ConnectTransport(key)
			transport.TLSClientConfig.RootCAs = roots
			return transport
		})
		defer manager.closeIdle()
		target := &config.Target{
			Address: net.JoinHostPort("127.0.0.1", port),
			ConnectProxy: &config.ConnectProxyConfig{
				ServerName: "127.0.0.1",
				BasicAuth:  &config.BasicAuthConfig{Username: username, Password: password},
			},
		}
		conn, err := manager.dial(t.Context(), target, "service.example:443")
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		return
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	proxy := newHTTP2ConnectTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic "+encoded {
			http.Error(w, "CONNECT authentication failed", http.StatusProxyAuthRequired)
			return
		}
		w.Header().Set("Authorization", "Bearer "+responseToken)
		w.Header().Set("Proxy-Authorization", "Basic "+encoded)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	})
	_, port, err := net.SplitHostPort(proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// GODEBUG is read at init. Keep the upstream in the parent so its
	// independent HTTP/2 implementation cannot write to the client log.
	for _, debug := range []string{"http2debug=1", "http2debug=2"} {
		t.Run(debug, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHTTP2ConnectDebugRedactsCredentials$")
			cmd.Env = append(os.Environ(), "GODEBUG="+debug, portEnv+"="+port)
			cmd.Stdin = bytes.NewReader(proxy.Certificate().Raw)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("authenticated H2 CONNECT subprocess: %v", err)
			}
			for _, secret := range []string{password, encoded, responseToken} {
				if bytes.Contains(output, []byte(secret)) {
					t.Fatal("credential present in HTTP/2 debug output")
				}
			}
			if !bytes.Contains(output, []byte(`Transport encoding header "proxy-authorization" = "[REDACTED]"`)) {
				t.Fatal("missing redacted outgoing proxy authorization header in debug output")
			}
			if debug == "http2debug=2" && !bytes.Contains(output, []byte(`header field "authorization" = "[REDACTED]"`)) {
				t.Fatal("missing redacted response authorization header in frame debug output")
			}
		})
	}
}
