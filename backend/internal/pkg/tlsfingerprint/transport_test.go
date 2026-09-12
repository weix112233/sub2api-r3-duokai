package tlsfingerprint

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func transportValue[T any](v T) *T { return &v }

func testProfileTransport(t *testing.T, server *httptest.Server, p *Profile, rawDial ...func(context.Context, string, string) (net.Conn, error)) (*Transport, *atomic.Int32) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dials := new(atomic.Int32)
	base := &http.Transport{
		IdleConnTimeout: time.Minute, MaxConnsPerHost: 2,
		ResponseHeaderTimeout: 2 * time.Second,
	}
	base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		dial := (&net.Dialer{Timeout: time.Second}).DialContext
		if len(rawDial) != 0 {
			dial = rawDial[0]
		}
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		conn := utls.UClient(raw, &utls.Config{RootCAs: roots, ServerName: host}, utls.HelloCustom)
		if err := conn.ApplyPreset(buildClientHelloSpecFromProfile(p)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	tr, err := NewTransport(base, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr, dials
}

func TestProfileTransportALPNAndFlow(t *testing.T) {
	for _, tc := range []struct {
		name string
		alpn []string
		h2   bool
		want int
	}{
		{"h2", []string{"h2", "http/1.1"}, true, 2},
		{"fallback", []string{"h2", "http/1.1"}, false, 1},
		{"no-alpn", []string{}, true, 1},
		{"inherited", nil, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("wire-flow"), 32768)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(body, payload) {
					t.Error("upload body changed or truncated:", err)
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(payload)
			}))
			server.EnableHTTP2 = tc.h2
			server.StartTLS()
			defer server.Close()
			p := &Profile{ALPNProtocols: tc.alpn, ShuffleExtensions: true}
			if p.HasHTTP2() {
				p.HTTP2 = &HTTP2Config{
					InitialWindowSize:      transportValue(uint32(1024)),
					ConnectionWindowUpdate: transportValue(uint32(0)),
					MaxHeaderListSize:      transportValue(uint32(32768)),
					EnablePush:             transportValue(true),
				}
			}
			tr, dials := testProfileTransport(t, server, p)
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			for i := 0; i < 2; i++ {
				resp, err := client.Post(server.URL, "application/octet-stream", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil || !bytes.Equal(data, payload) || resp.ProtoMajor != tc.want {
					t.Fatalf("response proto=%d bytes=%d error=%v", resp.ProtoMajor, len(data), readErr)
				}
				if tc.want == 2 && (resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0) {
					t.Fatal("HTTP/2 response lost verified TLS state")
				}
			}
			if dials.Load() != 1 {
				t.Fatalf("expected connection reuse, dials=%d", dials.Load())
			}
			tr.CloseIdleConnections()
			resp, err := client.Post(server.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if dials.Load() != 2 {
				t.Fatalf("CloseIdleConnections did not retire selected protocol: %d", dials.Load())
			}
		})
	}
}

func TestProfileTransportCancellationAndHeaderTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.Write([]byte("ok"))
			return
		}
		if r.URL.Path == "/body" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	tr, dials := testProfileTransport(t, server, &Profile{ALPNProtocols: []string{"h2"}})
	tr.ResponseHeaderTimeout = 50 * time.Millisecond
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	if _, err := client.Get(server.URL + "/headers"); err == nil {
		t.Fatal("expected response header timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/body", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("body cancellation: %v", err)
	}
	resp, err = client.Get(server.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(data) != "ok" || dials.Load() != 1 {
		t.Fatalf("cancel damaged concurrent connection: %q %v dials=%d", data, err, dials.Load())
	}
}

func TestProfileTransportRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	p := &Profile{ALPNProtocols: []string{"h2", "http/1.1"}}
	tr, err := NewTransport(&http.Transport{DialTLSContext: NewDialer(p, nil).DialTLSContext}, p)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	_, err = client.Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate not rejected: %v", err)
	}
}
