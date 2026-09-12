package tlsfingerprint

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Test-only proxy peers never connect to an address supplied by the client.
func testTunnelProxy(t *testing.T, scheme, target string, stall bool) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var sockets []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if stall {
					io.Copy(io.Discard, c)
					return
				}
				reader := bufio.NewReader(c)
				if scheme == "http" {
					req, err := http.ReadRequest(reader)
					if err != nil || req.Method != "CONNECT" || req.Host != target {
						return
					}
				} else {
					header := make([]byte, 2)
					if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 {
						return
					}
					if _, err := io.CopyN(io.Discard, reader, int64(header[1])); err != nil {
						return
					}
					c.Write([]byte{5, 0})
					request := make([]byte, 4)
					if _, err := io.ReadFull(reader, request); err != nil || request[1] != 1 {
						return
					}
					size := 0
					switch request[3] {
					case 1:
						size = 4
					case 4:
						size = 16
					case 3:
						n, err := reader.ReadByte()
						if err != nil {
							return
						}
						size = int(n)
					default:
						return
					}
					if _, err := io.CopyN(io.Discard, reader, int64(size+2)); err != nil {
						return
					}
				}
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				if scheme == "http" {
					io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				} else {
					c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				}
				c.SetDeadline(time.Time{})
				done := make(chan struct{})
				go func() {
					io.Copy(upstream, reader)
					upstream.Close()
					close(done)
				}()
				io.Copy(c, upstream)
				c.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range sockets {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	u, _ := url.Parse(scheme + "://" + ln.Addr().String())
	return u
}

func TestProfileTransportProxyH2AndCancellation(t *testing.T) {
	for _, scheme := range []string{"http", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "through-proxy")
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			p := &Profile{ALPNProtocols: []string{"h2", "http/1.1"},
				HTTP2: &HTTP2Config{InitialWindowSize: transportValue(uint32(2048))}}
			proxyURL := testTunnelProxy(t, scheme, server.Listener.Addr().String(), false)
			var dial func(context.Context, string, string) (net.Conn, error)
			if scheme == "http" {
				dial = NewHTTPProxyDialer(p, proxyURL).dialTunnel
			} else {
				dial = NewSOCKS5ProxyDialer(p, proxyURL).dialTunnel
			}
			tr, _ := testProfileTransport(t, server, p, dial)
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			tr.CloseIdleConnections()
			if err != nil || string(body) != "through-proxy" || resp.ProtoMajor != 2 {
				t.Fatalf("proxy response: %d %q %v", resp.ProtoMajor, body, err)
			}

			stalled := testTunnelProxy(t, scheme, server.Listener.Addr().String(), true)
			if scheme == "http" {
				dial = NewHTTPProxyDialer(p, stalled).DialTLSContext
			} else {
				dial = NewSOCKS5ProxyDialer(p, stalled).DialTLSContext
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			if conn, err := dial(ctx, "tcp", server.Listener.Addr().String()); err == nil {
				conn.Close()
				t.Fatal("stalled proxy ignored cancellation")
			}
			if time.Since(start) > time.Second {
				t.Fatal("proxy cancellation was not bounded")
			}
		})
	}
}
