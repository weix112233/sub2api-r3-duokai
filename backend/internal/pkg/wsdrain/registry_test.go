package wsdrain

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

func TestUpgradeTokensStayPendingUntilHandlerReturns(t *testing.T) {
	for _, values := range [][]string{{"h2c, websocket"}, {"h2c", "WebSocket"}, {" websocket "}} {
		t.Run(strings.Join(values, "|"), func(t *testing.T) {
			registry := New()
			accepted, register := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(register) }) }
			server := httptest.NewServer(registry.Handler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				conn, err := websocket.Accept(w, req, nil)
				if err != nil {
					return
				}
				close(accepted)
				<-register
				session := Track(req.Context(), conn, false)
				defer func() { _ = conn.CloseNow(); session.Release() }()
				_, _, _ = conn.Read(req.Context())
			})))
			defer server.Close()
			defer release()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			req.Header["Upgrade"] = values
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 16)))
			response, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
			<-accepted
			require.Equal(t, 1, registry.Snapshot().PendingUpgrades)
			registry.BeginDrain()
			done := make(chan error, 1)
			go func() { done <- registry.Wait(ctx) }()
			select {
			case result := <-done:
				t.Fatalf("drain returned before late registration: %v", result)
			case <-time.After(30 * time.Millisecond):
			}
			release()
			response.Body.Close()
			require.NoError(t, <-done)
			require.Zero(t, registry.Count())
		})
	}
}

func TestStaleAttemptCallbacksCannotEndCurrentAttempt(t *testing.T) {
	registry := New()
	sessionCh := make(chan *Session, 1)
	client, done := connection(t, registry, false, func(session *Session, conn *websocket.Conn) {
		sessionCh <- session
		_, _, _ = conn.Read(t.Context())
	})
	session := <-sessionCh
	first, ok := session.BeginAttempt()
	require.True(t, ok)
	first.Release()
	second, ok := session.BeginAttempt()
	require.True(t, ok)
	first.EndTurn(1)
	first.Release()
	require.Equal(t, 1, registry.Snapshot().Active)
	require.True(t, second.BeginTurn(2), "an earlier terminal callback may still be unwinding")
	second.EndTurn(1)
	require.Equal(t, 1, registry.Snapshot().Active)
	registry.BeginDrain()
	require.False(t, second.BeginTurn(3))
	second.EndTurn(2)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, _, err := client.Read(ctx)
	require.Equal(t, websocket.StatusServiceRestart, websocket.CloseStatus(err))
	require.NoError(t, registry.Wait(ctx))
	<-done
}

func connection(t *testing.T, r *Registry, continuous bool, handler func(*Session, *websocket.Conn)) (*websocket.Conn, <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	server := httptest.NewServer(r.Handler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer close(done)
		conn, err := websocket.Accept(w, req, nil)
		if err != nil {
			return
		}
		session := Track(req.Context(), conn, continuous)
		defer func() { _ = conn.CloseNow(); session.Release() }()
		handler(session, conn)
	})))
	t.Cleanup(server.Close)
	client, _, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseNow() })
	return client, done
}

func TestIdleWebSocketReceivesRestartCloseAndReleases(t *testing.T) {
	registry := New()
	ready := make(chan struct{})
	client, done := connection(t, registry, false, func(_ *Session, conn *websocket.Conn) {
		close(ready)
		_, _, _ = conn.Read(t.Context())
	})
	<-ready
	registry.BeginDrain()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, _, err := client.Read(ctx)
	require.Equal(t, websocket.StatusServiceRestart, websocket.CloseStatus(err))
	require.NoError(t, registry.Wait(ctx))
	<-done
	require.Zero(t, registry.Count())
}

func TestActiveTurnCompletesBeforeRestartClose(t *testing.T) {
	registry := New()
	ready, finish := make(chan struct{}), make(chan struct{})
	client, done := connection(t, registry, false, func(session *Session, conn *websocket.Conn) {
		attempt, ok := session.BeginAttempt()
		if !ok {
			return
		}
		close(ready)
		<-finish
		_ = conn.Write(t.Context(), websocket.MessageText, []byte("completed"))
		attempt.EndTurn(1)
		_, _, _ = conn.Read(t.Context())
	})
	<-ready
	registry.BeginDrain()
	require.Equal(t, 1, registry.Count())
	close(finish)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, body, err := client.Read(ctx)
	require.NoError(t, err)
	require.Equal(t, "completed", string(body))
	_, _, err = client.Read(ctx)
	require.Equal(t, websocket.StatusServiceRestart, websocket.CloseStatus(err))
	require.NoError(t, registry.Wait(ctx))
	<-done
}

func TestContinuousSessionDeadlineIsExplicitAndClosesSocket(t *testing.T) {
	registry := New()
	ready := make(chan struct{})
	client, done := connection(t, registry, true, func(_ *Session, conn *websocket.Conn) {
		close(ready)
		_, _, _ = conn.Read(t.Context())
	})
	<-ready
	registry.BeginDrain()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, registry.Wait(ctx), context.DeadlineExceeded)
	_, _, err := client.Read(t.Context())
	require.Error(t, err)
	<-done
	require.Zero(t, registry.Count())
}

func TestDrainingRejectsNewHTTPAndWebSocketAdmissions(t *testing.T) {
	registry := New()
	registry.BeginDrain()
	server := httptest.NewServer(registry.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("new handler admitted during shutdown")
	})))
	defer server.Close()
	response, err := http.Get(server.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 503, response.StatusCode)
	require.Equal(t, "5", response.Header.Get("Retry-After"))
	_, handshake, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.Error(t, err)
	require.Equal(t, 503, handshake.StatusCode)
	require.NoError(t, registry.Wait(t.Context()))
}
