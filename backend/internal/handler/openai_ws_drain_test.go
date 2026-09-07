//go:build unit

package handler

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/antibypass"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/pkg/wsdrain"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type drainHTTPUpstream struct{ service.HTTPUpstream }
type drainAntiBypassSettings struct{}

func (drainAntiBypassSettings) IsAntiBypassEnabled(context.Context) (bool, error) {
	return true, nil
}

func (u *drainHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}
func (u *drainHTTPUpstream) DoWithTLS(req *http.Request, proxy string, id int64, count int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxy, id, count)
}

type terminalGateListener struct {
	net.Listener
	atWrite chan struct{}
	release chan struct{}
	once    sync.Once
}
type terminalGateConn struct {
	net.Conn
	listener *terminalGateListener
}

func (l *terminalGateListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &terminalGateConn{Conn: conn, listener: l}, nil
}
func (c *terminalGateConn) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte("response.completed")) {
		c.listener.once.Do(func() { close(c.listener.atWrite) })
		<-c.listener.release
	}
	return c.Conn.Write(body)
}

func TestRealResponsesWSDrainKeepsFirstTurnAndTerminalWrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, mode := range []string{"ctx_pool", "http_bridge", "passthrough"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			started, allowUpstream := make(chan struct{}), make(chan struct{})
			var startOnce, releaseOnce sync.Once
			releaseUpstream := func() { releaseOnce.Do(func() { close(allowUpstream) }) }
			var connMu sync.Mutex
			var upstreamConns []*coderws.Conn
			terminal := []byte(`{"type":"response.completed","response":{"id":"resp_drain","model":"gpt-6-astra","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK"}]}],"usage":{"input_tokens":1,"output_tokens":1}}}`)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
					conn, err := coderws.Accept(w, r, nil)
					if err != nil {
						return
					}
					defer conn.CloseNow()
					connMu.Lock()
					upstreamConns = append(upstreamConns, conn)
					connMu.Unlock()
					if _, _, err = conn.Read(ctx); err != nil {
						return
					}
					startOnce.Do(func() { close(started) })
					select {
					case <-allowUpstream:
					case <-ctx.Done():
						return
					}
					_ = conn.Write(ctx, coderws.MessageText, terminal)
					_, _, _ = conn.Read(ctx)
					return
				}
				_, _ = io.Copy(io.Discard, r.Body)
				startOnce.Do(func() { close(started) })
				select {
				case <-allowUpstream:
				case <-ctx.Done():
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write(append(append([]byte("data: "), terminal...), '\n', '\n'))
			}))
			defer upstream.Close()
			defer func() {
				cancel()
				releaseUpstream()
				connMu.Lock()
				defer connMu.Unlock()
				for _, conn := range upstreamConns {
					_ = conn.CloseNow()
				}
			}()

			cfg := &config.Config{RunMode: config.RunModeSimple}
			cfg.Security.URLAllowlist.Enabled = false
			cfg.Security.URLAllowlist.AllowInsecureHTTP = true
			cfg.Security.URLAllowlist.AllowPrivateHosts = true
			cfg.Gateway.OpenAIWS.Enabled = true
			cfg.Gateway.OpenAIWS.APIKeyEnabled = true
			cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
			cfg.Gateway.OpenAIWS.IngressModeDefault = mode
			cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
			cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 5
			cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 3
			cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3
			cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
			account := service.Account{
				ID: 81, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
				Status: service.StatusActive, Schedulable: true, Concurrency: 1,
				Credentials: map[string]any{"api_key": "local-fixture-only", "base_url": upstream.URL},
				Extra:       map[string]any{"openai_apikey_responses_websockets_v2_mode": mode, "openai_passthrough": true},
			}
			repo := &grokCredentialHandlerRepo{accounts: []service.Account{account}}
			billing := service.NewBillingCacheService(nil, nil, nil, nil, nil, nil, cfg, nil)
			defer billing.Stop()
			gateway := service.NewOpenAIGatewayService(
				repo, nil, nil, nil, nil, nil, nil, cfg, nil, nil,
				service.NewBillingService(cfg, nil), nil, billing, &drainHTTPUpstream{},
				&service.DeferredService{}, nil, nil, nil, nil, nil, nil, nil,
			)
			cache := &concurrencyCacheMock{
				acquireUserSlotFn:    func(context.Context, int64, int, string) (bool, error) { return true, nil },
				acquireAccountSlotFn: func(context.Context, int64, int, string) (bool, error) { return true, nil },
			}
			h := NewOpenAIGatewayHandler(gateway, service.NewConcurrencyService(cache), billing, &service.APIKeyService{}, nil, nil, nil, nil, cfg)
			group := int64(82)
			key := &service.APIKey{ID: 83, GroupID: &group,
				User:  &service.User{ID: 84, Status: service.StatusActive},
				Group: &service.Group{ID: group, Platform: service.PlatformOpenAI, Status: service.StatusActive}}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(string(middleware.ContextKeyAPIKey), key)
				c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 84, Concurrency: 1})
				c.Next()
			})
			guardStore := miniredis.RunT(t)
			guardRedis := redis.NewClient(&redis.Options{Addr: guardStore.Addr()})
			defer guardRedis.Close()
			router.Use(gin.HandlerFunc(middleware.NewAntiBypassMiddleware(
				antibypass.NewGuard(guardRedis), drainAntiBypassSettings{}, cfg,
			)))
			router.GET("/v1/responses", h.ResponsesWebSocket)
			registry := wsdrain.New()
			server := httptest.NewUnstartedServer(registry.Handler(router))
			gate := &terminalGateListener{Listener: server.Listener, atWrite: make(chan struct{}), release: make(chan struct{})}
			server.Listener = gate
			server.Start()
			defer server.Close()
			var gateOnce sync.Once
			releaseGate := func() { gateOnce.Do(func() { close(gate.release) }) }
			defer releaseGate()
			client, _, err := coderws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
			require.NoError(t, err)
			defer client.CloseNow()
			require.NoError(t, client.Write(ctx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-6-astra","input":"local test","instructions":"local test","stream":true}`)))
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("actual upstream not reached")
			}
			require.Equal(t, 1, registry.Snapshot().Active, "first turn must be registered before either transport starts")
			inflight, err := guardRedis.ZCard(ctx, "sub2api:anti-bypass:v3:{user:84}:inflight").Result()
			require.NoError(t, err)
			require.EqualValues(t, 1, inflight, "the actual first inference must hold exactly one anti-bypass lease")
			rpm, err := guardRedis.ZCard(ctx, "sub2api:anti-bypass:v3:{user:84}:rpm").Result()
			require.NoError(t, err)
			require.EqualValues(t, 1, rpm, "handshake and inference must not double-count")
			releaseUpstream()
			select {
			case <-gate.atWrite:
			case <-ctx.Done():
				t.Fatal("client terminal write not reached")
			}
			require.Equal(t, 1, registry.Snapshot().Active, "accounting completion cannot release the drain lease")
			registry.BeginDrain()
			require.Zero(t, registry.Snapshot().Closing, "must not close before terminal reaches the client")
			releaseGate()
			for {
				_, payload, readErr := client.Read(ctx)
				require.NoError(t, readErr)
				if bytes.Contains(payload, []byte("response.completed")) {
					break
				}
			}
			_, _, err = client.Read(ctx)
			require.Equal(t, coderws.StatusServiceRestart, coderws.CloseStatus(err))
			require.NoError(t, registry.Wait(ctx))
			require.Zero(t, registry.Count())
			require.Eventually(t, func() bool {
				count, readErr := guardRedis.ZCard(context.Background(), "sub2api:anti-bypass:v3:{user:84}:inflight").Result()
				return readErr == nil && count == 0
			}, time.Second, time.Millisecond, "actual handler must release the anti-bypass turn")
		})
	}
}
