package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// openAIWSIngressCapacityShedRepo 补齐 SetError，避免非容量类错误（如
// workspace_suspended）走到账号状态副作用时打空指针。
type openAIWSIngressCapacityShedRepo struct {
	stubOpenAIAccountRepo
}

func (r *openAIWSIngressCapacityShedRepo) SetError(context.Context, int64, string) error { return nil }

func (r *openAIWSIngressCapacityShedRepo) SetRateLimited(context.Context, int64, time.Time) error {
	return nil
}

func (r *openAIWSIngressCapacityShedRepo) UpdateExtra(context.Context, int64, map[string]any) error {
	return nil
}

// WebSocket ingress preserves capacity and authorization error classifications.
func TestProxyResponsesWebSocketFromClient_PreservesCapacityShedCodeForClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		upstreamEvents [][]byte
		wantContains   []string
		wantAbsent     []string
	}{
		{
			name: "capacity_shed_error_and_failed_are_preserved",
			upstreamEvents: [][]byte{
				[]byte(`{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}`),
				[]byte(`{"type":"response.failed","response":{"id":"resp_shed","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}}`),
			},
			wantContains: []string{
				`"code":"server_is_overloaded"`,
				"Our servers are currently overloaded",
			},
			wantAbsent: []string{`"code":"server_error"`},
		},
		{
			name: "selected_model_capacity_without_code_is_normalized",
			upstreamEvents: [][]byte{
				[]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"Selected model is at capacity. Please try a different model."}}`),
				[]byte(`{"type":"response.failed","response":{"id":"resp_capacity","status":"failed","error":{"message":"Selected model is at capacity. Please try a different model."}}}`),
			},
			wantContains: []string{
				`"code":"server_is_overloaded"`,
				"Selected model is at capacity",
			},
			wantAbsent: []string{`"code":"server_error"`},
		},
		{
			name: "non_capacity_error_code_is_passed_through",
			upstreamEvents: [][]byte{
				[]byte(`{"type":"error","error":{"type":"invalid_request_error","code":"workspace_suspended","message":"workspace is suspended"}}`),
				[]byte(`{"type":"response.failed","response":{"id":"resp_suspended","status":"failed","error":{"code":"workspace_suspended","message":"workspace is suspended"}}}`),
			},
			wantContains: []string{
				`"code":"workspace_suspended"`,
				"workspace is suspended",
			},
			wantAbsent: []string{"server_error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newOpenAIWSV2TestConfig()
			cfg.Security.URLAllowlist.Enabled = false
			cfg.Security.URLAllowlist.AllowInsecureHTTP = true
			cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
			cfg.Gateway.OpenAIWS.MinIdlePerAccount = 0
			cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
			cfg.Gateway.OpenAIWS.QueueLimitPerConn = 8
			cfg.Gateway.OpenAIWS.DialTimeoutSeconds = 3
			cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
			cfg.Gateway.OpenAIWS.WriteTimeoutSeconds = 3

			events := make([][]byte, 0, len(tt.upstreamEvents))
			for _, event := range tt.upstreamEvents {
				events = append(events, append([]byte(nil), event...))
			}
			captureConn := &openAIWSCaptureConn{events: events}
			pool := newOpenAIWSConnPool(cfg)
			pool.setClientDialerForTest(&openAIWSCaptureDialer{conn: captureConn})

			account := Account{
				ID:          5401,
				Name:        "openai-ingress-capacity-shed",
				Platform:    PlatformOpenAI,
				Type:        AccountTypeAPIKey,
				Status:      StatusActive,
				Schedulable: true,
				Concurrency: 1,
				Credentials: map[string]any{"api_key": "sk-test"},
				Extra:       map[string]any{"responses_websockets_v2_enabled": true},
			}
			repo := &openAIWSIngressCapacityShedRepo{stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}}}
			svc := &OpenAIGatewayService{
				accountRepo:      repo,
				rateLimitService: &RateLimitService{accountRepo: repo},
				httpUpstream:     &httpUpstreamRecorder{},
				cache:            &stubGatewayCache{},
				cfg:              cfg,
				openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
				toolCorrector:    NewCodexToolCorrector(),
				openaiWSPool:     pool,
			}

			serverDone := make(chan struct{})
			wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(serverDone)
				conn, err := coderws.Accept(w, r, &coderws.AcceptOptions{CompressionMode: coderws.CompressionContextTakeover})
				if err != nil {
					return
				}
				defer func() { _ = conn.CloseNow() }()

				rec := httptest.NewRecorder()
				ginCtx, _ := gin.CreateTestContext(rec)
				req := r.Clone(r.Context())
				req.Header = req.Header.Clone()
				req.Header.Set("User-Agent", "unit-test-agent/1.0")
				ginCtx.Request = req

				readCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
				msgType, firstMessage, readErr := conn.Read(readCtx)
				cancel()
				if readErr != nil || (msgType != coderws.MessageText && msgType != coderws.MessageBinary) {
					return
				}
				_ = svc.ProxyResponsesWebSocketFromClient(r.Context(), ginCtx, conn, &account, "sk-test", firstMessage, nil)
			}))
			defer wsServer.Close()

			dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
			clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(wsServer.URL, "http"), nil)
			cancelDial()
			require.NoError(t, err)
			defer func() { _ = clientConn.CloseNow() }()

			writeCtx, cancelWrite := context.WithTimeout(context.Background(), 3*time.Second)
			err = clientConn.Write(writeCtx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.1","stream":false}`))
			cancelWrite()
			require.NoError(t, err)

			var frames []string
			for len(frames) < len(tt.upstreamEvents) {
				readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_, message, readErr := clientConn.Read(readCtx)
				cancel()
				if readErr != nil {
					break
				}
				frames = append(frames, string(message))
			}
			// 本轮已终止，主动断开客户端让 ingress 退出 turn 循环。
			_ = clientConn.CloseNow()

			require.NotEmpty(t, frames, "客户端应至少收到一个下发事件")
			joined := strings.Join(frames, "\n")
			for _, want := range tt.wantContains {
				require.Contains(t, joined, want, "客户端收到的事件:\n%s", joined)
			}
			for _, absent := range tt.wantAbsent {
				require.NotContains(t, joined, absent, "客户端收到的事件:\n%s", joined)
			}

			select {
			case <-serverDone:
			case <-time.After(5 * time.Second):
				t.Fatal("等待 ingress websocket 结束超时")
			}
		})
	}
}
