package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// --- mock: 只记录临时不可调度写入，其余方法不应被调用 ---

type capacityShedAccountRepoStub struct {
	AccountRepository // 嵌入接口，未实现的方法会 panic（不应被调用）

	tempUnschedCalls int
}

func (r *capacityShedAccountRepoStub) SetTempUnschedulable(_ context.Context, _ int64, _ time.Time, _ string) error {
	r.tempUnschedCalls++
	return nil
}

// 上游容量降载是请求级信号：故障因素（客户端身份、模型容量）与账号无关，
// 同账号重试用尽后不得把账号临时摘掉——否则一个被降载的请求会顺着 failover
// 把整池账号逐个封禁，而每个账号都会以同一个错误失败。
func TestTempUnscheduleRetryableErrorSkipsRequestScopedTransient(t *testing.T) {
	t.Run("请求级瞬时故障不写账号状态", func(t *testing.T) {
		repo := &capacityShedAccountRepoStub{}
		svc := &GatewayService{accountRepo: repo}

		svc.TempUnscheduleRetryableError(context.Background(), 1, &UpstreamFailoverError{
			StatusCode:             http.StatusBadGateway,
			RetryableOnSameAccount: true,
			RequestScopedTransient: true,
		})

		require.Zero(t, repo.tempUnschedCalls)
	})

	// 对照组：同样的 502 在未标记请求级瞬时故障时仍按原有语义临时摘号，
	// 确认上面的断言来自新增守卫而非其他前置条件。
	t.Run("未标记时保持原有临时摘号语义", func(t *testing.T) {
		repo := &capacityShedAccountRepoStub{}
		svc := &GatewayService{accountRepo: repo}

		svc.TempUnscheduleRetryableError(context.Background(), 1, &UpstreamFailoverError{
			StatusCode:             http.StatusBadGateway,
			RetryableOnSameAccount: true,
		})

		require.Equal(t, 1, repo.tempUnschedCalls)
	})
}

// 非池模式账号同样要先在同账号重试：换号不改变降载因素。
func TestStreamFailedEventCapacityShedRetriesOnSameAccount(t *testing.T) {
	nonPool := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	for _, code := range []string{"server_is_overloaded", "slow_down"} {
		payload := []byte(`{"type":"response.failed","response":{"error":{"code":"` + code + `"}}}`)
		require.True(t, isOpenAIUpstreamCapacityShedEvent(payload), code)
		require.True(t, openAIStreamFailedEventRetryableOnSameAccount(nonPool, payload, "overloaded"), code)
	}

	// 非降载的 failed 事件在非池模式下仍不做同账号重试，避免放大改动面。
	other := []byte(`{"type":"response.failed","response":{"error":{"code":"server_error"}}}`)
	require.False(t, isOpenAIUpstreamCapacityShedEvent(other))
	require.False(t, openAIStreamFailedEventRetryableOnSameAccount(nonPool, other, "boom"))
}

func TestStreamFailedEventCapacityShedMessageFallback(t *testing.T) {
	payload := []byte(`{"type":"response.failed","response":{"error":{"message":"Our servers are currently overloaded. Please try again later."}}}`)

	require.True(t, isOpenAIUpstreamCapacityShedEvent(payload))
	require.True(t, openAIStreamFailedEventRetryableOnSameAccount(
		&Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
		payload,
		"Our servers are currently overloaded. Please try again later.",
	))
}

func TestOpenAIPassthroughCapacityHTTPEnvelopeFailsOverForOAuth(t *testing.T) {
	payload := []byte(`{"type":"response.failed","response":{"status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}}`)

	require.True(t, shouldFailoverOpenAIPassthroughResponse(
		&Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
		http.StatusBadGateway,
		payload,
	))
	require.True(t, shouldFailoverOpenAIPassthroughResponse(
		&Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
		http.StatusServiceUnavailable,
		payload,
	))
}

func TestOpenAIPassthroughOrdinaryOAuthHTTP502DoesNotUseCapacityBodyRule(t *testing.T) {
	payload := []byte(`{"error":{"type":"server_error","message":"temporary upstream failure"}}`)

	require.False(t, shouldFailoverOpenAIPassthroughResponse(
		&Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
		http.StatusBadGateway,
		payload,
	))
}

func TestOpenAIStreamCapacityShedMarksRequestScopedTransient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	svc := &OpenAIGatewayService{cfg: &config.Config{}}
	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	payload := []byte(`{"type":"response.failed","response":{"error":{"code":"server_is_overloaded","message":"overloaded"}}}`)

	svc.recordOpenAIStreamUpstreamError(c, account, false, "rid-capacity-marker", "http_error", payload, "overloaded")

	require.True(t, IsOpenAIRequestScopedTransient(c))

	otherRec := httptest.NewRecorder()
	otherCtx, _ := gin.CreateTestContext(otherRec)
	otherCtx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	otherPayload := []byte(`{"type":"response.failed","response":{"error":{"code":"server_error","message":"upstream failed"}}}`)
	svc.recordOpenAIStreamUpstreamError(otherCtx, account, false, "rid-account-error", "http_error", otherPayload, "upstream failed")

	require.False(t, IsOpenAIRequestScopedTransient(otherCtx))
}

// 上游降载的真实序列是「event: error → event: response.failed」。error 帧不算
// 客户端输出：若把它当首输出 flush，clientOutputStarted 被固化，随后的 failed
// 事件就进不了 pre-output failover 分支，只能把致命错误原样转发给客户端。
func TestOpenAIStreamErrorFrameDoesNotStartClientOutput(t *testing.T) {
	cases := []struct {
		data      string
		eventType string
		want      bool
	}{
		{`{"type":"error","error":{"code":"server_is_overloaded","message":"overloaded"}}`, "error", false},
		{`{"type":"error","error":{"code":"slow_down","message":"slow down"}}`, "error", false},
		{`{"type":"error","error":{"type":"rate_limit_error","code":"rate_limit_exceeded","message":"limited"}}`, "error", false},
		// 不可重试类错误帧维持原样转发（不进 failover），保留上游错误细节。
		{`{"type":"error","error":{"type":"invalid_request_error","code":"content_policy_violation","message":"blocked"}}`, "error", true},
		{`{"error":{"message":"Our servers are currently overloaded. Please try again later."}}`, "", false},
		{`{"type":"response.failed","response":{"error":{"code":"server_is_overloaded"}}}`, "response.failed", false},
		{`{"type":"response.created","response":{"id":"resp_1"}}`, "response.created", false},
		{`{"type":"response.in_progress","response":{"id":"resp_1"}}`, "response.in_progress", false},
		{`{"type":"response.output_text.delta","delta":""}`, "response.output_text.delta", false},
		{`{"type":"response.output_text.delta","delta":"hi"}`, "response.output_text.delta", true},
		{`{"type":"response.function_call_arguments.delta","delta":""}`, "response.function_call_arguments.delta", false},
		{`{"type":"response.function_call_arguments.delta","delta":"{"}`, "response.function_call_arguments.delta", true},
		{`{"type":"response.custom_tool_call_input.delta","delta":""}`, "response.custom_tool_call_input.delta", false},
		{`{"type":"response.content_part.added","part":{"type":"output_text","text":""}}`, "response.content_part.added", false},
		{`{"type":"response.content_part.added","part":{"type":"output_text","text":"hi"}}`, "response.content_part.added", true},
		{`{"type":"response.output_item.added","item":{"id":"item_1","type":"function_call","arguments":""}}`, "response.output_item.added", false},
		{`{"type":"response.output_item.added","item":{"id":"item_1","type":"function_call","arguments":"{"}}`, "response.output_item.added", true},
		// Unknown events may carry provider-specific semantic output. Treat them
		// as committed rather than risking a cross-account replay after output.
		{`{"type":"response.provider_extension","payload":{"value":"x"}}`, "response.provider_extension", true},
		{`[DONE]`, "", true},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, openAIStreamDataStartsClientOutput(tc.data, tc.eventType), "data=%s type=%s", tc.data, tc.eventType)
	}
}

// 回归用例（真实上游降载序列）：created → in_progress → error 帧 → response.failed。
// 期望仍然走 pre-output failover（同账号重试 + 请求级瞬时标记），且不向客户端写出任何字节。
func TestOpenAIStreamCapacityShedErrorFramePrecedingFailedStillFailsOver(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
	}
	svc := &OpenAIGatewayService{cfg: cfg}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(strings.Join([]string{
			"event: response.created",
			`data: {"type":"response.created","response":{"id":"resp_1"},"sequence_number":0}`,
			"",
			"event: response.in_progress",
			`data: {"type":"response.in_progress","response":{"id":"resp_1"},"sequence_number":1}`,
			"",
			"event: error",
			`data: {"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."},"sequence_number":2}`,
			"",
			"event: response.failed",
			`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."},"usage":{"input_tokens":1234,"output_tokens":17,"input_tokens_details":{"cached_tokens":900}}},"sequence_number":3}`,
			"",
		}, "\n"))),
		Header: http.Header{"X-Request-Id": []string{"rid-shed-error-then-failed"}},
	}

	_, err := svc.handleStreamingResponse(c.Request.Context(), resp, c, &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acc"}, time.Now(), "model", "model")
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.ErrorAs(t, err, &failoverErr)
	require.True(t, failoverErr.RetryableOnSameAccount)
	require.True(t, failoverErr.RequestScopedTransient)
	require.False(t, c.Writer.Written())
	require.Empty(t, rec.Body.String())
}

func TestOpenAIStreamEmptyStructuralEventsBeforeCapacityStillFailOver(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
	}
	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acc"}
	body := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_1"}}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","delta":""}`,
		"",
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","delta":""}`,
		"",
		"event: response.content_part.added",
		`data: {"type":"response.content_part.added","part":{"type":"output_text","text":""}}`,
		"",
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","item":{"id":"item_1","type":"function_call","arguments":""}}`,
		"",
		"event: response.failed",
		`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}}`,
		"",
	}, "\n")

	for _, tc := range []struct {
		name string
		run  func(*OpenAIGatewayService, *gin.Context, *http.Response, *Account) error
	}{
		{
			name: "responses",
			run: func(svc *OpenAIGatewayService, c *gin.Context, resp *http.Response, account *Account) error {
				_, err := svc.handleStreamingResponse(c.Request.Context(), resp, c, account, time.Now(), "model", "model")
				return err
			},
		},
		{
			name: "passthrough",
			run: func(svc *OpenAIGatewayService, c *gin.Context, resp *http.Response, account *Account) error {
				_, err := svc.handleStreamingResponsePassthrough(c.Request.Context(), resp, c, account, time.Now(), "model", "model")
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     http.Header{"X-Request-Id": []string{"rid-empty-structure-capacity"}},
			}

			err := tc.run(&OpenAIGatewayService{cfg: cfg}, c, resp, account)
			require.Error(t, err)
			var failoverErr *UpstreamFailoverError
			require.ErrorAs(t, err, &failoverErr)
			require.True(t, failoverErr.RetryableOnSameAccount)
			require.True(t, failoverErr.RequestScopedTransient)
			require.False(t, c.Writer.Written())
			require.Empty(t, rec.Body.String())
		})
	}
}

func bindCapacityShedPassthroughRule(t *testing.T, c *gin.Context) {
	t.Helper()
	responseCode := http.StatusTeapot
	rule := &model.ErrorPassthroughRule{
		ID:              1,
		Enabled:         true,
		Platforms:       []string{PlatformOpenAI},
		ErrorCodes:      []int{http.StatusServiceUnavailable},
		Keywords:        []string{"server_is_overloaded"},
		MatchMode:       model.MatchModeAll,
		ResponseCode:    &responseCode,
		PassthroughBody: true,
	}
	ruleSvc := &ErrorPassthroughService{}
	ruleSvc.setLocalCache([]*model.ErrorPassthroughRule{rule})
	BindErrorPassthroughService(c, ruleSvc)
}

func capacityShedResponseFailedSSE() string {
	return strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_1"}}`,
		"",
		"event: response.failed",
		`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}}`,
		"",
	}, "\n")
}

// A matching passthrough rule must not commit an overload response before the
// request-scoped same-account retry path gets a chance to run.
func TestOpenAIStreamingCapacityShedSkipsPassthroughRule(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
	}
	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acc"}

	for _, tc := range []struct {
		name string
		run  func(*OpenAIGatewayService, *gin.Context, *http.Response, *Account) error
	}{
		{
			name: "responses",
			run: func(svc *OpenAIGatewayService, c *gin.Context, resp *http.Response, account *Account) error {
				_, err := svc.handleStreamingResponse(c.Request.Context(), resp, c, account, time.Now(), "model", "model")
				return err
			},
		},
		{
			name: "passthrough",
			run: func(svc *OpenAIGatewayService, c *gin.Context, resp *http.Response, account *Account) error {
				_, err := svc.handleStreamingResponsePassthrough(c.Request.Context(), resp, c, account, time.Now(), "model", "model")
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			bindCapacityShedPassthroughRule(t, c)

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(capacityShedResponseFailedSSE())),
				Header:     http.Header{"X-Request-Id": []string{"rid-capacity-shed-rule"}},
			}

			err := tc.run(&OpenAIGatewayService{cfg: cfg}, c, resp, account)
			require.Error(t, err)
			var failoverErr *UpstreamFailoverError
			require.ErrorAs(t, err, &failoverErr)
			require.True(t, failoverErr.RetryableOnSameAccount)
			require.True(t, failoverErr.RequestScopedTransient)
			require.False(t, c.Writer.Written())
			require.Empty(t, rec.Body.String())
		})
	}
}

// 流中途（已有真实输出）降载时无法安全 failover。必须保留真实降载码，避免
// Codex 把它当 server_error 自动重放整段长上下文，造成重复计费和重连风暴。
func TestOpenAIStreamCapacityShedAfterOutputPreservesCodeToPreventReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
	}
	svc := &OpenAIGatewayService{cfg: cfg}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(strings.Join([]string{
			"event: response.created",
			`data: {"type":"response.created","response":{"id":"resp_1"}}`,
			"",
			"event: response.output_text.delta",
			`data: {"type":"response.output_text.delta","delta":"partial"}`,
			"",
			"event: error",
			`data: {"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."},"sequence_number":2}`,
			"",
			"event: response.failed",
			`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."},"usage":{"input_tokens":1234,"output_tokens":17,"input_tokens_details":{"cached_tokens":900}}},"sequence_number":3}`,
			"",
		}, "\n"))),
		Header: http.Header{"X-Request-Id": []string{"rid-shed-after-output"}},
	}

	_, err := svc.handleStreamingResponse(c.Request.Context(), resp, c, &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acc"}, time.Now(), "model", "model")
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.False(t, errors.As(err, &failoverErr))

	body := rec.Body.String()
	require.Contains(t, body, "partial")
	require.Contains(t, body, "event: response.failed")
	require.Contains(t, body, `"code":"server_is_overloaded"`)
	require.NotContains(t, body, `"code":"server_error"`)
	require.Contains(t, body, "Our servers are currently overloaded")

	rawEvents, ok := c.Get(OpsUpstreamErrorsKey)
	require.True(t, ok)
	events, ok := rawEvents.([]*OpsUpstreamErrorEvent)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.NotNil(t, events[0].Usage)
	require.Equal(t, 1234, events[0].Usage.InputTokens)
	require.Equal(t, 900, events[0].Usage.CacheReadInputTokens)
	require.Equal(t, 17, events[0].Usage.OutputTokens)
	require.True(t, events[0].ClientOutputStarted)
	require.Equal(t, "response.output_text.delta", events[0].FirstClientOutputEventType)
	require.True(t, events[0].VisibleOutputSeen)
}

func TestOpenAIStreamCapacityAfterUnknownSemanticEventRecordsCommitBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
	}
	svc := &OpenAIGatewayService{cfg: cfg}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(strings.Join([]string{
			"event: response.created",
			`data: {"type":"response.created","response":{"id":"resp_1"}}`,
			"",
			"event: response.provider_extension",
			`data: {"type":"response.provider_extension","payload":{"value":"opaque-semantic-state"}}`,
			"",
			"event: response.failed",
			`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."},"usage":{"input_tokens":42,"output_tokens":0}}}`,
			"",
		}, "\n"))),
		Header: http.Header{"X-Request-Id": []string{"rid-unknown-before-capacity"}},
	}

	_, err := svc.handleStreamingResponse(c.Request.Context(), resp, c, &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Name: "acc"}, time.Now(), "model", "model")
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.False(t, errors.As(err, &failoverErr))

	rawEvents, ok := c.Get(OpsUpstreamErrorsKey)
	require.True(t, ok)
	events, ok := rawEvents.([]*OpsUpstreamErrorEvent)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.True(t, events[0].ClientOutputStarted)
	require.Equal(t, "response.provider_extension", events[0].FirstClientOutputEventType)
	require.False(t, events[0].VisibleOutputSeen)
	require.NotNil(t, events[0].Usage)
	require.Equal(t, 42, events[0].Usage.InputTokens)
}

func TestSanitizeOpenAIResponseFailedEventForClient_CapacityShedReplayBoundary(t *testing.T) {
	payload := []byte(`{"type":"response.failed","response":{"error":{"code":"server_is_overloaded","message":"overloaded"}}}`)

	beforeOutput, changed := sanitizeOpenAIResponseFailedEventForClient(payload, "response.failed", false)
	require.True(t, changed)
	require.Contains(t, string(beforeOutput), `"code":"server_error"`)

	afterOutput, changed := sanitizeOpenAIResponseFailedEventForClient(payload, "response.failed", true)
	require.False(t, changed)
	require.Equal(t, string(payload), string(afterOutput))
}

// helper 单测：只有降载码被改写，其余错误码（尤其 rate_limit_exceeded，客户端
// 依赖其原码解析重试延时）必须原样保留。
func TestSanitizeOpenAICapacityShedErrorCodeForClient(t *testing.T) {
	cases := []struct {
		name        string
		payload     string
		wantChanged bool
		wantContain string
	}{
		{
			name:        "failed事件嵌套code改写",
			payload:     `{"type":"response.failed","response":{"error":{"code":"server_is_overloaded","message":"overloaded"}}}`,
			wantChanged: true,
			wantContain: `"code":"server_error"`,
		},
		{
			name:        "error帧裸code改写",
			payload:     `{"type":"error","error":{"code":"slow_down","message":"slow down"}}`,
			wantChanged: true,
			wantContain: `"code":"server_error"`,
		},
		{
			name:        "rate_limit不改写",
			payload:     `{"type":"response.failed","response":{"error":{"code":"rate_limit_exceeded","message":"try again in 3s"}}}`,
			wantChanged: false,
			wantContain: `"code":"rate_limit_exceeded"`,
		},
		{
			name:        "普通server_error不改写",
			payload:     `{"type":"response.failed","response":{"error":{"code":"server_error","message":"boom"}}}`,
			wantChanged: false,
			wantContain: `"code":"server_error"`,
		},
		{
			name:        "非JSON不改写",
			payload:     `not-json`,
			wantChanged: false,
			wantContain: `not-json`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, changed := sanitizeOpenAICapacityShedErrorCodeForClient([]byte(tc.payload))
			require.Equal(t, tc.wantChanged, changed)
			require.Contains(t, string(out), tc.wantContain)
			if changed {
				require.NotContains(t, string(out), "server_is_overloaded")
				require.NotContains(t, string(out), "slow_down")
			}
		})
	}
}

// 出站身份的版本声明只能有一个来源：UA 的版本段、version 头、探针版本三处必须同源，
// 各自硬编码会漂移成互相矛盾的身份，而自相矛盾或陈旧的身份会被上游优先降载。
func TestCodexOutboundVersionHasSingleSource(t *testing.T) {
	require.True(t,
		strings.HasPrefix(codexCLIUserAgent, openai.CodexDefaultOriginator+"/"+codexCLIVersion+" "),
		"codexCLIUserAgent=%q 必须以 codexCLIVersion=%q 作为版本段", codexCLIUserAgent, codexCLIVersion,
	)
	require.Equal(t, codexCLIVersion, openAICodexProbeVersion)
	require.GreaterOrEqual(t, CompareVersions(codexCLIVersion, codexUpstreamMinVersion), 0,
		"codexCLIVersion=%q 不得低于上游最低门槛 %q", codexCLIVersion, codexUpstreamMinVersion,
	)
}
