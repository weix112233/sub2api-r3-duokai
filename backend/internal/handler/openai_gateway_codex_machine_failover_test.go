//go:build unit

package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- Codex OAuth machine 模式：真实 handler failover 循环下的 I2（无残留）用例 ---
// 走 h.Responses → SelectAccountWithSchedulerForCapability → Forward 的真实选号/切换循环：
// 首选 machine 账号上游 5xx 触发 failover，切到 off 账号后出站头与 body 必须是真实值，
// 不得残留上一账号的假名（service 层 TestCodexMachineChain_Failover_I2_NoResidualIDs 是手工
// stage，此处补真实循环）。

const (
	machineFailoverRoot = "01912e2a-6f3c-7d1e-9c4a-0f1e2d3c4b5a" // UUIDv7
	machineFailoverSeed = "11111111-1111-4111-8111-111111111111"
)

// machineFailoverPseudonym 与 service.codexMachinePseudonym 同算法（UUIDv7 保留前 6 字节），
// 用于在 handler 包内计算期望假名。
func machineFailoverPseudonym(seed, id string) string {
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte("sub2api:codex-machine:v1:" + id))
	sum := mac.Sum(nil)
	parsed := uuid.MustParse(id)
	var out uuid.UUID
	copy(out[0:6], parsed[0:6])
	copy(out[6:16], sum[0:10])
	out[6] = (out[6] & 0x0f) | 0x70
	out[8] = (out[8] & 0x3f) | 0x80
	return out.String()
}

type machineFailoverUpstream struct {
	service.HTTPUpstream
	mu       sync.Mutex
	hits     []int64
	headers  []http.Header
	bodies   [][]byte
	failByID map[int64]int
	failBody string
}

func (u *machineFailoverUpstream) Do(req *http.Request, _ string, accountID int64, _ int) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	u.mu.Lock()
	u.hits = append(u.hits, accountID)
	u.headers = append(u.headers, req.Header.Clone())
	u.bodies = append(u.bodies, append([]byte(nil), body...))
	status := u.failByID[accountID]
	u.mu.Unlock()
	if status > 0 {
		failureBody := u.failBody
		if failureBody == "" {
			failureBody = `{"error":{"message":"upstream unavailable"}}`
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(failureBody)),
		}, nil
	}
	if bytes.Contains(body, []byte(`"stream":true`)) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: io.NopCloser(bytes.NewBufferString(
				"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_machine_failover\",\"model\":\"gpt-5.2\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
			)),
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(bytes.NewBufferString(
			`{"id":"resp_machine_failover","object":"response","model":"gpt-5.2","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1}}`,
		)),
	}, nil
}

func (u *machineFailoverUpstream) snapshot() ([]int64, []http.Header, [][]byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]int64(nil), u.hits...), append([]http.Header(nil), u.headers...), append([][]byte(nil), u.bodies...)
}

func (u *machineFailoverUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, concurrency)
}

func machineFailoverTurnMetadata(root string) string {
	return `{"installation_id":"real-install","session_id":"` + root + `","thread_id":"` + root + `","turn_id":"turn-real","window_id":"` + root + `:0","sandbox":"seccomp","sandbox_mode":"workspace-write","thread_source":"cli"}`
}

func newCodexMachineFailoverHandler(t *testing.T) (*machineFailoverUpstream, *gin.Engine, func()) {
	t.Helper()
	groupID := int64(911)
	expires := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	accounts := []service.Account{
		{
			ID: 811, Name: "codex-machine", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
			Status: service.StatusActive, Schedulable: true, Concurrency: 1, Priority: 1,
			Credentials: map[string]any{"access_token": "machine-access", "chatgpt_account_id": "chatgpt-machine", "expires_at": expires},
			Extra: map[string]any{
				"codex_fingerprint_mode": "machine",
				"codex_fingerprint_seed": machineFailoverSeed,
			},
		},
		{
			ID: 812, Name: "codex-off", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
			Status: service.StatusActive, Schedulable: true, Concurrency: 1, Priority: 2,
			Credentials: map[string]any{"access_token": "off-access", "chatgpt_account_id": "chatgpt-off", "expires_at": expires},
			Extra:       map[string]any{"codex_fingerprint_mode": "off"},
		},
	}
	repo := &grokCredentialHandlerRepo{accounts: accounts, missingOnGet: map[int64]bool{}}
	upstream := &machineFailoverUpstream{failByID: map[int64]int{811: http.StatusInternalServerError}}

	cfg := &config.Config{RunMode: config.RunModeSimple}
	cfg.Gateway.MaxAccountSwitches = 3
	billingCache := service.NewBillingCacheService(nil, nil, nil, nil, nil, nil, cfg, nil)
	gateway := service.NewOpenAIGatewayService(
		repo, nil, nil, nil, nil, nil, nil, cfg, nil, nil,
		service.NewBillingService(cfg, nil), nil, billingCache, upstream,
		&service.DeferredService{}, nil, nil, nil, nil, nil, nil, nil,
	)
	cache := &concurrencyCacheMock{
		acquireUserSlotFn:    func(context.Context, int64, int, string) (bool, error) { return true, nil },
		acquireAccountSlotFn: func(context.Context, int64, int, string) (bool, error) { return true, nil },
	}
	h := NewOpenAIGatewayHandler(gateway, service.NewConcurrencyService(cache), billingCache, &service.APIKeyService{}, nil, nil, nil, nil, cfg)
	apiKey := &service.APIKey{
		ID: 912, GroupID: &groupID,
		User:  &service.User{ID: 913, Status: service.StatusActive},
		Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI, Status: service.StatusActive},
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyAPIKey), apiKey)
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: apiKey.User.ID, Concurrency: 1})
		c.Next()
	})
	router.POST("/openai/v1/responses", h.Responses)
	router.POST("/openai/v1/chat/completions", h.ChatCompletions)
	return upstream, router, func() { billingCache.Stop() }
}

func TestCapacityBudgetThroughRealHTTPHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name  string
		route string
		body  string
	}{
		{"responses_json", "/openai/v1/responses", `{"model":"gpt-5.2","stream":false,"input":"local test"}`},
		{"responses_sse", "/openai/v1/responses", `{"model":"gpt-5.2","stream":true,"input":"local test"}`},
		{"chat_json", "/openai/v1/chat/completions", `{"model":"gpt-5.2","stream":false,"messages":[{"role":"user","content":"local test"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, router, cleanup := newCodexMachineFailoverHandler(t)
			defer cleanup()
			upstream.failByID = map[int64]int{811: 503, 812: 503}
			upstream.failBody = `{"error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded."}}`
			req := httptest.NewRequest(http.MethodPost, tc.route, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			hits, _, _ := upstream.snapshot()
			require.Len(t, hits, 3, "capacity request must stop after three upstream failures")
			require.Equal(t, []int64{811, 811, 812}, hits)
			require.Contains(t, recorder.Body.String(), `"code":"server_is_overloaded"`)
			if recorder.Code == http.StatusOK {
				require.Equal(t, 1, strings.Count(recorder.Body.String(), "event: response.failed"))
			} else {
				require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
			}
		})
	}
}

func TestResponsesFailover_CodexMachineToOff_NoResidualIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream, router, cleanup := newCodexMachineFailoverHandler(t)
	defer cleanup()

	root := machineFailoverRoot
	tm := machineFailoverTurnMetadata(root)
	tmJSONBytes, err := json.Marshal(tm)
	require.NoError(t, err)
	tmJSON := string(tmJSONBytes)
	body := `{"model":"gpt-5.2","stream":false,"instructions":"You are Codex.","prompt_cache_key":"` + root + `",` +
		`"client_metadata":{"x-codex-installation-id":"real-install","session_id":"` + root + `","thread_id":"` + root +
		`","turn_id":"turn-real","x-codex-window-id":"` + root + `:0","x-codex-turn-metadata":` + tmJSON + `},` +
		`"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/responses", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "codex_cli_rs/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	req.Header.Set("originator", "codex_cli_rs")
	req.Header.Set("session-id", root)
	req.Header.Set("thread-id", root)
	req.Header.Set("x-client-request-id", root)
	req.Header.Set("x-codex-window-id", root+":0")
	req.Header.Set("x-codex-installation-id", "real-install")
	req.Header.Set("x-codex-turn-metadata", tm)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	hits, headers, bodies := upstream.snapshot()
	require.Equal(t, []int64{811, 812}, hits, "machine 账号 5xx 后必须切到 off 账号")

	// attempt 1（machine）：头 + body 全假名，无真实值
	p := machineFailoverPseudonym(machineFailoverSeed, root)
	h1, b1 := headers[0], string(bodies[0])
	require.Equal(t, p, h1.Get("session-id"))
	require.Equal(t, p, h1.Get("thread-id"))
	require.Equal(t, p, h1.Get("x-client-request-id"))
	require.Equal(t, p+":0", h1.Get("x-codex-window-id"))
	require.NotEqual(t, "real-install", h1.Get("x-codex-installation-id"))
	require.NotEmpty(t, h1.Get("x-codex-installation-id"))
	require.Empty(t, h1.Get("session_id"))
	require.Equal(t, p, gjson.Get(h1.Get("x-codex-turn-metadata"), "thread_id").String())
	require.Equal(t, p, gjson.Get(b1, "client_metadata.session_id").String())
	require.Equal(t, p, gjson.Get(b1, "client_metadata.thread_id").String())
	require.Equal(t, p, gjson.Get(b1, "prompt_cache_key").String())
	require.NotContains(t, b1, root)
	require.NotContains(t, b1, "real-install")
	for name, values := range h1 {
		for _, v := range values {
			require.NotContains(t, v, root, "attempt1 头 %s 不得含真实 thread", name)
			require.NotContains(t, v, "real-install", "attempt1 头 %s 不得含真实 installation", name)
		}
	}

	// Off disables convergence, not credential isolation. Both sinks must use
	// the second account's namespace without retaining the first account's IDs.
	h2, b2 := headers[1], string(bodies[1])
	require.Empty(t, h2.Get("session-id"), "off 账号不放行连字符会话头（HEAD 行为）")
	require.Empty(t, h2.Get("thread-id"))
	require.Empty(t, h2.Get("x-client-request-id"))
	require.NotEmpty(t, h2.Get("x-codex-window-id"))
	require.NotEmpty(t, h2.Get("x-codex-installation-id"))
	require.Equal(t, gjson.Get(b2, "client_metadata.x-codex-window-id").String(), h2.Get("x-codex-window-id"))
	require.Equal(t, gjson.Get(b2, "client_metadata.x-codex-installation-id").String(), h2.Get("x-codex-installation-id"))
	require.Equal(t, gjson.Get(b2, "client_metadata.thread_id").String(), gjson.Get(h2.Get("x-codex-turn-metadata"), "thread_id").String())
	require.Equal(t, gjson.Get(b2, "client_metadata.session_id").String(), gjson.Get(b2, "prompt_cache_key").String())
	require.NotContains(t, b2, root)
	require.NotContains(t, b2, "real-install")
	require.NotContains(t, b2, p)
	for name, values := range h2 {
		for _, v := range values {
			require.NotContains(t, v, p, "attempt2 头 %s 残留上一账号假名", name)
			require.NotContains(t, v, root)
			require.NotContains(t, v, "real-install")
		}
	}
}
