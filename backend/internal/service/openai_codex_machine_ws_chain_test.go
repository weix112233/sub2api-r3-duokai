package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- machine 模式：WS v2 链路整链用例（Forward → 握手头 + response.create payload），设计 §9 I1 / I4 / I5 ---

func newMachineWSChainService(t *testing.T) (*OpenAIGatewayService, *openAIWSCaptureDialer, *openAIWSCaptureConn) {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.URLAllowlist.Enabled = false
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIWS.APIKeyEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MinIdlePerAccount = 0
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1

	captureConn := &openAIWSCaptureConn{
		events: [][]byte{
			[]byte(`{"type":"response.completed","response":{"id":"resp_ws_machine","model":"gpt-5.2","usage":{"input_tokens":2,"output_tokens":1}}}`),
		},
	}
	captureDialer := &openAIWSCaptureDialer{conn: captureConn}
	pool := newOpenAIWSConnPool(cfg)
	pool.setClientDialerForTest(captureDialer)

	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     &httpUpstreamRecorder{},
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
		openaiWSPool:     pool,
	}
	return svc, captureDialer, captureConn
}

func newMachineWSChainAccount(t *testing.T, id int64, seed string) *Account {
	t.Helper()
	account := newTestOAuthAccount(id, map[string]any{
		codexFingerprintModeExtraKey:      "machine",
		codexFingerprintSeedExtraKey:      seed,
		"responses_websockets_v2_enabled": true,
	})
	account.Name = "oauth-ws-machine"
	account.Status = StatusActive
	account.Schedulable = true
	account.Concurrency = 1
	account.Credentials = map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"}
	return account
}

func TestCodexMachineChain_WSv2_RootWindow_I1_I4_I5(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot
	tm := machineChainTurnMetadata(root, root, root+":0", "")

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
	h := c.Request.Header
	h.Set("User-Agent", "codex_cli_rs/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	h.Set("originator", "codex_cli_rs")
	h.Set("session-id", root)
	h.Set("thread-id", root)
	h.Set("x-client-request-id", root)
	h.Set("x-codex-window-id", root+":0")
	h.Set("x-codex-installation-id", "real-install")
	h.Set("x-codex-turn-metadata", tm)
	h.Set("session_id", "underscore-session")

	svc, captureDialer, captureConn := newMachineWSChainService(t)
	account := newMachineWSChainAccount(t, 6101, testCodexFingerprintSeed)

	body := []byte(`{"model":"gpt-5.2","stream":true,"prompt_cache_key":"` + root + `","client_metadata":{"x-codex-installation-id":"real-install","session_id":"` + root + `","thread_id":"` + root + `","turn_id":"turn-real","x-codex-window-id":"` + root + `:0","x-codex-turn-metadata":` + jsonQuote(tm) + `},"input":[{"type":"input_text","text":"hi"}]}`)
	result, err := svc.Forward(context.Background(), c, account, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "resp_ws_machine", result.RequestID)
	require.NotNil(t, captureConn.lastWrite)

	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	p := codexMachinePseudonym([]byte(seed), root)
	wantInstall := resolveConvergedInstallationID(account, seed)
	payloadJSON := requestToJSONString(captureConn.lastWrite)
	handshake := captureDialer.lastHeaders

	// I1：握手头
	assert.Equal(t, wantInstall, handshake.Get("x-codex-installation-id"))
	assert.Equal(t, p, handshake.Get("session-id"))
	assert.Equal(t, p, handshake.Get("thread-id"))
	assert.Equal(t, p, handshake.Get("x-client-request-id"))
	assert.Equal(t, p+":0", handshake.Get("x-codex-window-id"))
	// I5：下划线头删除、真实值不出现
	assert.Empty(t, handshake.Get("session_id"))
	assert.Empty(t, handshake.Get("conversation_id"))
	for name, values := range handshake {
		for _, v := range values {
			assert.NotContains(t, v, root, "握手头 %s 不得含真实 thread", name)
			assert.NotContains(t, v, "real-install", "握手头 %s 不得含真实 installation", name)
		}
	}
	assert.NotContains(t, payloadJSON, root)
	assert.NotContains(t, payloadJSON, "real-install")

	// I4：payload 与握手头逐键相等（body sink 在 Forward 与 WS payload 两处应用，必须幂等）
	assert.Equal(t, p, gjson.Get(payloadJSON, "prompt_cache_key").String())
	assert.Equal(t, wantInstall, gjson.Get(payloadJSON, "client_metadata.x-codex-installation-id").String())
	assert.Equal(t, p, gjson.Get(payloadJSON, "client_metadata.session_id").String())
	assert.Equal(t, p, gjson.Get(payloadJSON, "client_metadata.thread_id").String())
	assert.Equal(t, p+":0", gjson.Get(payloadJSON, "client_metadata.x-codex-window-id").String())
	assert.Equal(t, "turn-real", gjson.Get(payloadJSON, "client_metadata.turn_id").String())

	bodyTM := gjson.Get(payloadJSON, "client_metadata.x-codex-turn-metadata").String()
	headTM := handshake.Get("x-codex-turn-metadata")
	require.NotEmpty(t, bodyTM)
	require.NotEmpty(t, headTM)
	for _, field := range []string{"installation_id", "session_id", "thread_id", "window_id", "sandbox", "turn_id"} {
		assert.Equal(t, gjson.Get(headTM, field).String(), gjson.Get(bodyTM, field).String(), "turn metadata 字段 %s 头/体一致", field)
	}
	assert.Equal(t, wantInstall, gjson.Get(headTM, "installation_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "session_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "thread_id").String())
	assert.Equal(t, p+":0", gjson.Get(headTM, "window_id").String())
	assert.Equal(t, "turn-real", gjson.Get(headTM, "turn_id").String())
	// sandbox 与实际握手 UA 的 OS 段一致（无账号级 UA ⇒ 规范 UA Ubuntu ⇒ seccomp）
	assert.Equal(t, codexMachineSandboxTagFromUA(handshake.Get("User-Agent")), gjson.Get(headTM, "sandbox").String())
	assert.Equal(t, "seccomp", gjson.Get(headTM, "sandbox").String())
}

// I1（子 Agent，WS）：只换 thread；parent' == 根窗口 thread'；x-openai-subagent 透传到握手头。
func TestCodexMachineChain_WSv2_SubagentWindow_I1(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := testMachineChainRoot
	child := testMachineChainChild

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
	h := c.Request.Header
	h.Set("User-Agent", "codex_cli_rs/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color")
	h.Set("originator", "codex_cli_rs")
	h.Set("session-id", root)
	h.Set("thread-id", child)
	h.Set("x-client-request-id", child)
	h.Set("x-codex-parent-thread-id", root)
	h.Set("x-openai-subagent", "explore")
	h.Set("x-codex-window-id", child+":1")

	svc, captureDialer, captureConn := newMachineWSChainService(t)
	account := newMachineWSChainAccount(t, 6102, testCodexFingerprintSeed)

	body := []byte(`{"model":"gpt-5.2","stream":true,"prompt_cache_key":"` + root + `","client_metadata":{"session_id":"` + root + `","thread_id":"` + child + `","x-codex-parent-thread-id":"` + root + `","x-openai-subagent":"explore","x-codex-window-id":"` + child + `:1","turn_id":"turn-child"},"input":[{"type":"input_text","text":"hi"}]}`)
	_, err := svc.Forward(context.Background(), c, account, body)
	require.NoError(t, err)
	require.NotNil(t, captureConn.lastWrite)

	seed, _ := codexFingerprintSeed(account.Extra)
	pRoot := codexMachinePseudonym([]byte(seed), root)
	pChild := codexMachinePseudonym([]byte(seed), child)
	handshake := captureDialer.lastHeaders
	payloadJSON := requestToJSONString(captureConn.lastWrite)

	assert.Equal(t, pRoot, handshake.Get("session-id"))
	assert.Equal(t, pChild, handshake.Get("thread-id"))
	assert.Equal(t, pChild, handshake.Get("x-client-request-id"))
	assert.Equal(t, pRoot, handshake.Get("x-codex-parent-thread-id"))
	assert.Equal(t, "explore", handshake.Get("x-openai-subagent"))
	assert.Equal(t, pChild+":1", handshake.Get("x-codex-window-id"))
	assert.Equal(t, pRoot, gjson.Get(payloadJSON, "prompt_cache_key").String())
	assert.Equal(t, pRoot, gjson.Get(payloadJSON, "client_metadata.session_id").String())
	assert.Equal(t, pChild, gjson.Get(payloadJSON, "client_metadata.thread_id").String())
	assert.Equal(t, pRoot, gjson.Get(payloadJSON, "client_metadata.x-codex-parent-thread-id").String())
	assert.Equal(t, "explore", gjson.Get(payloadJSON, "client_metadata.x-openai-subagent").String())
	assert.Equal(t, "turn-child", gjson.Get(payloadJSON, "client_metadata.turn_id").String())
	assert.NotContains(t, payloadJSON, root)
	assert.NotContains(t, payloadJSON, child)
}
