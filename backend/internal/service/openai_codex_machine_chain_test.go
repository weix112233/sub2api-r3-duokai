package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- machine 模式：HTTP 两条链路的整链用例（Forward → 上游请求捕获），设计 §9 I1–I5 ---

const (
	testMachineChainRoot  = "01912e2a-6f3c-7d1e-9c4a-0f1e2d3c4b5a" // 根窗口 thread（UUIDv7）
	testMachineChainChild = "01912e2a-7a11-7b22-8c33-0d4e5f6a7b8c" // 子 Agent thread（UUIDv7）
)

func machineChainTurnMetadata(sessionID, threadID, windowID, parentThreadID string) string {
	parent := ""
	if parentThreadID != "" {
		parent = `,"parent_thread_id":"` + parentThreadID + `"`
	}
	return `{"installation_id":"real-install","session_id":"` + sessionID + `","thread_id":"` + threadID + `","turn_id":"turn-real","window_id":"` + windowID + `","sandbox":"seccomp","sandbox_mode":"workspace-write","thread_source":"cli"` + parent + `}`
}

// machineChainRequest 构造一次真实 Codex 窗口形态的下游请求（头 + body 同源）。
func machineChainRequest(t *testing.T, path, sessionID, threadID, windowID, parentThreadID string) (*gin.Context, *httptest.ResponseRecorder, []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	tm := machineChainTurnMetadata(sessionID, threadID, windowID, parentThreadID)
	cmParent := ""
	if parentThreadID != "" {
		cmParent = `,"x-codex-parent-thread-id":"` + parentThreadID + `","x-openai-subagent":"explore"`
	}
	body := []byte(`{"model":"gpt-5.2","stream":false,"prompt_cache_key":"` + sessionID + `","instructions":"local-test-instructions","client_metadata":{"x-codex-installation-id":"real-install","session_id":"` + sessionID + `","thread_id":"` + threadID + `","turn_id":"turn-real","x-codex-window-id":"` + windowID + `"` + cmParent + `,"x-codex-turn-metadata":` + jsonQuote(tm) + `},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	h := c.Request.Header
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "codex_cli_rs/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	h.Set("originator", "codex_cli_rs")
	h.Set("session-id", sessionID)
	h.Set("thread-id", threadID)
	h.Set("x-client-request-id", threadID)
	h.Set("x-codex-window-id", windowID)
	h.Set("x-codex-installation-id", "real-install")
	h.Set("x-codex-turn-metadata", tm)
	h.Set("session_id", "underscore-session")
	h.Set("conversation_id", "underscore-conversation")
	if parentThreadID != "" {
		h.Set("x-codex-parent-thread-id", parentThreadID)
		h.Set("x-openai-subagent", "explore")
	}
	return c, rec, body
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func newMachineChainAccount(t *testing.T, id int64, seed string, passthrough bool, userAgent string) *Account {
	t.Helper()
	extra := map[string]any{
		codexFingerprintModeExtraKey: "machine",
		codexFingerprintSeedExtraKey: seed,
	}
	if passthrough {
		extra["openai_passthrough"] = true
	}
	account := newTestOAuthAccount(id, extra)
	account.Name = "oauth-machine"
	account.Concurrency = 1
	account.Status = StatusActive
	account.Schedulable = true
	account.RateMultiplier = f64p(1)
	account.Credentials = map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"}
	if userAgent != "" {
		account.Credentials["user_agent"] = userAgent
	}
	return account
}

func newMachineChainService() (*OpenAIGatewayService, *httpUpstreamRecorder) {
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": []string{"application/json"}, "x-request-id": []string{"rid-machine"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"invalid_request_error","message":"captured"}}`)),
	}}
	svc := &OpenAIGatewayService{
		cfg:          &config.Config{},
		httpUpstream: upstream,
	}
	return svc, upstream
}

// assertMachineChainRootWindow 对捕获的上游请求断言 I1 / I4 / I5。
func assertMachineChainRootWindow(t *testing.T, account *Account, req *http.Request, body []byte, wantSandbox string) string {
	t.Helper()
	require.NotNil(t, req)
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	key := []byte(seed)
	p := codexMachinePseudonym(key, testMachineChainRoot)
	wantInstall := resolveConvergedInstallationID(account, seed)

	// I1：根窗口 session' == thread' == pck' == client_request_id'，window' == thread':0
	assert.Equal(t, p, req.Header.Get("session-id"))
	assert.Equal(t, p, req.Header.Get("thread-id"))
	assert.Equal(t, p, req.Header.Get("x-client-request-id"))
	assert.Equal(t, p+":0", req.Header.Get("x-codex-window-id"))
	assert.Equal(t, p, gjson.GetBytes(body, "prompt_cache_key").String())
	assert.NotEqual(t, testMachineChainRoot, p)
	// I5：下划线头删除、真实 ID 不出现在任何出站头
	assert.Empty(t, req.Header.Get("session_id"))
	assert.Empty(t, req.Header.Get("conversation_id"))
	for name, values := range req.Header {
		for _, v := range values {
			assert.NotContains(t, v, testMachineChainRoot, "真实 thread 不得出现在出站头 %s", name)
			assert.NotContains(t, v, "real-install", "真实 installation 不得出现在出站头 %s", name)
		}
	}
	assert.NotContains(t, string(body), testMachineChainRoot, "真实 thread 不得出现在出站 body")
	assert.NotContains(t, string(body), "real-install")
	// I4：头 / client_metadata / 头内 turn metadata / 内嵌 turn metadata 逐键相等
	cm := gjson.GetBytes(body, "client_metadata")
	require.True(t, cm.IsObject())
	headTM := req.Header.Get("x-codex-turn-metadata")
	embTM := cm.Get("x-codex-turn-metadata").String()
	require.NotEmpty(t, headTM)
	require.NotEmpty(t, embTM)
	assert.Equal(t, wantInstall, req.Header.Get("x-codex-installation-id"))
	assert.Equal(t, wantInstall, cm.Get("x-codex-installation-id").String())
	assert.Equal(t, wantInstall, gjson.Get(headTM, "installation_id").String())
	assert.Equal(t, wantInstall, gjson.Get(embTM, "installation_id").String())
	assert.Equal(t, p, cm.Get("session_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "session_id").String())
	assert.Equal(t, p, gjson.Get(embTM, "session_id").String())
	assert.Equal(t, p, cm.Get("thread_id").String())
	assert.Equal(t, p, gjson.Get(headTM, "thread_id").String())
	assert.Equal(t, p, gjson.Get(embTM, "thread_id").String())
	assert.Equal(t, p+":0", cm.Get("x-codex-window-id").String())
	assert.Equal(t, p+":0", gjson.Get(headTM, "window_id").String())
	assert.Equal(t, p+":0", gjson.Get(embTM, "window_id").String())
	// turn 级字段透传
	assert.Equal(t, "turn-real", cm.Get("turn_id").String())
	assert.Equal(t, "turn-real", gjson.Get(headTM, "turn_id").String())
	assert.Equal(t, "turn-real", gjson.Get(embTM, "turn_id").String())
	assert.Equal(t, "workspace-write", gjson.Get(headTM, "sandbox_mode").String())
	assert.Equal(t, "cli", gjson.Get(embTM, "thread_source").String())
	// sandbox 与实际出站 UA 的 OS 段一致
	assert.Equal(t, wantSandbox, gjson.Get(headTM, "sandbox").String())
	assert.Equal(t, wantSandbox, gjson.Get(embTM, "sandbox").String())
	assert.Equal(t, wantSandbox, codexMachineSandboxTagFromUA(req.Header.Get("User-Agent")), "sandbox 标签必须与出站 UA 同源")
	return p
}

func TestCodexMachineChain_HTTP_NonPassthrough_RootWindow_I1_I4_I5(t *testing.T) {
	c, _, body := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc, upstream := newMachineChainService()
	// 账号级 Mac UA ⇒ 出站 UA 保留 Mac OS 段 ⇒ sandbox 改写为 seatbelt
	account := newMachineChainAccount(t, 6001, testCodexFingerprintSeed, false, "codex_cli_rs/0.120.0 (Mac OS 26.0.1; arm64) xterm-256color")

	_, _ = svc.Forward(context.Background(), c, account, body)
	require.NotNil(t, upstream.lastReq, "上游请求必须已发出")
	assertMachineChainRootWindow(t, account, upstream.lastReq, upstream.lastBody, "seatbelt")
}

func TestCodexMachineChain_HTTP_Passthrough_RootWindow_I1_I4_I5(t *testing.T) {
	c, _, body := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc, upstream := newMachineChainService()
	// 无账号级 UA ⇒ 规范 UA（Ubuntu）⇒ seccomp
	account := newMachineChainAccount(t, 6002, testCodexFingerprintSeed, true, "")

	_, _ = svc.Forward(context.Background(), c, account, body)
	require.NotNil(t, upstream.lastReq)
	assertMachineChainRootWindow(t, account, upstream.lastReq, upstream.lastBody, "seccomp")
	// 透传 body 其余字节原样
	assert.Equal(t, "hi", gjson.GetBytes(upstream.lastBody, "input.0.content.0.text").String())
}

// 两条 HTTP 链路对同一下游请求产出逐键相同的身份（透传 raw sink 与非透传 map sink 等价）。
func TestCodexMachineChain_HTTP_PassthroughAndNonPassthroughAgree(t *testing.T) {
	c1, _, body1 := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc1, up1 := newMachineChainService()
	_, _ = svc1.Forward(context.Background(), c1, newMachineChainAccount(t, 6003, testCodexFingerprintSeed, false, ""), body1)

	c2, _, body2 := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc2, up2 := newMachineChainService()
	_, _ = svc2.Forward(context.Background(), c2, newMachineChainAccount(t, 6004, testCodexFingerprintSeed, true, ""), body2)

	require.NotNil(t, up1.lastReq)
	require.NotNil(t, up2.lastReq)
	for _, name := range []string{"x-codex-installation-id", "session-id", "thread-id", "x-client-request-id", "x-codex-window-id"} {
		assert.Equal(t, up1.lastReq.Header.Get(name), up2.lastReq.Header.Get(name), name)
	}
	assert.Equal(t, gjson.GetBytes(up1.lastBody, "prompt_cache_key").String(), gjson.GetBytes(up2.lastBody, "prompt_cache_key").String())
	assert.Equal(t, gjson.GetBytes(up1.lastBody, "client_metadata.session_id").String(), gjson.GetBytes(up2.lastBody, "client_metadata.session_id").String())
	assert.Equal(t, gjson.GetBytes(up1.lastBody, "client_metadata.x-codex-window-id").String(), gjson.GetBytes(up2.lastBody, "client_metadata.x-codex-window-id").String())
	assert.Equal(t, gjson.Get(up1.lastReq.Header.Get("x-codex-turn-metadata"), "session_id").String(), gjson.Get(up2.lastReq.Header.Get("x-codex-turn-metadata"), "session_id").String())
}

// I1（子 Agent 窗口）：同一根会话下子 Agent 请求只换 thread，parent' == 父窗口 thread'。
func TestCodexMachineChain_HTTP_SubagentWindow_I1(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			account := newMachineChainAccount(t, 6010, testCodexFingerprintSeed, passthrough, "")

			cRoot, _, bodyRoot := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
			svcRoot, upRoot := newMachineChainService()
			_, _ = svcRoot.Forward(context.Background(), cRoot, account, bodyRoot)
			require.NotNil(t, upRoot.lastReq)

			cChild, _, bodyChild := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainChild, testMachineChainChild+":1", testMachineChainRoot)
			svcChild, upChild := newMachineChainService()
			_, _ = svcChild.Forward(context.Background(), cChild, account, bodyChild)
			require.NotNil(t, upChild.lastReq)

			seed, _ := codexFingerprintSeed(account.Extra)
			pRoot := codexMachinePseudonym([]byte(seed), testMachineChainRoot)
			pChild := codexMachinePseudonym([]byte(seed), testMachineChainChild)

			assert.Equal(t, pRoot, upChild.lastReq.Header.Get("session-id"), "子 Agent 仍属同一根会话")
			assert.Equal(t, upRoot.lastReq.Header.Get("session-id"), upChild.lastReq.Header.Get("session-id"))
			assert.Equal(t, pChild, upChild.lastReq.Header.Get("thread-id"))
			assert.Equal(t, pChild, upChild.lastReq.Header.Get("x-client-request-id"))
			assert.Equal(t, pChild+":1", upChild.lastReq.Header.Get("x-codex-window-id"))
			assert.Equal(t, upRoot.lastReq.Header.Get("thread-id"), upChild.lastReq.Header.Get("x-codex-parent-thread-id"), "parent' == 父窗口 thread'")
			assert.Equal(t, "explore", upChild.lastReq.Header.Get("x-openai-subagent"))
			assert.Equal(t, pRoot, gjson.GetBytes(upChild.lastBody, "prompt_cache_key").String(), "pck 仍是根会话假名")
			assert.Equal(t, pChild, gjson.GetBytes(upChild.lastBody, "client_metadata.thread_id").String())
			assert.Equal(t, pRoot, gjson.GetBytes(upChild.lastBody, "client_metadata.x-codex-parent-thread-id").String())
			assert.Equal(t, "explore", gjson.GetBytes(upChild.lastBody, "client_metadata.x-openai-subagent").String())
			childTM := upChild.lastReq.Header.Get("x-codex-turn-metadata")
			assert.Equal(t, pRoot, gjson.Get(childTM, "parent_thread_id").String())
			assert.Equal(t, pChild, gjson.Get(childTM, "thread_id").String())
			assert.NotContains(t, string(upChild.lastBody), testMachineChainChild)
			assert.NotContains(t, string(upChild.lastBody), testMachineChainRoot)
		})
	}
}

// I2：同一下游请求在两个 machine 账号（不同 seed）得到不同假名。
func TestCodexMachineChain_HTTP_I2_DifferentAccountsDifferentPseudonyms(t *testing.T) {
	c1, _, body1 := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc1, up1 := newMachineChainService()
	_, _ = svc1.Forward(context.Background(), c1, newMachineChainAccount(t, 6021, testCodexFingerprintSeed, false, ""), body1)

	c2, _, body2 := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
	svc2, up2 := newMachineChainService()
	_, _ = svc2.Forward(context.Background(), c2, newMachineChainAccount(t, 6022, testCodexMachineSeedB, false, ""), body2)

	require.NotNil(t, up1.lastReq)
	require.NotNil(t, up2.lastReq)
	assert.NotEqual(t, up1.lastReq.Header.Get("session-id"), up2.lastReq.Header.Get("session-id"))
	assert.NotEqual(t, up1.lastReq.Header.Get("thread-id"), up2.lastReq.Header.Get("thread-id"))
	assert.NotEqual(t, up1.lastReq.Header.Get("x-codex-window-id"), up2.lastReq.Header.Get("x-codex-window-id"))
	assert.NotEqual(t, gjson.GetBytes(up1.lastBody, "prompt_cache_key").String(), gjson.GetBytes(up2.lastBody, "prompt_cache_key").String())
	assert.NotEqual(t, up1.lastReq.Header.Get("x-codex-installation-id"), up2.lastReq.Header.Get("x-codex-installation-id"))
}

// I2（failover）：同一 gin context 内 machine 账号 A → machine 账号 B → off 账号，
// 上一账号的 ids 不得残留（stage 无条件覆写）。
func TestCodexMachineChain_Failover_I2_NoResidualIDs(t *testing.T) {
	svc := &OpenAIGatewayService{}
	c := newFingerprintStageTestContext(t)
	c.Request.Header.Set("session-id", testMachineChainRoot)
	c.Request.Header.Set("thread-id", testMachineChainRoot)
	c.Request.Header.Set("x-codex-window-id", testMachineChainRoot+":0")
	// 入站带顶层 installation 头（compact 形态）：machine 只改不增 ⇒ 存在才改写，用于断言 A/B 账号 installation 不同
	c.Request.Header.Set("x-codex-installation-id", "real-install")
	c.Request.Header.Set("originator", "codex_cli_rs")
	// 带 prompt_cache_key：透传源头逻辑仅在有 session_id 头或 pck 时才设置下划线
	// session_id（openai_gateway_passthrough.go:558-566），attempt 3 据此断言源头逻辑不变。
	body := []byte(`{"model":"gpt-5.2","input":[],"stream":true,"prompt_cache_key":"` + testMachineChainRoot + `"}`)

	accountA := newTestOAuthAccount(6031, map[string]any{"openai_passthrough": true, codexFingerprintModeExtraKey: "machine", codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	accountB := newTestOAuthAccount(6032, map[string]any{"openai_passthrough": true, codexFingerprintModeExtraKey: "machine", codexFingerprintSeedExtraKey: testCodexMachineSeedB})
	accountOff := newTestOAuthAccount(6033, map[string]any{"openai_passthrough": true, codexFingerprintModeExtraKey: "off"})

	// attempt 1：账号 A
	stageCodexFingerprintIDs(c, resolveCodexFingerprintIDsFromRequest(accountA, c.Request.Header))
	reqA, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, accountA, body, "tok")
	require.NoError(t, err)
	pA := codexMachinePseudonym([]byte(testCodexFingerprintSeed), testMachineChainRoot)
	assert.Equal(t, pA, reqA.Header.Get("session-id"))
	assert.Empty(t, reqA.Header.Get("session_id"))

	// attempt 2：failover 到账号 B
	stageCodexFingerprintIDs(c, nil)
	stageCodexFingerprintIDs(c, resolveCodexFingerprintIDsFromRequest(accountB, c.Request.Header))
	reqB, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, accountB, body, "tok")
	require.NoError(t, err)
	pB := codexMachinePseudonym([]byte(testCodexMachineSeedB), testMachineChainRoot)
	assert.Equal(t, pB, reqB.Header.Get("session-id"))
	assert.NotEqual(t, pA, pB)
	assert.NotEqual(t, reqA.Header.Get("x-codex-installation-id"), reqB.Header.Get("x-codex-installation-id"))

	// attempt 3：failover 到 off 账号，维持 HEAD 行为（连字符会话头不放行）、HEAD 既有白名单键原样、无残留
	stageCodexFingerprintIDs(c, nil)
	stageCodexFingerprintIDs(c, resolveCodexFingerprintIDsFromRequest(accountOff, c.Request.Header))
	reqOff, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, accountOff, body, "tok")
	require.NoError(t, err)
	assert.Empty(t, reqOff.Header.Get("session-id"), "off 账号不放行连字符会话头（HEAD 行为）")
	assert.Empty(t, reqOff.Header.Get("thread-id"))
	for name, values := range reqOff.Header {
		for _, v := range values {
			assert.NotContains(t, v, pA, "off 账号头 %s 残留账号 A 假名", name)
			assert.NotContains(t, v, pB, "off 账号头 %s 残留账号 B 假名", name)
		}
	}
	// r3 fail-closed：off 账号透传时客户端原始身份头（window/installation）同样
	// 被终态删除，仅下划线 session_id 以亲和隔离值恢复。
	assert.Empty(t, reqOff.Header.Get("x-codex-window-id"), "off 账号客户端 window 头终态删除（r3 形状）")
	assert.Empty(t, reqOff.Header.Get("x-codex-installation-id"), "off 账号客户端 installation 头终态删除（r3 形状）")
	assert.NotEqual(t, testMachineChainRoot+":0", reqOff.Header.Get("x-codex-window-id"))
	assert.NotEqual(t, "real-install", reqOff.Header.Get("x-codex-installation-id"))
	assert.NotEmpty(t, reqOff.Header.Get("session_id"), "off 模式的下划线 session_id 源头逻辑不变")
}

// compact：machine 也 resolve/stage 并应用两个 sink；session 维持跳过。
func TestCodexMachineChain_HTTP_Compact_MachineRewritesOthersSkip(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name+"/machine", func(t *testing.T) {
			c, _, body := machineChainRequest(t, "/v1/responses/compact", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6041, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			seed, _ := codexFingerprintSeed(account.Extra)
			p := codexMachinePseudonym([]byte(seed), testMachineChainRoot)
			assert.Equal(t, p, upstream.lastReq.Header.Get("session-id"))
			assert.Equal(t, p, upstream.lastReq.Header.Get("thread-id"))
			assert.Equal(t, p+":0", upstream.lastReq.Header.Get("x-codex-window-id"))
			assert.Equal(t, resolveConvergedInstallationID(account, seed), upstream.lastReq.Header.Get("x-codex-installation-id"))
			assert.Empty(t, upstream.lastReq.Header.Get("session_id"), "machine 下 compact 的下划线 session_id 也被删除")
			assert.Empty(t, upstream.lastReq.Header.Get("conversation_id"))
			assert.Equal(t, "application/json", upstream.lastReq.Header.Get("Accept"))
			for name, values := range upstream.lastReq.Header {
				for _, v := range values {
					assert.NotContains(t, v, testMachineChainRoot, "compact 出站头 %s 不得含真实 thread", name)
				}
			}
		})
		t.Run(name+"/session_unchanged", func(t *testing.T) {
			c, _, body := machineChainRequest(t, "/v1/responses/compact", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
			svc, upstream := newMachineChainService()
			extra := map[string]any{codexFingerprintModeExtraKey: "session"}
			if passthrough {
				extra["openai_passthrough"] = true
			}
			account := newTestOAuthAccount(6042, extra)
			account.Status = StatusActive
			account.Schedulable = true
			account.Concurrency = 1
			account.RateMultiplier = f64p(1)
			account.Credentials = map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"}
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			assert.NotEmpty(t, upstream.lastReq.Header.Get("session_id"), "session 模式 compact 维持跳过收敛，下划线 session_id 仍由源头逻辑设置")
			assert.NotEqual(t, resolveConvergedSessionID(testCodexFingerprintSeed), upstream.lastReq.Header.Get("session-id"), "session 模式 compact 不应用头 sink")
		})
	}
}

// I7 辅助：off / device / session / full 在同一下游请求下的出站行为不因 machine 引入而变化。
// r3 语义：终态 sanitizer 对非 machine 一律 fail-closed——连字符身份头（含收敛值）
// 全删，body 身份键全删，pck 改写为 pcv2 网关键；下划线 session_id/conversation_id
// 由亲和派生隔离值设置。四个模式在 HTTP 出站形状上一致（与 r3 生产相同）。
func TestCodexMachineChain_HTTP_OtherModesUnchanged(t *testing.T) {
	assertR3FailClosedShape := func(t *testing.T, req *http.Request, body []byte) {
		assert.Empty(t, req.Header.Get("session-id"))
		assert.Empty(t, req.Header.Get("thread-id"))
		assert.Empty(t, req.Header.Get("x-client-request-id"))
		assert.Empty(t, req.Header.Get("x-codex-window-id"))
		assert.Empty(t, req.Header.Get("x-codex-installation-id"))
		assert.Empty(t, req.Header.Get("x-codex-turn-metadata"))
		assert.NotEmpty(t, req.Header.Get("session_id"), "下划线 session_id 仍由亲和派生隔离值设置")
		assert.NotEqual(t, "underscore-session", req.Header.Get("session_id"), "客户端原始下划线 session 不得出站")
		assert.NotEqual(t, testMachineChainRoot, req.Header.Get("session_id"), "客户端原始 cache key 不得作为 session 出站")
		assert.NotEmpty(t, req.Header.Get("conversation_id"))
		assert.NotEqual(t, "underscore-conversation", req.Header.Get("conversation_id"))
		assert.False(t, gjson.GetBytes(body, "client_metadata.session_id").Exists(), "body 身份键 fail-closed 删除")
		assert.False(t, gjson.GetBytes(body, "client_metadata.thread_id").Exists(), "body 身份键 fail-closed 删除")
		outboundPck := gjson.GetBytes(body, "prompt_cache_key").String()
		assert.True(t, strings.HasPrefix(outboundPck, "pcv2-"), "pck 改写为 pcv2 网关键: %s", outboundPck)
		assert.NotEqual(t, testMachineChainRoot, outboundPck, "原始客户端 cache key 不得出站")
	}
	cases := []struct {
		mode string
		want func(t *testing.T, account *Account, req *http.Request, body []byte)
	}{
		{"off", func(t *testing.T, account *Account, req *http.Request, body []byte) {
			assertR3FailClosedShape(t, req, body)
		}},
		{"device", func(t *testing.T, account *Account, req *http.Request, body []byte) {
			seed, _ := codexFingerprintSeed(account.Extra)
			assertR3FailClosedShape(t, req, body)
			assert.Empty(t, req.Header.Get("x-codex-installation-id"), "device 收敛 installation 同样被终态删除（r3 形状）")
			assert.NotEqual(t, resolveConvergedInstallationID(account, seed), req.Header.Get("x-codex-installation-id"))
		}},
		{"session", func(t *testing.T, account *Account, req *http.Request, body []byte) {
			seed, _ := codexFingerprintSeed(account.Extra)
			assertR3FailClosedShape(t, req, body)
			assert.NotEqual(t, resolveConvergedSessionID(seed), req.Header.Get("session_id"), "收敛值不得替代亲和隔离值出站")
			assert.NotContains(t, string(body), resolveConvergedSessionID(seed), "收敛值不得进入 body")
		}},
		{"full", func(t *testing.T, account *Account, req *http.Request, body []byte) {
			seed, _ := codexFingerprintSeed(account.Extra)
			assertR3FailClosedShape(t, req, body)
			assert.NotEqual(t, resolveConvergedSessionID(seed), req.Header.Get("session_id"), "收敛值不得替代亲和隔离值出站")
			assert.NotContains(t, string(body), resolveConvergedSessionID(seed), "收敛值不得进入 body")
		}},
	}
	for _, tc := range cases {
		for _, passthrough := range []bool{false, true} {
			name := tc.mode + "/non_passthrough"
			if passthrough {
				name = tc.mode + "/passthrough"
			}
			t.Run(name, func(t *testing.T) {
				c, _, body := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
				svc, upstream := newMachineChainService()
				extra := map[string]any{codexFingerprintModeExtraKey: tc.mode}
				if passthrough {
					extra["openai_passthrough"] = true
				}
				account := newTestOAuthAccount(6050, extra)
				account.Status = StatusActive
				account.Schedulable = true
				account.Concurrency = 1
				account.RateMultiplier = f64p(1)
				account.Credentials = map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc"}
				_, _ = svc.Forward(context.Background(), c, account, body)
				require.NotNil(t, upstream.lastReq)
				tc.want(t, account, upstream.lastReq, upstream.lastBody)
			})
		}
	}
}

// 非 Codex 下游（无 session-id / thread-id 头）在 machine 下不合成任何 Codex 会话身份：
// 保留网关自身的下划线 session_id、不再补设 conversation_id、pck 假名化，见
// openai_codex_machine_thirdparty_test.go（决策：docs/plan/2026-08-19-第三方Agent的Codex-provider出站形态证据.md §6 方案 B）。

// 真实 Codex 常规 Responses 请求不发顶层 x-codex-installation-id（core/src/client.rs:1197-1211），
// 只在 client_metadata / turn metadata 内携带；machine 头 sink 只改不增，body 内的 installation 仍改写。
func TestCodexMachineChain_HTTP_InstallationHeaderOnlyRewrittenWhenPresent(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			c, _, body := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
			c.Request.Header.Del("x-codex-installation-id")
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6071, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			wantInstall := resolveConvergedInstallationID(account, testCodexFingerprintSeed)
			_, present := upstream.lastReq.Header[http.CanonicalHeaderKey("x-codex-installation-id")]
			assert.False(t, present, "顶层 installation 头不补")
			assert.Equal(t, wantInstall, gjson.GetBytes(upstream.lastBody, "client_metadata.x-codex-installation-id").String())
			assert.Equal(t, wantInstall, gjson.Get(gjson.GetBytes(upstream.lastBody, "client_metadata.x-codex-turn-metadata").String(), "installation_id").String())
			assert.Equal(t, wantInstall, gjson.Get(upstream.lastReq.Header.Get("x-codex-turn-metadata"), "installation_id").String())
		})
	}
}

// 缺 seed 的 machine（仅直接改库可达）必须整体等价 off：resolver 返回 nil 之外，非透传链路的
// applyCodexClientMetadata 门控也要按"有效模式"判断，否则 off 会补 installation 而它不会
// （第三轮 Codex 复审 §14.4 低-1）。用同一请求分别打 off 账号与无 seed 的 machine 账号，出站 body 与
// 身份相关头必须逐字节相同。
func TestCodexMachineChain_HTTP_MachineWithoutSeedBehavesLikeOff(t *testing.T) {
	const deviceID = "22222222-2222-4222-8222-222222222222"
	body := []byte(`{"model":"gpt-5.2","stream":false,"prompt_cache_key":"` + testMachineChainRoot + `","instructions":"x","client_metadata":{"session_id":"` + testMachineChainRoot + `","thread_id":"` + testMachineChainRoot + `"},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
	run := func(t *testing.T, mode string) ([]byte, http.Header) {
		t.Helper()
		gin.SetMode(gin.TestMode)
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("session-id", testMachineChainRoot)
		c.Request.Header.Set("thread-id", testMachineChainRoot)
		svc, upstream := newMachineChainService()
		account := newMachineChainAccount(t, 6082, "", false, "")
		account.Extra[codexFingerprintModeExtraKey] = mode
		delete(account.Extra, codexFingerprintSeedExtraKey)
		account.Extra["openai_device_id"] = deviceID
		_, _ = svc.Forward(context.Background(), c, account, body)
		require.NotNil(t, upstream.lastReq)
		return upstream.lastBody, upstream.lastReq.Header
	}
	offBody, offHeader := run(t, "off")
	machineBody, machineHeader := run(t, "machine")

	// off 基线（r3 fail-closed）：body 身份键（含 device installation 补充与客户端
	// session/thread）终态删除，pck 改写为 pcv2 网关键。
	require.False(t, gjson.GetBytes(offBody, "client_metadata.x-codex-installation-id").Exists(), "off 基线：device installation 终态删除")
	require.False(t, gjson.GetBytes(offBody, "client_metadata.session_id").Exists(), "off 基线：客户端 session 身份键终态删除")
	require.True(t, strings.HasPrefix(gjson.GetBytes(offBody, "prompt_cache_key").String(), "pcv2-"), "off 基线：pck 改写为 pcv2")
	assert.JSONEq(t, string(offBody), string(machineBody), "无 seed 的 machine 出站 body 必须与 off 完全一致")
	for _, name := range []string{"x-codex-installation-id", "session-id", "thread-id", "x-client-request-id", "x-codex-window-id", "x-codex-turn-metadata", "session_id"} {
		assert.Equal(t, offHeader.Values(name), machineHeader.Values(name), "头 %s 必须与 off 一致", name)
	}
}
