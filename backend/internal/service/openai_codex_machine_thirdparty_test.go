package service

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- machine 模式 × 非 Codex 下游（第三方 Agent / SDK 形态）：不合成、只改不增（决策 B）---
//
// 依据 docs/plan/2026-08-19-第三方Agent的Codex-provider出站形态证据.md §5/§6：OpenCode / Hermes / pi-ai
// 用 OAuth 直连 Codex 后端时都不带 turn metadata / client_metadata / installation / window / thread-id，
// 会话头只有下划线 session_id（Hermes / pi）或连字符 session-id（OpenCode）。因此 machine 对
// 未携带 Codex 会话身份（无 session-id / thread-id）的下游：
//   - 保留网关既有的下划线 session_id（源头逻辑不变：Forward = isolate(apiKeyID, pck')，
//     透传 = isolate(apiKeyID, 客户端 session_id 或 pck')），
//   - conversation_id 一律不再补设（Codex 0.81.0 已删除，第三方 Agent 也不发），
//   - 不合成 session-id / thread-id / x-client-request-id / x-codex-window-id / x-codex-turn-metadata /
//     x-codex-installation-id，不创建 client_metadata；body prompt_cache_key 仍按账号密钥 1:1 假名化。

const testMachineThirdPartyAPIKeyID int64 = 7

// machineThirdPartyRequest 构造一次非 Codex 下游请求：无 session-id / thread-id / x-codex-* 头。
func machineThirdPartyRequest(t *testing.T, path, body string, apiKeyID int64, headers map[string]string) (*gin.Context, []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("User-Agent", "OpenAI/Python 1.55.0")
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	if apiKeyID > 0 {
		c.Set("api_key", &APIKey{ID: apiKeyID})
	}
	return c, []byte(body)
}

const machineThirdPartyBodyWithPck = `{"model":"gpt-5.2","stream":false,"prompt_cache_key":"opencode-key","instructions":"x","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`

// codexSyntheticIdentityHeaderNames 是 machine 对非 Codex 下游绝不能补出来的 Codex 窗口身份头。
var codexSyntheticIdentityHeaderNames = [...]string{
	"session-id",
	"thread-id",
	"x-client-request-id",
	"x-codex-window-id",
	"x-codex-turn-metadata",
	"x-codex-installation-id",
	"x-codex-parent-thread-id",
	"conversation_id",
}

// assertMachineThirdPartyOutbound 断言非 Codex 下游在 machine 下的出站形态：只有下划线 session_id、
// 无 conversation_id、无任何合成的 Codex 会话头、无 client_metadata、pck 已假名化。
func assertMachineThirdPartyOutbound(t *testing.T, req *http.Request, body []byte, wantSessionID, clientPck, wantPck string) {
	t.Helper()
	require.NotNil(t, req)
	assert.Equal(t, wantSessionID, req.Header.Get("session_id"), "下划线 session_id 保留（第三方 Agent 形态）")
	for _, name := range codexSyntheticIdentityHeaderNames {
		_, present := req.Header[http.CanonicalHeaderKey(name)]
		assert.False(t, present, "不得合成 / 补设头 %s", name)
	}
	assert.False(t, gjson.GetBytes(body, "client_metadata").Exists(), "不得创建 client_metadata")
	assert.Equal(t, wantPck, gjson.GetBytes(body, "prompt_cache_key").String())
	assert.NotContains(t, string(body), clientPck, "下游原 pck 不得出现在出站 body")
	for name, values := range req.Header {
		for _, v := range values {
			assert.NotContains(t, v, clientPck, "下游原 pck 不得出现在出站头 %s", name)
		}
	}
}

// HTTP 两条链路：非 Codex 下游（下划线 session_id + body pck，无 client_metadata）。
func TestCodexMachineChain_HTTP_ThirdParty_KeepsUnderscoreSessionNoConversation(t *testing.T) {
	seedKey := []byte(testCodexFingerprintSeed)
	pckP := codexMachinePseudonym(seedKey, "opencode-key")

	t.Run("non_passthrough", func(t *testing.T) {
		c, body := machineThirdPartyRequest(t, "/v1/responses", machineThirdPartyBodyWithPck, testMachineThirdPartyAPIKeyID, map[string]string{"session_id": "underscore-only"})
		svc, upstream := newMachineChainService()
		account := newMachineChainAccount(t, 6501, testCodexFingerprintSeed, false, "")
		_, _ = svc.Forward(context.Background(), c, account, body)
		// 非透传源头：session_id = isolate(apiKeyID, 出站 pck)（openai_gateway_forward.go buildUpstreamRequest）
		assertMachineThirdPartyOutbound(t, upstream.lastReq, upstream.lastBody, isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, pckP), "opencode-key", pckP)
	})
	t.Run("passthrough", func(t *testing.T) {
		c, body := machineThirdPartyRequest(t, "/v1/responses", machineThirdPartyBodyWithPck, testMachineThirdPartyAPIKeyID, map[string]string{"session_id": "underscore-only"})
		svc, upstream := newMachineChainService()
		account := newMachineChainAccount(t, 6502, testCodexFingerprintSeed, true, "")
		_, _ = svc.Forward(context.Background(), c, account, body)
		// 透传源头：客户端带 session_id 时 session_id = isolate(apiKeyID, 客户端 session_id)（openai_gateway_passthrough.go）
		assertMachineThirdPartyOutbound(t, upstream.lastReq, upstream.lastBody, isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, "underscore-only"), "opencode-key", pckP)
		assert.Equal(t, "hi", gjson.GetBytes(upstream.lastBody, "input.0.content.0.text").String(), "透传 body 其余字节原样")
	})
	t.Run("passthrough_without_client_session_header", func(t *testing.T) {
		c, body := machineThirdPartyRequest(t, "/v1/responses", machineThirdPartyBodyWithPck, testMachineThirdPartyAPIKeyID, nil)
		svc, upstream := newMachineChainService()
		account := newMachineChainAccount(t, 6503, testCodexFingerprintSeed, true, "")
		_, _ = svc.Forward(context.Background(), c, account, body)
		assertMachineThirdPartyOutbound(t, upstream.lastReq, upstream.lastBody, isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, pckP), "opencode-key", pckP)
	})
}

// Hermes 形态：下划线 session_id + x-client-request-id（= pck），无 session-id / thread-id。
// x-client-request-id 是"存在则改"的头：假名化但不新增其他头。
func TestCodexMachineChain_HTTP_ThirdParty_HermesShape_ClientRequestIDPseudonymized(t *testing.T) {
	seedKey := []byte(testCodexFingerprintSeed)
	pckP := codexMachinePseudonym(seedKey, "opencode-key")
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			c, body := machineThirdPartyRequest(t, "/v1/responses", machineThirdPartyBodyWithPck, testMachineThirdPartyAPIKeyID, map[string]string{
				"session_id":          "opencode-key",
				"x-client-request-id": "opencode-key",
			})
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6511, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			assert.Equal(t, pckP, upstream.lastReq.Header.Get("x-client-request-id"), "存在则按 P 改写")
			assert.Equal(t, pckP, gjson.GetBytes(upstream.lastBody, "prompt_cache_key").String())
			assert.NotEmpty(t, upstream.lastReq.Header.Get("session_id"))
			for _, hdr := range []string{"session-id", "thread-id", "x-codex-window-id", "x-codex-turn-metadata", "x-codex-installation-id", "conversation_id"} {
				_, present := upstream.lastReq.Header[http.CanonicalHeaderKey(hdr)]
				assert.False(t, present, "不得合成 / 补设头 %s", hdr)
			}
			assert.False(t, gjson.GetBytes(upstream.lastBody, "client_metadata").Exists())
			for hdr, values := range upstream.lastReq.Header {
				for _, v := range values {
					assert.NotContains(t, v, "opencode-key", "头 %s", hdr)
				}
			}
		})
	}
}

// OpenCode 形态：只有连字符 session-id（无 thread-id / turn metadata / client_metadata）。
// 视为携带 Codex 会话身份：session-id 假名化、下划线 session_id 删除、其余不补。
func TestCodexMachineChain_HTTP_ThirdParty_OpenCodeShape_HyphenSessionOnly(t *testing.T) {
	seedKey := []byte(testCodexFingerprintSeed)
	pckP := codexMachinePseudonym(seedKey, "opencode-key")
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			c, body := machineThirdPartyRequest(t, "/v1/responses", machineThirdPartyBodyWithPck, testMachineThirdPartyAPIKeyID, map[string]string{
				"session-id": "opencode-key",
				"originator": "opencode",
			})
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6521, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			assert.Equal(t, pckP, upstream.lastReq.Header.Get("session-id"))
			assert.Empty(t, upstream.lastReq.Header.Get("session_id"), "带 Codex 会话头 ⇒ 下划线 session_id 删除")
			for _, hdr := range []string{"thread-id", "x-client-request-id", "x-codex-window-id", "x-codex-turn-metadata", "x-codex-installation-id", "conversation_id"} {
				_, present := upstream.lastReq.Header[http.CanonicalHeaderKey(hdr)]
				assert.False(t, present, "不得合成 / 补设头 %s", hdr)
			}
			assert.False(t, gjson.GetBytes(upstream.lastBody, "client_metadata").Exists())
			assert.Equal(t, pckP, gjson.GetBytes(upstream.lastBody, "prompt_cache_key").String())
		})
	}
}

// 无 pck、无任何会话键的第三方请求：machine 什么都不补（既有源头逻辑本就不设 session_id）。
func TestCodexMachineChain_HTTP_ThirdParty_NoPckNothingAdded(t *testing.T) {
	const bodyNoPck = `{"model":"gpt-5.2","stream":false,"instructions":"x","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			c, body := machineThirdPartyRequest(t, "/v1/responses", bodyNoPck, testMachineThirdPartyAPIKeyID, nil)
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6531, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			for _, hdr := range []string{"session_id", "conversation_id", "session-id", "thread-id", "x-client-request-id", "x-codex-window-id", "x-codex-turn-metadata", "x-codex-installation-id"} {
				_, present := upstream.lastReq.Header[http.CanonicalHeaderKey(hdr)]
				assert.False(t, present, "不得补设头 %s", hdr)
			}
			assert.False(t, gjson.GetBytes(upstream.lastBody, "prompt_cache_key").Exists(), "无 pck 不补 pck")
			assert.False(t, gjson.GetBytes(upstream.lastBody, "client_metadata").Exists())
		})
	}
}

// 真实 Codex 下游（有 session-id / thread-id）：下划线 session_id 与 conversation_id 仍一律删除
// （Codex ≥ rust-v0.131.0 不发 session_id、0.81.0 删除 conversation_id）。
func TestCodexMachineChain_HTTP_CodexDownstream_UnderscoreHeadersDropped(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		name := "non_passthrough"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			c, _, body := machineChainRequest(t, "/v1/responses", testMachineChainRoot, testMachineChainRoot, testMachineChainRoot+":0", "")
			svc, upstream := newMachineChainService()
			account := newMachineChainAccount(t, 6541, testCodexFingerprintSeed, passthrough, "")
			_, _ = svc.Forward(context.Background(), c, account, body)
			require.NotNil(t, upstream.lastReq)
			_, sessionPresent := upstream.lastReq.Header[http.CanonicalHeaderKey("session_id")]
			_, conversationPresent := upstream.lastReq.Header[http.CanonicalHeaderKey("conversation_id")]
			assert.False(t, sessionPresent)
			assert.False(t, conversationPresent)
			assert.NotEmpty(t, upstream.lastReq.Header.Get("session-id"))
		})
	}
}

// 兼容桥（chat completions / messages）：桥不带 Codex 会话头，出站与 Forward 非 Codex 下游同形态——
// 保留桥 post-build 的下划线 session_id、无 conversation_id、无合成头、无 client_metadata。
// r3 形态：chat 桥 session 为 UUID(isolate(apiKeyID, pck))；messages 桥由
// buildUpstreamRequest 亲和派生设置 isolate 裸值 16-hex（r3 自身无 UUID 覆盖块）。
func TestCodexMachineChain_Bridges_ThirdPartyShape(t *testing.T) {
	account := newMachineChainAccount(t, 6551, testCodexFingerprintSeed, false, "")
	wantChatSession := generateSessionUUID(isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, "cache-key-123"))
	wantMessagesSession := isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, "cache-key-123")
	pckP := codexMachinePseudonym([]byte(testCodexFingerprintSeed), "cache-key-123")

	t.Run("chat_completions", func(t *testing.T) {
		const body = `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}],"stream":false}`
		c := machineThirdPartyBridgeContext(t, "/v1/chat/completions", body, testMachineThirdPartyAPIKeyID)
		svc, up := newMachineChainService()
		_, _ = svc.ForwardAsChatCompletions(context.Background(), c, account, []byte(body), "cache-key-123", "gpt-5.4")
		require.NotNil(t, up.lastReq)
		assert.Equal(t, "https://chatgpt.com/backend-api/codex/responses", up.lastReq.URL.String())
		assert.Equal(t, wantChatSession, up.lastReq.Header.Get("session_id"))
		for _, hdr := range codexSyntheticIdentityHeaderNames {
			_, present := up.lastReq.Header[http.CanonicalHeaderKey(hdr)]
			assert.False(t, present, "不得合成 / 补设头 %s", hdr)
		}
		assert.False(t, gjson.GetBytes(up.lastBody, "client_metadata").Exists())
		// chat 桥 body 带 pck（既有行为）：machine 下 1:1 假名化
		assert.Equal(t, pckP, gjson.GetBytes(up.lastBody, "prompt_cache_key").String())
		assert.NotContains(t, string(up.lastBody), "cache-key-123")
	})
	t.Run("messages", func(t *testing.T) {
		const body = `{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":false}`
		c := machineThirdPartyBridgeContext(t, "/v1/messages", body, testMachineThirdPartyAPIKeyID)
		svc, up := newMachineChainService()
		_, _ = svc.ForwardAsAnthropic(context.Background(), c, account, []byte(body), "cache-key-123", "gpt-5.4")
		require.NotNil(t, up.lastReq)
		assert.Equal(t, wantMessagesSession, up.lastReq.Header.Get("session_id"))
		for _, hdr := range codexSyntheticIdentityHeaderNames {
			_, present := up.lastReq.Header[http.CanonicalHeaderKey(hdr)]
			assert.False(t, present, "不得合成 / 补设头 %s", hdr)
		}
		assert.False(t, gjson.GetBytes(up.lastBody, "client_metadata").Exists())
		assert.False(t, gjson.GetBytes(up.lastBody, "prompt_cache_key").Exists(), "messages 桥 OAuth 路径不带 body pck（既有行为），machine 不补")
		// 桥 post-build 恢复的 Codex 身份头仍在
		assert.NotEmpty(t, up.lastReq.Header.Get("originator"))
		assert.Equal(t, "responses=experimental", up.lastReq.Header.Get("OpenAI-Beta"))
	})
}

func machineThirdPartyBridgeContext(t *testing.T, path, body string, apiKeyID int64) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("User-Agent", "OpenAI/Python 1.55.0")
	c.Set("api_key", &APIKey{ID: apiKeyID})
	return c
}

// off 模式下两座桥保持 r3 生产行为：绑定不查 mode——chat 桥 session 为
// UUID(isolate(apiKeyID, pck)) + conversation 同隔离值；messages 桥 session 为
// isolate 16-hex、无 conversation 兜底；chat 桥 pck 仍走 pcv2 网关键改写
// （off 只关指纹合成，不动 pcv2）；不产生任何 Codex 会话头。
func TestCodexMachineChain_Bridges_OffModeUnchanged(t *testing.T) {
	account := newMachineChainAccount(t, 6552, testCodexFingerprintSeed, false, "")
	account.Extra[codexFingerprintModeExtraKey] = "off"
	wantChatSession := generateSessionUUID(isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, "cache-key-123"))
	wantIsolated := isolateOpenAISessionID(testMachineThirdPartyAPIKeyID, "cache-key-123")

	t.Run("chat_completions", func(t *testing.T) {
		const body = `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}],"stream":false}`
		c := machineThirdPartyBridgeContext(t, "/v1/chat/completions", body, testMachineThirdPartyAPIKeyID)
		svc, up := newMachineChainService()
		_, _ = svc.ForwardAsChatCompletions(context.Background(), c, account, []byte(body), "cache-key-123", "gpt-5.4")
		require.NotNil(t, up.lastReq)
		assert.Equal(t, wantChatSession, up.lastReq.Header.Get("session_id"))
		assert.Equal(t, wantIsolated, up.lastReq.Header.Get("conversation_id"), "off 模式 chat 桥仍按既有逻辑设置 conversation_id（同隔离值）")
		assert.Empty(t, up.lastReq.Header.Get("session-id"))
		assert.Empty(t, up.lastReq.Header.Get("x-codex-turn-metadata"))
		// r3：off 模式 pck 仍改写为 pcv2 网关键，原始客户端值不得出站。
		outboundPck := gjson.GetBytes(up.lastBody, "prompt_cache_key").String()
		assert.NotEqual(t, "cache-key-123", outboundPck, "off 模式不得透传原始 pck")
		assert.True(t, strings.HasPrefix(outboundPck, "pcv2-"), "off 模式 pck 仍走 pcv2 网关键: %s", outboundPck)
		assert.False(t, gjson.GetBytes(up.lastBody, "client_metadata.x-codex-turn-metadata").Exists())
	})
	t.Run("messages", func(t *testing.T) {
		const body = `{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":false}`
		c := machineThirdPartyBridgeContext(t, "/v1/messages", body, testMachineThirdPartyAPIKeyID)
		svc, up := newMachineChainService()
		_, _ = svc.ForwardAsAnthropic(context.Background(), c, account, []byte(body), "cache-key-123", "gpt-5.4")
		require.NotNil(t, up.lastReq)
		assert.Equal(t, wantIsolated, up.lastReq.Header.Get("session_id"))
		assert.Empty(t, up.lastReq.Header.Get("conversation_id"), "messages 桥无 conversation 兜底")
		assert.Empty(t, up.lastReq.Header.Get("session-id"))
		assert.Empty(t, up.lastReq.Header.Get("x-codex-turn-metadata"))
		assert.False(t, gjson.GetBytes(up.lastBody, "prompt_cache_key").Exists(), "messages 桥 OAuth 路径不带 body pck（既有行为）")
		assert.False(t, gjson.GetBytes(up.lastBody, "client_metadata.x-codex-turn-metadata").Exists())
	})
}

// machine 只改不增 × 账号有 openai_device_id：非透传链路的 applyCodexClientMetadata（加法 helper）
// 在 machine 模式必须跳过——下游没发 client_metadata / installation 键时不得新增，且与透传链路输出一致
// （第二轮 Codex 复审 §14.3 高-2）。
func TestCodexMachineChain_HTTP_DeviceIDDoesNotAddInstallation(t *testing.T) {
	const deviceID = "22222222-2222-4222-8222-222222222222"
	cases := []struct {
		name string
		body string
	}{
		{name: "no_client_metadata", body: machineThirdPartyBodyWithPck},
		{name: "client_metadata_without_installation", body: `{"model":"gpt-5.2","stream":false,"prompt_cache_key":"opencode-key","instructions":"x","client_metadata":{"session_id":"` + testMachineChainRoot + `","thread_id":"` + testMachineChainRoot + `"},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`},
	}
	for _, tc := range cases {
		for _, passthrough := range []bool{false, true} {
			name := tc.name + "/non_passthrough"
			if passthrough {
				name = tc.name + "/passthrough"
			}
			t.Run(name, func(t *testing.T) {
				c, body := machineThirdPartyRequest(t, "/v1/responses", tc.body, testMachineThirdPartyAPIKeyID, nil)
				svc, upstream := newMachineChainService()
				account := newMachineChainAccount(t, 6561, testCodexFingerprintSeed, passthrough, "")
				account.Extra["openai_device_id"] = deviceID
				_, _ = svc.Forward(context.Background(), c, account, body)
				require.NotNil(t, upstream.lastReq)
				cm := gjson.GetBytes(upstream.lastBody, "client_metadata")
				if tc.name == "no_client_metadata" {
					assert.False(t, cm.Exists(), "有 device_id 也不得创建 client_metadata")
				} else {
					require.True(t, cm.IsObject())
					assert.False(t, cm.Get("x-codex-installation-id").Exists(), "有 device_id 也不得补 installation 键")
					assert.Equal(t, codexMachinePseudonym([]byte(testCodexFingerprintSeed), testMachineChainRoot), cm.Get("session_id").String())
				}
				assert.NotContains(t, string(upstream.lastBody), deviceID)
				assert.Empty(t, upstream.lastReq.Header.Get("x-codex-installation-id"))
			})
		}
	}
}

// machineThirdPartyWSFrame 构造非 Codex 下游的 response.create 帧（无 client_metadata，带 pck）。
func machineThirdPartyWSFrame(previousResponseID, text string) string {
	prev := ""
	if previousResponseID != "" {
		prev = `,"previous_response_id":"` + previousResponseID + `"`
	}
	return `{"type":"response.create","model":"gpt-5.2","stream":false,"prompt_cache_key":"opencode-key"` + prev +
		`,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"` + text + `"}]}]}`
}

// machineThirdPartyWSSetClientHeaders 非 Codex 下游的握手头：无 session-id / thread-id；带下划线 session_id
// 与顶层 x-codex-installation-id（后者在 WS 握手白名单内，存在则改）。
func machineThirdPartyWSSetClientHeaders(h http.Header) {
	h.Set("User-Agent", "OpenAI/Python 1.55.0")
	h.Set("session_id", "underscore-only")
	h.Set("x-codex-installation-id", "sdk-install")
}

// machineThirdPartyWSAssertHandshake 断言握手头：无合成头、保留下划线 session_id、无 conversation_id、
// 存在的 installation 头按账号收敛值改写。
func machineThirdPartyWSAssertHandshake(t *testing.T, h http.Header, account *Account) {
	t.Helper()
	require.NotNil(t, h)
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	for _, name := range []string{"session-id", "thread-id", "x-client-request-id", "x-codex-window-id", "x-codex-turn-metadata", "conversation_id"} {
		_, present := h[http.CanonicalHeaderKey(name)]
		assert.False(t, present, "不得合成 / 补设握手头 %s", name)
	}
	assert.NotEmpty(t, h.Get("session_id"), "下划线 session_id 保留（第三方 Agent 形态）")
	assert.Equal(t, resolveConvergedInstallationID(account, seed), h.Get("x-codex-installation-id"), "下游带了顶层 installation 头 ⇒ 改为账号收敛值")
	for name, values := range h {
		for _, v := range values {
			assert.NotContains(t, v, "sdk-install", "下游 installation 不得出现在握手头 %s", name)
		}
	}
}

// machineThirdPartyWSAssertPayload 断言送往上游的帧：不创建 client_metadata、pck 假名化。
func machineThirdPartyWSAssertPayload(t *testing.T, payloadJSON string, account *Account) {
	t.Helper()
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	assert.False(t, gjson.Get(payloadJSON, "client_metadata").Exists(), "不得创建 client_metadata")
	assert.Equal(t, codexMachinePseudonym([]byte(seed), "opencode-key"), gjson.Get(payloadJSON, "prompt_cache_key").String())
	assert.NotContains(t, payloadJSON, "opencode-key")
}

// 客户端 WS 入口 ctx_pool：非 Codex 下游握手 + 两帧。
func TestCodexMachineChain_WSIngress_ThirdParty_CtxPool(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := machineWSIngressPoolConfig()
	captureConn := &openAIWSCaptureConn{
		events: [][]byte{
			[]byte(`{"type":"response.completed","response":{"id":"resp_tp_ingress_1","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`),
			[]byte(`{"type":"response.completed","response":{"id":"resp_tp_ingress_2","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`),
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
	account := newMachineWSChainAccount(t, 6571, testCodexFingerprintSeed)

	server, serverErrCh := machineWSIngressServeWithHeaders(t, svc, account, machineThirdPartyWSSetClientHeaders)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("", "hi"))
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_ingress_1", gjson.GetBytes(first, "response.id").String())
	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("resp_tp_ingress_1", "again"))
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_ingress_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")
	select {
	case serverErr := <-serverErrCh:
		require.NoError(t, serverErr)
	case <-time.After(5 * time.Second):
		t.Fatal("等待 ingress websocket 结束超时")
	}

	machineThirdPartyWSAssertHandshake(t, captureDialer.lastHeaders, account)
	require.Len(t, captureConn.writes, 2)
	machineThirdPartyWSAssertPayload(t, requestToJSONString(captureConn.writes[0]), account)
	machineThirdPartyWSAssertPayload(t, requestToJSONString(captureConn.writes[1]), account)
}

// 客户端 WS 入口 http_bridge：每帧一个 HTTP 请求，出站头与帧 body 都是第三方形态。
func TestCodexMachineChain_WSIngress_ThirdParty_HTTPBridge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := machineWSIngressPoolConfig()
	cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	cfg.Gateway.OpenAIWS.IngressModeDefault = OpenAIWSIngressModeCtxPool
	upstream := &httpUpstreamRecorder{responses: []*http.Response{
		machineWSIngressSSEResponse("resp_tp_bridge_1"),
		machineWSIngressSSEResponse("resp_tp_bridge_2"),
	}}
	svc := &OpenAIGatewayService{
		cfg:              cfg,
		httpUpstream:     upstream,
		cache:            &stubGatewayCache{},
		openaiWSResolver: NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:    NewCodexToolCorrector(),
	}
	account := newMachineWSChainAccount(t, 6572, testCodexFingerprintSeed)
	account.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModeHTTPBridge

	server, serverErrCh := machineWSIngressServeWithHeaders(t, svc, account, machineThirdPartyWSSetClientHeaders)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("", "hi"))
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_bridge_1", gjson.GetBytes(first, "response.id").String())
	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("resp_tp_bridge_1", "again"))
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_bridge_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")
	select {
	case serverErr := <-serverErrCh:
		require.NoError(t, serverErr)
	case <-time.After(5 * time.Second):
		t.Fatal("等待 http_bridge websocket 结束超时")
	}

	require.Len(t, upstream.requests, 2)
	require.Len(t, upstream.bodies, 2)
	for i := range upstream.requests {
		machineThirdPartyWSAssertHandshake(t, upstream.requests[i].Header, account)
		machineThirdPartyWSAssertPayload(t, string(upstream.bodies[i]), account)
	}
}

// 客户端 WS 入口 passthrough：握手头 + 首帧（主 goroutine）+ 后续帧（relay filter）。
func TestCodexMachineChain_WSIngress_ThirdParty_Passthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := passthroughLifecycleConfig()
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIFirstOutputTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.IngressInterTurnIdleTimeoutSeconds = 3
	cfg.Gateway.OpenAIWS.ReadTimeoutSeconds = 3
	upstream := newStagedPassthroughConn()
	dialer := &machineWSIngressHeaderCaptureDialer{conn: upstream}
	svc := &OpenAIGatewayService{
		cfg:                       cfg,
		httpUpstream:              &httpUpstreamRecorder{},
		cache:                     &stubGatewayCache{},
		openaiWSResolver:          NewOpenAIWSProtocolResolver(cfg),
		toolCorrector:             NewCodexToolCorrector(),
		openaiWSPassthroughDialer: dialer,
	}
	account := newMachineWSChainAccount(t, 6573, testCodexFingerprintSeed)
	account.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModePassthrough

	server, serverErrCh := machineWSIngressServeWithHeaders(t, svc, account, machineThirdPartyWSSetClientHeaders)
	defer server.Close()
	clientConn := machineWSIngressDial(t, server)
	defer func() { _ = clientConn.CloseNow() }()

	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("", "hi"))
	firstUpstream := requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	upstream.Send(`{"type":"response.completed","response":{"id":"resp_tp_pt_1","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`)
	first := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_pt_1", gjson.GetBytes(first, "response.id").String())

	machineWSIngressWrite(t, clientConn, machineThirdPartyWSFrame("resp_tp_pt_1", "again"))
	secondUpstream := requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	upstream.Send(`{"type":"response.completed","response":{"id":"resp_tp_pt_2","model":"gpt-5.2","usage":{"input_tokens":1,"output_tokens":1}}}`)
	second := machineWSIngressRead(t, clientConn)
	require.Equal(t, "resp_tp_pt_2", gjson.GetBytes(second, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")
	select {
	case serverErr := <-serverErrCh:
		if serverErr != nil {
			require.Contains(t, serverErr.Error(), "StatusNormalClosure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待 passthrough websocket 结束超时")
	}

	machineThirdPartyWSAssertHandshake(t, dialer.headers(), account)
	machineThirdPartyWSAssertPayload(t, string(firstUpstream), account)
	machineThirdPartyWSAssertPayload(t, string(secondUpstream), account)
	assert.Equal(t, "resp_tp_pt_1", gjson.GetBytes(secondUpstream, "previous_response_id").String())
}
