package service

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// compactProbeSSESuccessBody 是原生 v2 压缩成功的最小 SSE 形态：
// output_item.done 携带 compaction item + response.completed。
const compactProbeSSESuccessBody = "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"compaction\",\"id\":\"cmp_probe\",\"encrypted_content\":\"blob\"}}\n\n" +
	"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_probe\",\"output\":[]}}\n\n"

func TestAccountTestService_TestAccountConnection_OpenAICompactOAuthSuccessPersistsSupport(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          1,
		Name:        "openai-oauth",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"access_token":               "oauth-token",
			"chatgpt_account_id":         "chatgpt-acc",
			"chatgpt_account_is_fedramp": true,
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "x-request-id": []string{"rid-probe"}},
		Body:       io.NopCloser(strings.NewReader(compactProbeSSESuccessBody)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/1/test", bytes.NewReader(nil))

	err := svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact)
	require.NoError(t, err)

	// 原生 v2：探测普通 /responses 线，不再打已下线的 /responses/compact。
	require.Equal(t, chatgptCodexAPIURL, upstream.lastReq.URL.String())
	require.Equal(t, "chatgpt.com", upstream.lastReq.Host)
	require.Equal(t, "text/event-stream", upstream.lastReq.Header.Get("Accept"))
	require.Contains(t, upstream.lastReq.Header.Get("x-codex-beta-features"), "remote_compaction_v2")
	require.NotEmpty(t, upstream.lastReq.Header.Get("Session_Id"))
	require.Equal(t, HTTPUpstreamProfileOpenAI, HTTPUpstreamProfileFromContext(upstream.lastReq.Context()))
	require.Equal(t, codexCLIUserAgent, upstream.lastReq.Header.Get("User-Agent"))
	require.Equal(t, "chatgpt-acc", upstream.lastReq.Header.Get("chatgpt-account-id"))
	require.Equal(t, "true", upstream.lastReq.Header.Get("x-openai-fedramp"))
	require.Equal(t, "gpt-5.4", gjson.GetBytes(upstream.lastBody, "model").String())
	require.True(t, gjson.GetBytes(upstream.lastBody, "stream").Bool())
	require.False(t, gjson.GetBytes(upstream.lastBody, "store").Bool())
	inputItems := gjson.GetBytes(upstream.lastBody, "input").Array()
	require.NotEmpty(t, inputItems)
	require.Equal(t, "compaction_trigger", inputItems[len(inputItems)-1].Get("type").String())

	updates := <-updateCalls
	require.Equal(t, true, updates["openai_compact_supported"])
	require.Equal(t, http.StatusOK, updates["openai_compact_last_status"])
	require.Contains(t, rec.Body.String(), `"type":"test_complete"`)
}

func TestAccountTestService_TestAccountConnection_OpenAICompactOAuth404MarksUnsupported(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          2,
		Name:        "openai-oauth",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"access_token":       "oauth-token",
			"chatgpt_account_id": "chatgpt-acc",
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`404 page not found`)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/2/test", bytes.NewReader(nil))

	err := svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact)
	require.Error(t, err)

	updates := <-updateCalls
	require.Equal(t, false, updates["openai_compact_supported"])
	require.Equal(t, http.StatusNotFound, updates["openai_compact_last_status"])
	require.Contains(t, rec.Body.String(), `"type":"error"`)
}

func TestAccountTestService_TestAccountConnection_OpenAICompactAPIKeyUsesNativeResponsesPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          3,
		Name:        "openai-apikey",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":  "sk-test",
			"base_url": "https://example.com/v1",
			// post-#5641：compact_model_mapping 仅作用于 legacy /responses/compact，
			// 原生 v2 探测不应用它。
			"compact_model_mapping": map[string]any{"gpt-5.4": "gpt-5.4-openai-compact"},
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(compactProbeSSESuccessBody)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/3/test", bytes.NewReader(nil))

	err := svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact)
	require.NoError(t, err)

	require.Equal(t, "https://example.com/v1/responses", upstream.lastReq.URL.String())
	requireOpenAICodexProbeHeaders(t, upstream.lastReq.Header)
	require.Contains(t, upstream.lastReq.Header.Get("x-codex-beta-features"), "remote_compaction_v2")
	require.Equal(t, "gpt-5.4", gjson.GetBytes(upstream.lastBody, "model").String(),
		"原生 v2 探测不应用 compact_model_mapping")
	updates := <-updateCalls
	require.Equal(t, true, updates["openai_compact_supported"])
}

func TestAccountTestService_TestAccountConnection_OpenAICompactAPIKeyDefaultBaseURLUsesResponsesPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          4,
		Name:        "openai-apikey-default",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key": "sk-test",
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(compactProbeSSESuccessBody)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/4/test", bytes.NewReader(nil))

	err := svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact)
	require.NoError(t, err)
	require.Equal(t, "https://api.openai.com/v1/responses", upstream.lastReq.URL.String())
	<-updateCalls
}

func TestAccountTestService_TestAccountConnection_OpenAICompact2xxWithoutItemMarksUnsupported(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          5,
		Name:        "openai-oauth-no-item",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"access_token":       "oauth-token",
			"chatgpt_account_id": "chatgpt-acc",
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	// 200 但流里没有 compaction item：链路吞掉了 compaction_trigger 的形态
	//（#5478 的 "got 0 items"），必须判定为不支持。
	noItemBody := "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"id\":\"msg_1\"}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_x\",\"output\":[]}}\n\n"
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(noItemBody)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/5/test", bytes.NewReader(nil))

	err := svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact)
	require.Error(t, err)

	updates := <-updateCalls
	require.Equal(t, false, updates["openai_compact_supported"])
	require.Contains(t, rec.Body.String(), `"type":"error"`)
}

// 探测与真实转发走同一 /responses 端点，出站身份必须与真实 Codex 同构：
// session/thread 为 UUID、携带 x-codex-installation-id（收敛账号用收敛值）。
func TestAccountTestService_TestAccountConnection_OpenAICompactProbeIdentityMatchesRealTraffic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          6,
		Name:        "openai-oauth-identity",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"access_token":       "oauth-token",
			"chatgpt_account_id": "chatgpt-acc",
		},
		// 本基线缺省模式为 session（与上游 #5610 缺省 off 不同）；显式写出来以验证
		// 探测身份与真实流量同构。
		Extra: map[string]any{
			"codex_fingerprint_mode":     "session",
			codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(compactProbeSSESuccessBody)),
	}}
	svc := &AccountTestService{accountRepo: repo, httpUpstream: upstream}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/6/test", bytes.NewReader(nil))

	require.NoError(t, svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact))

	// 显式 session 收敛模式：出站身份 = 账号级收敛值
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	converged := resolveConvergedSessionID(seed)
	require.Equal(t, converged, upstream.lastReq.Header.Get("session-id"))
	require.Equal(t, converged, upstream.lastReq.Header.Get("session_id"))
	require.Equal(t, resolveConvergedInstallationID(&account, seed), upstream.lastReq.Header.Get("x-codex-installation-id"),
		"真实 Codex 每个请求必带 installation-id，探测不得缺失")
	require.NotContains(t, upstream.lastReq.Header.Get("session-id"), "probe_compact",
		"探测标识不得是可被上游一眼识别的字面量")
	<-updateCalls
}

// machine 模式探测：出站头形态 = 真实 Codex 常规请求（codex-api/src/endpoint/responses.rs:87-93 +
// core/src/client.rs:1186-1211）：连字符 session-id / thread-id / x-client-request-id（= thread）+
// window "{thread}:{n}"，全部假名化；无下划线 Session_ID / Conversation_ID。
// native v2 body 同样先构造 prompt_cache_key + client_metadata（含内嵌 turn
// metadata）的真实形态，再由 machine sink 整体假名化。
func TestAccountTestService_TestAccountConnection_OpenAICompactProbeMachineModeIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	updateCalls := make(chan map[string]any, 1)
	account := Account{
		ID:          16,
		Name:        "openai-oauth-machine-probe",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"access_token":       "oauth-token",
			"chatgpt_account_id": "chatgpt-acc",
		},
		Extra: map[string]any{
			"codex_fingerprint_mode":     "machine",
			codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
		},
	}
	repo := &snapshotUpdateAccountRepo{
		stubOpenAIAccountRepo: stubOpenAIAccountRepo{accounts: []Account{account}},
		updateExtraCalls:      updateCalls,
	}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(compactProbeSSESuccessBody)),
	}}
	svc := &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts/16/test", bytes.NewReader(nil))

	require.NoError(t, svc.TestAccountConnection(c, account.ID, "gpt-5.4", "", AccountTestModeCompact))

	h := upstream.lastReq.Header
	probeID := compactProbeSessionID(account.ID)
	want := codexMachinePseudonym([]byte(testCodexFingerprintSeed), probeID)
	require.Equal(t, want, h.Get("session-id"))
	require.Equal(t, want, h.Get("thread-id"), "根会话 session == thread（I1）")
	require.Equal(t, want, h.Get("x-client-request-id"), "真实 Codex x-client-request-id = thread")
	require.Equal(t, want+":0", h.Get("x-codex-window-id"), "window = {thread}:{n} 形态且前段假名化")
	require.NotEqual(t, probeID, want, "探测标识必须经假名化")
	require.Empty(t, h.Get("session_id"), "machine 不发下划线 session_id")
	require.Empty(t, h.Get("conversation_id"))
	for name, values := range h {
		for _, v := range values {
			require.NotContains(t, v, probeID, "真实探测标识不得出现在出站头 %s", name)
		}
	}

	// E(b)：body 也是真实 compaction 形态（client.rs:921-938 恒设 prompt_cache_key + client_metadata；
	// responses_metadata.rs:278-315 / :357-386），且与头共用同一份 IDs 假名化。
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	wantInstall := resolveConvergedInstallationID(&account, seed)
	body := string(upstream.lastBody)
	require.Equal(t, want, gjson.Get(body, "prompt_cache_key").String(), "prompt_cache_key = session（client.rs:484-488）且假名化")
	cm := gjson.Get(body, "client_metadata")
	require.True(t, cm.IsObject(), "真实 Codex 恒带 client_metadata")
	require.Equal(t, want, cm.Get("session_id").String())
	require.Equal(t, want, cm.Get("thread_id").String())
	require.Equal(t, want+":0", cm.Get("x-codex-window-id").String())
	require.Equal(t, wantInstall, cm.Get("x-codex-installation-id").String(), "body installation 经 sink 收敛为账号级值")
	require.NotEmpty(t, cm.Get("turn_id").String())
	tm := cm.Get("x-codex-turn-metadata").String()
	require.True(t, gjson.Valid(tm), "x-codex-turn-metadata 是内嵌 JSON 字符串")
	require.Equal(t, want, gjson.Get(tm, "session_id").String())
	require.Equal(t, want, gjson.Get(tm, "thread_id").String())
	require.Equal(t, want+":0", gjson.Get(tm, "window_id").String())
	require.Equal(t, wantInstall, gjson.Get(tm, "installation_id").String())
	require.Equal(t, cm.Get("turn_id").String(), gjson.Get(tm, "turn_id").String())
	turnUUID, err := uuid.Parse(cm.Get("turn_id").String())
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), turnUUID.Version(), "turn_id 与真实 submission/turn id 同为 UUIDv7（session/mod.rs:907-914）")
	require.Equal(t, "compaction", gjson.Get(tm, "request_kind").String())
	require.Equal(t, "responses_compaction_v2", gjson.Get(tm, "compaction.implementation").String())
	// 与真实 compaction turn 同构的字段集合与顺序（CodexTurnMetadataPayload 声明顺序，responses_metadata.rs:476-524）：
	// installation_id, session_id, thread_id, agent_name, turn_id, window_id, request_kind, thread_source, sandbox,
	// sandbox_mode, auto_review_enabled, node_repl_auto_review_required, node_repl_disabled, turn_started_at_unix_ms,
	// compaction{trigger, reason, implementation, phase, strategy}；sink 原位改值不改序。
	var tmKeys []string
	gjson.Parse(tm).ForEach(func(k, _ gjson.Result) bool { tmKeys = append(tmKeys, k.String()); return true })
	require.Equal(t, []string{
		"installation_id", "session_id", "thread_id", "agent_name", "turn_id", "window_id", "request_kind", "thread_source",
		"sandbox", "sandbox_mode", "auto_review_enabled", "node_repl_auto_review_required", "node_repl_disabled",
		"turn_started_at_unix_ms", "compaction",
	}, tmKeys)
	var compactionKeys []string
	gjson.Get(tm, "compaction").ForEach(func(k, _ gjson.Result) bool { compactionKeys = append(compactionKeys, k.String()); return true })
	require.Equal(t, []string{"trigger", "reason", "implementation", "phase", "strategy"}, compactionKeys)
	require.Equal(t, codexMachineCompactProbeAgentName, gjson.Get(tm, "agent_name").String(), "根线程 agent_name 恒 /root")
	require.Equal(t, codexMachineCompactProbeThreadSource, gjson.Get(tm, "thread_source").String())
	require.False(t, gjson.Get(tm, "node_repl_auto_review_required").Bool())
	require.False(t, gjson.Get(tm, "node_repl_disabled").Bool())
	require.Greater(t, gjson.Get(tm, "turn_started_at_unix_ms").Int(), int64(0))
	// sandbox_mode 取 TUI 默认 workspace-write，auto_review_enabled 默认 false；sandbox 与出站 UA 的 OS 段同源。
	require.Equal(t, codexMachineCompactProbeSandboxMode, gjson.Get(tm, "sandbox_mode").String())
	require.False(t, gjson.Get(tm, "auto_review_enabled").Bool())
	wantSandbox := codexMachineSandboxTagFromUA(h.Get("User-Agent"))
	require.NotEmpty(t, wantSandbox, "测试账号 UA 必须可判定 OS")
	require.Equal(t, wantSandbox, gjson.Get(tm, "sandbox").String(), "sandbox 与出站 UA 的 OS 段同源")
	// 头侧 x-codex-turn-metadata（compatibility_headers）与 body 内嵌一致
	require.Equal(t, tm, h.Get("x-codex-turn-metadata"), "头与 body 的 turn metadata 必须是同一份")
	require.NotContains(t, body, probeID, "真实探测标识不得出现在 body")
	<-updateCalls
}

func TestCompactProbeSessionID_IsUUIDShaped(t *testing.T) {
	for _, id := range []int64{0, 1, 987654} {
		got := compactProbeSessionID(id)
		_, err := uuid.Parse(got)
		require.NoError(t, err, "探测会话标识必须是 UUID 形态: %s", got)
	}
	require.Equal(t, compactProbeSessionID(7), compactProbeSessionID(7), "同账号应稳定复用同一会话")
	require.NotEqual(t, compactProbeSessionID(7), compactProbeSessionID(8))
}
