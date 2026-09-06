package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- machine 模式配套：白名单对齐（§6）、WS 握手键（§7）、seed 生命周期（§2） ---

// codexIdentityHeaderParityList 是三处放行判定就 Codex 身份类头而言必须逐键相等的共享期望列表。
var codexIdentityHeaderParityList = []string{
	"x-codex-installation-id",
	"x-codex-window-id",
	"session-id",
	"thread-id",
	"x-client-request-id",
	"x-openai-subagent",
	"x-codex-parent-thread-id",
}

// codexSessionIdentityHeaderList 是本轮新增放行的会话/子 Agent 身份头，仅 machine 模式的 /responses
// 两条 HTTP 链路放行；其他模式维持 HEAD 行为（HTTP 丢弃；WS 握手 HEAD 已拷贝前三个，后两个同样仅 machine）。
var codexSessionIdentityHeaderList = []string{
	"session-id",
	"thread-id",
	"x-client-request-id",
	"x-openai-subagent",
	"x-codex-parent-thread-id",
}

// codexSubagentIdentityHeaderList 是 WS 握手拷贝列表中本轮新增、仅 machine 拷贝的子 Agent 头。
var codexSubagentIdentityHeaderList = []string{
	"x-openai-subagent",
	"x-codex-parent-thread-id",
}

func TestCodexIdentityHeaders_WhitelistParityAcrossHTTPAndWS(t *testing.T) {
	// machine：三处放行判定就 Codex 身份类头逐键相等
	for _, name := range codexIdentityHeaderParityList {
		assert.True(t, isOpenAIResponsesClientHeaderAllowed(name, true), "非透传 /responses（machine）放行判定缺少 %s", name)
		assert.True(t, isOpenAIPassthroughAllowedRequestHeader(name, false, true), "透传 /responses（machine）放行判定缺少 %s", name)
	}
	// 非 machine：会话/子 Agent 身份头维持 HEAD 行为（HTTP 两条链路都不放行）
	for _, name := range codexSessionIdentityHeaderList {
		assert.False(t, isOpenAIResponsesClientHeaderAllowed(name, false), "非透传 /responses（非 machine）不应放行 %s", name)
		assert.False(t, isOpenAIPassthroughAllowedRequestHeader(name, false, false), "透传 /responses（非 machine）不应放行 %s", name)
	}
	// 会话身份头只存在于独立集合：不得混入被 /v1/images/* 复用的 openaiPassthroughAllowedHeaders，
	// 也不进入非透传基础集合 openaiAllowedHeaders（图片链路无指纹改写，不应放行会话身份头）。
	for _, name := range codexSessionIdentityHeaderList {
		assert.True(t, openaiCodexSessionIdentityHeaders[name], "openaiCodexSessionIdentityHeaders 缺少 %s", name)
		assert.False(t, openaiPassthroughAllowedHeaders[name], "openaiPassthroughAllowedHeaders 不应包含 %s（images 复用）", name)
		assert.False(t, openaiAllowedHeaders[name], "openaiAllowedHeaders 不应包含 %s", name)
	}
	// WS 拷贝列表：machine 账号逐个拷贝；非 machine 账号只拷贝 HEAD 既有的 5 个，子 Agent 头不拷贝
	svc := &OpenAIGatewayService{cfg: &config.Config{}}
	c := newFingerprintStageTestContext(t)
	for _, name := range codexIdentityHeaderParityList {
		c.Request.Header.Set(name, "value-"+name)
	}
	machine := newTestOAuthAccount(7001, map[string]any{codexFingerprintModeExtraKey: "machine", codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	headers, _, err := svc.buildOpenAIWSHeaders(context.Background(), c, machine, "tok", OpenAIWSProtocolDecision{Transport: OpenAIUpstreamTransportResponsesWebsocketV2}, false, "", "", "", "", "")
	require.NoError(t, err)
	for _, name := range codexIdentityHeaderParityList {
		assert.Equal(t, "value-"+name, headers.Get(name), "WS 握手头拷贝列表（machine）缺少 %s", name)
	}
	for _, mode := range []string{"off", "device", "session", "full"} {
		// 本用例只验证握手白名单，不混入账号 namespace 或 staged 指纹 sink。
		other := &Account{
			ID:       7001,
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra:    map[string]any{codexFingerprintModeExtraKey: mode},
		}
		headers, _, err := svc.buildOpenAIWSHeaders(context.Background(), c, other, "tok", OpenAIWSProtocolDecision{Transport: OpenAIUpstreamTransportResponsesWebsocketV2}, false, "", "", "", "", "")
		require.NoError(t, err)
		for _, name := range codexSubagentIdentityHeaderList {
			assert.Empty(t, headers.Get(name), "mode=%s WS 握手不应拷贝 %s", mode, name)
		}
		for _, name := range []string{"x-codex-window-id", "x-codex-installation-id", "session-id", "thread-id", "x-client-request-id"} {
			assert.Equal(t, "value-"+name, headers.Get(name), "mode=%s WS 握手 HEAD 既有拷贝 %s 不变", mode, name)
		}
	}
}

// 非 machine 模式：本轮新增的会话/子 Agent 身份头在两条 HTTP 链路维持 HEAD 行为（丢弃）。
// HEAD 既有白名单键仍存在；off 下由官方账号 namespace 隔离，device 的 installation
// 再由本地指纹 sink 覆盖为账号收敛值。
func TestCodexIdentityHeaders_NonMachineModesDropSessionIdentityHeaders(t *testing.T) {
	svc := &OpenAIGatewayService{}
	body := []byte(`{"model":"gpt-5.2","input":[],"stream":true}`)
	for _, mode := range []string{"off", "device"} {
		for _, passthrough := range []bool{false, true} {
			extra := map[string]any{codexFingerprintModeExtraKey: mode, codexFingerprintSeedExtraKey: testCodexFingerprintSeed}
			if passthrough {
				extra["openai_passthrough"] = true
			}
			account := newTestOAuthAccount(7002, extra)
			account.Credentials = map[string]any{"chatgpt_account_id": "chatgpt-acc"}
			c := newFingerprintStageTestContext(t)
			c.Request.Header.Set("originator", "codex_cli_rs")
			for _, name := range codexIdentityHeaderParityList {
				c.Request.Header.Set(name, "value-"+name)
			}
			stageCodexFingerprintIDs(c, resolveCodexFingerprintIDsFromRequest(account, c.Request.Header))

			var req *http.Request
			var err error
			if passthrough {
				req, err = svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "tok")
			} else {
				req, err = svc.buildUpstreamRequest(context.Background(), c, account, body, "tok", true, "", true)
			}
			require.NoError(t, err)
			for _, name := range codexSessionIdentityHeaderList {
				assert.Empty(t, req.Header.Get(name), "mode=%s passthrough=%v 头 %s 应维持 HEAD 行为被丢弃", mode, passthrough, name)
			}
			assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "window", "value-x-codex-window-id"), req.Header.Get("x-codex-window-id"), "mode=%s passthrough=%v", mode, passthrough)
			if mode == "off" {
				assert.Equal(t, scopeCodexAccountIdentityValue(account, 0, "installation", "value-x-codex-installation-id"), req.Header.Get("x-codex-installation-id"), "passthrough=%v", passthrough)
			} else {
				seed, ok := codexFingerprintSeed(account.Extra)
				require.True(t, ok)
				assert.Equal(t, resolveConvergedInstallationID(account, seed), req.Header.Get("x-codex-installation-id"), "passthrough=%v", passthrough)
			}
		}
	}
}

// §7：machine 归入 session/full 一侧的握手兼容键——不同下游窗口的假名不共用同一条 WS 连接。
func TestNormalizeOpenAIWSHandshakeCompatibility_MachineKeysOnWindowIdentity(t *testing.T) {
	account := activeCodexFingerprintPoolAccountForTest(7003)
	account.Extra[codexFingerprintModeExtraKey] = "machine"

	base := stableOpenAIWSIdentityHeadersForTest()
	base.Del("session_id") // machine 下下划线键已被头 sink 删除
	keyA := normalizeOpenAIWSHandshakeCompatibility(account, base)
	assert.Equal(t, "install-a", keyA.codexInstallationID)
	assert.Equal(t, "session-hyphen-a", keyA.sessionIDHyphen)
	assert.Equal(t, "thread-a", keyA.threadID)
	assert.Equal(t, "client-request-a", keyA.clientRequestID)
	assert.Equal(t, "window-a", keyA.codexWindowID)
	assert.Empty(t, keyA.sessionIDUnderscore)

	// 同一窗口 + 不同 turn metadata ⇒ 同键
	same := base.Clone()
	same.Set("x-codex-turn-metadata", `{"turn_id":"turn-b"}`)
	assert.Equal(t, keyA, normalizeOpenAIWSHandshakeCompatibility(account, same))

	// 另一窗口（thread / window 不同）⇒ 键不同
	other := base.Clone()
	other.Set("thread-id", "thread-b")
	other.Set("x-client-request-id", "client-request-b")
	other.Set("x-codex-window-id", "window-b")
	assert.NotEqual(t, keyA, normalizeOpenAIWSHandshakeCompatibility(account, other))

	// 无 seed 的 machine 退化为 off：键只含 beta features
	noSeed := &Account{ID: 7004, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{codexFingerprintModeExtraKey: "machine"}}
	keyOff := normalizeOpenAIWSHandshakeCompatibility(noSeed, base)
	assert.Empty(t, keyOff.codexInstallationID)
	assert.Empty(t, keyOff.threadID)
}

func TestOpenAIWSConnPool_MachineModeDoesNotShareConnAcrossWindows(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 2
	cfg.Gateway.OpenAIWS.MinIdlePerAccount = 0
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 2

	pool := newOpenAIWSConnPool(cfg)
	dialer := &openAIWSCountingDialer{}
	pool.setClientDialerForTest(dialer)
	account := activeCodexFingerprintPoolAccountForTest(7005)
	account.Extra[codexFingerprintModeExtraKey] = "machine"

	first := stableOpenAIWSIdentityHeadersForTest()
	first.Del("session_id")
	lease1, err := pool.Acquire(context.Background(), openAIWSAcquireRequest{Account: account, WSURL: "wss://example.com/v1/responses", Headers: first})
	require.NoError(t, err)
	conn1 := lease1.ConnID()
	lease1.Release()

	// 同一窗口复用
	again := first.Clone()
	again.Set("x-codex-turn-metadata", `{"turn_id":"turn-x"}`)
	lease2, err := pool.Acquire(context.Background(), openAIWSAcquireRequest{Account: account, WSURL: "wss://example.com/v1/responses", Headers: again})
	require.NoError(t, err)
	assert.True(t, lease2.Reused())
	assert.Equal(t, conn1, lease2.ConnID())
	lease2.Release()

	// 另一窗口不复用
	other := first.Clone()
	other.Set("thread-id", "thread-b")
	other.Set("x-client-request-id", "client-request-b")
	other.Set("x-codex-window-id", "window-b")
	lease3, err := pool.Acquire(context.Background(), openAIWSAcquireRequest{Account: account, WSURL: "wss://example.com/v1/responses", Headers: other})
	require.NoError(t, err)
	assert.False(t, lease3.Reused())
	assert.NotEqual(t, conn1, lease3.ConnID())
	lease3.Release()
	assert.Equal(t, 2, dialer.DialCount())
}

// §2 seed 生命周期：machine 与 device/session/full 同一套规则。
func TestAdminCreateAccount_MachineModeMintsSeed(t *testing.T) {
	repo := &upstreamBillingProbeAccountRepo{}
	svc := &adminServiceImpl{accountRepo: repo}
	created, err := svc.CreateAccount(context.Background(), &CreateAccountInput{
		Name:                 "codex-oauth-machine",
		Platform:             PlatformOpenAI,
		Type:                 AccountTypeOAuth,
		SkipDefaultGroupBind: true,
		Extra: map[string]any{
			codexFingerprintModeExtraKey: "machine",
			codexFingerprintSeedExtraKey: userSuppliedCodexFingerprintSeed,
		},
	})
	require.NoError(t, err)
	seed := requireValidCodexFingerprintSeed(t, created.Extra)
	require.NotEqual(t, userSuppliedCodexFingerprintSeed, seed, "用户提交的 seed 必须被剥离并重新生成")
	require.Equal(t, "machine", created.Extra[codexFingerprintModeExtraKey])
	require.Equal(t, codexFingerprintMachine, created.GetCodexFingerprintMode())
}

func TestAdminUpdateAccount_SwitchToMachinePreservesSeed(t *testing.T) {
	accountID := int64(7010)
	repo := &upstreamBillingProbeAccountRepo{accounts: map[int64]*Account{
		accountID: {
			ID:       accountID,
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Status:   StatusActive,
			Extra: map[string]any{
				codexFingerprintModeExtraKey: "device",
				codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
			},
		},
	}}
	svc := &adminServiceImpl{accountRepo: repo}
	updated, err := svc.UpdateAccount(context.Background(), accountID, &UpdateAccountInput{
		Extra: map[string]any{codexFingerprintModeExtraKey: "machine"},
	})
	require.NoError(t, err)
	require.Equal(t, testCodexFingerprintSeed, requireValidCodexFingerprintSeed(t, updated.Extra), "device → machine 保留 seed，installation 不变")
	require.Equal(t, resolveConvergedInstallationID(updated, testCodexFingerprintSeed), resolveConvergedInstallationID(repo.accounts[accountID], testCodexFingerprintSeed))
}

func TestAdminUpdateAccount_EnableMachineFromNoSeedMintsSeed(t *testing.T) {
	accountID := int64(7011)
	repo := &upstreamBillingProbeAccountRepo{accounts: map[int64]*Account{
		accountID: {ID: accountID, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Extra: map[string]any{}},
	}}
	svc := &adminServiceImpl{accountRepo: repo}
	updated, err := svc.UpdateAccount(context.Background(), accountID, &UpdateAccountInput{
		Extra: map[string]any{codexFingerprintModeExtraKey: "machine"},
	})
	require.NoError(t, err)
	requireValidCodexFingerprintSeed(t, updated.Extra)
}

func TestBulkUpdateAccounts_MachineModeEnsuresSeed(t *testing.T) {
	repo := &upstreamBillingProbeAccountRepo{}
	result, err := (&adminServiceImpl{accountRepo: repo}).BulkUpdateAccounts(context.Background(), &BulkUpdateAccountsInput{
		AccountIDs: []int64{7021, 7022},
		Extra:      map[string]any{codexFingerprintModeExtraKey: "machine"},
	})
	require.NoError(t, err)
	require.Equal(t, 2, result.Success)
	require.Len(t, repo.bulkUpdates, 1)
	require.True(t, repo.bulkUpdates[0].EnsureCodexFingerprintSeed, "machine 键级更新必须触发仓储层原子 ensure seed")
	require.Equal(t, "machine", repo.bulkUpdates[0].Extra[codexFingerprintModeExtraKey])
}
