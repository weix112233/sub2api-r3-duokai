package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// --- machine 模式：单元层用例（设计文档 §3 / §4 / §9） ---

const (
	// 第二个账号的 seed，用于 I2（跨账号不同假名）。
	testCodexMachineSeedB = "33333333-3333-4333-8333-333333333333"
	// 固定的 UUIDv7 / UUIDv4 输入，便于逐字节比较。
	testCodexMachineV7 = "01912e2a-6f3c-7d1e-9c4a-0f1e2d3c4b5a"
	testCodexMachineV4 = "9b8f0f1e-2d3c-4b5a-8f6e-7d8c9b0a1f2e"
)

// expectCodexMachinePseudonym 在测试里独立复算设计 §3 的假名算法，避免实现与用例同错。
func expectCodexMachinePseudonym(t *testing.T, seed, id string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(seed))
	mac.Write([]byte("sub2api:codex-machine:v1:" + id))
	sum := mac.Sum(nil)
	var out uuid.UUID
	if parsed, err := uuid.Parse(id); err == nil && parsed.Version() == 7 {
		copy(out[0:6], parsed[0:6])
		copy(out[6:16], sum[0:10])
		out[6] = (out[6] & 0x0f) | 0x70
	} else {
		copy(out[:], sum[0:16])
		out[6] = (out[6] & 0x0f) | 0x40
	}
	out[8] = (out[8] & 0x3f) | 0x80
	return out.String()
}

func newTestMachineAccount(t *testing.T, id int64, seed string) *Account {
	t.Helper()
	return newTestOAuthAccount(id, map[string]any{
		codexFingerprintModeExtraKey: "machine",
		codexFingerprintSeedExtraKey: seed,
	})
}

func newTestMachineIDs(t *testing.T, id int64, seed string) *codexFingerprintIDs {
	t.Helper()
	ids := resolveCodexFingerprintIDs(newTestMachineAccount(t, id, seed), "", codexFingerprintMachine)
	require.NotNil(t, ids)
	return ids
}

func TestCodexFingerprintMachine_ModeParsingAndSeedRequirement(t *testing.T) {
	assert.Equal(t, codexFingerprintMachine, codexFingerprintModeFromExtra(map[string]any{codexFingerprintModeExtraKey: "machine"}))
	assert.Equal(t, codexFingerprintMachine, codexFingerprintModeFromExtra(map[string]any{codexFingerprintModeExtraKey: " machine "}))
	assert.True(t, codexFingerprintModeRequiresSeed(codexFingerprintMachine))
	// 账号级读取：OAuth 账号显式配置 machine 时生效
	account := newTestMachineAccount(t, 5001, testCodexFingerprintSeed)
	assert.Equal(t, codexFingerprintMachine, account.GetCodexFingerprintMode())
	// Create / Update / 键级更新在 machine 下都要生成或保留 seed
	created := prepareCodexFingerprintExtraForCreate(PlatformOpenAI, AccountTypeOAuth, map[string]any{codexFingerprintModeExtraKey: "machine"})
	_, ok := codexFingerprintSeed(created)
	assert.True(t, ok, "Create 在 machine 模式下必须生成 seed")
	updated := prepareCodexFingerprintExtraForUpdate(&Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}, map[string]any{codexFingerprintModeExtraKey: "machine"})
	_, ok = codexFingerprintSeed(updated)
	assert.True(t, ok, "Update 从无 seed 切到 machine 必须生成 seed")
	assert.True(t, ShouldEnsureCodexFingerprintSeedForExtraUpdates(map[string]any{codexFingerprintModeExtraKey: "machine"}))
}

func TestResolveCodexFingerprintIDs_MachineMode(t *testing.T) {
	account := newTestMachineAccount(t, 5002, testCodexFingerprintSeed)
	ids := resolveCodexFingerprintIDs(account, "client-session", codexFingerprintMachine)
	require.NotNil(t, ids)
	assert.Equal(t, codexFingerprintMachine, ids.mode)
	assert.Equal(t, account.ID, ids.accountID)
	assert.Equal(t, resolveConvergedInstallationID(account, testCodexFingerprintSeed), ids.installationID, "installation 与 device 模式同值")
	assert.Equal(t, []byte(testCodexFingerprintSeed), ids.pseudonymKey)
	// machine 不生成 turn 级字段
	assert.Empty(t, ids.sessionID)
	assert.Empty(t, ids.threadID)
	assert.Empty(t, ids.turnID)
	assert.Empty(t, ids.windowID)
	assert.Zero(t, ids.turnStartedAtUnixMs)
	assert.Empty(t, ids.sandboxTag, "sandboxTag 由调用链 stamp")

	// FromRequest 入口同样支持 machine
	h := http.Header{}
	h.Set("session-id", testCodexMachineV7)
	fromReq := resolveCodexFingerprintIDsFromRequest(account, h)
	require.NotNil(t, fromReq)
	assert.Equal(t, codexFingerprintMachine, fromReq.mode)

	// 无 seed（直接改库）时退化为 off
	noSeed := &Account{ID: 5003, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{codexFingerprintModeExtraKey: "machine"}}
	assert.Nil(t, resolveCodexFingerprintIDs(noSeed, "", codexFingerprintMachine))
}

// I6：保版本——v7 入 v7 出且前 6 字节相同；v4 入 v4 出；非 UUID 入 v4 出。
func TestCodexMachinePseudonym_I6_PreservesVersion(t *testing.T) {
	key := []byte(testCodexFingerprintSeed)

	outV7 := codexMachinePseudonym(key, testCodexMachineV7)
	parsedV7, err := uuid.Parse(outV7)
	require.NoError(t, err)
	inV7 := uuid.MustParse(testCodexMachineV7)
	assert.Equal(t, uuid.Version(7), parsedV7.Version())
	assert.Equal(t, uuid.RFC4122, parsedV7.Variant())
	assert.Equal(t, inV7[0:6], parsedV7[0:6], "v7 假名保留 48 位时间戳")
	assert.NotEqual(t, testCodexMachineV7, outV7)
	assert.Equal(t, expectCodexMachinePseudonym(t, testCodexFingerprintSeed, testCodexMachineV7), outV7)

	outV4 := codexMachinePseudonym(key, testCodexMachineV4)
	parsedV4, err := uuid.Parse(outV4)
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(4), parsedV4.Version())
	assert.Equal(t, uuid.RFC4122, parsedV4.Variant())
	assert.NotEqual(t, testCodexMachineV4, outV4)
	assert.Equal(t, expectCodexMachinePseudonym(t, testCodexFingerprintSeed, testCodexMachineV4), outV4)

	outPlain := codexMachinePseudonym(key, "opencode-session-abc")
	parsedPlain, err := uuid.Parse(outPlain)
	require.NoError(t, err)
	assert.Equal(t, uuid.Version(4), parsedPlain.Version())
	assert.Equal(t, uuid.RFC4122, parsedPlain.Variant())
	assert.Equal(t, expectCodexMachinePseudonym(t, testCodexFingerprintSeed, "opencode-session-abc"), outPlain)
}

func TestCodexMachinePseudonym_EmptyAndWhitespace(t *testing.T) {
	key := []byte(testCodexFingerprintSeed)
	assert.Empty(t, codexMachinePseudonym(key, ""))
	assert.Empty(t, codexMachinePseudonym(key, "   "))
	// 首尾空白被 trim 后与原值同名
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), codexMachinePseudonym(key, "  "+testCodexMachineV7+"  "))
}

// I2：同一下游 ID 在两个账号（不同 seed）得到不同假名。
func TestCodexMachinePseudonym_I2_DifferentSeedsDifferentPseudonyms(t *testing.T) {
	a := codexMachinePseudonym([]byte(testCodexFingerprintSeed), testCodexMachineV7)
	b := codexMachinePseudonym([]byte(testCodexMachineSeedB), testCodexMachineV7)
	assert.NotEqual(t, a, b)
	// 通过 resolve 得到的 key 也不同
	idsA := newTestMachineIDs(t, 5101, testCodexFingerprintSeed)
	idsB := newTestMachineIDs(t, 5102, testCodexMachineSeedB)
	assert.NotEqual(t, codexMachinePseudonym(idsA.pseudonymKey, testCodexMachineV4), codexMachinePseudonym(idsB.pseudonymKey, testCodexMachineV4))
}

// I3：同一账号内 1:1——不同下游 ID 得到不同假名，同一 ID 恒得同一假名。
func TestCodexMachinePseudonym_I3_OneToOneWithinAccount(t *testing.T) {
	key := []byte(testCodexFingerprintSeed)
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), codexMachinePseudonym(key, testCodexMachineV7), "确定性")
	assert.NotEqual(t, codexMachinePseudonym(key, testCodexMachineV7), codexMachinePseudonym(key, testCodexMachineV4))
	// 单一域：同一 ID 用于 session / thread / pck 得到同一假名（I1 的基础）
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), codexMachinePseudonym(key, testCodexMachineV7))
}

func TestCodexMachineWindowPseudonym(t *testing.T) {
	key := []byte(testCodexFingerprintSeed)
	p := codexMachinePseudonym(key, testCodexMachineV7)
	assert.Equal(t, p+":0", codexMachineWindowPseudonym(key, testCodexMachineV7+":0"))
	assert.Equal(t, p+":17", codexMachineWindowPseudonym(key, testCodexMachineV7+":17"))
	assert.Equal(t, p, codexMachineWindowPseudonym(key, testCodexMachineV7), "整体是 UUID 时直接假名化")
	assert.Equal(t, "not-a-uuid:0", codexMachineWindowPseudonym(key, "not-a-uuid:0"), "前段非 UUID 原样")
	assert.Equal(t, "window-a", codexMachineWindowPseudonym(key, "window-a"), "非 UUID 原样")
	assert.Equal(t, "", codexMachineWindowPseudonym(key, ""))
}

func TestCodexMachineSandboxTagFromUA(t *testing.T) {
	assert.Equal(t, "seatbelt", codexMachineSandboxTagFromUA("codex-tui/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color"))
	assert.Equal(t, "windows_sandbox", codexMachineSandboxTagFromUA("codex_cli_rs/0.146.0 (Windows 10.0.26100; x86_64) WindowsTerminal"))
	assert.Equal(t, "seccomp", codexMachineSandboxTagFromUA("codex_cli_rs/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color"))
	assert.Equal(t, "seccomp", codexMachineSandboxTagFromUA("codex_cli_rs/0.146.0 (Arch Linux rolling; x86_64) alacritty"))
	assert.Equal(t, "", codexMachineSandboxTagFromUA("codex_cli_rs/0.1.0"), "无 OS 段不改写")
	// 规范 UA（Ubuntu 后缀）⇒ seccomp
	assert.Equal(t, "seccomp", codexMachineSandboxTagFromUA(codexCLIUserAgent))
}

// §4.3 sandbox 映射 3×5 表 + accountTag 为空 + external。
func TestRewriteCodexMachineSandbox_Table(t *testing.T) {
	cases := []struct {
		accountTag string
		current    string
		want       string
	}{
		{"seatbelt", "seatbelt", "seatbelt"},
		{"seatbelt", "seccomp", "seatbelt"},
		{"seatbelt", "windows_sandbox", "seatbelt"},
		{"seatbelt", "windows_elevated", "seatbelt"},
		{"seatbelt", "none", "none"},
		{"seccomp", "seatbelt", "seccomp"},
		{"seccomp", "seccomp", "seccomp"},
		{"seccomp", "windows_sandbox", "seccomp"},
		{"seccomp", "windows_elevated", "seccomp"},
		{"seccomp", "none", "none"},
		{"windows_sandbox", "seatbelt", "windows_sandbox"},
		{"windows_sandbox", "seccomp", "windows_sandbox"},
		{"windows_sandbox", "windows_sandbox", "windows_sandbox"},
		{"windows_sandbox", "windows_elevated", "windows_elevated"},
		{"windows_sandbox", "none", "none"},
		{"", "seatbelt", "seatbelt"},
		{"", "seccomp", "seccomp"},
		{"seatbelt", "external", "external"},
		{"windows_sandbox", "external", "external"},
		{"seccomp", "custom-value", "custom-value"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, rewriteCodexMachineSandbox(tc.current, tc.accountTag), "accountTag=%q current=%q", tc.accountTag, tc.current)
	}
}

func TestStampCodexMachineSandboxTag(t *testing.T) {
	// nil 安全
	stampCodexMachineSandboxTag(nil, "")
	// 非 machine 模式 no-op
	sessionIDs := resolveCodexFingerprintIDs(newTestOAuthAccount(5201, map[string]any{codexFingerprintModeExtraKey: "session"}), "s", codexFingerprintSession)
	require.NotNil(t, sessionIDs)
	stampCodexMachineSandboxTag(sessionIDs, "codex-tui/0.146.0 (Mac OS 26.0.1; arm64) xterm-256color")
	assert.Empty(t, sessionIDs.sandboxTag)

	// machine：overrideUA 为空 ⇒ 规范 UA（Ubuntu）⇒ seccomp
	ids := newTestMachineIDs(t, 5202, testCodexFingerprintSeed)
	stampCodexMachineSandboxTag(ids, "")
	assert.Equal(t, "seccomp", ids.sandboxTag)
	// 账号级 Mac UA ⇒ seatbelt（resolveCodexOutboundIdentity 只重建版本段，保留 OS 段）
	stampCodexMachineSandboxTag(ids, "codex-tui/0.120.0 (Mac OS 26.0.1; arm64) xterm-256color")
	assert.Equal(t, "seatbelt", ids.sandboxTag)
	stampCodexMachineSandboxTag(ids, "codex_cli_rs/0.146.0 (Windows 10.0.26100; x86_64) WindowsTerminal")
	assert.Equal(t, "windows_sandbox", ids.sandboxTag)
	// 非官方 UA 整体回退规范身份 ⇒ seccomp
	stampCodexMachineSandboxTag(ids, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	assert.Equal(t, "seccomp", ids.sandboxTag)
}

func TestRewriteCodexMachineTurnMetadata(t *testing.T) {
	ids := newTestMachineIDs(t, 5301, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	key := ids.pseudonymKey
	parent := testCodexMachineV4
	raw := `{"installation_id":"real-install","session_id":"` + testCodexMachineV7 + `","thread_id":"` + testCodexMachineV7 + `","parent_thread_id":"` + parent + `","forked_from_thread_id":"` + parent + `","turn_id":"turn-1","window_id":"` + testCodexMachineV7 + `:2","sandbox":"seccomp","sandbox_mode":"workspace-write","thread_source":"cli","turn_started_at_unix_ms":123,"workspaces":[{"cwd":"/tmp"}],"tool_namespaces_info":{"a":1}}`
	out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
	require.True(t, changed)
	assert.Equal(t, ids.installationID, gjson.Get(out, "installation_id").String())
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), gjson.Get(out, "session_id").String())
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), gjson.Get(out, "thread_id").String())
	assert.Equal(t, codexMachinePseudonym(key, parent), gjson.Get(out, "parent_thread_id").String())
	assert.Equal(t, codexMachinePseudonym(key, parent), gjson.Get(out, "forked_from_thread_id").String())
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7)+":2", gjson.Get(out, "window_id").String())
	assert.Equal(t, "seatbelt", gjson.Get(out, "sandbox").String())
	// 透传字段不动
	assert.Equal(t, "turn-1", gjson.Get(out, "turn_id").String())
	assert.Equal(t, "workspace-write", gjson.Get(out, "sandbox_mode").String())
	assert.Equal(t, "cli", gjson.Get(out, "thread_source").String())
	assert.Equal(t, int64(123), gjson.Get(out, "turn_started_at_unix_ms").Int())
	assert.Equal(t, "/tmp", gjson.Get(out, "workspaces.0.cwd").String())
	assert.Equal(t, int64(1), gjson.Get(out, "tool_namespaces_info.a").Int())

	// 只改不增：缺失的身份字段（含 installation_id）不补，无改写时原样返回
	minimal, changed := rewriteCodexMachineTurnMetadata(`{"turn_id":"t"}`, ids)
	assert.False(t, changed)
	assert.Equal(t, `{"turn_id":"t"}`, minimal)
	assert.False(t, gjson.Get(minimal, "installation_id").Exists(), "installation_id 不补")
	// 非法 JSON / 非对象：不是 Codex 会产生的形态，原样放行
	for _, raw := range []string{`not-json`, `[1,2]`, `"str"`, `null`} {
		out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
		assert.False(t, changed, "raw=%s", raw)
		assert.Equal(t, raw, out, "raw=%s", raw)
	}

	// sandboxTag 为空时 sandbox 原样
	noTag := newTestMachineIDs(t, 5302, testCodexFingerprintSeed)
	untouched, _ := rewriteCodexMachineTurnMetadata(`{"sandbox":"seccomp"}`, noTag)
	assert.Equal(t, "seccomp", gjson.Get(untouched, "sandbox").String())

	// 空串不改写
	same, changed := rewriteCodexMachineTurnMetadata("", ids)
	assert.False(t, changed)
	assert.Equal(t, "", same)
}

// 真实 Codex 的 turn metadata 由 serde 按 struct 声明顺序序列化；sink 只原位改值，
// 不得把键序变成字母序或改动其余字节（否则成为可观测的网关痕迹）。
func TestRewriteCodexMachineTurnMetadata_PreservesKeyOrderAndBytes(t *testing.T) {
	ids := newTestMachineIDs(t, 5303, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	raw := `{"session_id":"` + testCodexMachineV7 + `","thread_id":"` + testCodexMachineV7 + `","agent_name":"/root","turn_id":"turn-1","thread_source":"user","sandbox":"seccomp","sandbox_mode":"workspace-write","auto_review_enabled":false,"node_repl_auto_review_required":false,"node_repl_disabled":false,"turn_started_at_unix_ms":123}`
	out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
	require.True(t, changed)
	pseudo := codexMachinePseudonym(ids.pseudonymKey, testCodexMachineV7)
	want := `{"session_id":"` + pseudo + `","thread_id":"` + pseudo + `","agent_name":"/root","turn_id":"turn-1","thread_source":"user","sandbox":"seatbelt","sandbox_mode":"workspace-write","auto_review_enabled":false,"node_repl_auto_review_required":false,"node_repl_disabled":false,"turn_started_at_unix_ms":123}`
	assert.Equal(t, want, out, "只改值不改序、不改其余字节")

	// 探针的 compaction 有序 struct 经 sink 后同样保序（installation_id 位于首位）
	probe := `{"installation_id":"` + testCodexMachineV4 + `","session_id":"` + testCodexMachineV7 + `","thread_id":"` + testCodexMachineV7 + `","agent_name":"/root","turn_id":"t","window_id":"` + testCodexMachineV7 + `:0","request_kind":"compaction","thread_source":"user","compaction":{"trigger":"manual"}}`
	out, changed = rewriteCodexMachineTurnMetadata(probe, ids)
	require.True(t, changed)
	assert.True(t, strings.HasPrefix(out, `{"installation_id":"`+ids.installationID+`","session_id":"`+pseudo+`","thread_id":"`+pseudo+`","agent_name":"/root","turn_id":"t","window_id":"`+pseudo+`:0","request_kind":"compaction"`), out)
	assert.True(t, strings.HasSuffix(out, `,"compaction":{"trigger":"manual"}}`), out)
}

// 下游 turn metadata 顶层出现重复键时（真实 Codex 的 serde struct 不会产生；只有畸形/恶意下游会），
// gjson/sjson 只读写第一处，第二处的真实身份会原样透传。规则：顶层重复键只保留最后一次出现
// （与 encoding/json / serde_json Value 的"后者覆盖"语义一致），再做身份改写；其余键序与字节不动。
func TestRewriteCodexMachineTurnMetadata_DuplicateTopLevelKeysDeduped(t *testing.T) {
	ids := newTestMachineIDs(t, 5304, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	first := testCodexMachineV7
	last := testCodexMachineV4
	pseudoLast := codexMachinePseudonym(ids.pseudonymKey, last)

	t.Run("duplicate_identity_key_keeps_last_and_pseudonymizes", func(t *testing.T) {
		raw := `{"session_id":"` + first + `","turn_id":"turn-1","thread_id":"` + first + `","sandbox":"seccomp","thread_id":"` + last + `","compaction":{"trigger":"manual","thread_id":"` + first + `"}}`
		out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
		require.True(t, changed)
		want := `{"session_id":"` + codexMachinePseudonym(ids.pseudonymKey, first) + `","turn_id":"turn-1","sandbox":"seatbelt","thread_id":"` + pseudoLast + `","compaction":{"trigger":"manual","thread_id":"` + first + `"}}`
		assert.Equal(t, want, out, "只保留最后一个 thread_id 并假名化；其余键序不动；嵌套对象字节不动（嵌套 thread_id 本就不在 §4.3 改写范围）")
		assert.Equal(t, 1, strings.Count(out, `"thread_id":"`+pseudoLast+`"`))
		assert.NotContains(t, out, `"thread_id":"`+last+`"`, "顶层真实 thread_id 不得透传")
		assert.Equal(t, pseudoLast, gjson.Get(out, "thread_id").String())
	})

	t.Run("duplicate_non_identity_key_also_deduped", func(t *testing.T) {
		raw := `{"turn_id":"turn-1","session_id":"` + last + `","turn_id":"turn-2"}`
		out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
		require.True(t, changed)
		assert.Equal(t, `{"session_id":"`+pseudoLast+`","turn_id":"turn-2"}`, out)
	})

	t.Run("duplicate_without_identity_fields_still_deduped", func(t *testing.T) {
		out, changed := rewriteCodexMachineTurnMetadata(`{"turn_id":"a","turn_id":"b"}`, ids)
		require.True(t, changed)
		assert.Equal(t, `{"turn_id":"b"}`, out)
	})

	t.Run("no_duplicates_bytes_untouched", func(t *testing.T) {
		raw := `{"turn_id":"t", "sandbox_mode":"workspace-write"}`
		out, changed := rewriteCodexMachineTurnMetadata(raw, ids)
		assert.False(t, changed)
		assert.Equal(t, raw, out, "无重复、无身份字段时连空白都不动")
	})
}

func TestApplyCodexMachineHeaders_RewritesOnlyPresentIdentityHeaders(t *testing.T) {
	ids := newTestMachineIDs(t, 5401, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	key := ids.pseudonymKey
	root := testCodexMachineV7
	child := testCodexMachineV4

	h := http.Header{}
	h.Set("session-id", root)
	h.Set("thread-id", child)
	h.Set("x-client-request-id", root)
	h.Set("x-codex-parent-thread-id", root)
	h.Set("x-codex-window-id", child+":1")
	h.Set("x-openai-subagent", "explore")
	h.Set("x-codex-turn-state", "opaque-turn-state")
	h.Set("x-codex-beta-features", "remote_compaction_v2")
	h.Set("session_id", "isolated-session")
	h.Set("conversation_id", "isolated-conversation")
	// 顶层 installation 头仅 compact 携带（client.rs:613-614）；存在则改写
	h.Set("x-codex-installation-id", "real")
	h.Set("x-codex-turn-metadata", `{"installation_id":"real","session_id":"`+root+`","thread_id":"`+child+`","window_id":"`+child+`:1","sandbox":"seccomp","turn_id":"turn-x"}`)

	// 通过总入口委派（ids.mode == machine）
	applyCodexFingerprintHeaders(h, ids)

	assert.Equal(t, ids.installationID, h.Get("x-codex-installation-id"))
	assert.Equal(t, codexMachinePseudonym(key, root), h.Get("session-id"))
	assert.Equal(t, codexMachinePseudonym(key, child), h.Get("thread-id"))
	assert.Equal(t, codexMachinePseudonym(key, root), h.Get("x-client-request-id"))
	assert.Equal(t, codexMachinePseudonym(key, root), h.Get("x-codex-parent-thread-id"))
	assert.Equal(t, codexMachinePseudonym(key, child)+":1", h.Get("x-codex-window-id"))
	assert.Equal(t, "explore", h.Get("x-openai-subagent"))
	assert.Equal(t, "opaque-turn-state", h.Get("x-codex-turn-state"))
	assert.Equal(t, "remote_compaction_v2", h.Get("x-codex-beta-features"))
	// I5：下划线头删除
	assert.Empty(t, h.Get("session_id"))
	assert.Empty(t, h.Get("conversation_id"))
	_, hasSessionUnderscore := h["Session_id"]
	assert.False(t, hasSessionUnderscore)
	// I4：头内 turn metadata 与头同值
	tm := h.Get("x-codex-turn-metadata")
	assert.Equal(t, ids.installationID, gjson.Get(tm, "installation_id").String())
	assert.Equal(t, h.Get("session-id"), gjson.Get(tm, "session_id").String())
	assert.Equal(t, h.Get("thread-id"), gjson.Get(tm, "thread_id").String())
	assert.Equal(t, h.Get("x-codex-window-id"), gjson.Get(tm, "window_id").String())
	assert.Equal(t, "seatbelt", gjson.Get(tm, "sandbox").String())
	assert.Equal(t, "turn-x", gjson.Get(tm, "turn_id").String())
}

func TestApplyCodexMachineHeaders_DoesNotAddMissingHeaders(t *testing.T) {
	ids := newTestMachineIDs(t, 5402, testCodexFingerprintSeed)
	h := http.Header{}
	h.Set("session_id", "isolated-only")
	h.Set("conversation_id", "isolated-only")
	applyCodexMachineHeaders(h, ids)
	// 真实 Codex 常规请求不发顶层 installation 头（client.rs:1197-1211 / :1121-1130），只改不增
	for _, name := range []string{"x-codex-installation-id", "session-id", "thread-id", "x-client-request-id", "x-codex-parent-thread-id", "x-codex-window-id", "x-codex-turn-metadata"} {
		_, present := h[http.CanonicalHeaderKey(name)]
		assert.False(t, present, "不得补 %s", name)
	}
	// 无 Codex 会话身份（第三方 Agent 形态）：保留下划线 session_id，conversation_id 一律删除
	assert.Equal(t, "isolated-only", h.Get("session_id"))
	_, hasConversation := h[http.CanonicalHeaderKey("conversation_id")]
	assert.False(t, hasConversation)
	// nil 安全
	applyCodexMachineHeaders(nil, ids)
	applyCodexMachineHeaders(h, nil)
}

// 下划线 session_id 的去留只取决于下游是否携带 Codex 会话身份（session-id / thread-id 任一）。
func TestApplyCodexMachineHeaders_UnderscoreSessionDroppedOnlyWithCodexSessionIdentity(t *testing.T) {
	ids := newTestMachineIDs(t, 5404, testCodexFingerprintSeed)
	cases := []struct {
		name        string
		set         map[string]string
		wantDropped bool
	}{
		{"session-id_only", map[string]string{"session-id": testCodexMachineV7}, true},
		{"thread-id_only", map[string]string{"thread-id": testCodexMachineV7}, true},
		{"x-client-request-id_only", map[string]string{"x-client-request-id": testCodexMachineV7}, false},
		{"none", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("session_id", "isolated-only")
			h.Set("conversation_id", "isolated-only")
			for k, v := range tc.set {
				h.Set(k, v)
			}
			applyCodexMachineHeaders(h, ids)
			_, hasSession := h[http.CanonicalHeaderKey("session_id")]
			assert.Equal(t, !tc.wantDropped, hasSession)
			_, hasConversation := h[http.CanonicalHeaderKey("conversation_id")]
			assert.False(t, hasConversation, "conversation_id 一律删除")
			for k := range tc.set {
				assert.NotEqual(t, testCodexMachineV7, h.Get(k), "存在的会话头按 P 改写")
				assert.NotEmpty(t, h.Get(k))
			}
		})
	}
}

// I7 辅助：同一输入在 session 模式下头 sink 仍设置 session_id（现有分支不受影响）。
func TestApplyCodexFingerprintHeaders_SessionModeStillSetsUnderscoreSessionID(t *testing.T) {
	account := newTestOAuthAccount(5403, map[string]any{codexFingerprintModeExtraKey: "session"})
	ids := resolveCodexFingerprintIDs(account, testCodexMachineV7, codexFingerprintSession)
	require.NotNil(t, ids)
	h := http.Header{}
	h.Set("session-id", testCodexMachineV7)
	h.Set("session_id", "isolated")
	applyCodexFingerprintHeaders(h, ids)
	assert.Equal(t, ids.sessionID, h.Get("session_id"))
	assert.Equal(t, ids.sessionID, h.Get("session-id"))
}

func TestApplyCodexMachineClientMetadata_MapCore(t *testing.T) {
	ids := newTestMachineIDs(t, 5501, testCodexFingerprintSeed)
	ids.sandboxTag = "seccomp"
	key := ids.pseudonymKey
	root := testCodexMachineV7
	child := testCodexMachineV4
	existing := map[string]any{
		"x-codex-installation-id":  "real-install",
		"session_id":               root,
		"thread_id":                child,
		"x-codex-parent-thread-id": root,
		"x-codex-window-id":        child + ":0",
		"turn_id":                  "turn-a",
		"parent_turn_id":           "turn-p",
		"root_turn_id":             "turn-r",
		"x-openai-subagent":        "explore",
		"request_kind":             "chat",
		"x-codex-turn-metadata":    `{"installation_id":"real","session_id":"` + root + `","thread_id":"` + child + `","window_id":"` + child + `:0","sandbox":"seatbelt"}`,
	}
	require.True(t, applyCodexFingerprintToClientMetadataMap(existing, ids), "总入口委派 machine 分支")
	assert.Equal(t, ids.installationID, existing["x-codex-installation-id"])
	assert.Equal(t, codexMachinePseudonym(key, root), existing["session_id"])
	assert.Equal(t, codexMachinePseudonym(key, child), existing["thread_id"])
	assert.Equal(t, codexMachinePseudonym(key, root), existing["x-codex-parent-thread-id"])
	assert.Equal(t, codexMachinePseudonym(key, child)+":0", existing["x-codex-window-id"])
	assert.Equal(t, "turn-a", existing["turn_id"])
	assert.Equal(t, "turn-p", existing["parent_turn_id"])
	assert.Equal(t, "turn-r", existing["root_turn_id"])
	assert.Equal(t, "explore", existing["x-openai-subagent"])
	assert.Equal(t, "chat", existing["request_kind"])
	embedded, _ := existing["x-codex-turn-metadata"].(string)
	assert.Equal(t, existing["session_id"], gjson.Get(embedded, "session_id").String())
	assert.Equal(t, existing["thread_id"], gjson.Get(embedded, "thread_id").String())
	assert.Equal(t, existing["x-codex-window-id"], gjson.Get(embedded, "window_id").String())
	assert.Equal(t, "seccomp", gjson.Get(embedded, "sandbox").String())

	// 只改不增：仅 turn_id 的对象不补任何键（含 installation），返回未改写
	sparse := map[string]any{"turn_id": "t"}
	require.False(t, applyCodexMachineClientMetadata(sparse, ids))
	assert.Equal(t, map[string]any{"turn_id": "t"}, sparse)
	assert.NotContains(t, sparse, "session_id")
	assert.NotContains(t, sparse, "x-codex-window-id")
	assert.False(t, applyCodexMachineClientMetadata(nil, ids))
	assert.False(t, applyCodexMachineClientMetadata(sparse, nil))
}

func TestApplyCodexFingerprintClientMetadata_Machine_DoesNotCreateObjectAndRewritesPromptCacheKey(t *testing.T) {
	ids := newTestMachineIDs(t, 5502, testCodexFingerprintSeed)
	key := ids.pseudonymKey
	// 无 client_metadata：不创建对象，只改 prompt_cache_key
	body := map[string]any{"model": "gpt-5.2", "prompt_cache_key": testCodexMachineV7}
	require.True(t, applyCodexFingerprintClientMetadata(body, ids))
	assert.NotContains(t, body, "client_metadata", "machine 不创建 client_metadata")
	assert.Equal(t, codexMachinePseudonym(key, testCodexMachineV7), body["prompt_cache_key"])

	// pck 任意非空字符串都改写（不要求等于 body session_id）
	body2 := map[string]any{"prompt_cache_key": "opencode-key", "client_metadata": map[string]any{"session_id": "other"}}
	require.True(t, applyCodexFingerprintClientMetadata(body2, ids))
	assert.Equal(t, codexMachinePseudonym(key, "opencode-key"), body2["prompt_cache_key"])
	cm := body2["client_metadata"].(map[string]any)
	assert.Equal(t, codexMachinePseudonym(key, "other"), cm["session_id"])
	// 只改不增：client_metadata 没带 installation 键时不补
	assert.NotContains(t, cm, "x-codex-installation-id")

	// 空 pck / 非字符串 pck 不动，且无 client_metadata ⇒ 无改动
	body3 := map[string]any{"prompt_cache_key": "", "model": "gpt-5.2"}
	assert.False(t, applyCodexFingerprintClientMetadata(body3, ids))
	assert.NotContains(t, body3, "client_metadata")
	body4 := map[string]any{"prompt_cache_key": 42}
	assert.False(t, applyCodexFingerprintClientMetadata(body4, ids))
	assert.Equal(t, 42, body4["prompt_cache_key"])
	// client_metadata 是非对象值：只改不增，不替换
	body5 := map[string]any{"client_metadata": "weird"}
	assert.False(t, applyCodexFingerprintClientMetadata(body5, ids))
	assert.Equal(t, "weird", body5["client_metadata"])
}

// map 版与 raw 版对同一输入输出字节级等价（machine）。
func TestApplyCodexFingerprintClientMetadataRaw_Machine_MatchesMapVariant(t *testing.T) {
	ids := newTestMachineIDs(t, 5503, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	root := testCodexMachineV7
	child := testCodexMachineV4
	inputs := []string{
		`{"model":"gpt-5.2","prompt_cache_key":"` + root + `","client_metadata":{"x-codex-installation-id":"real","session_id":"` + root + `","thread_id":"` + child + `","x-codex-parent-thread-id":"` + root + `","x-codex-window-id":"` + child + `:3","turn_id":"turn-1","x-openai-subagent":"explore","x-codex-turn-metadata":"{\"installation_id\":\"real\",\"session_id\":\"` + root + `\",\"thread_id\":\"` + child + `\",\"window_id\":\"` + child + `:3\",\"sandbox\":\"seccomp\",\"turn_id\":\"turn-1\"}"},"input":[{"type":"input_text","text":"hi"}]}`,
		`{"model":"gpt-5.2","prompt_cache_key":"plain-key","input":[]}`,
		`{"model":"gpt-5.2","client_metadata":{"turn_id":"t"},"input":[]}`,
		`{"model":"gpt-5.2","input":[]}`,
		`{"model":"gpt-5.2","prompt_cache_key":"","client_metadata":"weird"}`,
	}
	for _, in := range inputs {
		mapIDs := *ids
		rawIDs := *ids
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(in), &decoded))
		mapChanged := applyCodexFingerprintClientMetadata(decoded, &mapIDs)
		mapOut, err := json.Marshal(decoded)
		require.NoError(t, err)

		rawOut, rawChanged, err := applyCodexFingerprintClientMetadataRaw([]byte(in), &rawIDs)
		require.NoError(t, err)
		assert.Equal(t, mapChanged, rawChanged, "changed 标志一致: %s", in)

		var mapNorm, rawNorm map[string]any
		require.NoError(t, json.Unmarshal(mapOut, &mapNorm))
		require.NoError(t, json.Unmarshal(rawOut, &rawNorm))
		assert.Equal(t, mapNorm, rawNorm, "map/raw 语义等价: %s", in)
		if !rawChanged {
			assert.Equal(t, []byte(in), rawOut, "未改动时 raw 字节原样")
		}
	}

	// 具体断言 raw 输出：不创建 client_metadata、pck 假名化、其余字节保留
	out, changed, err := applyCodexFingerprintClientMetadataRaw([]byte(`{"model":"gpt-5.2","prompt_cache_key":"plain-key","input":[1]}`), ids)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.False(t, gjson.GetBytes(out, "client_metadata").Exists())
	assert.Equal(t, codexMachinePseudonym(ids.pseudonymKey, "plain-key"), gjson.GetBytes(out, "prompt_cache_key").String())
	assert.Equal(t, "gpt-5.2", gjson.GetBytes(out, "model").String())
	assert.Equal(t, int64(1), gjson.GetBytes(out, "input.0").Int())
}

// I1 + I4（单元层）：根窗口 session == thread == pck == client_request_id，且三个 sink 逐键相等。
func TestCodexMachine_I1_I4_RootWindowSinksAgree(t *testing.T) {
	ids := newTestMachineIDs(t, 5601, testCodexFingerprintSeed)
	ids.sandboxTag = "seatbelt"
	root := testCodexMachineV7
	tm := `{"installation_id":"real","session_id":"` + root + `","thread_id":"` + root + `","window_id":"` + root + `:0","sandbox":"seccomp","turn_id":"turn-1"}`

	h := http.Header{}
	h.Set("session-id", root)
	h.Set("thread-id", root)
	h.Set("x-client-request-id", root)
	h.Set("x-codex-window-id", root+":0")
	h.Set("x-codex-turn-metadata", tm)
	applyCodexFingerprintHeaders(h, ids)

	body := map[string]any{
		"prompt_cache_key": root,
		"client_metadata": map[string]any{
			"x-codex-installation-id": "real",
			"session_id":              root,
			"thread_id":               root,
			"x-codex-window-id":       root + ":0",
			"turn_id":                 "turn-1",
			"x-codex-turn-metadata":   tm,
		},
	}
	require.True(t, applyCodexFingerprintClientMetadata(body, ids))
	cm := body["client_metadata"].(map[string]any)

	p := codexMachinePseudonym(ids.pseudonymKey, root)
	// I1
	assert.Equal(t, p, h.Get("session-id"))
	assert.Equal(t, p, h.Get("thread-id"))
	assert.Equal(t, p, h.Get("x-client-request-id"))
	assert.Equal(t, p+":0", h.Get("x-codex-window-id"))
	assert.Equal(t, p, body["prompt_cache_key"])
	// I4：头 / client_metadata / 头内 turn metadata / 内嵌 turn metadata
	headTM := h.Get("x-codex-turn-metadata")
	embTM := cm["x-codex-turn-metadata"].(string)
	// 常规请求真实 Codex 不发顶层 installation 头 ⇒ 只改不增，不补；client_metadata 与两处 turn metadata 收敛为同一值
	assert.Empty(t, h.Get("x-codex-installation-id"))
	assert.Equal(t, ids.installationID, cm["x-codex-installation-id"])
	assert.Equal(t, ids.installationID, gjson.Get(headTM, "installation_id").String())
	assert.Equal(t, ids.installationID, gjson.Get(embTM, "installation_id").String())
	assert.Equal(t, h.Get("session-id"), cm["session_id"])
	assert.Equal(t, h.Get("session-id"), gjson.Get(headTM, "session_id").String())
	assert.Equal(t, h.Get("session-id"), gjson.Get(embTM, "session_id").String())
	assert.Equal(t, h.Get("thread-id"), cm["thread_id"])
	assert.Equal(t, h.Get("thread-id"), gjson.Get(headTM, "thread_id").String())
	assert.Equal(t, h.Get("thread-id"), gjson.Get(embTM, "thread_id").String())
	assert.Equal(t, h.Get("x-codex-window-id"), cm["x-codex-window-id"])
	assert.Equal(t, h.Get("x-codex-window-id"), gjson.Get(headTM, "window_id").String())
	assert.Equal(t, h.Get("x-codex-window-id"), gjson.Get(embTM, "window_id").String())
	assert.Equal(t, "seatbelt", gjson.Get(headTM, "sandbox").String())
	assert.Equal(t, "seatbelt", gjson.Get(embTM, "sandbox").String())
	assert.Equal(t, "turn-1", gjson.Get(headTM, "turn_id").String())
	assert.Equal(t, "turn-1", cm["turn_id"])
}

// I1（子 Agent）：只换 thread，parent 等于父窗口的 thread'。
func TestCodexMachine_I1_SubagentParentEqualsRootThread(t *testing.T) {
	ids := newTestMachineIDs(t, 5602, testCodexFingerprintSeed)
	root := testCodexMachineV7
	child := testCodexMachineV4

	rootHeaders := http.Header{}
	rootHeaders.Set("session-id", root)
	rootHeaders.Set("thread-id", root)
	rootHeaders.Set("x-codex-window-id", root+":0")
	applyCodexFingerprintHeaders(rootHeaders, ids)

	childHeaders := http.Header{}
	childHeaders.Set("session-id", root)
	childHeaders.Set("thread-id", child)
	childHeaders.Set("x-codex-parent-thread-id", root)
	childHeaders.Set("x-openai-subagent", "explore")
	childHeaders.Set("x-codex-window-id", child+":1")
	applyCodexFingerprintHeaders(childHeaders, ids)

	assert.Equal(t, rootHeaders.Get("session-id"), childHeaders.Get("session-id"), "同一根会话")
	assert.Equal(t, rootHeaders.Get("thread-id"), childHeaders.Get("x-codex-parent-thread-id"), "parent' == 父窗口 thread'")
	assert.NotEqual(t, rootHeaders.Get("thread-id"), childHeaders.Get("thread-id"))
	assert.Equal(t, codexMachinePseudonym(ids.pseudonymKey, child)+":1", childHeaders.Get("x-codex-window-id"))
	assert.Equal(t, "explore", childHeaders.Get("x-openai-subagent"))
}

// 幂等：同一 ids 对同一份头 / body 重复应用 sink（WS 链路 Forward + payload 两次、重试再次）结果不变，
// 已签发的假名不会被再次当作真实值二次映射。
func TestCodexMachine_SinksAreIdempotentOnSameIDs(t *testing.T) {
	ids := newTestMachineIDs(t, 5603, testCodexFingerprintSeed)
	ids.sandboxTag = "seccomp"
	root := testCodexMachineV7
	tm := `{"session_id":"` + root + `","thread_id":"` + root + `","window_id":"` + root + `:0","sandbox":"seatbelt","turn_id":"turn-1"}`

	h := http.Header{}
	h.Set("session-id", root)
	h.Set("thread-id", root)
	h.Set("x-client-request-id", root)
	h.Set("x-codex-window-id", root+":0")
	h.Set("x-codex-turn-metadata", tm)
	body := map[string]any{
		"prompt_cache_key": root,
		"client_metadata": map[string]any{
			"session_id":            root,
			"thread_id":             root,
			"x-codex-window-id":     root + ":0",
			"x-codex-turn-metadata": tm,
		},
	}

	applyCodexFingerprintHeaders(h, ids)
	require.True(t, applyCodexFingerprintClientMetadata(body, ids))
	firstHeaders := h.Clone()
	firstBody, err := json.Marshal(body)
	require.NoError(t, err)

	applyCodexFingerprintHeaders(h, ids)
	// 第二次 body 应用：所有身份键都已是假名 ⇒ 无改写，返回 false
	assert.False(t, applyCodexFingerprintClientMetadata(body, ids))
	secondBody, err := json.Marshal(body)
	require.NoError(t, err)

	assert.Equal(t, firstHeaders, h)
	assert.JSONEq(t, string(firstBody), string(secondBody))
	p := codexMachinePseudonym(ids.pseudonymKey, root)
	assert.Equal(t, p, h.Get("thread-id"))
	assert.Equal(t, p, body["prompt_cache_key"])
	assert.NotEqual(t, codexMachinePseudonym(ids.pseudonymKey, p), h.Get("thread-id"), "假名不得被二次映射")

	// 未经该 ids 签发的假名（例如另一账号）不在 memo 内，仍会被映射
	other := newTestMachineIDs(t, 5604, testCodexMachineSeedB)
	assert.NotEqual(t, p, other.machinePseudonym(p))
}
