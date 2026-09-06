package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexFingerprintIDsContextKey 是暂存在 gin context 的收敛 ID 集合键。
// 由 Forward（非透传）或 forwardOpenAIPassthrough（透传）解析后写入，请求
// 构造器读取用于出站头改写——请求体与出站头必须共享同一份 IDs，保证
// turn_id 等随机字段一致。
const codexFingerprintIDsContextKey = "codex_fingerprint_ids"

// stageCodexFingerprintIDs 将本 attempt 解析出的收敛 ID 暂存到 gin context。
// 必须无条件覆写（含 nil）：failover 从收敛账号切到 off 账号时，上一账号的
// IDs 不得残留并被误应用到新账号的出站头（typed-nil 由应用侧 nil 守卫吸收）。
func stageCodexFingerprintIDs(c *gin.Context, ids *codexFingerprintIDs) {
	if c != nil {
		c.Set(codexFingerprintIDsContextKey, ids)
	}
}

func stagedCodexFingerprintIDs(c *gin.Context, account *Account) *codexFingerprintIDs {
	if c == nil || account == nil || !account.UsesOpenAICodexProtocol() {
		return nil
	}
	value, ok := c.Get(codexFingerprintIDsContextKey)
	if !ok {
		return nil
	}
	ids, ok := value.(*codexFingerprintIDs)
	if !ok || ids == nil || ids.accountID != account.ID {
		return nil
	}
	return ids
}

// applyStagedCodexFingerprintHeaders 读取 context 暂存的收敛 ID 并改写出站头。
// 非透传与透传两个请求构造器共用本函数，防止应用语义漂移。仅解析该
// snapshot 的 OAuth 账号可读取，避免 stale context 跨账号 failover 泄漏。
func applyStagedCodexFingerprintHeaders(c *gin.Context, account *Account, h http.Header) {
	applyCodexFingerprintHeaders(h, stagedCodexFingerprintIDs(c, account))
}

func applyStagedCodexFingerprintClientMetadata(c *gin.Context, account *Account, reqBody map[string]any) bool {
	return applyCodexFingerprintClientMetadata(reqBody, stagedCodexFingerprintIDs(c, account))
}

// applyStagedCodexFingerprintClientMetadataRaw 是 raw 字节版的 staged body sink，供客户端 WS
// 入口的 response.create 帧使用（帧是原始 JSON 字节，与透传 HTTP 一样禁全量 Unmarshal）。
func applyStagedCodexFingerprintClientMetadataRaw(c *gin.Context, account *Account, body []byte) ([]byte, bool, error) {
	return applyCodexFingerprintClientMetadataRaw(body, stagedCodexFingerprintIDs(c, account))
}

// stageCodexMachineFingerprintIDsForWSIngress 在客户端 WS 入口（ProxyResponsesWebSocketFromClient）
// 建连时 resolve/stage 指纹 IDs，仅 machine 模式。
//   - 该入口不经过 Forward / forwardOpenAIPassthrough，baseline 对所有模式都不 stage：握手头 sink
//     （openai_ws_forwarder_payload.go applyStagedCodexFingerprintHeaders）读到 nil ⇒ 不改写，
//     response.create 帧的 client_metadata 也无人改写。
//   - 只接 machine：machine 的 IDs 不含 turn 级随机字段（turnID / turnStartedAtUnixMs 零值，
//     三个 sink 的 machine 分支不读），一份 snapshot 跨整条连接的多个 turn 复用，语义等价于
//     每 turn 各 resolve 一次（假名是纯函数，pseudonymIssued 仅做幂等）。session / full 每次
//     resolve 都生成新的 turn_id，按连接 stage 会让多 turn 共用同一 turn_id，与 HTTP 语义不一致；
//     改动 session / full / device 在 WS 入口的行为超出本期范围，维持 baseline（见设计 §5）。
//   - 无条件先清空：与 Forward 阶段一致，避免同一 gin context 上一次 attempt（其他账号）的残留。
func (s *OpenAIGatewayService) stageCodexMachineFingerprintIDsForWSIngress(c *gin.Context, account *Account) {
	stageCodexFingerprintIDs(c, nil)
	if c == nil || account == nil || account.GetCodexFingerprintMode() != codexFingerprintMachine {
		return
	}
	var clientHeaders http.Header
	if c.Request != nil {
		clientHeaders = c.Request.Header
	}
	fpIDs := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	// machine：按 WS 握手终态出站 UA（buildOpenAIWSHeaders 的 enforceCodexIdentityHeadersWithUA 同源）补记 sandbox 标签。
	stampCodexMachineSandboxTag(fpIDs, s.codexIdentityOverrideUA(account))
	stageCodexFingerprintIDs(c, fpIDs)
}

// stageCodexMachineFingerprintIDsForCompatBridge 在兼容桥（chat completions / messages）构造好
// Responses body 之后 resolve/stage 指纹 IDs 并应用 raw body sink，仅 machine 模式。
//   - 两座桥不经过 Forward，baseline 对所有模式都不 stage；machine 下桥的下游是非 Codex 客户端
//     （无 session-id / thread-id 头），出站必须与 Forward 非 Codex 下游同形态：body sink 只改不增
//     （桥自建 body 无 client_metadata ⇒ 只假名化 prompt_cache_key），头 sink 删除 conversation_id、
//     保留桥 post-build 的下划线 session_id（见 applyCodexMachineHeaders）。
//   - 无条件先清空：与 Forward 阶段一致，避免同一 gin context 上一次 attempt（其他账号）的残留。
func (s *OpenAIGatewayService) stageCodexMachineFingerprintIDsForCompatBridge(c *gin.Context, account *Account, body []byte) ([]byte, error) {
	stageCodexFingerprintIDs(c, nil)
	if activeCodexFingerprintMode(account) != codexFingerprintMachine {
		return body, nil
	}
	var clientHeaders http.Header
	if c != nil && c.Request != nil {
		clientHeaders = c.Request.Header
	}
	fpIDs := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	if fpIDs == nil {
		return body, nil
	}
	// machine：按桥终态出站 UA（buildUpstreamRequest 的 enforceCodexIdentityHeadersWithUA 同源）补记 sandbox 标签。
	stampCodexMachineSandboxTag(fpIDs, s.codexIdentityOverrideUA(account))
	next, _, err := applyCodexFingerprintClientMetadataRaw(body, fpIDs)
	if err != nil {
		return body, err
	}
	stageCodexFingerprintIDs(c, fpIDs)
	return next, nil
}

// codexFingerprintMode 控制 OAuth 账号出站请求的设备指纹收敛强度。
// 多人共享同一 OAuth 账号时，每个用户的 Codex 客户端会携带各自不同的
// installation_id / session_id / thread_id，上游据此判定设备数和会话数。
// 收敛模式将这些标识改写为账号级恒定值，减少上游可见的设备/会话指纹。
type codexFingerprintMode string

const (
	// codexFingerprintOff 不做任何收敛，原样透传客户端标识。
	codexFingerprintOff codexFingerprintMode = "off"
	// codexFingerprintDevice 仅收敛 installation_id 为账号级恒定值。
	// 上游看到 1 台设备 + 多会话（每用户各自的 session）。
	codexFingerprintDevice codexFingerprintMode = "device"
	// codexFingerprintSession 收敛 installation_id + session_id，
	// thread_id 按客户端原始 session-id 确定性派生（每个真实 Codex 会话一个独立线程）。
	// 上游看到 1 台设备 + 1 会话 + N 线程，最接近正常用户 spawn 子代理的模式。
	codexFingerprintSession codexFingerprintMode = "session"
	// codexFingerprintFull 收敛所有标识：installation_id + session_id + thread_id。
	// 上游看到 1 台设备 + 1 会话 + 1 线程，最激进。
	codexFingerprintFull codexFingerprintMode = "full"
	// codexFingerprintMachine "单机多窗口"：installation_id 收敛为账号级恒定值，
	// session/thread/window/prompt_cache_key 等会话标识按账号 seed 做 1:1 保版本假名化
	// （每个下游窗口仍是一个独立会话，只是换了名字），sandbox 与账号 OS 对齐，
	// 并删除真实 Codex 不再发送的 session_id / conversation_id 下划线头。
	// 上游看到 1 台设备 + N 个彼此自洽的窗口，最接近"一台机器上开多个 Codex 窗口"。
	codexFingerprintMachine codexFingerprintMode = "machine"
)

const (
	codexFingerprintModeExtraKey = "codex_fingerprint_mode"
	codexFingerprintSeedExtraKey = "codex_fingerprint_seed"
)

func canonicalCodexFingerprintSeed(value any) (string, bool) {
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil || trimmed != parsed.String() {
		return "", false
	}
	return trimmed, true
}

func newCodexFingerprintSeed() string {
	return uuid.NewString()
}

func stripCodexFingerprintSeed(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	stripped := maps.Clone(extra)
	delete(stripped, codexFingerprintSeedExtraKey)
	return stripped
}

// codexFingerprintModeFromExtra 只认 extra 里显式写入的模式（未设置/非法 ⇒ off）。
// 供 seed 管理辅助函数使用：是否铸造/保留 seed 以显式 opt-in 为准；
// 运行时生效模式见 GetCodexFingerprintMode（本基线缺省 machine）。
func codexFingerprintModeFromExtra(extra map[string]any) codexFingerprintMode {
	if extra == nil {
		return codexFingerprintOff
	}
	raw, _ := extra[codexFingerprintModeExtraKey].(string)
	switch codexFingerprintMode(strings.TrimSpace(raw)) {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
		return codexFingerprintMode(strings.TrimSpace(raw))
	default:
		return codexFingerprintOff
	}
}

func codexFingerprintModeRequiresSeed(mode codexFingerprintMode) bool {
	switch mode {
	case codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
		return true
	default:
		return false
	}
}

func codexFingerprintSeed(extra map[string]any) (string, bool) {
	if extra == nil {
		return "", false
	}
	return canonicalCodexFingerprintSeed(extra[codexFingerprintSeedExtraKey])
}

func prepareCodexFingerprintExtraForCreate(platform, accountType string, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if platform != PlatformOpenAI ||
		(accountType != AccountTypeOAuth && accountType != AccountTypeSetupToken) ||
		!codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(prepared)) {
		return prepared
	}
	if prepared == nil {
		prepared = make(map[string]any, 1)
	}
	prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	return prepared
}

func prepareCodexFingerprintExtraForUpdate(account *Account, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if account == nil || !account.IsOpenAIOAuthLike() {
		return prepared
	}
	if seed, ok := codexFingerprintSeed(account.Extra); ok {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = seed
		return prepared
	}
	if codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(prepared)) {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	}
	return prepared
}

func sanitizedCodexFingerprintExtraUpdates(updates map[string]any) map[string]any {
	if updates == nil {
		return nil
	}
	sanitized := maps.Clone(updates)
	delete(sanitized, codexFingerprintSeedExtraKey)
	return sanitized
}

// ShouldEnsureCodexFingerprintSeedForExtraUpdates reports whether a JSONB key-level
// extra update is enabling Codex fingerprint convergence and therefore must atomically
// preserve or create the system-managed per-account seed in the repository update.
func ShouldEnsureCodexFingerprintSeedForExtraUpdates(updates map[string]any) bool {
	if updates == nil {
		return false
	}
	return codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(updates))
}

// GetCodexFingerprintMode 从账号 extra JSON 读取指纹收敛模式。
// 未设置或非法时默认 machine（单机多窗口）；显式 off/device/session/full 仍保留。
func (a *Account) GetCodexFingerprintMode() codexFingerprintMode {
	if a == nil || !a.IsOpenAIOAuthLike() {
		return codexFingerprintOff
	}
	raw := strings.TrimSpace(a.GetExtraString(codexFingerprintModeExtraKey))
	switch codexFingerprintMode(raw) {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
		return codexFingerprintMode(raw)
	default:
		if a.Type == AccountTypeSetupToken {
			return codexFingerprintOff
		}
		return codexFingerprintMachine
	}
}

// activeCodexFingerprintMode 返回账号“有效”指纹模式：显式 off 或缺少系统管理
// seed 时等价 off（需求 #5：无 seed ⇒ 不改写，宁可指纹收敛降级也不伪造随机设备）。
// seed 化收敛（v2 派生）与 machine 假名都以 seed 为根，seed 缺失即身份根缺失。
func activeCodexFingerprintMode(account *Account) codexFingerprintMode {
	if account == nil || account.GetCodexFingerprintMode() == codexFingerprintOff {
		return codexFingerprintOff
	}
	if _, ok := codexFingerprintSeed(account.Extra); !ok {
		return codexFingerprintOff
	}
	return account.GetCodexFingerprintMode()
}

// NormalizeOpenAICodexFingerprintExtraForCreate makes the default explicit at
// every account persistence boundary. Persisting the default prevents alternate
// import paths from requiring a manual update.
// machine 移植扩展：模式需要 seed 时同时在创建边界铸造系统管理的账号级 seed
// （上游等价物是 service 层 prepareCodexFingerprintExtraForCreate；本基线在 repo
// 层兜底，覆盖 CRS 同步等绕过 service 层的创建路径）。
func NormalizeOpenAICodexFingerprintExtraForCreate(account *Account) {
	if account == nil || !account.IsOpenAIOAuth() {
		return
	}
	if account.Extra == nil {
		account.Extra = make(map[string]any, 1)
	}
	raw, ok := account.Extra[codexFingerprintModeExtraKey].(string)
	switch codexFingerprintMode(strings.TrimSpace(raw)) {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
		if ok && strings.TrimSpace(raw) != "" {
			// 显式模式已写入；seed 仍按需铸造（调用方可能绕过 service 层 prepare）。
			ensureCodexFingerprintSeedForCreate(account)
			return
		}
	}
	account.Extra[codexFingerprintModeExtraKey] = string(codexFingerprintMachine)
	ensureCodexFingerprintSeedForCreate(account)
}

// ensureCodexFingerprintSeedForCreate 在创建边界为需要 seed 的模式铸造系统 seed；
// 已有合法 seed（service 层 prepare 已铸造）时保留，用户带入的非法值被覆盖。
func ensureCodexFingerprintSeedForCreate(account *Account) {
	if !codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(account.Extra)) {
		return
	}
	if _, ok := codexFingerprintSeed(account.Extra); ok {
		return
	}
	account.Extra[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
}

// normalizeOpenAICodexFingerprintExtraForUpdate keeps an existing explicit
// mode when an edit payload omits the default field. This is important for
// bulk/import callers that submit a partial extra object.
func normalizeOpenAICodexFingerprintExtraForUpdate(
	account *Account,
	extra map[string]any,
	previousWasOpenAIOAuth bool,
	previousMode codexFingerprintMode,
) map[string]any {
	if account == nil || !account.IsOpenAIOAuth() {
		return extra
	}
	if extra == nil {
		extra = make(map[string]any, 1)
	}
	if _, ok := extra[codexFingerprintModeExtraKey]; ok {
		raw, isString := extra[codexFingerprintModeExtraKey].(string)
		switch codexFingerprintMode(strings.TrimSpace(raw)) {
		case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
			if isString && strings.TrimSpace(raw) != "" {
				return extra
			}
		}
		extra[codexFingerprintModeExtraKey] = string(codexFingerprintMachine)
		return extra
	}

	mode := codexFingerprintMachine
	if previousWasOpenAIOAuth {
		switch previousMode {
		case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull, codexFingerprintMachine:
			mode = previousMode
		}
	}
	extra[codexFingerprintModeExtraKey] = string(mode)
	return extra
}

// deriveStableUUIDv4 从种子确定性派生一个 UUIDv4 格式的字符串。
// 同一种子永远返回同一值。
func deriveStableUUIDv4(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// resolveConvergedInstallationID 返回账号级恒定的 installation_id。
// 优先使用管理员配置的真实 device_id，无则从系统管理的账号随机种子确定性派生。
func resolveConvergedInstallationID(account *Account, seed string) string {
	if account == nil {
		return ""
	}
	if deviceID := account.GetOpenAIDeviceID(); deviceID != "" {
		return deviceID
	}
	if seed == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-install-id:v2:" + seed)
}

// resolveConvergedSessionID 返回账号级恒定的 session_id。
func resolveConvergedSessionID(seed string) string {
	if seed == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-session-id:v2:" + seed)
}

// resolveConvergedThreadID 按客户端原始 session-id 确定性派生 thread_id。
// 每个真实 Codex 会话（不同客户端启动实例）获得一个独立线程，
// 模拟正常用户 spawn 子代理或开多窗口的模式。
func resolveConvergedThreadID(seed, clientSessionID string) string {
	if seed == "" || clientSessionID == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-thread-id:v2:" + seed + ":" + clientSessionID)
}

// codexFingerprintIDs 收敛后的完整 ID 集合。
// 由 resolveCodexFingerprintIDs 一次性生成，同一个实例在头改写和体改写之间共享，
// 确保所有载体中的 turn_id 等随机字段一致。体改写时还会补记原始
// client_metadata.session_id，用于识别 root prompt_cache_key 的默认值。
type codexFingerprintIDs struct {
	accountID                     int64
	mode                          codexFingerprintMode
	installationID                string
	sessionID                     string
	threadID                      string
	turnID                        string
	windowID                      string
	turnStartedAtUnixMs           int64
	originalBodySessionID         string
	originalBodySessionIDCaptured bool
	// pseudonymKey 仅 machine 模式使用：假名函数 P 的 HMAC 密钥（= 账号 seed 的字节）。
	pseudonymKey []byte
	// pseudonymIssued 仅 machine 模式使用：本请求内已签发的假名集合，使 sink 对同一
	// ids 重复应用幂等（WS 链路对共享 body map 会应用两次：openai_gateway_forward.go
	// 的 body sink 与 openai_ws_forwarder_v2.go 的 payload sink），见 machinePseudonym。
	pseudonymIssued map[string]struct{}
	// sandboxTag 仅 machine 模式使用：账号 OS 对应的平台沙箱标签（seatbelt /
	// seccomp / windows_sandbox），空串表示不改写 turn metadata 的 sandbox 字段。
	sandboxTag string
}

// resolveCodexFingerprintIDs 按收敛模式计算出站 ID 集合。
// clientSessionID 是客户端原始的 session-id 头值（连字符形式），用于 session 模式下
// 的 thread_id 派生——每个真实 Codex 会话得到一个独立线程。
// 返回 nil 表示 off 模式或无合法 seed（等价 off，不需要改写）。
// 注意：包含随机生成的 turn_id，调用方必须只调用一次并共享结果给头改写和体改写。
func resolveCodexFingerprintIDs(account *Account, clientSessionID string, mode codexFingerprintMode) *codexFingerprintIDs {
	if account == nil || mode == codexFingerprintOff {
		return nil
	}
	seed, ok := codexFingerprintSeed(account.Extra)
	if !ok {
		return nil
	}

	ids := &codexFingerprintIDs{
		accountID:           account.ID,
		mode:                mode,
		turnStartedAtUnixMs: time.Now().UnixMilli(),
	}

	ids.installationID = resolveConvergedInstallationID(account, seed)
	if ids.installationID == "" {
		return nil
	}

	switch mode {
	case codexFingerprintDevice:
		return ids

	case codexFingerprintSession:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = resolveConvergedThreadID(seed, clientSessionID)
		if ids.threadID == "" {
			ids.threadID = ids.sessionID
		}
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids

	case codexFingerprintFull:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = ids.sessionID
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids

	case codexFingerprintMachine:
		// machine 不生成 turn 级字段（sessionID / threadID / turnID / windowID /
		// turnStartedAtUnixMs 保持零值，三个 sink 的 machine 分支也不读它们），
		// 只携带假名密钥；sandboxTag 由各调用链在 resolve 后按出站 UA 补记
		// （stampCodexMachineSandboxTag）。
		return &codexFingerprintIDs{
			accountID:      account.ID,
			mode:           mode,
			installationID: ids.installationID,
			pseudonymKey:   []byte(seed),
		}
	}

	return nil
}

// extractClientSessionID 从请求头中提取客户端原始的会话标识。
// 优先取 session-id（连字符形式，Codex CLI 标准），回退到 session_id（下划线形式）。
// 返回的值尚未被 isolateOpenAISessionID 改写，是客户端的真实标识。
func extractClientSessionID(h http.Header) string {
	if v := strings.TrimSpace(h.Get("session-id")); v != "" {
		return v
	}
	return strings.TrimSpace(h.Get("session_id"))
}

// resolveCodexFingerprintIDsFromRequest 从客户端原始请求头中提取 session-id，
// 结合账号配置一次性解析收敛 ID 集合。调用方应将返回的 ids 同时传给
// applyCodexFingerprintHeaders 和 applyCodexFingerprintClientMetadata。
func resolveCodexFingerprintIDsFromRequest(account *Account, clientHeaders http.Header) *codexFingerprintIDs {
	if account == nil {
		return nil
	}
	mode := account.GetCodexFingerprintMode()
	if mode == codexFingerprintOff {
		return nil
	}
	clientSessionID := ""
	if clientHeaders != nil {
		clientSessionID = extractClientSessionID(clientHeaders)
	}
	return resolveCodexFingerprintIDs(account, clientSessionID, mode)
}

// applyCodexFingerprintHeaders 按预计算的收敛 ID 改写出站 HTTP 头中的设备指纹。
// 在 buildUpstreamRequest 的白名单透传之后、enforceCodexIdentityHeaders 之前调用。
func applyCodexFingerprintHeaders(h http.Header, ids *codexFingerprintIDs) {
	if h == nil || ids == nil {
		return
	}

	// machine 模式：只改不增的假名化 + 删除下划线会话头，独立实现（openai_codex_machine_identity.go）。
	if ids.mode == codexFingerprintMachine {
		applyCodexMachineHeaders(h, ids)
		return
	}

	// 所有非 off 模式都收敛 installation_id
	h.Set("x-codex-installation-id", ids.installationID)

	if ids.mode == codexFingerprintDevice {
		rewriteCodexTurnMetadataFields(h, map[string]any{
			"installation_id": ids.installationID,
		})
		return
	}

	// session / full 模式：改写所有相关头
	h.Set("x-codex-window-id", ids.windowID)
	h.Set("x-client-request-id", ids.threadID)
	// 连字符形式和下划线形式都改写，保证一致
	h.Set("session-id", ids.sessionID)
	h.Set("session_id", ids.sessionID)
	h.Set("thread-id", ids.threadID)

	rewriteCodexTurnMetadataFields(h, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
}

// rewriteCodexTurnMetadataFields 解析 x-codex-turn-metadata 头中的 JSON，
// 替换指定字段后回写。合法对象保留未指定字段（如 sandbox、thread_source）；
// 非法/非对象值重建为最小合法 metadata，避免 flat 与 embedded identity 分裂。
func rewriteCodexTurnMetadataFields(h http.Header, fields map[string]any) {
	raw := strings.TrimSpace(h.Get("x-codex-turn-metadata"))
	if raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	h.Set("x-codex-turn-metadata", string(rebuilt))
}

// applyCodexFingerprintClientMetadata 按预计算的收敛 ID 改写请求体中的 client_metadata。
// 使用与头改写相同的 ids 实例，确保 turn_id 等随机字段一致。
func applyCodexFingerprintClientMetadata(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil || ids == nil {
		return false
	}

	captureCodexFingerprintOriginalBodySessionID(ids, reqBody["client_metadata"])
	existing, _ := reqBody["client_metadata"].(map[string]any)
	// machine 只改不增：下游没有 client_metadata 对象时不创建（真实 Codex 没有
	// client_metadata 的请求也没有该键；第三方 Agent 直连 Codex 后端也不带该键），
	// 仅继续处理顶层 prompt_cache_key。
	skipClientMetadata := ids.mode == codexFingerprintMachine && existing == nil
	if existing == nil {
		existing = make(map[string]any)
	}

	modified := false
	if !skipClientMetadata && applyCodexFingerprintToClientMetadataMap(existing, ids) {
		reqBody["client_metadata"] = existing
		modified = true
	}
	if applyCodexFingerprintPromptCacheKey(reqBody, ids) {
		modified = true
	}
	return modified
}

// applyCodexFingerprintToClientMetadataMap 是 client_metadata 改写的共享核心，
// map 版（非透传，body 已解码）与 raw 字节版（透传热路径）都经由它，保证两条
// 路径的收敛语义永不漂移。
func applyCodexFingerprintToClientMetadataMap(existing map[string]any, ids *codexFingerprintIDs) bool {
	if existing == nil || ids == nil {
		return false
	}

	// machine 模式：只改不增的假名化，独立实现（openai_codex_machine_identity.go）。
	if ids.mode == codexFingerprintMachine {
		return applyCodexMachineClientMetadata(existing, ids)
	}

	modified := false

	if ids.installationID != "" {
		existing["x-codex-installation-id"] = ids.installationID
		modified = true
	}

	if ids.mode == codexFingerprintDevice {
		rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
			"installation_id": ids.installationID,
		})
		return modified
	}

	// session / full 模式
	existing["session_id"] = ids.sessionID
	existing["thread_id"] = ids.threadID
	existing["turn_id"] = ids.turnID
	existing["x-codex-window-id"] = ids.windowID

	rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
	return true
}

func captureCodexFingerprintOriginalBodySessionID(ids *codexFingerprintIDs, clientMetadata any) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if clientMetadata == nil {
		return
	}
	switch metadata := clientMetadata.(type) {
	case map[string]any:
		if sessionID, ok := metadata["session_id"].(string); ok {
			ids.originalBodySessionID = strings.TrimSpace(sessionID)
		}
	case map[string]string:
		ids.originalBodySessionID = strings.TrimSpace(metadata["session_id"])
	}
}

func captureCodexFingerprintOriginalBodySessionIDRaw(ids *codexFingerprintIDs, value gjson.Result) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if value.Exists() && value.Type == gjson.String {
		ids.originalBodySessionID = strings.TrimSpace(value.String())
	}
}

func shouldRewriteCodexFingerprintPromptCacheKey(ids *codexFingerprintIDs, promptCacheKey string) bool {
	if ids == nil || !ids.originalBodySessionIDCaptured || ids.originalBodySessionID == "" || ids.sessionID == "" {
		return false
	}
	if ids.mode != codexFingerprintSession && ids.mode != codexFingerprintFull {
		return false
	}
	return promptCacheKey == ids.originalBodySessionID
}

func applyCodexFingerprintPromptCacheKey(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil {
		return false
	}
	promptCacheKey, ok := reqBody["prompt_cache_key"].(string)
	if !ok || strings.TrimSpace(promptCacheKey) == "" {
		return false
	}
	// machine：非空字符串一律 1:1 假名化（不要求等于 body session_id；根会话
	// pck == session_id ⇒ pck' == session'，见设计 I1）。唯一调用方
	// applyCodexFingerprintClientMetadata 已保证 ids 非 nil。
	if ids.mode == codexFingerprintMachine {
		rewritten := ids.machinePseudonym(promptCacheKey)
		if rewritten == promptCacheKey {
			return false
		}
		reqBody["prompt_cache_key"] = rewritten
		return true
	}
	if !shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey) {
		return false
	}
	if promptCacheKey == ids.sessionID {
		return false
	}
	reqBody["prompt_cache_key"] = ids.sessionID
	return true
}

// applyCodexFingerprintClientMetadataRaw 在原始 JSON 字节上改写 client_metadata，
// 供透传路径使用——透传是热路径，禁止对可能高达数十 MB 的 body 做全量
// Unmarshal（见 forwardOpenAIPassthrough 的轻量提取注释）。实现为：gjson 提取
// client_metadata 小对象单独解码，经共享核心改写后 sjson 一次性拼回，body
// 其余字节原样保留；root prompt_cache_key 仅在可证明是 body session 默认值时
// 做标量改写（machine：非空一律 1:1 假名化）。语义与
// applyCodexFingerprintClientMetadata 逐点一致。
func applyCodexFingerprintClientMetadataRaw(body []byte, ids *codexFingerprintIDs) ([]byte, bool, error) {
	if len(body) == 0 || ids == nil {
		return body, false, nil
	}
	// 非 JSON 对象的 body（数组/标量/畸形）没有 client_metadata 语义，
	// sjson 在这类根上写字段会改写整体结构，直接放行保持原样。
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
		return body, false, nil
	}

	existing := map[string]any{}
	// machine 只改不增：与 map 版一致，client_metadata 不是对象时不创建。
	skipClientMetadata := false
	if cm := gjson.GetBytes(body, "client_metadata"); cm.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.GetBytes(body, "client_metadata.session_id"))
		if err := json.Unmarshal([]byte(cm.Raw), &existing); err != nil {
			return body, false, fmt.Errorf("decode client_metadata for fingerprint: %w", err)
		}
	} else {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
		skipClientMetadata = ids.mode == codexFingerprintMachine
	}

	next := body
	modified := false
	if !skipClientMetadata && applyCodexFingerprintToClientMetadataMap(existing, ids) {
		raw, err := json.Marshal(existing)
		if err != nil {
			return body, false, fmt.Errorf("encode converged client_metadata: %w", err)
		}
		var setErr error
		next, setErr = sjson.SetRawBytes(body, "client_metadata", raw)
		if setErr != nil {
			return body, false, fmt.Errorf("splice converged client_metadata: %w", setErr)
		}
		modified = true
	}
	promptCacheKey := gjson.GetBytes(body, "prompt_cache_key")
	if promptCacheKey.Exists() && promptCacheKey.Type == gjson.String && strings.TrimSpace(promptCacheKey.String()) != "" {
		// 与 applyCodexFingerprintPromptCacheKey 逐点一致：machine 非空即 1:1 假名化，
		// session / full 仅在可证明是 body session 默认值时改写为收敛 session。
		target := ""
		if ids.mode == codexFingerprintMachine {
			if rewritten := ids.machinePseudonym(promptCacheKey.String()); rewritten != promptCacheKey.String() {
				target = rewritten
			}
		} else if shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey.String()) {
			target = ids.sessionID
		}
		if target != "" {
			rewritten, err := sjson.SetBytes(next, "prompt_cache_key", target)
			if err != nil {
				return body, false, fmt.Errorf("splice converged prompt_cache_key: %w", err)
			}
			next = rewritten
			modified = true
		}
	}
	return next, modified, nil
}

// rewriteClientMetadataEmbeddedTurnMetadata 改写 client_metadata 中内嵌的
// x-codex-turn-metadata JSON 字符串里的指定字段。非法/非对象值会重建，
// 避免 flat client_metadata 与 embedded metadata 暴露两套身份。
func rewriteClientMetadataEmbeddedTurnMetadata(clientMetadata map[string]any, fields map[string]any) {
	raw, ok := clientMetadata["x-codex-turn-metadata"].(string)
	if !ok || raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	if rebuilt, err := json.Marshal(metadata); err == nil {
		clientMetadata["x-codex-turn-metadata"] = string(rebuilt)
	}
}
