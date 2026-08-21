package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// 本文件实现 codexFingerprintMachine（"单机多窗口"）模式的假名函数与三个 sink 的改写规则。
// 设计依据：docs/plan/2026-08-19-Codex-OAuth共享账号-machine模式实施设计.md §3–§5。
//
// 原则"只改不增"：下游没发的身份键不补，下游发了的必须改（installation 亦然：真实 Codex
// 只在 compact 请求发顶层 x-codex-installation-id 头，core/src/client.rs:613-614；常规
// Responses HTTP / WS 握手都不发，只在 client_metadata / turn metadata 内携带，
// responses_metadata.rs:281,358——因此头 sink 也只在下游带该头时改写）；
// 改写是确定性的纯映射，三个 sink（出站头 / client_metadata / turn metadata）各自独立
// 应用即可保证同值，不需要像 session/full 那样预生成 turn_id。

// codexMachinePseudonymPrefix 假名函数 P 的 HMAC 消息域前缀（单一域：session /
// thread / pck / client_request_id / parent_thread / forked_from 共用同一个 P，
// 因此根会话下游 session == thread == pck 时上游三者仍相等，见设计 §3 / I1）。
const codexMachinePseudonymPrefix = "sub2api:codex-machine:v1:"

// codexMachineSandbox* 是 Codex turn metadata 中 sandbox 字段的平台标签值域
// （codex-rs sandboxing/src/manager.rs as_metric_tag + core/src/sandbox_tags.rs）。
const (
	codexMachineSandboxSeatbelt        = "seatbelt"
	codexMachineSandboxSeccomp         = "seccomp"
	codexMachineSandboxWindows         = "windows_sandbox"
	codexMachineSandboxWindowsElevated = "windows_elevated"
)

// codexMachinePseudonym 假名函数 P：用账号 seed 作 HMAC 密钥把下游身份 ID 映射为
// 同一账号内 1:1、跨账号不同的假名（设计 §3）。
//   - 空串（trim 后）返回空串，调用方按"只改不增"跳过；
//   - 输入是 UUIDv7 时保留前 6 字节（48 位 unix_ms 时间戳），其余取 HMAC 并重打 version 7；
//   - 其他版本 UUID 或非 UUID 字符串一律映射为 UUIDv4 形态。
func codexMachinePseudonym(key []byte, id string) string {
	raw := strings.TrimSpace(id)
	if raw == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(codexMachinePseudonymPrefix + raw))
	sum := mac.Sum(nil)

	var out uuid.UUID
	if parsed, err := uuid.Parse(raw); err == nil && parsed.Version() == 7 {
		copy(out[0:6], parsed[0:6])
		copy(out[6:16], sum[0:10])
		out[6] = (out[6] & 0x0f) | 0x70 // version 7
	} else {
		copy(out[0:16], sum[0:16])
		out[6] = (out[6] & 0x0f) | 0x40 // version 4
	}
	out[8] = (out[8] & 0x3f) | 0x80 // RFC 4122 variant
	return out.String()
}

// machinePseudonym 是 P 的请求级幂等封装：同一 ids 已签发过的假名再次传入时原样返回。
// 需要幂等的原因：WS 链路对同一份 body map 先后应用两次 body sink（Forward 阶段
// openai_gateway_forward.go 的 applyCodexFingerprintClientMetadata 与
// openai_ws_forwarder_v2.go 的 applyStagedCodexFingerprintClientMetadata；后者还会
// 在重试的每个 attempt 上重复），session/full 写绝对值天然幂等，machine 的 P 不是。
// 下游不可能持有本请求签发的假名（上游不回显这些头），因此该判定不会误伤真实 ID。
func (ids *codexFingerprintIDs) machinePseudonym(id string) string {
	raw := strings.TrimSpace(id)
	if raw == "" {
		return ""
	}
	if _, issued := ids.pseudonymIssued[raw]; issued {
		return raw
	}
	out := codexMachinePseudonym(ids.pseudonymKey, raw)
	if ids.pseudonymIssued == nil {
		ids.pseudonymIssued = make(map[string]struct{})
	}
	ids.pseudonymIssued[out] = struct{}{}
	return out
}

// codexMachineWindowPseudonym 窗口 ID 改写规则 W。x-codex-window-id 形态为
// "{thread_id}:{n}"（codex-rs client.rs X_CODEX_WINDOW_ID_HEADER）：前段假名化、后段保留；
// 整体是 UUID（无冒号）时直接假名化；其他形态原样返回。
func codexMachineWindowPseudonym(key []byte, value string) string {
	return codexMachineWindowPseudonymWith(func(id string) string { return codexMachinePseudonym(key, id) }, value)
}

// machineWindowPseudonym 是 W 的请求级幂等封装（前段经 machinePseudonym）。
func (ids *codexFingerprintIDs) machineWindowPseudonym(value string) string {
	return codexMachineWindowPseudonymWith(ids.machinePseudonym, value)
}

func codexMachineWindowPseudonymWith(pseudonym func(string) string, value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return value
	}
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		head := raw[:idx]
		if _, err := uuid.Parse(head); err == nil {
			return pseudonym(head) + raw[idx:]
		}
		return value
	}
	if _, err := uuid.Parse(raw); err == nil {
		return pseudonym(raw)
	}
	return value
}

// codexMachineSandboxTagFromUA 由出站 User-Agent 的 OS 段推导账号 OS 对应的平台沙箱标签。
// 对应 codex-rs get_platform_sandbox 的三支：macOS ⇒ seatbelt、Windows ⇒ windows_sandbox、
// 其他（linux 发行版）⇒ seccomp；解析不到 OS 段返回空串（不改写）。
func codexMachineSandboxTagFromUA(userAgent string) string {
	osSegment := openai.CodexUserAgentOSSegment(userAgent)
	switch {
	case osSegment == "":
		return ""
	case strings.HasPrefix(osSegment, "Mac OS"):
		return codexMachineSandboxSeatbelt
	case strings.HasPrefix(osSegment, "Windows"):
		return codexMachineSandboxWindows
	default:
		return codexMachineSandboxSeccomp
	}
}

// rewriteCodexMachineSandbox 按账号沙箱标签改写 turn metadata 的 sandbox 字段（设计 §4.3 表）：
// 仅当 current 是平台相关标签时改写；none / external 等平台无关值原样保留；
// accountTag 为空表示 UA 无法判定 OS，不改写。
func rewriteCodexMachineSandbox(current, accountTag string) string {
	if accountTag == "" {
		return current
	}
	switch current {
	case codexMachineSandboxSeatbelt, codexMachineSandboxSeccomp, codexMachineSandboxWindows, codexMachineSandboxWindowsElevated:
	default:
		return current
	}
	if accountTag == codexMachineSandboxWindows {
		// Windows 账号：windows_sandbox / windows_elevated 都是合法的 Windows 值，保留；
		// 类 Unix 标签改为 windows_sandbox。
		if current == codexMachineSandboxWindows || current == codexMachineSandboxWindowsElevated {
			return current
		}
		return codexMachineSandboxWindows
	}
	return accountTag
}

// stampCodexMachineSandboxTag 在 resolve 之后按调用链持有的账号级 overrideUA 补记
// ids.sandboxTag。三条链路（非透传 / 透传 / probe）在 resolve 后都必须调用，
// overrideUA 与终态收口 enforceCodexIdentityHeadersWithUA 传入的值同源，保证
// sandbox 与实际出站 UA 的 OS 段一致。非 machine 模式 no-op。
func stampCodexMachineSandboxTag(ids *codexFingerprintIDs, overrideUA string) {
	if ids == nil || ids.mode != codexFingerprintMachine {
		return
	}
	ids.sandboxTag = codexMachineSandboxTagFromUA(resolveCodexOutboundIdentity(overrideUA).userAgent)
}

// codexMachineHeaderPseudonymNames 头 sink 中按 P 改写的身份头（存在则改，不存在不补）。
var codexMachineHeaderPseudonymNames = [...]string{
	"session-id",
	"thread-id",
	"x-client-request-id",
	"x-codex-parent-thread-id",
}

// codexMachineHasSessionIdentity 判定出站头是否携带 Codex 会话身份（连字符 session-id / thread-id，
// codex-api/src/requests/headers.rs build_session_headers）。真实 Codex 与 OpenCode 带；Hermes / pi-ai /
// OpenAI SDK 直连形态不带（docs/plan/2026-08-19-第三方Agent的Codex-provider出站形态证据.md §5）。
func codexMachineHasSessionIdentity(h http.Header) bool {
	if h == nil {
		return false
	}
	return strings.TrimSpace(h.Get("session-id")) != "" || strings.TrimSpace(h.Get("thread-id")) != ""
}

// applyCodexMachineHeaders 头 sink 的 machine 分支（设计 §4.1）。
func applyCodexMachineHeaders(h http.Header, ids *codexFingerprintIDs) {
	if h == nil || ids == nil {
		return
	}
	// 只改不增：真实 Codex 仅 compact 发顶层 installation 头（client.rs:613-614），
	// 常规请求不发；下游带了才改成账号 installation。
	if v := h.Get("x-codex-installation-id"); strings.TrimSpace(v) != "" {
		h.Set("x-codex-installation-id", ids.installationID)
	}
	for _, name := range codexMachineHeaderPseudonymNames {
		if v := h.Get(name); strings.TrimSpace(v) != "" {
			h.Set(name, ids.machinePseudonym(v))
		}
	}
	if v := h.Get("x-codex-window-id"); strings.TrimSpace(v) != "" {
		h.Set("x-codex-window-id", ids.machineWindowPseudonym(v))
	}
	// 下划线会话头：三条链路的源头设置都在本 sink 之前，这里一处处理即可覆盖。
	//   - conversation_id：Codex 0.81.0 已删除，第三方 Agent（OpenCode / Hermes / pi-ai）也不发 ⇒ 一律删除。
	//   - session_id：Codex ≥ rust-v0.131.0 不再发送 ⇒ 下游携带 Codex 会话身份（session-id / thread-id）时删除；
	//     下游不带（Hermes / pi-ai 形态只有下划线 session_id）时保留网关既有的隔离值，不合成任何 Codex 会话头
	//     （决策 B：透明代理不为非 Codex 下游伪造窗口身份）。
	h.Del("conversation_id")
	if codexMachineHasSessionIdentity(h) {
		h.Del("session_id")
	}
	if raw := strings.TrimSpace(h.Get("x-codex-turn-metadata")); raw != "" {
		if rebuilt, ok := rewriteCodexMachineTurnMetadata(raw, ids); ok {
			h.Set("x-codex-turn-metadata", rebuilt)
		}
	}
}

// codexMachineClientMetadataPseudonymKeys body sink 中按 P 改写的 client_metadata 键。
var codexMachineClientMetadataPseudonymKeys = [...]string{
	"session_id",
	"thread_id",
	"x-codex-parent-thread-id",
}

// applyCodexMachineClientMetadata body sink 的 machine 分支（设计 §4.2）。
// 调用方保证 existing 对应的 client_metadata 对象在下游 body 中真实存在。
// 返回值表示是否有键被改写（只改不增：不含身份键的对象原样返回 false）。
func applyCodexMachineClientMetadata(existing map[string]any, ids *codexFingerprintIDs) bool {
	if existing == nil || ids == nil {
		return false
	}
	modified := false
	set := func(key, next string) {
		if existing[key] != next {
			existing[key] = next
			modified = true
		}
	}
	// 真实 Codex 的 client_metadata 恒含 installation（responses_metadata.rs:281），
	// 但仍按只改不增处理：下游带了才改。
	if v, ok := existing["x-codex-installation-id"].(string); ok && strings.TrimSpace(v) != "" {
		set("x-codex-installation-id", ids.installationID)
	}
	for _, key := range codexMachineClientMetadataPseudonymKeys {
		if v, ok := existing[key].(string); ok && strings.TrimSpace(v) != "" {
			set(key, ids.machinePseudonym(v))
		}
	}
	if v, ok := existing["x-codex-window-id"].(string); ok && strings.TrimSpace(v) != "" {
		set("x-codex-window-id", ids.machineWindowPseudonym(v))
	}
	if raw, ok := existing["x-codex-turn-metadata"].(string); ok && strings.TrimSpace(raw) != "" {
		if rebuilt, changed := rewriteCodexMachineTurnMetadata(raw, ids); changed {
			set("x-codex-turn-metadata", rebuilt)
		}
	}
	return modified
}

// codexMachineTurnMetadataPseudonymFields turn metadata 中按 P 改写的字段。
var codexMachineTurnMetadataPseudonymFields = [...]string{
	"session_id",
	"thread_id",
	"parent_thread_id",
	"forked_from_thread_id",
}

// rewriteCodexMachineTurnMetadata turn metadata 规则（设计 §4.3），头内 JSON 与
// client_metadata 内嵌 JSON 字符串共用。合法对象保留其余字段（turn_id / sandbox_mode /
// workspaces 等透传），只改写存在的身份字段；非法 JSON / 非对象值不是 Codex 会产生的
// 形态，按只改不增原样放行（与 off 模式一致）。无字段被改写时返回 (raw, false)。
// 用 gjson 读 / sjson 原位改值而不是 map 往返：真实 Codex 的 turn metadata 是 serde 按 struct
// 声明顺序序列化的（responses_metadata.rs:476-524），map 重编码会把键序变成字母序，成为可观测的
// 网关痕迹；原位改值保留下游（或探针有序 struct）给出的键序与其余字节。
func rewriteCodexMachineTurnMetadata(raw string, ids *codexFingerprintIDs) (string, bool) {
	if strings.TrimSpace(raw) == "" || ids == nil {
		return raw, false
	}
	if !gjson.Valid(raw) {
		return raw, false
	}
	metadata := gjson.Parse(raw)
	if !metadata.IsObject() {
		return raw, false
	}
	// 顶层重复键先去重再改写：gjson/sjson 只读写第一处，第二处的真实身份会原样透传；
	// 真实 Codex 的 serde struct 不会产生重复键，只有畸形/恶意下游会。
	out, modified := dedupeCodexTurnMetadataTopLevelKeys(metadata)
	if modified {
		metadata = gjson.Parse(out)
	}
	set := func(field, next string) {
		if metadata.Get(field).String() == next {
			return
		}
		rewritten, err := sjson.Set(out, field, next)
		if err != nil {
			return
		}
		out = rewritten
		modified = true
	}
	stringField := func(field string) (string, bool) {
		v := metadata.Get(field)
		if v.Type != gjson.String {
			return "", false
		}
		return v.String(), true
	}
	if v, ok := stringField("installation_id"); ok && strings.TrimSpace(v) != "" {
		set("installation_id", ids.installationID)
	}
	for _, field := range codexMachineTurnMetadataPseudonymFields {
		if v, ok := stringField(field); ok && strings.TrimSpace(v) != "" {
			set(field, ids.machinePseudonym(v))
		}
	}
	if v, ok := stringField("window_id"); ok && strings.TrimSpace(v) != "" {
		set("window_id", ids.machineWindowPseudonym(v))
	}
	if v, ok := stringField("sandbox"); ok {
		set("sandbox", rewriteCodexMachineSandbox(v, ids.sandboxTag))
	}
	if !modified {
		return raw, false
	}
	return out, true
}

// dedupeCodexTurnMetadataTopLevelKeys 去除 turn metadata 顶层对象的重复键，只保留每个键最后一次
// 出现（与 encoding/json、serde_json Value 的"后者覆盖"语义一致），其余键的相对顺序与原始字节
// （key.Raw / value.Raw，含嵌套对象）不动；嵌套对象内的重复键不处理（不在 §4.3 改写范围）。
// 无重复键时返回 (metadata.Raw, false)，连空白都不改。
func dedupeCodexTurnMetadataTopLevelKeys(metadata gjson.Result) (string, bool) {
	type entry struct {
		key      string
		keyRaw   string
		valueRaw string
	}
	var entries []entry
	lastIndex := make(map[string]int)
	metadata.ForEach(func(key, value gjson.Result) bool {
		entries = append(entries, entry{key: key.String(), keyRaw: key.Raw, valueRaw: value.Raw})
		lastIndex[key.String()] = len(entries) - 1
		return true
	})
	if len(lastIndex) == len(entries) {
		return metadata.Raw, false
	}
	var b strings.Builder
	b.WriteByte('{')
	wrote := false
	for i, e := range entries {
		if lastIndex[e.key] != i {
			continue
		}
		if wrote {
			b.WriteByte(',')
		}
		b.WriteString(e.keyRaw)
		b.WriteByte(':')
		b.WriteString(e.valueRaw)
		wrote = true
	}
	b.WriteByte('}')
	return b.String(), true
}
