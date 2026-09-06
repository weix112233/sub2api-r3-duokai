package service

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// AccountTestModeDefault drives the standard /responses connection test.
	AccountTestModeDefault = "default"
	// AccountTestModeCompact drives the remote-compaction probe test
	// (native v2: streaming /responses with a compaction_trigger input item).
	AccountTestModeCompact = "compact"
)

func normalizeAccountTestMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case AccountTestModeCompact:
		return AccountTestModeCompact
	default:
		return AccountTestModeDefault
	}
}

// createOpenAICompactProbePayload 构造原生 remote compaction v2 探测载荷：
// 流式 /responses + input 末尾 {"type":"compaction_trigger"}。上游已下线
// legacy unary /responses/compact（v1 形态恒 404，#5598/#5624），现行 codex
// 默认协议即 v2（RemoteCompactionV2 Stable + default_enabled）。
func createOpenAICompactProbePayload(model string, isOAuth bool) map[string]any {
	payload := map[string]any{
		"model":        strings.TrimSpace(model),
		"instructions": "You are a helpful coding assistant.",
		"input": []any{
			map[string]any{
				"type":    "message",
				"role":    "user",
				"content": "Respond with OK.",
			},
			map[string]any{"type": "compaction_trigger"},
		},
		"stream": true,
	}
	// ChatGPT internal API 要求 store: false，与真实转发一致。
	if isOAuth {
		payload["store"] = false
	}
	return payload
}

// openAICompactProbeFoundCompactionItem 判定探测响应是否产出了 compaction
// 输出 item——v2 契约的核心（codex 缺它即 fatal "got 0 items"）。三种形态都
// 认：① SSE 的 output_item.done/added（原生 v2 主形态，codex 只从这里收集
// item）；② SSE 终态 response.completed 的 response.output[]（部分上游只在
// 终态给出 item）；③ 整体 JSON 的 output[]（老网关链把请求降级成 unary）。
func openAICompactProbeFoundCompactionItem(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	bodyText := string(body)
	if _, found := findRawCompactionItemFromSSE(bodyText); found {
		return true
	}
	if finalResponse, ok := extractCodexFinalResponse(bodyText); ok &&
		responsesOutputHasCompactionItem(finalResponse) {
		return true
	}
	return responsesOutputHasCompactionItem(body)
}

const (
	// codexMachineCompactProbeAgentName 根线程 agent_name（codex-rs protocol/src/agent_path.rs AgentPath::ROOT，
	// Display 为 "/root"）。
	codexMachineCompactProbeAgentName = "/root"
	// codexMachineCompactProbeThreadSource TUI 根线程 thread_source（ThreadSource::User.as_str()）。
	codexMachineCompactProbeThreadSource = "user"
	// codexMachineCompactProbeSandboxMode 探测 turn metadata 的 sandbox_mode：TUI 默认 workspace-write。
	codexMachineCompactProbeSandboxMode = "workspace-write"
)

// codexMachineCompactProbeCompaction compaction 子对象，字段顺序按 codex-rs core/src/responses_metadata.rs
// CompactionTurnMetadata（:95-101）。手动 /compact ⇒ manual / user_requested / responses_compaction_v2 /
// standalone_turn / memento（core/src/compact_remote_v2.rs:116-118）。
type codexMachineCompactProbeCompaction struct {
	Trigger        string `json:"trigger"`
	Reason         string `json:"reason"`
	Implementation string `json:"implementation"`
	Phase          string `json:"phase"`
	Strategy       string `json:"strategy"`
}

// codexMachineCompactProbeTurnMetadata compaction turn 的 x-codex-turn-metadata 载荷。字段与顺序按
// CodexTurnMetadataPayload 声明顺序（responses_metadata.rs:476-524）；compaction 请求 has_turn_identity
// 且 has_request_identity（:353-368）⇒ 在常规 turn 字段之外多出 installation_id / window_id /
// request_kind / compaction。使用有序 struct 而非 map，保证序列化键序与 serde 一致。
type codexMachineCompactProbeTurnMetadata struct {
	InstallationID             string                             `json:"installation_id"`
	SessionID                  string                             `json:"session_id"`
	ThreadID                   string                             `json:"thread_id"`
	AgentName                  string                             `json:"agent_name"`
	TurnID                     string                             `json:"turn_id"`
	WindowID                   string                             `json:"window_id"`
	RequestKind                string                             `json:"request_kind"`
	ThreadSource               string                             `json:"thread_source"`
	Sandbox                    string                             `json:"sandbox,omitempty"`
	SandboxMode                string                             `json:"sandbox_mode,omitempty"`
	AutoReviewEnabled          bool                               `json:"auto_review_enabled"`
	NodeReplAutoReviewRequired bool                               `json:"node_repl_auto_review_required"`
	NodeReplDisabled           bool                               `json:"node_repl_disabled"`
	TurnStartedAtUnixMs        int64                              `json:"turn_started_at_unix_ms"`
	Compaction                 codexMachineCompactProbeCompaction `json:"compaction"`
}

// applyCodexMachineCompactProbeIdentity 给 machine 模式探测 payload 补上真实 Codex compaction 的
// body 身份（sink 前的"真实客户端"形态），返回同一份 turn metadata JSON 供 x-codex-turn-metadata
// 头使用；调用方随后用同一份 IDs 走 machine 头/体 sink 假名化（只改不增，所以必须先带上）。
// 形态依据（codex-rs HEAD 711a5f8b3a）：core/src/client.rs:921-938 恒设 prompt_cache_key（= session_id，
// :484-488）与 client_metadata；core/src/responses_metadata.rs:278-315 client_metadata 键
// （x-codex-installation-id / session_id / thread_id / x-codex-window-id / turn_id / x-codex-turn-metadata）；
// :353-383 turn_metadata_payload：compaction 请求带 installation/session/thread/agent_name/turn/window、
// request_kind="compaction"、compaction{…}；thread_source 序列化为 as_str（protocol.rs:2593-2605）。
// turn_id 与真实 submission/turn id 同为 UUIDv7（core/src/session/mod.rs:907-914 new_submission_id）。
// installation 用探测会话派生的稳定占位值，经 sink 改写为账号收敛 installation；agent_name 根线程恒
// "/root"；sandbox_mode 取 TUI 默认 workspace-write（core/src/config/mod.rs 默认 SandboxPolicy），
// auto_review_enabled 默认 false；sandbox 取 sandboxTag（账号 UA 的 OS 段），OS 无法判定时不写 sandbox；
// node_repl_* 来自模型信息，内置模型未设置 ⇒ false（protocol/src/openai_models.rs:457-464）。
func applyCodexMachineCompactProbeIdentity(payload map[string]any, probeSessionID string, sandboxTag string, now time.Time) string {
	turnID := uuid.Must(uuid.NewV7()).String()
	installationID := deriveStableUUIDv4("sub2api:codex-compact-probe:v1:installation:" + probeSessionID)
	windowID := probeSessionID + ":0"
	turnMetadata := codexMachineCompactProbeTurnMetadata{
		InstallationID:      installationID,
		SessionID:           probeSessionID,
		ThreadID:            probeSessionID,
		AgentName:           codexMachineCompactProbeAgentName,
		TurnID:              turnID,
		WindowID:            windowID,
		RequestKind:         "compaction",
		ThreadSource:        codexMachineCompactProbeThreadSource,
		Sandbox:             sandboxTag,
		SandboxMode:         codexMachineCompactProbeSandboxMode,
		AutoReviewEnabled:   false,
		TurnStartedAtUnixMs: now.UnixMilli(),
		Compaction: codexMachineCompactProbeCompaction{
			Trigger:        "manual",
			Reason:         "user_requested",
			Implementation: "responses_compaction_v2",
			Phase:          "standalone_turn",
			Strategy:       "memento",
		},
	}
	// 纯字符串/布尔/整数字段的 struct，Marshal 不会失败。
	turnMetadataJSON, _ := json.Marshal(turnMetadata)
	payload["prompt_cache_key"] = probeSessionID
	payload["client_metadata"] = map[string]any{
		"x-codex-installation-id": installationID,
		"session_id":              probeSessionID,
		"thread_id":               probeSessionID,
		"turn_id":                 turnID,
		"x-codex-window-id":       windowID,
		"x-codex-turn-metadata":   string(turnMetadataJSON),
	}
	return string(turnMetadataJSON)
}

func shouldMarkOpenAICompactUnsupported(status int, body []byte) bool {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	case http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity:
		lower := strings.ToLower(strings.TrimSpace(extractUpstreamErrorMessage(body) + " " + string(body)))
		if strings.Contains(lower, "compact") {
			for _, keyword := range []string{
				"unsupported",
				"not support",
				"does not support",
				"not available",
				"disabled",
			} {
				if strings.Contains(lower, keyword) {
					return true
				}
			}
		}
	}
	return false
}

// buildOpenAICompactProbeExtraUpdates 计算探测结果的账号 extra 更新。
// compactionFound 是 v2 契约判据：HTTP 2xx 但响应无 compaction item 时同样
// 记为不支持（链路把 compaction_trigger 吞掉的形态，等价 codex 的 "got 0
// items" fatal，#5478/#5648）。极端场景（上游链只支持 legacy unary compact）
// 可用账号级 openai_compact_mode=force_on 人工覆盖。
func buildOpenAICompactProbeExtraUpdates(resp *http.Response, body []byte, probeErr error, compactionFound bool, now time.Time) map[string]any {
	updates := map[string]any{
		"openai_compact_checked_at":  now.Format(time.RFC3339),
		"openai_compact_last_status": nil,
	}

	if resp != nil {
		updates["openai_compact_last_status"] = resp.StatusCode
	}

	switch {
	case probeErr != nil:
		updates["openai_compact_last_error"] = truncateString(sanitizeUpstreamErrorMessage(probeErr.Error()), 2048)
	case resp == nil:
		updates["openai_compact_last_error"] = "compact probe failed"
	default:
		errMsg := strings.TrimSpace(extractUpstreamErrorMessage(body))
		if errMsg == "" && len(body) > 0 {
			errMsg = strings.TrimSpace(string(body))
		}
		if errMsg == "" && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			errMsg = "HTTP " + strconv.Itoa(resp.StatusCode)
		}
		errMsg = truncateString(sanitizeUpstreamErrorMessage(errMsg), 2048)
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300 && compactionFound:
			updates["openai_compact_supported"] = true
			updates["openai_compact_last_error"] = ""
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			updates["openai_compact_supported"] = false
			updates["openai_compact_last_error"] = "upstream returned 2xx without a compaction output item (native remote compaction v2 unsupported)"
		default:
			if shouldMarkOpenAICompactUnsupported(resp.StatusCode, body) {
				updates["openai_compact_supported"] = false
			}
			updates["openai_compact_last_error"] = errMsg
		}
	}

	return updates
}

func mergeExtraUpdates(base map[string]any, more map[string]any) map[string]any {
	if len(base) == 0 && len(more) == 0 {
		return nil
	}
	out := make(map[string]any, len(base)+len(more))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range more {
		out[key] = value
	}
	return out
}

// compactProbeSessionID 返回探测请求使用的会话标识。真实 Codex 的
// session-id / thread-id 恒为 UUID（codex-protocol ThreadId 是 UUIDv7），
// 探测既然与真实流量走同一族 /responses 端点，标识形态就必须同构——
// 否则上游能凭 "probe_compact_5" 这类字面量一眼区分出探测流量。
// 账号级稳定派生：重复探测复用同一会话，而不是每次新开一个。
// machine 模式下该值经假名化出站（window 假名化只接受 UUID 形态前缀，
// 见 codexMachineWindowPseudonymWith），字面量形态会原样漏出。
func compactProbeSessionID(accountID int64) string {
	if accountID <= 0 {
		return deriveStableUUIDv4("sub2api:codex-compact-probe:v1:anonymous")
	}
	return deriveStableUUIDv4("sub2api:codex-compact-probe:v1:" + strconv.FormatInt(accountID, 10))
}
