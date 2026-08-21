package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
)

// codexOutboundIdentifierKeys are protocol identity fields that must stay
// local to sub2api. The list includes both JSON/header spellings and the
// Codex metadata containers that can carry the four identifiers.
var codexOutboundIdentifierKeys = map[string]struct{}{
	"installation_id":               {},
	"session_id":                    {},
	"thread_id":                     {},
	"turn_id":                       {},
	"conversation_id":               {},
	"window_id":                     {},
	"installation-id":               {},
	"session-id":                    {},
	"thread-id":                     {},
	"turn-id":                       {},
	"conversation-id":               {},
	"window-id":                     {},
	"x-codex-installation-id":       {},
	"x-codex-session-id":            {},
	"x-codex-thread-id":             {},
	"x-codex-turn-id":               {},
	"x_codex_installation_id":       {},
	"x_codex_session_id":            {},
	"x_codex_thread_id":             {},
	"x_codex_turn_id":               {},
	"x-codex-window-id":             {},
	"x_codex_window_id":             {},
	"x-codex-turn-metadata":         {},
	"x_codex_turn_metadata":         {},
	"x-codex-parent-thread-id":      {},
	"x-codex-forked-from-thread-id": {},
	"x-codex-root-thread-id":        {},
	"x-codex-parent-turn-id":        {},
	"x-codex-forked-from-turn-id":   {},
	"x-codex-root-turn-id":          {},
	"turn_metadata":                 {},
	"turn-metadata":                 {},
	"prompt_cache_key":              {},
	"prompt-cache-key":              {},
	"client_request_id":             {},
	"client-request-id":             {},
	"request_id":                    {},
	"request-id":                    {},
	"correlation_id":                {},
	"correlation-id":                {},
	"trace_id":                      {},
	"trace-id":                      {},
	"span_id":                       {},
	"span-id":                       {},
	"traceparent":                   {},
	"tracestate":                    {},
	"baggage":                       {},
	"sentry-trace":                  {},
	"sentry_trace":                  {},
	"x-client-request-id":           {},
	"x-request-id":                  {},
	"x-correlation-id":              {},
	"x-amzn-trace-id":               {},
	"x-cloud-trace-context":         {},
	"x-b3-traceid":                  {},
	"x-b3-spanid":                   {},
	"x-b3-sampled":                  {},
	"uber-trace-id":                 {},
	"grpc-trace-bin":                {},
	"x-ot-span-context":             {},
	"x-datadog-trace-id":            {},
	"x-datadog-parent-id":           {},
	"x-datadog-sampling-priority":   {},
	"x-datadog-origin":              {},
	"newrelic":                      {},
	"x-newrelic-id":                 {},
	"x-newrelic-transaction":        {},
	"forwarded":                     {},
	"x-forwarded-for":               {},
	"x-forwarded-host":              {},
	"x-forwarded-proto":             {},
	"x-forwarded-port":              {},
	"x-forwarded-server":            {},
	"x-original-forwarded-for":      {},
	"x-real-ip":                     {},
	"x-client-ip":                   {},
	"client-ip":                     {},
	"x-cluster-client-ip":           {},
	"true-client-ip":                {},
	"cf-connecting-ip":              {},
	"fastly-client-ip":              {},
	"fly-client-ip":                 {},
	"x-envoy-external-address":      {},
	"x-appengine-user-ip":           {},
}

var codexOutboundMetadataKeys = map[string]struct{}{
	"x-codex-turn-state":            {},
	"x_codex_turn_state":            {},
	"parent_thread_id":              {},
	"parent-thread-id":              {},
	"x-codex-parent-thread-id":      {},
	"forked_from_thread_id":         {},
	"forked-from-thread-id":         {},
	"x-codex-forked-from-thread-id": {},
	"root_thread_id":                {},
	"root-thread-id":                {},
	"x-codex-root-thread-id":        {},
	"parent_turn_id":                {},
	"parent-turn-id":                {},
	"x-codex-parent-turn-id":        {},
	"root_turn_id":                  {},
	"root-turn-id":                  {},
	"x-codex-root-turn-id":          {},
	"forked_from_turn_id":           {},
	"forked-from-turn-id":           {},
	"x-codex-forked-from-turn-id":   {},
	"workspaces":                    {},
	"workspace":                     {},
	"workspace_root":                {},
	"workspace-root":                {},
	"workspace_roots":               {},
	"workspace-roots":               {},
	"git_remote":                    {},
	"git-remote":                    {},
	"git_remote_url":                {},
	"git-remote-url":                {},
	"remote_url":                    {},
	"remote-url":                    {},
	"repository_url":                {},
	"repository-url":                {},
	"repo_url":                      {},
	"repo-url":                      {},
	"repository_fingerprint":        {},
	"repository-fingerprint":        {},
	"commit_hash":                   {},
	"commit-hash":                   {},
	"head_commit":                   {},
	"head-commit":                   {},
	"dirty":                         {},
	"sandbox":                       {},
	"sandbox_mode":                  {},
	"sandbox-mode":                  {},
	"request_kind":                  {},
	"request-kind":                  {},
	"turn_started_at_unix_ms":       {},
	"turn-started-at-unix-ms":       {},
	"tool_names":                    {},
	"tool-names":                    {},
	"mcp_servers":                   {},
	"mcp-servers":                   {},
	"mcp_server_names":              {},
	"mcp-server-names":              {},
	"mcp_tools":                     {},
	"mcp-tools":                     {},
	"mcp_tool_names":                {},
	"mcp-tool-names":                {},
	"plugin_names":                  {},
	"plugin-names":                  {},
	"plugins":                       {},
	"plugin_path":                   {},
	"plugin-path":                   {},
	"plugin_paths":                  {},
	"plugin-paths":                  {},
	"plugin_script_path":            {},
	"plugin-script-path":            {},
	"skill_names":                   {},
	"skill-names":                   {},
	"skills":                        {},
	"skill_path":                    {},
	"skill-path":                    {},
	"skill_paths":                   {},
	"skill-paths":                   {},
	"skill_root":                    {},
	"skill-root":                    {},
	"skill_repository_url":          {},
	"skill-repository-url":          {},
	"script_path":                   {},
	"script-path":                   {},
	"artifact_path":                 {},
	"artifact-path":                 {},
	"tool_catalog":                  {},
	"tool-catalog":                  {},
}

var codexOutboundKeyReplacer = strings.NewReplacer("-", "_", ".", "_")

func normalizeCodexOutboundKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = codexOutboundKeyReplacer.Replace(key)
	return key
}

func compactCodexOutboundKey(key string) string {
	return strings.ReplaceAll(normalizeCodexOutboundKey(key), "_", "")
}

func isCodexOutboundIdentifierKey(key string) bool {
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	if _, ok := codexOutboundIdentifierKeys[lowerKey]; ok {
		return true
	}
	normalized := normalizeCodexOutboundKey(key)
	switch normalized {
	case "installation_id", "session_id", "thread_id", "turn_id", "conversation_id", "window_id",
		"x_codex_installation_id", "x_codex_session_id", "x_codex_thread_id",
		"x_codex_turn_id", "x_codex_window_id", "x_codex_turn_metadata",
		"turn_metadata", "prompt_cache_key",
		"client_request_id", "request_id", "correlation_id", "trace_id", "span_id",
		"traceparent", "tracestate", "baggage", "sentry_trace",
		"x_client_request_id", "x_request_id", "x_correlation_id",
		"x_amzn_trace_id", "x_cloud_trace_context", "x_b3_traceid",
		"x_b3_spanid", "x_b3_sampled", "uber_trace_id",
		"grpc_trace_bin", "x_ot_span_context", "x_datadog_trace_id",
		"x_datadog_parent_id", "x_datadog_sampling_priority", "x_datadog_origin",
		"newrelic", "x_newrelic_id", "x_newrelic_transaction",
		"forwarded", "x_forwarded_for", "x_forwarded_host", "x_forwarded_proto",
		"x_forwarded_port", "x_forwarded_server", "x_original_forwarded_for",
		"x_real_ip", "x_client_ip", "client_ip", "x_cluster_client_ip",
		"true_client_ip", "cf_connecting_ip", "fastly_client_ip",
		"fly_client_ip", "x_envoy_external_address", "x_appengine_user_ip",
		"parent_thread_id", "forked_from_thread_id", "root_thread_id",
		"parent_turn_id", "forked_from_turn_id", "root_turn_id",
		"x_codex_parent_thread_id", "x_codex_forked_from_thread_id",
		"x_codex_root_thread_id", "x_codex_parent_turn_id",
		"x_codex_forked_from_turn_id", "x_codex_root_turn_id":
		return true
	}

	switch compactCodexOutboundKey(key) {
	case "installationid", "sessionid", "threadid", "turnid", "conversationid", "windowid",
		"xcodexinstallationid", "xcodexsessionid", "xcodexthreadid",
		"xcodexturnid", "xcodexwindowid", "xcodexturnmetadata",
		"turnmetadata", "promptcachekey",
		"clientrequestid", "requestid", "correlationid", "traceid", "spanid",
		"traceparent", "tracestate", "baggage", "sentrytrace",
		"xclientrequestid", "xrequestid", "xcorrelationid",
		"xamzntraceid", "xcloudtracecontext", "xb3traceid",
		"xb3spanid", "xb3sampled", "ubertraceid",
		"grpctracebin", "xotspancontext", "xdatadogtraceid",
		"xdatadogparentid", "xdatadogsamplingpriority", "xdatadogorigin",
		"newrelic", "xnewrelicid", "xnewrelictransaction",
		"forwarded", "xforwardedfor", "xforwardedhost", "xforwardedproto",
		"xforwardedport", "xforwardedserver", "xoriginalforwardedfor",
		"xrealip", "xclientip", "clientip", "xclusterclientip",
		"trueclientip", "cfconnectingip", "fastlyclientip",
		"flyclientip", "xenvoyexternaladdress", "xappengineuserip",
		"parentthreadid", "forkedfromthreadid", "rootthreadid",
		"parentturnid", "forkedfromturnid", "rootturnid",
		"xcodexparentthreadid", "xcodexforkedfromthreadid",
		"xcodexrootthreadid", "xcodexparentturnid",
		"xcodexforkedfromturnid", "xcodexrootturnid":
		return true
	}
	return false
}

func isCodexOutboundMetadataKey(key string) bool {
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	if _, ok := codexOutboundMetadataKeys[lowerKey]; ok {
		return true
	}
	normalized := normalizeCodexOutboundKey(key)
	if _, ok := codexOutboundMetadataKeys[normalized]; ok {
		return true
	}
	switch compactCodexOutboundKey(key) {
	case "parentthreadid", "forkedfromthreadid", "rootthreadid",
		"parentturnid", "forkedfromturnid", "rootturnid",
		"workspaces", "workspace", "workspaceroot", "workspaceroots",
		"gitremote", "gitremoteurl", "remoteurl", "repositoryurl", "repourl",
		"repositoryfingerprint", "commithash", "headcommit", "dirty",
		"sandbox", "sandboxmode",
		"requestkind", "turnstartedatunixms", "toolnames",
		"mcpservers", "mcpservernames", "mcptools", "mcptoolnames",
		"pluginnames", "plugins", "pluginpath", "pluginpaths", "pluginscriptpath",
		"skillnames", "skills", "skillpath", "skillpaths", "skillroot",
		"skillrepositoryurl", "scriptpath", "artifactpath", "toolcatalog":
		return true
	default:
		return false
	}
}

// sanitizeCodexOutboundHeaders is the final HTTP/WS handshake boundary.
// It deliberately runs after all account overrides and identity construction
// so later compatibility code cannot re-introduce client or proxy IDs.
func sanitizeCodexOutboundHeaders(headers http.Header) bool {
	return sanitizeCodexOutboundHeadersWithFingerprint(headers, nil)
}

// sanitizeCodexOutboundHeadersWithFingerprint removes client identifiers while
// retaining only values produced by the current gateway fingerprint attempt.
// Matching is exact and source-bound; UUID shape or other value formats are
// never used as proof of gateway ownership.
func sanitizeCodexOutboundHeadersWithFingerprint(
	headers http.Header,
	ids *codexFingerprintIDs,
) bool {
	return sanitizeCodexOutboundHeadersWithFingerprintAndAffinity(headers, ids, nil)
}

func sanitizeCodexOutboundHeadersWithFingerprintAndAffinity(
	headers http.Header,
	ids *codexFingerprintIDs,
	affinity *openAIGatewaySessionAffinity,
) bool {
	if headers == nil {
		return false
	}
	changed := false
	removedCount := 0
	for key := range headers {
		if !isCodexOutboundIdentifierKey(key) {
			continue
		}
		if isCodexOutboundTurnMetadataKey(key) {
			rebuilt, keep := sanitizeGatewayTurnMetadataHeader(headers.Get(key), ids)
			if keep {
				if headers.Get(key) != rebuilt {
					headers.Set(key, rebuilt)
					changed = true
				}
				continue
			}
		}
		if isGatewayCodexIdentifierHeaderValue(key, headers.Get(key), ids) ||
			isGatewayOpenAIAffinityHeaderValue(key, headers.Get(key), affinity) {
			continue
		}
		delete(headers, key)
		changed = true
		removedCount++
	}
	// r3 恢复语义：终态删除后把亲和隔离值重新写回（session/full 的收敛头 sink 会
	// 覆盖掉此前设置的亲和值，删除后必须恢复，r3 生产即如此）。machine 不恢复
	// 下划线头——machine 规格要求连字符假名头承载会话身份，下划线一律删除。
	if affinity != nil && (ids == nil || ids.mode != codexFingerprintMachine) {
		restore := func(name, value string) {
			value = strings.TrimSpace(value)
			if value == "" {
				return
			}
			if headers.Get(name) != value {
				headers.Set(name, value)
				changed = true
			}
		}
		restore("session_id", affinity.sessionID)
		restore("conversation_id", affinity.conversationID)
	}
	if removedCount > 0 {
		slog.Debug(
			"openai.identifier_sanitized",
			"surface", "headers",
			"removed_count", removedCount,
		)
	}
	return changed
}

func sanitizeCodexOutboundRequest(req *http.Request) bool {
	return sanitizeCodexOutboundRequestWithFingerprint(req, nil)
}

func sanitizeCodexOutboundRequestWithFingerprint(req *http.Request, ids *codexFingerprintIDs) bool {
	if req == nil {
		return false
	}
	return sanitizeCodexOutboundRequestWithFingerprintAndAffinity(
		req,
		ids,
		openAIGatewaySessionAffinityFromContext(req.Context()),
	)
}

func sanitizeCodexOutboundRequestWithFingerprintAndAffinity(
	req *http.Request,
	ids *codexFingerprintIDs,
	affinity *openAIGatewaySessionAffinity,
) bool {
	if req == nil {
		return false
	}
	return sanitizeCodexOutboundHeadersWithFingerprintAndAffinity(req.Header, ids, affinity)
}

// SanitizeCodexOutboundHeaders is the transport-level fallback for callers
// outside the OpenAI gateway service. It removes protocol identifiers,
// client tracing/correlation headers and forwarded client network metadata;
// authentication, proxy, TLS and ordinary content-negotiation headers remain.
func SanitizeCodexOutboundHeaders(headers http.Header) bool {
	return sanitizeCodexOutboundHeaders(headers)
}

// SanitizeCodexOutboundRequest is the request-aware transport fallback. It
// removes raw client identifiers, then restores only gateway-bound session
// affinity carried in the request context.
func SanitizeCodexOutboundRequest(req *http.Request) bool {
	return sanitizeCodexOutboundRequest(req)
}

// sanitizeCodexOutboundMap removes identifier fields recursively from an
// already decoded upstream payload. Extended metadata is removed only below
// client_metadata so user input and tool arguments remain intact.
func sanitizeCodexOutboundMap(value any) bool {
	return sanitizeCodexOutboundMapValueWithFingerprint(value, true, true, nil)
}

func sanitizeCodexOutboundMapValue(value any, protocolEnvelope bool, rootEnvelope bool) bool {
	return sanitizeCodexOutboundMapValueWithFingerprint(value, protocolEnvelope, rootEnvelope, nil)
}

func sanitizeCodexOutboundMapValueWithFingerprint(
	value any,
	protocolEnvelope bool,
	rootEnvelope bool,
	ids *codexFingerprintIDs,
) bool {
	switch current := value.(type) {
	case map[string]any:
		changed := false
		for key, nested := range current {
			normalizedKey := normalizeCodexOutboundKey(key)
			metadataKey := isCodexOutboundMetadataKey(key)
			if protocolEnvelope &&
				(isCodexOutboundIdentifierKey(key) ||
					normalizedKey == "prompt_cache_key" ||
					metadataKey) {
				if normalizedKey == "prompt_cache_key" && isGatewayPromptCacheKeyValue(nested) {
					continue
				}
				if isCodexOutboundTurnMetadataKey(key) {
					if rebuilt, keep := sanitizeGatewayTurnMetadataValue(nested, ids); keep {
						if rebuilt != nested {
							current[key] = rebuilt
							changed = true
						}
						continue
					}
				}
				if isGatewayCodexIdentifierValue(key, nested, ids) {
					continue
				}
				// machine 模式：client_metadata 的 turn_id 属 turn 级字段，按规格
				// 透传（真实 Codex 每 turn 自带随机 turn id，与账号身份不相关）；
				// 其余身份键仍只保留网关签发值。
				if ids != nil && ids.mode == codexFingerprintMachine && normalizedKey == "turn_id" {
					continue
				}
				// machine 模式：metadata 行为字段（sandbox / workspaces / mcp 等，
				// 与 turn-metadata 内同一套透传规格）不属于账号身份，原样透传；
				// 身份关联键仍走上面的签发值判定。仅 metadata 键放行——标识/
				// 追踪键（identifier 非 metadata）不在其列，避免 client 侧追踪头
				// 借道透传。
				if ids != nil &&
					ids.mode == codexFingerprintMachine &&
					metadataKey &&
					!isCodexMachineTurnMetadataIdentityKey(key) {
					continue
				}
				delete(current, key)
				changed = true
				continue
			}
			compactKey := compactCodexOutboundKey(key)
			childProtocolEnvelope := protocolEnvelope &&
				(!rootEnvelope ||
					compactKey == "clientmetadata" ||
					compactKey == "turnmetadata" ||
					compactKey == "xcodexturnmetadata")
			if sanitizeCodexOutboundMapValueWithFingerprint(nested, childProtocolEnvelope, false, ids) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, nested := range current {
			if sanitizeCodexOutboundMapValueWithFingerprint(nested, protocolEnvelope, false, ids) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func isCodexOutboundTurnMetadataKey(key string) bool {
	normalized := normalizeCodexOutboundKey(key)
	return normalized == "x_codex_turn_metadata" || normalized == "turn_metadata"
}

func isGatewayCodexIdentifierValue(key string, value any, ids *codexFingerprintIDs) bool {
	raw, ok := value.(string)
	if !ok {
		return false
	}
	return isGatewayCodexIdentifierString(key, raw, ids)
}

func isGatewayCodexIdentifierHeaderValue(key, value string, ids *codexFingerprintIDs) bool {
	return isGatewayCodexIdentifierString(key, value, ids)
}

func isGatewayCodexIdentifierString(key, value string, ids *codexFingerprintIDs) bool {
	if ids == nil {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	// 仅 machine 模式存在「网关产物可保留」的豁免：
	// - 会话/窗口身份是按值签发的 1:1 假名（HMAC(seed, 原值)），不落在 ids 的
	//   sessionID/threadID 等固定字段上；签发时记入 pseudonymIssued 备忘（见
	//   machinePseudonym），以成员判定作为网关产物证明——绝不用 UUID 形状猜测。
	// - installation 是账号级收敛恒定值（与真实设备安装 ID 同构）。
	// session/device/full 的收敛值不豁免：r3 生产终态 sanitizer 对非 machine
	// 一律 fail-closed 删除（含本网关收敛头），候选版保持该出站形状不变。
	if ids.mode != codexFingerprintMachine {
		return false
	}
	if isCodexMachineIssuedIdentifierValue(key, value, ids) {
		return true
	}
	switch normalizeCodexOutboundKey(key) {
	case "installation_id", "x_codex_installation_id":
		return ids.installationID != "" && value == ids.installationID
	default:
		return false
	}
}

// isCodexMachineIssuedIdentifierValue 判定 value 是否为本次 machine attempt 已签发的
// 假名。只覆盖 machine sink 会改写的身份键（含连字符/下划线两种拼写，normalize 后
// 同一形态）；installation 走上面的等值分支（ids.installationID 恒有值），不在此列。
func isCodexMachineIssuedIdentifierValue(key, value string, ids *codexFingerprintIDs) bool {
	normalized := normalizeCodexOutboundKey(key)
	switch normalized {
	case "session_id", "x_codex_session_id",
		"thread_id", "x_codex_thread_id", "x_client_request_id",
		"parent_thread_id", "x_codex_parent_thread_id",
		"prompt_cache_key":
		_, issued := ids.pseudonymIssued[value]
		return issued
	case "window_id", "x_codex_window_id":
		return isCodexMachineIssuedWindowValue(value, ids)
	default:
		return false
	}
}

// isCodexMachineIssuedWindowValue 判定窗口假名：machineWindowPseudonym 只产生
// 「基础假名」或「基础假名:计数」两种形态（codexMachineWindowPseudonymWith），
// 成员判定同样按这两种形态精确匹配。
func isCodexMachineIssuedWindowValue(value string, ids *codexFingerprintIDs) bool {
	if _, issued := ids.pseudonymIssued[value]; issued {
		return true
	}
	idx := strings.LastIndex(value, ":")
	if idx <= 0 || idx == len(value)-1 {
		return false
	}
	for _, r := range value[idx+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	_, issued := ids.pseudonymIssued[value[:idx]]
	return issued
}

func sanitizeGatewayTurnMetadataHeader(raw string, ids *codexFingerprintIDs) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	// machine：键序保持的过滤式清洗。真实 Codex 的 turn metadata 由 serde 按声明序
	// 序列化，map 重编码会把键序变成字母序，成为可观测的网关痕迹（machine sink 的
	// gjson/sjson 原位改写即为此，见 rewriteCodexMachineTurnMetadata）。清洗只按规则
	// 保留/删除字段、不改写值，保序输出即可。非 machine 维持 r3 原有 map 重建形态。
	if ids != nil && ids.mode == codexFingerprintMachine {
		return sanitizeGatewayMachineTurnMetadataOrdered(trimmed, ids)
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(trimmed), &metadata); err != nil {
		return "", false
	}
	sanitizeGatewayTurnMetadataMap(metadata, ids)
	if len(metadata) == 0 {
		return "", false
	}
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return "", false
	}
	return string(rebuilt), true
}

// sanitizeGatewayMachineTurnMetadataOrdered 是 turn metadata 头/内嵌值的 machine
// 保序清洗：先按 map 语义去重顶层键（保留最后一次出现，与 sanitizeGatewayTurnMetadataMap
// 在 map 上的"后者覆盖"一致），再按 machine 规则过滤——身份键只留网关签发/收敛值，
// 其余键（turn_id、sandbox、compaction 等行为字段）透传。全部字段被删时返回 false。
func sanitizeGatewayMachineTurnMetadataOrdered(raw string, ids *codexFingerprintIDs) (string, bool) {
	if raw == "" || !gjson.Valid(raw) {
		return "", false
	}
	metadata := gjson.Parse(raw)
	if !metadata.IsObject() {
		return "", false
	}
	deduped, _ := dedupeCodexTurnMetadataTopLevelKeys(metadata)
	metadata = gjson.Parse(deduped)

	var b strings.Builder
	b.WriteByte('{')
	wrote := false
	metadata.ForEach(func(k, v gjson.Result) bool {
		key := k.String()
		if !isGatewayCodexIdentifierValue(key, v.Value(), ids) &&
			isCodexMachineTurnMetadataIdentityKey(key) {
			return true
		}
		if wrote {
			b.WriteByte(',')
		}
		b.WriteString(k.Raw)
		b.WriteByte(':')
		b.WriteString(v.Raw)
		wrote = true
		return true
	})
	if !wrote {
		return "", false
	}
	b.WriteByte('}')
	return b.String(), true
}

func sanitizeGatewayTurnMetadataValue(value any, ids *codexFingerprintIDs) (any, bool) {
	raw, ok := value.(string)
	if !ok {
		return nil, false
	}
	rebuilt, keep := sanitizeGatewayTurnMetadataHeader(raw, ids)
	if !keep {
		return nil, false
	}
	return rebuilt, true
}

func sanitizeGatewayTurnMetadataMap(metadata map[string]any, ids *codexFingerprintIDs) bool {
	if metadata == nil {
		return false
	}
	changed := false
	for key, value := range metadata {
		if isGatewayCodexIdentifierValue(key, value, ids) {
			continue
		}
		// machine 模式：turn 级/行为字段透传（turn_id、sandbox、sandbox_mode、
		// agent_name、thread_source、compaction、workspaces 等，见 machine chain
		// 规格 I4「turn 级字段透传」）；身份关联键（session/thread/window/
		// installation/parent 等）仍只保留网关签发值。
		if ids != nil && ids.mode == codexFingerprintMachine && !isCodexMachineTurnMetadataIdentityKey(key) {
			continue
		}
		delete(metadata, key)
		changed = true
	}
	return changed
}

// isCodexMachineTurnMetadataIdentityKey machine turn metadata 中的身份关联键：
// 这些键的原始值属于客户端真实标识，未签发即删除；其余键按行为字段透传。
func isCodexMachineTurnMetadataIdentityKey(key string) bool {
	switch normalizeCodexOutboundKey(key) {
	case "session_id", "x_codex_session_id",
		"thread_id", "x_codex_thread_id", "x_client_request_id",
		"installation_id", "x_codex_installation_id",
		"window_id", "x_codex_window_id",
		"conversation_id",
		"parent_thread_id", "x_codex_parent_thread_id",
		"forked_from_thread_id", "root_thread_id",
		"prompt_cache_key":
		return true
	default:
		return false
	}
}

func isGatewayPromptCacheKeyValue(value any) bool {
	key, ok := value.(string)
	if !ok {
		return false
	}
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, openAIOutboundPromptCacheKeyPrefix) {
		return false
	}
	if len(key) > openAIOutboundPromptCacheKeyMaxLength {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(key[len(openAIOutboundPromptCacheKeyPrefix):])
	if err != nil {
		return false
	}
	return len(decoded) == openAIOutboundPromptCacheKeyDigestBytes
}

// sanitizeCodexOutboundJSON is the raw-body seam used by HTTP passthrough,
// WS ingress and Live. It avoids a full decode for ordinary requests that do
// not contain any target key, while failing closed if a suspicious JSON body
// cannot be decoded for sanitization.
func sanitizeCodexOutboundJSON(body []byte) ([]byte, bool, error) {
	return sanitizeCodexOutboundJSONWithFingerprint(body, nil)
}

func sanitizeCodexOutboundJSONWithFingerprint(
	body []byte,
	ids *codexFingerprintIDs,
) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}
	if !containsCodexOutboundSanitizationMarker(body) {
		return body, false, nil
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		slog.Warn(
			"openai.identifier_sanitization_failed",
			"surface", "json_body",
			"error_kind", "invalid_json",
		)
		return body, false, fmt.Errorf("decode Codex outbound payload for identifier sanitization: %w", err)
	}
	if !sanitizeCodexOutboundMapValueWithFingerprint(decoded, true, true, ids) {
		return body, false, nil
	}
	sanitized, err := json.Marshal(decoded)
	if err != nil {
		slog.Warn(
			"openai.identifier_sanitization_failed",
			"surface", "json_body",
			"error_kind", "encode_json",
		)
		return body, false, fmt.Errorf("encode Codex outbound payload after identifier sanitization: %w", err)
	}
	slog.Debug(
		"openai.identifier_sanitized",
		"surface", "json_body",
		"changed", true,
	)
	return sanitized, true, nil
}

func containsCodexOutboundSanitizationMarker(body []byte) bool {
	for i := 0; i < len(body); i++ {
		if body[i] != '"' {
			continue
		}

		keyStart := i + 1
		keyEnd := keyStart
		escaped := false
		for keyEnd < len(body) {
			switch body[keyEnd] {
			case '\\':
				escaped = true
				keyEnd += 2
				continue
			case '"':
				goto keyComplete
			default:
				keyEnd++
			}
		}
		return false

	keyComplete:
		next := keyEnd + 1
		for next < len(body) {
			switch body[next] {
			case ' ', '\t', '\r', '\n':
				next++
			default:
				goto separatorFound
			}
		}
		return false

	separatorFound:
		i = keyEnd
		if next >= len(body) || body[next] != ':' {
			continue
		}
		// Any escaped object key must be decoded before classification. JSON
		// Unicode escapes can otherwise hide protocol keys from the fast path.
		if escaped {
			return true
		}

		key := string(body[keyStart:keyEnd])
		compactKey := compactCodexOutboundKey(key)
		if isCodexOutboundIdentifierKey(key) ||
			isCodexOutboundMetadataKey(key) ||
			compactKey == "clientmetadata" ||
			compactKey == "turnmetadata" ||
			compactKey == "xcodexturnmetadata" {
			return true
		}
	}
	return false
}
