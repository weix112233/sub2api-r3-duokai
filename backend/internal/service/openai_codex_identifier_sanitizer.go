package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	if headers == nil {
		return false
	}
	changed := false
	for key := range headers {
		if !isCodexOutboundIdentifierKey(key) {
			continue
		}
		delete(headers, key)
		changed = true
	}
	return changed
}

type openAIUpstreamSessionAffinityContextKey struct{}

type openAIUpstreamSessionAffinity struct {
	sessionID      string
	conversationID string
}

func shouldBindOpenAIUpstreamSessionAffinity(account *Account) bool {
	return account != nil &&
		account.Type == AccountTypeOAuth &&
		!account.IsOpenAIAgentIdentity()
}

// WithOpenAIUpstreamSessionAffinity binds gateway-generated session affinity
// to the request context. Callers must pass only values derived locally from
// real request session semantics, never raw client identifiers.
func WithOpenAIUpstreamSessionAffinity(req *http.Request, sessionID, conversationID string) *http.Request {
	if req == nil {
		return nil
	}
	affinity := openAIUpstreamSessionAffinity{
		sessionID:      strings.TrimSpace(sessionID),
		conversationID: strings.TrimSpace(conversationID),
	}
	return req.WithContext(context.WithValue(
		req.Context(),
		openAIUpstreamSessionAffinityContextKey{},
		affinity,
	))
}

func openAIUpstreamSessionAffinityFromRequest(req *http.Request) openAIUpstreamSessionAffinity {
	if req == nil {
		return openAIUpstreamSessionAffinity{}
	}
	affinity, _ := req.Context().Value(openAIUpstreamSessionAffinityContextKey{}).(openAIUpstreamSessionAffinity)
	return affinity
}

func sanitizeCodexOutboundHeadersWithSessionAffinity(
	headers http.Header,
	sessionID string,
	conversationID string,
) bool {
	changed := sanitizeCodexOutboundHeaders(headers)
	if headers == nil {
		return changed
	}
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
	restore("session_id", sessionID)
	restore("conversation_id", conversationID)
	return changed
}

func sanitizeCodexOutboundRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	affinity := openAIUpstreamSessionAffinityFromRequest(req)
	return sanitizeCodexOutboundHeadersWithSessionAffinity(
		req.Header,
		affinity.sessionID,
		affinity.conversationID,
	)
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
	return sanitizeCodexOutboundMapValue(value, true, true)
}

func sanitizeCodexOutboundMapValue(value any, protocolEnvelope bool, rootEnvelope bool) bool {
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
			if sanitizeCodexOutboundMapValue(nested, childProtocolEnvelope, false) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, nested := range current {
			if sanitizeCodexOutboundMapValue(nested, protocolEnvelope, false) {
				changed = true
			}
		}
		return changed
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
	if len(body) == 0 {
		return body, false, nil
	}
	if !containsCodexOutboundSanitizationMarker(body) {
		return body, false, nil
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return body, false, fmt.Errorf("decode Codex outbound payload for identifier sanitization: %w", err)
	}
	if !sanitizeCodexOutboundMap(decoded) {
		return body, false, nil
	}
	sanitized, err := json.Marshal(decoded)
	if err != nil {
		return body, false, fmt.Errorf("encode Codex outbound payload after identifier sanitization: %w", err)
	}
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
