package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeCodexOutboundHeaders_RemovesAllIdentifierCarriers(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Codex-Installation-ID", "install-client")
	headers.Set("Session-ID", "session-client")
	headers.Set("session_id", "session-proxy")
	headers.Set("Thread-Id", "thread-client")
	headers.Set("turn_id", "turn-client")
	headers.Set("X-Codex-Window-ID", "thread-client:0")
	headers.Set("X-Codex-Turn-Metadata", `{"installation_id":"i","session_id":"s","thread_id":"t","turn_id":"u"}`)
	headers.Set("X-Codex-Turn-State", "turn-state-local")
	headers.Set("X-Codex-Parent-Thread-ID", "parent-thread-client")
	headers.Set("X-Codex-Root-Turn-ID", "root-turn-client")
	headers.Set("X_Codex_Session_ID", "session-underscore")
	headers.Set("X_Codex_Thread_ID", "thread-underscore")
	headers.Set("X_Codex_Turn_ID", "turn-underscore")
	headers.Set("X-Client-Request-ID", "client-request-id")
	headers.Set("X-Request-ID", "request-id")
	headers.Set("Traceparent", "00-client-trace-client-span-01")
	headers.Set("Tracestate", "vendor=client")
	headers.Set("Baggage", "tenant=client")
	headers.Set("X-Forwarded-For", "192.0.2.10")
	headers.Set("X-Forwarded-Host", "client.example")
	headers.Set("CF-Connecting-IP", "192.0.2.10")
	headers.Set("True-Client-IP", "192.0.2.10")
	headers.Set("X-Real-IP", "192.0.2.10")
	headers.Set("X-Datadog-Trace-ID", "123456")
	headers.Set("Newrelic", "client-trace")
	headers.Set("Accept-Language", "zh-CN")

	require.True(t, sanitizeCodexOutboundHeaders(headers))
	for _, key := range []string{
		"X-Codex-Installation-ID",
		"Session-ID",
		"session_id",
		"Thread-Id",
		"turn_id",
		"X-Codex-Window-ID",
		"X-Codex-Turn-Metadata",
		"X-Codex-Parent-Thread-ID",
		"X-Codex-Root-Turn-ID",
		"X_Codex_Session_ID",
		"X_Codex_Thread_ID",
		"X_Codex_Turn_ID",
		"X-Client-Request-ID",
		"X-Request-ID",
		"Traceparent",
		"Tracestate",
		"Baggage",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Real-IP",
		"X-Datadog-Trace-ID",
		"Newrelic",
	} {
		require.Empty(t, headers.Get(key), key)
	}
	require.Equal(t, "turn-state-local", headers.Get("X-Codex-Turn-State"))
	require.Equal(t, "zh-CN", headers.Get("Accept-Language"))
}

func TestSanitizeCodexOutboundRequest_RestoresOnlyBoundSessionAffinity(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set("session_id", "raw-client-session")
	req.Header.Set("conversation_id", "raw-client-conversation")
	req.Header.Set("x-codex-thread-id", "raw-client-thread")
	req.Header.Set("x-request-id", "raw-request-id")

	isolatedSessionID := isolateOpenAISessionID(77, "raw-client-session")
	isolatedConversationID := isolateOpenAISessionID(77, "raw-client-conversation")
	req = WithOpenAIUpstreamSessionAffinity(req, isolatedSessionID, isolatedConversationID)

	require.True(t, sanitizeCodexOutboundRequest(req))
	require.Equal(t, isolatedSessionID, req.Header.Get("session_id"))
	require.Equal(t, isolatedConversationID, req.Header.Get("conversation_id"))
	require.NotEqual(t, "raw-client-session", req.Header.Get("session_id"))
	require.NotEqual(t, "raw-client-conversation", req.Header.Get("conversation_id"))
	require.Empty(t, req.Header.Get("x-codex-thread-id"))
	require.Empty(t, req.Header.Get("x-request-id"))
}

func TestSanitizeCodexOutboundRequest_DropsUnboundRawSessionIdentifiers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.Header.Set("session_id", "raw-client-session")
	req.Header.Set("conversation_id", "raw-client-conversation")

	require.True(t, sanitizeCodexOutboundRequest(req))
	require.Empty(t, req.Header.Get("session_id"))
	require.Empty(t, req.Header.Get("conversation_id"))
}

func TestSanitizeCodexOutboundJSON_RemovesNestedIdentifiersAndMetadata(t *testing.T) {
	body := []byte(`{
		"installation_id": "install-client",
		"session_id": "session-client",
		"thread_id": "thread-client",
		"turn_id": "turn-client",
		"prompt_cache_key": "client-session-cache-key",
		"client_metadata": {
			"x-codex-installation-id": "install-client",
			"session_id": "session-client",
			"x-codex-parent-thread-id": "parent-thread-client",
			"forked-from-turn-id": "forked-turn-client",
			"plugins": ["local-plugin"],
			"plugin_path": "/Users/private/.codex/plugins/local-plugin",
			"skills": ["local-skill"],
			"skill_root": "/Users/private/.codex/skills/local-skill",
			"mcpServerNames": ["private-mcp"],
			"gitRemoteUrl": "ssh://private/repository",
			"repository_url": "ssh://private/repository",
			"tool-catalog": ["local-tool"],
			"nested": {
				"thread_id": "thread-client",
				"turn_id": "turn-client",
				"trace": "keep"
			},
			"x-codex-turn-metadata": "{\"installation_id\":\"i\",\"session_id\":\"s\",\"thread_id\":\"t\",\"turn_id\":\"u\"}"
		},
		"input": [{"type": "message", "text": "keep"}]
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(sanitized, &decoded))
	for _, key := range []string{"installation_id", "session_id", "thread_id", "turn_id"} {
		_, exists := decoded[key]
		require.False(t, exists, key)
	}
	require.NotContains(t, decoded, "prompt_cache_key")
	require.Equal(t, []any{map[string]any{"type": "message", "text": "keep"}}, decoded["input"])

	clientMetadata, ok := decoded["client_metadata"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, clientMetadata, "x-codex-installation-id")
	require.NotContains(t, clientMetadata, "session_id")
	require.NotContains(t, clientMetadata, "x-codex-turn-metadata")
	require.NotContains(t, clientMetadata, "x-codex-parent-thread-id")
	require.NotContains(t, clientMetadata, "forked-from-turn-id")
	require.NotContains(t, clientMetadata, "plugins")
	require.NotContains(t, clientMetadata, "plugin_path")
	require.NotContains(t, clientMetadata, "skills")
	require.NotContains(t, clientMetadata, "skill_root")
	require.NotContains(t, clientMetadata, "mcpServerNames")
	require.NotContains(t, clientMetadata, "gitRemoteUrl")
	require.NotContains(t, clientMetadata, "repository_url")
	require.NotContains(t, clientMetadata, "tool-catalog")
	nested, ok := clientMetadata["nested"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "keep", nested["trace"])
	require.NotContains(t, nested, "thread_id")
	require.NotContains(t, nested, "turn_id")
}

func TestSanitizeCodexOutboundJSON_NoOpWithoutTargetFields(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"message","text":"hello"}]}`)
	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, body, sanitized)
}

func TestSanitizeCodexOutboundJSON_DetectsCompatibilitySpellings(t *testing.T) {
	body := []byte(`{
		"prompt-cache-key": "client-session-cache-key",
		"parent-thread-id": "parent-thread-client",
		"workspaces": [{"root": "/Users/private/project"}]
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(sanitized, &decoded))
	require.NotContains(t, decoded, "prompt-cache-key")
	require.NotContains(t, decoded, "parent-thread-id")
	require.NotContains(t, decoded, "workspaces")
}

func TestSanitizeCodexOutboundJSON_DetectsEscapedKeys(t *testing.T) {
	body := []byte(`{
		"\u0073ession_id": "client-session",
		"\u0070rompt_cache_key": "client-cache",
		"\u0077orkspaces": [{"root": "/Users/private/project"}],
		"messages": [{"role": "user", "content": "keep"}]
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(sanitized), "client-session")
	require.NotContains(t, string(sanitized), "client-cache")
	require.NotContains(t, string(sanitized), "private/project")
	require.Contains(t, string(sanitized), `"messages"`)
}

func TestSanitizeCodexOutboundJSON_DetectsUnderscoreCodexKeys(t *testing.T) {
	body := []byte(`{
		"x_codex_session_id": "session-client",
		"x_codex_thread_id": "thread-client",
		"x_codex_turn_id": "turn-client",
		"x_codex_turn_state": {"turn_id":"nested-turn"},
		"x_codex_parent_thread_id": "parent-thread-client",
		"input": [{"type": "message", "text": "keep"}]
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(sanitized), "session-client")
	require.NotContains(t, string(sanitized), "thread-client")
	require.NotContains(t, string(sanitized), "turn-client")
	require.NotContains(t, string(sanitized), "nested-turn")
	require.NotContains(t, string(sanitized), "parent-thread-client")
	require.Contains(t, string(sanitized), `"input"`)
}

func TestSanitizeCodexOutboundJSON_DetectsCamelCaseAndTraceMetadata(t *testing.T) {
	body := []byte(`{
		"sessionId": "session-client",
		"threadId": "thread-client",
		"turnId": "turn-client",
		"promptCacheKey": "cache-client",
		"clientMetadata": {
			"installationId": "installation-client",
			"parentThreadId": "parent-thread-client",
			"traceparent": "00-client-trace-client-span-01",
			"mcpServers": ["local-mcp"],
			"gitRemote": "ssh://private/repository"
		},
		"messages": [{"role": "user", "content": "keep"}]
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)
	for _, value := range []string{
		"session-client",
		"thread-client",
		"turn-client",
		"cache-client",
		"installation-client",
		"parent-thread-client",
		"client-trace",
		"local-mcp",
		"private/repository",
	} {
		require.NotContains(t, string(sanitized), value)
	}
	require.Contains(t, string(sanitized), `"messages"`)
	require.Contains(t, string(sanitized), `"keep"`)
}

func TestSanitizeCodexOutboundJSON_PreservesUserDataWithSameFieldNames(t *testing.T) {
	body := []byte(`{
		"model": "gpt-5.6-sol",
		"input": [{
			"type": "message",
			"content": {
				"session_id": "user-provided-data",
				"thread_id": "user-provided-data",
				"client_metadata": {
					"installation_id": "user-provided-data",
					"plugin_path": "/user/provided/plugin",
					"repository_url": "https://user.example/repository",
					"turn_metadata": {
						"turn_id": "user-provided-data",
						"workspace": "user-provided-data"
					}
				}
			}
		}],
		"client_metadata": {
			"session_id": "protocol-session",
			"workspace": "/private/workspace"
		}
	}`)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(sanitized, &decoded))
	input := decoded["input"].([]any)
	content := input[0].(map[string]any)["content"].(map[string]any)
	require.Equal(t, "user-provided-data", content["session_id"])
	require.Equal(t, "user-provided-data", content["thread_id"])
	userMetadata := content["client_metadata"].(map[string]any)
	require.Equal(t, "user-provided-data", userMetadata["installation_id"])
	require.Equal(t, "/user/provided/plugin", userMetadata["plugin_path"])
	require.Equal(t, "https://user.example/repository", userMetadata["repository_url"])
	userTurnMetadata := userMetadata["turn_metadata"].(map[string]any)
	require.Equal(t, "user-provided-data", userTurnMetadata["turn_id"])
	require.Equal(t, "user-provided-data", userTurnMetadata["workspace"])
	clientMetadata := decoded["client_metadata"].(map[string]any)
	require.NotContains(t, clientMetadata, "session_id")
	require.NotContains(t, clientMetadata, "workspace")
}

func TestSanitizeCodexOutboundJSON_FailsClosedForSuspiciousInvalidJSON(t *testing.T) {
	_, _, err := sanitizeCodexOutboundJSON([]byte(`{"session_id":`))
	require.Error(t, err)
}

func TestSanitizeCodexOutboundJSON_DeepMetadataDoesNotCrossIntoUserContent(t *testing.T) {
	const depth = 128

	protocolLeaf := map[string]any{"session_id": "protocol-session"}
	protocolRoot := protocolLeaf
	userLeaf := map[string]any{"session_id": "user-session"}
	userRoot := userLeaf
	for i := 0; i < depth; i++ {
		protocolRoot = map[string]any{"nested": protocolRoot}
		userRoot = map[string]any{"nested": userRoot}
	}

	body, err := json.Marshal(map[string]any{
		"client_metadata": protocolRoot,
		"input": []any{map[string]any{
			"type": "message",
			"content": map[string]any{
				"client_metadata": userRoot,
			},
		}},
	})
	require.NoError(t, err)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(sanitized, &decoded))

	protocolCursor := decoded["client_metadata"].(map[string]any)
	userCursor := decoded["input"].([]any)[0].(map[string]any)["content"].(map[string]any)["client_metadata"].(map[string]any)
	for i := 0; i < depth; i++ {
		protocolCursor = protocolCursor["nested"].(map[string]any)
		userCursor = userCursor["nested"].(map[string]any)
	}
	require.NotContains(t, protocolCursor, "session_id")
	require.Equal(t, "user-session", userCursor["session_id"])
}

func BenchmarkSanitizeCodexOutboundJSON_NoMarkerFastPath(b *testing.B) {
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"message","text":"` +
		string(bytes.Repeat([]byte("x"), 64*1024)) +
		`"}]}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		sanitized, changed, err := sanitizeCodexOutboundJSON(body)
		if err != nil || changed || len(sanitized) != len(body) {
			b.Fatalf("unexpected fast-path result: changed=%v err=%v", changed, err)
		}
	}
}

func BenchmarkSanitizeCodexOutboundJSON_WithMetadata(b *testing.B) {
	body := []byte(`{
		"model":"gpt-5.6-sol",
		"prompt_cache_key":"client-session",
		"client_metadata":{
			"session_id":"client-session",
			"traceparent":"00-client-trace-client-span-01",
			"workspaces":[{"root":"/private/project"}]
		},
		"input":[{"type":"message","text":"hello"}]
	}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		_, changed, err := sanitizeCodexOutboundJSON(body)
		if err != nil || !changed {
			b.Fatalf("unexpected sanitize result: changed=%v err=%v", changed, err)
		}
	}
}
