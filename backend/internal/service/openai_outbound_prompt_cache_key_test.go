package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestRewriteOpenAIOutboundPromptCacheKey_PreservesConversationAnchorAcrossContentGrowth(t *testing.T) {
	base := []byte(`{
		"model":"gpt-5.4",
		"installation_id":"client-install",
		"tools":[{"type":"function","name":"lookup","description":"lookup"}],
		"instructions":"You are a coding assistant.",
		"input":[{"type":"message","role":"user","content":"first question"}]
	}`)
	later := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup","description":"lookup"}],
		"instructions":"You are a coding assistant.",
		"input":[
			{"type":"message","role":"user","content":"first question"},
			{"type":"message","role":"assistant","content":"answer"},
			{"type":"message","role":"user","content":"follow up"}
		]
	}`)

	sanitizedBase, _, err := sanitizeCodexOutboundJSON(base)
	require.NoError(t, err)
	sanitizedLater, _, err := sanitizeCodexOutboundJSON(later)
	require.NoError(t, err)

	first, firstKey, err := rewriteOpenAIOutboundPromptCacheKeyForSession(sanitizedBase, "")
	require.NoError(t, err)
	second, secondKey, err := rewriteOpenAIOutboundPromptCacheKeyForSession(sanitizedLater, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
	require.Equal(t, firstKey, secondKey)
	require.LessOrEqual(t, len(firstKey), openAIOutboundPromptCacheKeyMaxLength)
	require.Len(t, firstKey, 48)
	require.True(t, isGatewayPromptCacheKeyValue(firstKey))

	var firstDecoded map[string]any
	require.NoError(t, json.Unmarshal(first, &firstDecoded))
	require.Equal(t, firstKey, firstDecoded["prompt_cache_key"])
	require.NotContains(t, string(first), "client-install")

	var secondDecoded map[string]any
	require.NoError(t, json.Unmarshal(second, &secondDecoded))
	require.Equal(t, secondKey, secondDecoded["prompt_cache_key"])
}

func TestRewriteOpenAIOutboundPromptCacheKey_SeparatesSessionsSharingStablePrefix(t *testing.T) {
	first := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup","description":"lookup"}],
		"instructions":"You are a coding assistant.",
		"input":[{"type":"message","role":"user","content":"first session"}]
	}`)
	second := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup","description":"lookup"}],
		"instructions":"You are a coding assistant.",
		"input":[{"type":"message","role":"user","content":"second session"}]
	}`)

	_, firstKey, err := rewriteOpenAIOutboundPromptCacheKeyForSession(first, "")
	require.NoError(t, err)
	_, secondKey, err := rewriteOpenAIOutboundPromptCacheKeyForSession(second, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
	require.NotEmpty(t, secondKey)
	require.NotEqual(t, firstKey, secondKey)
}

func TestRewriteOpenAIOutboundPromptCacheKey_RejectsSharedPrefixWithoutConversationAnchor(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup","description":"lookup"}],
		"instructions":"You are a coding assistant."
	}`)

	rewritten, key, err := rewriteOpenAIOutboundPromptCacheKeyForSession(body, "")
	require.NoError(t, err)
	require.Empty(t, key)
	require.NotContains(t, string(rewritten), "prompt_cache_key")
}

func TestRewriteOpenAIOutboundPromptCacheKey_UsesConversationAnchorWithoutStablePrefix(t *testing.T) {
	first := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"message","role":"user","content":"first question"}]
	}`)
	second := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"message","role":"user","content":"different question"}]
	}`)

	_, firstKey, err := rewriteOpenAIOutboundPromptCacheKey(first, "")
	require.NoError(t, err)
	_, secondKey, err := rewriteOpenAIOutboundPromptCacheKey(second, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
	require.NotEmpty(t, secondKey)
	require.NotEqual(t, firstKey, secondKey)
}

func TestRewriteOpenAIOutboundPromptCacheKey_PreservesClientAffinityOpaque(t *testing.T) {
	first := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"client-session",
		"input":[{"type":"message","role":"user","content":"first question"}]
	}`)
	later := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"client-session",
		"input":[{"type":"message","role":"user","content":"follow up"}]
	}`)

	rewrittenFirst, firstKey, err := rewriteOpenAIOutboundPromptCacheKey(first, "")
	require.NoError(t, err)
	rewrittenLater, laterKey, err := rewriteOpenAIOutboundPromptCacheKey(later, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
	require.Equal(t, firstKey, laterKey)
	require.NotContains(t, string(rewrittenFirst), "client-session")
	require.NotContains(t, string(rewrittenLater), "client-session")
	require.Contains(t, string(rewrittenFirst), openAIOutboundPromptCacheKeyPrefix)
	require.Contains(t, string(rewrittenLater), openAIOutboundPromptCacheKeyPrefix)
}

func TestRewriteOpenAIOutboundPromptCacheKey_DiffersForStablePrefixChanges(t *testing.T) {
	base := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup"}],
		"instructions":"instruction-a",
		"input":[{"type":"message","role":"user","content":"question"}]
	}`)
	changed := []byte(`{
		"model":"gpt-5.4",
		"tools":[{"type":"function","name":"lookup"}],
		"instructions":"instruction-b",
		"input":[{"type":"message","role":"user","content":"question"}]
	}`)

	_, firstKey, err := rewriteOpenAIOutboundPromptCacheKey(base, "")
	require.NoError(t, err)
	_, secondKey, err := rewriteOpenAIOutboundPromptCacheKey(changed, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)
	require.NotEmpty(t, secondKey)
	require.NotEqual(t, firstKey, secondKey)
}

func TestRewriteOpenAIOutboundPromptCacheKey_UsesContentAnchorWithoutClientKey(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"message","role":"user","content":"question"}]
	}`)

	rewritten, key, err := rewriteOpenAIOutboundPromptCacheKey(body, "")
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Contains(t, string(rewritten), openAIOutboundPromptCacheKeyPrefix)
}

func TestRewriteOpenAIOutboundPromptCacheKey_RemovesKeyWithoutAnyAffinity(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4"}`)

	rewritten, key, err := rewriteOpenAIOutboundPromptCacheKey(body, "")
	require.NoError(t, err)
	require.Empty(t, key)
	require.NotContains(t, string(rewritten), "prompt_cache_key")
}

func TestRewriteOpenAIOutboundPromptCacheKey_PreservesGatewayKeyOnFollowUp(t *testing.T) {
	existingKey := deriveOpenAIOutboundPromptCacheKeyFromClientKey("existing-session", "gpt-5.4")
	require.True(t, isGatewayPromptCacheKeyValue(existingKey))
	body := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"` + existingKey + `",
		"input":[{"type":"message","role":"user","content":"follow up"}]
	}`)

	rewritten, key, err := rewriteOpenAIOutboundPromptCacheKey(body, "")
	require.NoError(t, err)
	require.Equal(t, existingKey, key)
	require.Contains(t, string(rewritten), `"prompt_cache_key":"`+existingKey+`"`)
}

func TestRewriteOpenAIOutboundPromptCacheKey_MigratesOversizedLegacyKey(t *testing.T) {
	legacyKey := "pcv1-" + strings.Repeat("a", 64)
	require.Greater(t, len(legacyKey), openAIOutboundPromptCacheKeyMaxLength)
	require.False(t, isGatewayPromptCacheKeyValue(legacyKey))

	body := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"` + legacyKey + `",
		"input":[{"type":"message","role":"user","content":"follow up"}]
	}`)

	rewritten, key, err := rewriteOpenAIOutboundPromptCacheKey(body, "")
	require.NoError(t, err)
	require.True(t, isGatewayPromptCacheKeyValue(key))
	require.LessOrEqual(t, len(key), openAIOutboundPromptCacheKeyMaxLength)
	require.NotEqual(t, legacyKey, key)
	require.NotContains(t, string(rewritten), legacyKey)
}

func TestRewriteOpenAIOutboundPromptCacheKey_StableClientAffinitySurvivesContentChange(t *testing.T) {
	first := []byte(`{
		"model":"gpt-5.6-sol",
		"prompt_cache_key":"client-thread",
		"instructions":"stable instructions",
		"input":[{"type":"message","role":"user","content":"first turn"}]
	}`)
	later := []byte(`{
		"model":"gpt-5.6-sol",
		"prompt_cache_key":"client-thread",
		"instructions":"stable instructions",
		"input":[
			{"type":"message","role":"user","content":"first turn"},
			{"type":"message","role":"assistant","content":"long answer"},
			{"type":"message","role":"user","content":"follow up"}
		]
	}`)

	sanitizedFirst, _, err := sanitizeCodexOutboundJSON(first)
	require.NoError(t, err)
	sanitizedLater, _, err := sanitizeCodexOutboundJSON(later)
	require.NoError(t, err)

	fallbackKey := deriveOpenAIOutboundPromptCacheKeyFallback("client-thread", "gpt-5.6-sol")
	rewrittenFirst, firstKey, err := rewriteOpenAIOutboundPromptCacheKeyWithFallback(
		sanitizedFirst,
		"gpt-5.6-sol",
		fallbackKey,
	)
	require.NoError(t, err)
	rewrittenLater, laterKey, err := rewriteOpenAIOutboundPromptCacheKeyWithFallback(
		sanitizedLater,
		"gpt-5.6-sol",
		fallbackKey,
	)
	require.NoError(t, err)

	require.NotEmpty(t, firstKey)
	require.Equal(t, firstKey, laterKey)
	require.Equal(t, firstKey, gjson.GetBytes(rewrittenFirst, "prompt_cache_key").String())
	require.Equal(t, firstKey, gjson.GetBytes(rewrittenLater, "prompt_cache_key").String())
	require.NotContains(t, string(rewrittenFirst), "client-thread")
	require.NotContains(t, string(rewrittenLater), "client-thread")
	require.NotEqual(
		t,
		firstKey,
		deriveOpenAIOutboundPromptCacheKeyFallback("different-client-thread", "gpt-5.6-sol"),
	)
}

func TestRewriteOpenAIOutboundPromptCacheKeyWithFallback_PreservesSessionAcrossSparseFollowUp(t *testing.T) {
	first := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"client-session",
		"input":[{"type":"message","role":"user","content":"first question"}]
	}`)
	sparseFollowUp := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"input_text","text":"follow up"}]
	}`)

	rewrittenFirst, firstKey, err := rewriteOpenAIOutboundPromptCacheKey(first, "")
	require.NoError(t, err)
	require.NotEmpty(t, firstKey)

	rewrittenFollowUp, followUpKey, err := rewriteOpenAIOutboundPromptCacheKeyWithFallback(
		sparseFollowUp,
		"",
		firstKey,
	)
	require.NoError(t, err)
	require.Equal(t, firstKey, followUpKey)
	require.Equal(t, firstKey, gjson.GetBytes(rewrittenFollowUp, "prompt_cache_key").String())
	require.NotContains(t, string(rewrittenFirst), "client-session")
	require.NotContains(t, string(rewrittenFollowUp), "client-session")
}

func TestRewriteOpenAIOutboundPromptCacheKeyMap_ReplacesClientKey(t *testing.T) {
	payload := map[string]any{
		"model":            "gpt-5.4",
		"prompt_cache_key": "client-session",
		"instructions":     "stable instructions",
		"tools":            []any{map[string]any{"type": "function", "name": "lookup"}},
		"input":            []any{map[string]any{"type": "message", "role": "user", "content": "question"}},
	}

	key, err := rewriteOpenAIOutboundPromptCacheKeyMap(payload, "")
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Equal(t, key, payload["prompt_cache_key"])
}
