package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestSendCCUpstreamRequest_SanitizesOpenAIBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"client-session",
		"client_metadata":{
			"session_id":"client-session",
			"parent_thread_id":"parent-thread",
			"workspaces":[{"root":"/private/project"}]
		},
		"messages":[{"role":"user","content":"hello"}]
	}`)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	c.Request.Header.Set("Traceparent", "00-client-trace-client-span-01")
	c.Request.Header.Set("X-Forwarded-For", "192.0.2.10")
	c.Request.Header.Set("X-Codex-Session-ID", "client-header-session")

	upstream := &httpUpstreamRecorder{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"id":"chatcmpl-test"}`)),
		},
	}
	svc := &OpenAIGatewayService{
		cfg: &config.Config{
			Security: config.SecurityConfig{
				URLAllowlist: config.URLAllowlistConfig{
					Enabled:           false,
					AllowInsecureHTTP: true,
				},
			},
		},
		httpUpstream: upstream,
	}
	account := &Account{
		ID:          101,
		Name:        "privacy-openai-apikey",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Concurrency: 1,
		Credentials: map[string]any{
			credKeyHeaderOverrideEnabled: true,
			credKeyHeaderOverrides: map[string]any{
				"x-codex-parent-thread-id": "override-parent",
				"x-client-request-id":      "override-client",
				"traceparent":              "override-trace",
				"x-forwarded-for":          "198.51.100.25",
			},
		},
	}

	resp, err := svc.sendCCUpstreamRequest(
		context.Background(),
		c,
		account,
		"http://upstream.example/v1/chat/completions",
		body,
		false,
		"test-token",
		"",
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Body.Close())

	require.NotContains(t, string(upstream.lastBody), "prompt_cache_key")
	require.NotContains(t, string(upstream.lastBody), "session_id")
	require.NotContains(t, string(upstream.lastBody), "parent_thread_id")
	require.NotContains(t, string(upstream.lastBody), "workspaces")
	require.Contains(t, string(upstream.lastBody), `"messages"`)
	require.Empty(t, upstream.lastReq.Header.Get("x-codex-parent-thread-id"))
	require.Empty(t, upstream.lastReq.Header.Get("x-client-request-id"))
	require.Empty(t, upstream.lastReq.Header.Get("traceparent"))
	require.Empty(t, upstream.lastReq.Header.Get("x-forwarded-for"))
	require.Empty(t, upstream.lastReq.Header.Get("x-codex-session-id"))
}

func TestPromptCacheKey_RemainsLocalAffinityOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &OpenAIGatewayService{}
	body := []byte(`{
		"model":"gpt-5.4",
		"prompt_cache_key":"client-session",
		"messages":[{"role":"user","content":"hello"}]
	}`)

	newContext := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		return c
	}

	firstHash := svc.GenerateSessionHash(newContext(), body)
	secondHash := svc.GenerateSessionHash(newContext(), body)
	require.NotEmpty(t, firstHash)
	require.Equal(t, firstHash, secondHash)

	sanitized, changed, err := sanitizeCodexOutboundJSON(body)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotContains(t, string(sanitized), "prompt_cache_key")
	require.NotContains(t, string(sanitized), "client-session")
	require.Contains(t, string(sanitized), `"messages"`)
}
