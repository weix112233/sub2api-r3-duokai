package middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/antibypass"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newAntiBypassTraceRouter(
	t *testing.T,
	key *service.APIKey,
	next gin.HandlerFunc,
) (*gin.Engine, *redis.Client, *antibypass.Decision) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: store.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	decision := new(antibypass.Decision)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		*decision = antibypass.Decision{}
		c.Set(string(ContextKeyAPIKey), key)
		c.Next()
		*decision, _ = AntiBypassDecisionFromContext(c)
	})
	router.Use(gin.HandlerFunc(NewAntiBypassMiddleware(
		antibypass.NewGuard(client), antiBypassSettingsStub{enabled: true}, nil,
	)))
	router.POST("/*path", next)
	return router, client, decision
}

func TestAntiBypassHTTPTraceIDAllowsNormalConversationTurns(t *testing.T) {
	for _, traceID := range []string{"one-conversation", strings.Repeat("t", 300)} {
		t.Run(fmt.Sprintf("trace_length_%d", len(traceID)), func(t *testing.T) {
			key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
			var forwardedHeaders, forwardedBodies []string
			router, client, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
				body, err := io.ReadAll(c.Request.Body)
				require.NoError(t, err)
				forwardedHeaders = append(forwardedHeaders, c.GetHeader("X-Client-Request-ID"))
				forwardedBodies = append(forwardedBodies, string(body))
				c.Status(http.StatusOK)
			})
			requests := []struct {
				path string
				body string
			}{
				{"/v1/responses", `{"input":"first question"}`},
				{"/v1/responses", `{"input":"next question"}`},
				{"/v1/responses", `{"input":[{"type":"function_call_output","call_id":"call_1","output":"2"}]}`},
				{"/responses", `{"input":"follow up"}`},
				{"/v1/responses/compact", `{"input":"compact this conversation"}`},
			}
			for _, request := range requests {
				req := httptest.NewRequest(http.MethodPost, request.path, strings.NewReader(request.body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Client-Request-ID", traceID)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				require.Equal(t, http.StatusOK, response.Code, request.path)
				require.True(t, decision.Allowed)
				require.Equal(t, traceID, forwardedHeaders[len(forwardedHeaders)-1])
				require.Equal(t, request.body, forwardedBodies[len(forwardedBodies)-1])
			}
			require.Len(t, forwardedBodies, len(requests))
			requestKeys, err := client.Keys(context.Background(), "sub2api:anti-bypass:v3:{user:7}:request:*").Result()
			require.NoError(t, err)
			require.Empty(t, requestKeys, "HTTP tracing must not allocate an operation-ID budget")
		})
	}
}

func TestAntiBypassHTTPTraceIDPreservesExplicitIdempotency(t *testing.T) {
	key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
	calls := 0
	router, _, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
		calls++
		c.Status(http.StatusOK)
	})
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-Request-ID", "shared-conversation")
		req.Header.Set("Idempotency-Key", "explicit-operation")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	for attempt := 0; attempt < 4; attempt++ {
		require.Equal(t, http.StatusOK, request(`{"input":"same operation"}`).Code)
		require.True(t, decision.Allowed)
	}
	conflict := request(`{"input":"different operation"}`)
	require.Equal(t, http.StatusTooManyRequests, conflict.Code)
	require.Contains(t, conflict.Body.String(), "ANTI_BYPASS_BLOCKED")
	require.Equal(t, antibypass.ReasonDuplicateRequest, decision.Reason)
	require.Equal(t, 4, calls)
}

func TestAntiBypassHTTPTraceIDIgnoredWithoutPurgingLegacyState(t *testing.T) {
	key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
	router, client, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	ctx := context.Background()
	guard := antibypass.NewGuard(client)
	legacy, err := guard.Check(ctx, antibypass.DefaultConfig(), antibypass.Request{
		UserID: 7, APIKeyID: 1, ClientRequestID: "legacy-conversation",
		ClientIP: "192.0.2.1", ClientFingerprint: "legacy-client",
		Method: http.MethodPost, Path: "/v1/responses", Body: []byte(`{"input":"old turn"}`),
	})
	require.NoError(t, err)
	require.True(t, legacy.Allowed)
	guard.ReleaseDecision(ctx, 7, legacy)
	keys, err := client.Keys(ctx, "sub2api:anti-bypass:v3:{user:7}:request:*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	before, err := client.HGetAll(ctx, keys[0]).Result()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"new turn"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Request-ID", "legacy-conversation")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, decision.Allowed)
	after, err := client.HGetAll(ctx, keys[0]).Result()
	require.NoError(t, err)
	require.Equal(t, before, after, "the repair must not purge or rewrite old request-ID state")
	rpm, err := client.ZCard(ctx, "sub2api:anti-bypass:v3:{user:7}:rpm").Result()
	require.NoError(t, err)
	require.EqualValues(t, 2, rpm)
}

func TestAntiBypassHTTPTraceIDDoesNotBypassRPM(t *testing.T) {
	key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
	calls := 0
	router, _, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
		calls++
		c.Status(http.StatusOK)
	})
	limit := antibypass.DefaultConfig().RPMLimit
	for attempt := 0; attempt <= limit; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"bounded repeated request"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-Request-ID", "constant-trace")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if attempt < limit {
			require.Equal(t, http.StatusOK, response.Code, "attempt %d", attempt+1)
		} else {
			require.Equal(t, http.StatusTooManyRequests, response.Code)
			require.Equal(t, antibypass.ReasonRPM, decision.Reason)
		}
	}
	require.Equal(t, limit, calls)
}

func TestAntiBypassHTTPTraceIDDoesNotBypassConcurrency(t *testing.T) {
	key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
	calls := 0
	router, client, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
		calls++
		c.Status(http.StatusOK)
	})
	ctx := context.Background()
	guard := antibypass.NewGuard(client)
	cfg := antibypass.DefaultConfig()
	leases := make([]antibypass.Decision, 0, cfg.MaxConcurrent)
	t.Cleanup(func() {
		for _, lease := range leases {
			guard.ReleaseDecision(ctx, 7, lease)
		}
	})
	for i := 0; i < cfg.MaxConcurrent; i++ {
		lease, err := guard.Check(ctx, cfg, antibypass.Request{
			UserID: 7, APIKeyID: 1, ClientIP: "192.0.2.1", ClientFingerprint: "active-client",
			Method: http.MethodPost, Path: "/v1/responses", Body: []byte(`{"input":"held request"}`),
		})
		require.NoError(t, err)
		require.True(t, lease.Allowed)
		leases = append(leases, lease)
	}
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"next request"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-Request-ID", "constant-trace")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	require.Equal(t, http.StatusTooManyRequests, request().Code)
	require.Equal(t, antibypass.ReasonConcurrency, decision.Reason)
	require.Zero(t, calls)
	guard.ReleaseDecision(ctx, 7, leases[0])
	require.Equal(t, http.StatusOK, request().Code)
	require.Equal(t, 1, calls)
}

func TestAntiBypassHTTPTraceIDDoesNotBypassCrossKeyReplay(t *testing.T) {
	key := &service.APIKey{ID: 1, User: &service.User{ID: 7}}
	calls := 0
	router, _, decision := newAntiBypassTraceRouter(t, key, func(c *gin.Context) {
		calls++
		c.Status(http.StatusOK)
	})
	request := func(traceID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"input":"same payload"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-Request-ID", traceID)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	require.Equal(t, http.StatusOK, request("conversation-a").Code)
	key.ID = 2
	for _, traceID := range []string{"conversation-a", "conversation-b"} {
		require.Equal(t, http.StatusTooManyRequests, request(traceID).Code)
		require.Equal(t, antibypass.ReasonReplay, decision.Reason)
	}
	require.Equal(t, 1, calls)
}

func TestAntiBypassTraceFixPreservesFrameOperationChecks(t *testing.T) {
	t.Run("conflicting_body", func(t *testing.T) {
		session, _ := newBusinessFrameSession(t)
		first, err := session.Inspect(context.Background(), []byte(`{"type":"response.create","event_id":"operation-1","input":"first"}`), true)
		require.NoError(t, err)
		require.Empty(t, first.Reason)
		session.Finish(1)
		conflict, err := session.Inspect(context.Background(), []byte(`{"type":"response.create","event_id":"operation-1","input":"second"}`), true)
		require.NoError(t, err)
		require.Equal(t, antibypass.ReasonDuplicateRequest, conflict.Reason)
	})
	t.Run("bounded_attempts", func(t *testing.T) {
		session, _ := newBusinessFrameSession(t)
		limit := session.config.MaxClientRequestAttempts
		for attempt := 1; attempt <= limit+1; attempt++ {
			detection, err := session.Inspect(context.Background(), []byte(`{"type":"response.create","event_id":"operation-2","input":"same"}`), true)
			require.NoError(t, err)
			if attempt <= limit {
				require.Empty(t, detection.Reason)
				session.Finish(attempt)
			} else {
				require.Equal(t, antibypass.ReasonDuplicateRequest, detection.Reason)
			}
		}
	})
}
