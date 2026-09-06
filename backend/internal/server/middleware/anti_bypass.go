package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/antibypass"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"

	"github.com/gin-gonic/gin"
)

const (
	antiBypassDecisionContextKey = "anti_bypass_decision"
	antiBypassDefaultBodyLimit   = 2 << 20
)

// AntiBypassMiddleware is deliberately separate from billing enforcement. It
// remains a no-op until the dedicated system setting is explicitly enabled.
type AntiBypassMiddleware gin.HandlerFunc

type AntiBypassSettings interface {
	IsAntiBypassEnabled(ctx context.Context) (bool, error)
}

func NewAntiBypassMiddleware(
	guard *antibypass.Guard,
	settings AntiBypassSettings,
	cfg *config.Config,
) AntiBypassMiddleware {
	switchCache := &antiBypassSwitchCache{settings: settings}
	return AntiBypassMiddleware(func(c *gin.Context) {
		if c == nil {
			return
		}
		if c.Request == nil {
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}
		if settings == nil {
			recordAntiBypassEvent(c, antibypass.Decision{Reason: antibypass.ReasonStorageUnavailable})
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}
		// Install even when disabled so a long-lived WS connection observes
		// subsequent switch changes. No request body or credential is captured.
		frameCtx := antibypass.WithFrameInspector(c.Request.Context(), func(ctx context.Context, payload []byte) (antibypass.Detection, error) {
			enabled, settingErr := switchCache.Enabled(ctx)
			if settingErr != nil {
				return antibypass.Detection{Reason: antibypass.ReasonStorageUnavailable}, settingErr
			}
			if !enabled {
				return antibypass.Detection{}, nil
			}
			if guard == nil {
				return antibypass.Detection{Reason: antibypass.ReasonStorageUnavailable}, errors.New("anti-bypass guard missing")
			}
			if len(payload) > antiBypassDefaultBodyLimit {
				return antibypass.Detection{Reason: antibypass.ReasonBodyTooLarge}, nil
			}
			_, detection := antibypass.DetectJailbreak(payload, antiBypassDefaultBodyLimit)
			return detection, nil
		})
		c.Request = c.Request.WithContext(frameCtx)
		enabled, err := switchCache.Enabled(c.Request.Context())
		if err != nil {
			recordAntiBypassEvent(c, antibypass.Decision{Reason: antibypass.ReasonStorageUnavailable})
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}
		if !enabled {
			c.Next()
			return
		}
		if c.Request.URL == nil {
			recordAntiBypassEvent(c, antibypass.Decision{Reason: antibypass.ReasonStorageUnavailable})
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}
		if !isProtectedGatewayRequest(c.Request) {
			c.Next()
			return
		}
		if guard == nil {
			recordAntiBypassEvent(c, antibypass.Decision{Reason: antibypass.ReasonStorageUnavailable})
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}

		apiKey, ok := GetAPIKeyFromContext(c)
		if !ok || apiKey == nil || apiKey.ID <= 0 || apiKey.User == nil || apiKey.User.ID <= 0 {
			decision := antibypass.Decision{Reason: antibypass.ReasonInvalidSubject}
			recordAntiBypassEvent(c, decision)
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_IDENTITY_UNAVAILABLE", "Gateway security identity is temporarily unavailable")
			return
		}
		if conflictingCredentialHeaders(c.Request) {
			decision := antibypass.Decision{Reason: antibypass.ReasonHeaderConflict}
			recordAntiBypassEvent(c, decision)
			AbortWithError(c, http.StatusBadRequest, "ANTI_BYPASS_HEADER_CONFLICT", "Ambiguous or duplicate API credential headers")
			return
		}

		var body []byte
		if isInspectableBody(c.Request) || isPromptBearingGatewayRequest(c.Request) {
			var bodyErr error
			body, bodyErr = readBodyForInspection(c.Request, antiBypassDefaultBodyLimit)
			if bodyErr != nil {
				decision := antibypass.Decision{Reason: antibypass.ReasonBodyTooLarge}
				recordAntiBypassEvent(c, decision)
				AbortWithError(c, http.StatusRequestEntityTooLarge, "ANTI_BYPASS_BODY_TOO_LARGE", "Request body exceeds the security inspection limit")
				return
			}
		}
		if isPromptBearingGatewayRequest(c.Request) {
			if blocked, detection := antibypass.DetectJailbreak(body, antiBypassDefaultBodyLimit); blocked {
				blockedDecision := antibypass.Decision{
					Reason:  detection.Reason,
					Current: int64(detection.SignalCount),
				}
				recordAntiBypassEvent(c, blockedDecision)
				AbortWithError(c, http.StatusForbidden, "ANTI_BYPASS_PROMPT_BLOCKED", "Request blocked by gateway prompt security policy")
				return
			}
		}

		guardConfig := antibypass.DefaultConfig()
		decision, err := guard.Check(c.Request.Context(), guardConfig, antibypass.Request{
			UserID:         apiKey.User.ID,
			APIKeyID:       apiKey.ID,
			IdempotencyKey: strings.TrimSpace(c.Request.Header.Get("Idempotency-Key")),
			ClientRequestID: strings.TrimSpace(
				c.Request.Header.Get("X-Client-Request-ID"),
			),
			// Anti-bypass attribution must not inherit the legacy raw-forwarded
			// header trust switch. Only Gin's trusted-proxy chain is authoritative.
			ClientIP:          ip.GetTrustedClientIP(c),
			ClientFingerprint: antibypass.FingerprintFromHeaders(c.Request.Header),
			Method:            c.Request.Method,
			Path:              c.Request.URL.Path,
			Body:              body,
		})
		if err != nil {
			recordAntiBypassEvent(c, decision)
			c.Header("Retry-After", "1")
			AbortWithError(c, http.StatusServiceUnavailable, "ANTI_BYPASS_UNAVAILABLE", "Gateway security policy is temporarily unavailable")
			return
		}
		if !decision.Allowed {
			recordAntiBypassEvent(c, decision)
			retrySeconds := int(decision.RetryAfter.Seconds())
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			c.Header("Retry-After", strconv.Itoa(retrySeconds))
			AbortWithError(c, http.StatusTooManyRequests, "ANTI_BYPASS_BLOCKED", "Request blocked by gateway anti-bypass policy")
			return
		}

		c.Set(antiBypassDecisionContextKey, decision)
		requestCtx, cancelRequest := context.WithCancel(c.Request.Context())
		c.Request = c.Request.WithContext(requestCtx)
		renewalDone := make(chan struct{})
		renewalFinished := make(chan struct{})
		go func() {
			defer close(renewalFinished)
			if renewalErr := guard.MaintainDecision(requestCtx, decision, renewalDone); renewalErr != nil {
				slog.Error("anti_bypass_lease_refresh_failed",
					"user_id", apiKey.User.ID,
					"api_key_id", apiKey.ID,
					"error", renewalErr,
				)
				cancelRequest()
			}
		}()
		defer func() {
			close(renewalDone)
			cancelRequest()
			<-renewalFinished
			releaseCtx, cancel := antiBypassReleaseContext(c.Request.Context())
			defer cancel()
			guard.ReleaseDecision(releaseCtx, apiKey.User.ID, decision)
		}()
		c.Next()
	})
}

func antiBypassReleaseContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), time.Second)
}

type antiBypassSwitchCache struct {
	settings AntiBypassSettings
	mu       sync.Mutex
	enabled  bool
	expires  time.Time
	loaded   bool
}

func (cache *antiBypassSwitchCache) Enabled(ctx context.Context) (bool, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := time.Now()
	if cache.loaded && now.Before(cache.expires) {
		return cache.enabled, nil
	}
	enabled, err := cache.settings.IsAntiBypassEnabled(ctx)
	if err != nil {
		return false, err
	}
	cache.enabled = enabled
	cache.expires = now.Add(5 * time.Second)
	cache.loaded = true
	return enabled, nil
}

func isProtectedGatewayRequest(request *http.Request) bool {
	if request == nil || request.URL == nil {
		return false
	}
	path := strings.TrimRight(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodGet && path == "/v1/realtime":
		return true
	case request.Method == http.MethodGet:
		return false
	default:
		return true
	}
}

func isInspectableBody(request *http.Request) bool {
	if request == nil {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(request.Header.Get("Content-Type")))
	return contentType == "" ||
		strings.HasPrefix(contentType, "application/json") ||
		strings.HasSuffix(contentType, "+json") ||
		strings.HasPrefix(contentType, "text/")
}

func isPromptBearingGatewayRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Method == http.MethodGet {
		return false
	}
	path := strings.TrimRight(request.URL.Path, "/")
	for _, suffix := range []string{
		"/messages",
		"/messages/count_tokens",
		"/responses",
		"/completions",
		"/chat/completions",
		"/alpha/search",
		"/embeddings",
		"/web_search",
		"/x_search",
	} {
		if path == suffix || strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return strings.HasPrefix(path, "/responses/") ||
		strings.HasPrefix(path, "/v1/responses/") ||
		strings.HasPrefix(path, "/backend-api/codex/responses/") ||
		strings.HasPrefix(path, "/v1beta/models/") ||
		strings.HasPrefix(path, "/antigravity/v1beta/models/")
}

func conflictingCredentialHeaders(request *http.Request) bool {
	if request == nil {
		return false
	}

	credentialCount := 0
	for _, raw := range request.Header.Values("Authorization") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, ",") {
			return true
		}
		parts := strings.Fields(raw)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != "" {
			credentialCount++
			if credentialCount > 1 {
				return true
			}
		}
	}

	for _, name := range []string{"X-API-Key", "X-Goog-API-Key"} {
		for _, raw := range request.Header.Values(name) {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if strings.Contains(raw, ",") {
				return true
			}
			credentialCount++
			if credentialCount > 1 {
				return true
			}
		}
	}
	return false
}

func readBodyForInspection(request *http.Request, maxBytes int) ([]byte, error) {
	if request == nil || request.Body == nil || maxBytes <= 0 {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(maxBytes)+1))
	if err != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > maxBytes {
		return nil, errors.New("request body exceeds anti-bypass inspection limit")
	}
	return body, nil
}

func recordAntiBypassEvent(c *gin.Context, decision antibypass.Decision) {
	if c == nil {
		return
	}
	c.Set(antiBypassDecisionContextKey, decision)
	MarkIngressRejected(c, IngressRejectAntiBypass)
	apiKey, _ := GetAPIKeyFromContext(c)
	var userID, apiKeyID int64
	if apiKey != nil {
		apiKeyID = apiKey.ID
		if apiKey.User != nil {
			userID = apiKey.User.ID
		}
	}
	path := ""
	if c.Request != nil && c.Request.URL != nil {
		path = c.Request.URL.Path
	}
	slog.Warn("anti_bypass_request_blocked",
		"reason", decision.Reason,
		"user_id", userID,
		"api_key_id", apiKeyID,
		"path", path,
	)
}

func AntiBypassDecisionFromContext(c *gin.Context) (antibypass.Decision, bool) {
	if c == nil {
		return antibypass.Decision{}, false
	}
	value, ok := c.Get(antiBypassDecisionContextKey)
	if !ok {
		return antibypass.Decision{}, false
	}
	decision, ok := value.(antibypass.Decision)
	return decision, ok
}
