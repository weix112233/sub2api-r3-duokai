package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// openAIGatewaySessionAffinity is a gateway-owned, request-scoped pair of
// stable conversation headers. It is derived from the already-normalized
// prompt-cache/session anchor; client identifier values are never copied.
type openAIGatewaySessionAffinity struct {
	sessionID      string
	conversationID string
}

type openAIGatewaySessionAffinityContextKey struct{}
type openAIWSPromptCacheKeyPresenceContextKey struct{}
type openAIWSClientPromptCacheKeyContextKey struct{}

func shouldUseOpenAIGatewaySessionAffinity(account *Account) bool {
	// r3 语义：OAuth 非 Agent 一律绑定稳定隔离会话（含 off 模式）。绑定值是
	// 网关派生的 isolate 值而非客户端原始标识，off 模式剔除会造成 166 个 off
	// 账号的会话/缓存连续性回归。
	return account != nil &&
		account.Type == AccountTypeOAuth &&
		!account.IsOpenAIAgentIdentity()
}

func deriveOpenAIGatewaySessionAffinity(
	apiKeyID int64,
	seed string,
	includeConversation bool,
) *openAIGatewaySessionAffinity {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return nil
	}

	isolated := isolateOpenAISessionID(apiKeyID, seed)
	if isolated == "" {
		return nil
	}

	affinity := &openAIGatewaySessionAffinity{sessionID: isolated}
	if includeConversation {
		affinity.conversationID = isolated
	}
	return affinity
}

// deriveOpenAIGatewaySessionAffinityWithIndependentSeeds 保持 r3 透传链路的
// 源头语义：session 与 conversation 各自按客户端显式头（缺失时回退 cache key）
// 独立隔离，两个出站值可以不同。任一种子为空时对应头由终态 sanitizer 删除。
func deriveOpenAIGatewaySessionAffinityWithIndependentSeeds(
	apiKeyID int64,
	sessionSeed string,
	conversationSeed string,
) *openAIGatewaySessionAffinity {
	sessionSeed = strings.TrimSpace(sessionSeed)
	conversationSeed = strings.TrimSpace(conversationSeed)
	if sessionSeed == "" && conversationSeed == "" {
		return nil
	}

	affinity := &openAIGatewaySessionAffinity{}
	if sessionSeed != "" {
		affinity.sessionID = isolateOpenAISessionID(apiKeyID, sessionSeed)
	}
	if conversationSeed != "" {
		affinity.conversationID = isolateOpenAISessionID(apiKeyID, conversationSeed)
	}
	if affinity.sessionID == "" && affinity.conversationID == "" {
		return nil
	}
	return affinity
}

func withOpenAIGatewaySessionAffinity(
	ctx context.Context,
	affinity *openAIGatewaySessionAffinity,
) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if affinity == nil {
		return ctx
	}
	return context.WithValue(ctx, openAIGatewaySessionAffinityContextKey{}, affinity)
}

// WithOpenAIUpstreamSessionAffinity binds gateway-generated session affinity
// to the request context (r3 跨包契约：repository 层终态清洗据此保护/回填隔离值).
// Callers must pass only values derived locally from real request session
// semantics, never raw client identifiers.
func WithOpenAIUpstreamSessionAffinity(req *http.Request, sessionID, conversationID string) *http.Request {
	if req == nil {
		return nil
	}
	affinity := &openAIGatewaySessionAffinity{
		sessionID:      strings.TrimSpace(sessionID),
		conversationID: strings.TrimSpace(conversationID),
	}
	return req.WithContext(withOpenAIGatewaySessionAffinity(req.Context(), affinity))
}

func openAIGatewaySessionAffinityFromContext(ctx context.Context) *openAIGatewaySessionAffinity {
	if ctx == nil {
		return nil
	}
	affinity, _ := ctx.Value(openAIGatewaySessionAffinityContextKey{}).(*openAIGatewaySessionAffinity)
	return affinity
}

func withOpenAIWSPromptCacheKeyPresence(ctx context.Context, present bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, openAIWSPromptCacheKeyPresenceContextKey{}, present)
}

func openAIWSPromptCacheKeyWasPresent(ctx context.Context) (bool, bool) {
	if ctx == nil {
		return false, false
	}
	present, ok := ctx.Value(openAIWSPromptCacheKeyPresenceContextKey{}).(bool)
	return present, ok
}

func withOpenAIWSClientPromptCacheKey(ctx context.Context, key string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(
		ctx,
		openAIWSClientPromptCacheKeyContextKey{},
		strings.TrimSpace(key),
	)
}

func openAIWSClientPromptCacheKeyFromContext(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	key, _ := c.Request.Context().Value(openAIWSClientPromptCacheKeyContextKey{}).(string)
	return strings.TrimSpace(key)
}

func applyOpenAIGatewaySessionAffinityHeaders(
	headers http.Header,
	affinity *openAIGatewaySessionAffinity,
) {
	if headers == nil || affinity == nil {
		return
	}
	if affinity.sessionID != "" {
		headers.Set("session_id", affinity.sessionID)
	}
	if affinity.conversationID != "" {
		headers.Set("conversation_id", affinity.conversationID)
	}
}

func isGatewayOpenAIAffinityHeaderValue(
	key string,
	value string,
	affinity *openAIGatewaySessionAffinity,
) bool {
	if affinity == nil {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "session_id", "session-id":
		return affinity.sessionID != "" && value == affinity.sessionID
	case "conversation_id", "conversation-id":
		return affinity.conversationID != "" && value == affinity.conversationID
	default:
		return false
	}
}
