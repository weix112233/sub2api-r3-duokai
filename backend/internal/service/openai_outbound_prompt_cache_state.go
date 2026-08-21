package service

import "github.com/gin-gonic/gin"

const openAIOutboundPromptCacheKeyContextKey = "openai_outbound_prompt_cache_key"

func setOpenAIOutboundPromptCacheKey(c *gin.Context, promptCacheKey string) {
	if c == nil || !isGatewayPromptCacheKeyValue(promptCacheKey) {
		return
	}
	c.Set(openAIOutboundPromptCacheKeyContextKey, promptCacheKey)
}

func openAIOutboundPromptCacheKeyFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(openAIOutboundPromptCacheKeyContextKey)
	if !ok {
		return ""
	}
	promptCacheKey, _ := value.(string)
	if !isGatewayPromptCacheKeyValue(promptCacheKey) {
		return ""
	}
	return promptCacheKey
}
