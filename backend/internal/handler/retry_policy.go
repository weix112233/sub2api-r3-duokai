package handler

import "github.com/Wei-Shaw/sub2api/internal/service"

// Keep one capacity budget across account changes. Three failed attempts allow
// an initial attempt, one same-account retry and one alternative account.
type openAICapacityRetryBudget struct {
	failures int
}

func (b *openAICapacityRetryBudget) exhausted(err *service.UpstreamFailoverError) bool {
	if b == nil || !err.IsOpenAICapacityShed() {
		return false
	}
	b.failures++
	return b.failures >= 3
}

func shouldRetrySameAccount(account *service.Account, failoverErr *service.UpstreamFailoverError) bool {
	if account == nil {
		return false
	}
	return retrySameAccountAllowed(account.Platform, failoverErr)
}
