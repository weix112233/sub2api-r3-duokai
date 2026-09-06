package handler

import "github.com/Wei-Shaw/sub2api/internal/service"

func shouldRetrySameAccount(account *service.Account, failoverErr *service.UpstreamFailoverError) bool {
	if account == nil {
		return false
	}
	return retrySameAccountAllowed(account.Platform, failoverErr)
}
