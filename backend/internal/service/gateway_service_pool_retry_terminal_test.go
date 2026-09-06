//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type poolRetryTerminalRepoStub struct {
	mockAccountRepoForGemini
	setErrorCalls     int
	setRateLimitCalls int
	lastError         string
	lastReset         time.Time
}

func (r *poolRetryTerminalRepoStub) SetError(_ context.Context, _ int64, message string) error {
	r.setErrorCalls++
	r.lastError = message
	return nil
}

func (r *poolRetryTerminalRepoStub) SetRateLimited(_ context.Context, _ int64, resetAt time.Time) error {
	r.setRateLimitCalls++
	r.lastReset = resetAt
	return nil
}

func TestGatewayService_TempUnscheduleRetryableError_Pool401DisablesAccount(t *testing.T) {
	const accountID = int64(739)
	repo := &poolRetryTerminalRepoStub{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{
				accountID: {
					ID:          accountID,
					Platform:    PlatformOpenAI,
					Type:        AccountTypeAPIKey,
					Credentials: map[string]any{"pool_mode": true},
				},
			},
		},
	}
	rateLimit := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	gateway := &GatewayService{accountRepo: repo, rateLimitService: rateLimit}
	openAIGateway := &OpenAIGatewayService{accountRepo: repo, rateLimitService: rateLimit}
	rateLimit.SetAccountRuntimeBlocker(openAIGateway)

	gateway.TempUnscheduleRetryableError(context.Background(), accountID, &UpstreamFailoverError{
		StatusCode:             http.StatusUnauthorized,
		RetryableOnSameAccount: true,
	})

	require.Equal(t, 1, repo.setErrorCalls)
	require.Zero(t, repo.setRateLimitCalls)
	require.Contains(t, repo.lastError, "pool-mode retry budget exhausted")
	require.True(t, openAIGateway.isOpenAIAccountRuntimeBlocked(repo.accountsByID[accountID]))
}

func TestGatewayService_TempUnscheduleRetryableError_Pool429UsesFallbackCooldown(t *testing.T) {
	const accountID = int64(749)
	repo := &poolRetryTerminalRepoStub{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{
				accountID: {
					ID:          accountID,
					Platform:    PlatformOpenAI,
					Type:        AccountTypeAPIKey,
					Credentials: map[string]any{"pool_mode": true},
				},
			},
		},
	}
	before := time.Now()
	rateLimit := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	gateway := &GatewayService{accountRepo: repo, rateLimitService: rateLimit}
	openAIGateway := &OpenAIGatewayService{accountRepo: repo, rateLimitService: rateLimit}
	rateLimit.SetAccountRuntimeBlocker(openAIGateway)

	gateway.TempUnscheduleRetryableError(context.Background(), accountID, &UpstreamFailoverError{
		StatusCode:             http.StatusTooManyRequests,
		RetryableOnSameAccount: true,
	})

	require.Zero(t, repo.setErrorCalls)
	require.Equal(t, 1, repo.setRateLimitCalls)
	require.GreaterOrEqual(t, repo.lastReset, before.Add(299*time.Second))
	require.Less(t, repo.lastReset, before.Add(301*time.Second))
	require.True(t, openAIGateway.isOpenAIAccountRuntimeBlocked(repo.accountsByID[accountID]))
}

func TestGatewayService_TempUnscheduleRetryableError_RequestScopedTransientDoesNotPenalize(t *testing.T) {
	repo := &poolRetryTerminalRepoStub{}
	gateway := &GatewayService{accountRepo: repo}

	gateway.TempUnscheduleRetryableError(context.Background(), 900, &UpstreamFailoverError{
		StatusCode:             http.StatusTooManyRequests,
		RetryableOnSameAccount: true,
		RequestScopedTransient: true,
	})

	require.Zero(t, repo.setErrorCalls)
	require.Zero(t, repo.setRateLimitCalls)
}
