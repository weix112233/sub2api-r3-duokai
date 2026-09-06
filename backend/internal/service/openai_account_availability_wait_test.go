//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type openAIAvailabilityWaitRepoStub struct {
	mockAccountRepoForGemini
	candidates []Account
}

func (r *openAIAvailabilityWaitRepoStub) ListModelAvailabilityCandidates(
	_ context.Context,
	_ *int64,
	_ []string,
	_ bool,
) ([]Account, error) {
	return append([]Account(nil), r.candidates...), nil
}

func openAIAvailabilityWaitAccount(id int64) Account {
	return Account{
		ID:          id,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
	}
}

func TestNextOpenAITransientAvailabilityChoosesEarliestRecoverableWindow(t *testing.T) {
	now := time.Now()
	later := now.Add(200 * time.Millisecond)
	earlier := now.Add(40 * time.Millisecond)
	rateLimited := openAIAvailabilityWaitAccount(1)
	rateLimited.RateLimitResetAt = &later
	overloaded := openAIAvailabilityWaitAccount(2)
	overloaded.OverloadUntil = &earlier
	healthy := openAIAvailabilityWaitAccount(3)

	repo := &openAIAvailabilityWaitRepoStub{
		candidates: []Account{rateLimited, overloaded, healthy},
	}
	svc := &OpenAIGatewayService{accountRepo: repo}

	next, found, err := svc.nextOpenAITransientAvailability(
		context.Background(),
		nil,
		"",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		"",
		false,
	)

	require.NoError(t, err)
	require.True(t, found)
	require.InDelta(t, earlier.UnixNano(), next.UnixNano(), float64(20*time.Millisecond))
}

func TestNextOpenAITransientAvailabilityDoesNotWaitForDeterministicNoCapacity(t *testing.T) {
	unsupported := openAIAvailabilityWaitAccount(4)
	unsupported.Credentials = map[string]any{
		"model_mapping": map[string]any{"other-model": "other-model"},
	}
	repo := &openAIAvailabilityWaitRepoStub{candidates: []Account{unsupported}}
	svc := &OpenAIGatewayService{accountRepo: repo}

	_, found, err := svc.nextOpenAITransientAvailability(
		context.Background(),
		nil,
		"gpt-5.6-sol",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		"",
		false,
	)

	require.NoError(t, err)
	require.False(t, found)
}

func TestNextOpenAITransientAvailabilityDoesNotWaitForUnsupportedCompact(t *testing.T) {
	unsupported := openAIAvailabilityWaitAccount(10)
	unsupported.Extra = map[string]any{
		"openai_compact_mode": OpenAICompactModeForceOff,
	}
	resetAt := time.Now().Add(time.Second)
	unsupported.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{candidates: []Account{unsupported}}
	svc := &OpenAIGatewayService{accountRepo: repo}

	_, found, err := svc.nextOpenAITransientAvailability(
		context.Background(),
		nil,
		"gpt-5.6-sol",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityResponses,
		"",
		true,
	)

	require.NoError(t, err)
	require.False(t, found)
}

func TestWaitForOpenAITransientAvailabilityStopsAfterRelease(t *testing.T) {
	resetAt := time.Now().Add(40 * time.Millisecond)
	account := openAIAvailabilityWaitAccount(5)
	account.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{candidates: []Account{account}}
	svc := &OpenAIGatewayService{accountRepo: repo}

	start := time.Now()
	waited, err := svc.waitForOpenAITransientAvailability(
		context.Background(),
		nil,
		"",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		"",
		false,
	)

	require.NoError(t, err)
	require.True(t, waited)
	require.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)
}

func TestSelectAccountWithSchedulerWaitsThenReselectsTransientAccount(t *testing.T) {
	resetAt := time.Now().Add(40 * time.Millisecond)
	account := openAIAvailabilityWaitAccount(6)
	account.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accounts:     []Account{account},
			accountsByID: map[int64]*Account{account.ID: &account},
		},
		candidates: []Account{account},
	}
	svc := &OpenAIGatewayService{
		accountRepo: repo,
		cfg:         &config.Config{RunMode: config.RunModeSimple},
	}

	start := time.Now()
	selection, _, err := svc.SelectAccountWithScheduler(
		context.Background(),
		nil,
		"",
		"",
		"gpt-5.6-sol",
		nil,
		OpenAIUpstreamTransportAny,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	require.Equal(t, account.ID, selection.Account.ID)
	require.True(t, selection.Acquired)
	require.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)
}

func TestSelectAccountWithSchedulerDoesNotWaitAfterExplicitExclusion(t *testing.T) {
	resetAt := time.Now().Add(time.Second)
	account := openAIAvailabilityWaitAccount(7)
	account.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accounts:     []Account{account},
			accountsByID: map[int64]*Account{account.ID: &account},
		},
		candidates: []Account{account},
	}
	svc := &OpenAIGatewayService{
		accountRepo: repo,
		cfg:         &config.Config{RunMode: config.RunModeSimple},
	}

	start := time.Now()
	selection, _, err := svc.SelectAccountWithScheduler(
		context.Background(),
		nil,
		"",
		"",
		"gpt-5.6-sol",
		map[int64]struct{}{account.ID: {}},
		OpenAIUpstreamTransportAny,
		false,
	)

	require.ErrorIs(t, err, ErrNoAvailableAccounts)
	require.Nil(t, selection)
	require.Less(t, time.Since(start), 200*time.Millisecond)
}

func TestWaitForOpenAITransientAvailabilityHonorsContextCancellation(t *testing.T) {
	resetAt := time.Now().Add(time.Second)
	account := openAIAvailabilityWaitAccount(8)
	account.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{candidates: []Account{account}}
	svc := &OpenAIGatewayService{accountRepo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	waited, err := svc.waitForOpenAITransientAvailability(
		ctx,
		nil,
		"",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		"",
		false,
	)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, waited)
}

func TestWaitForOpenAITransientAvailabilityRejectsWindowBeyondBudget(t *testing.T) {
	resetAt := time.Now().Add(openAITransientAvailabilityWaitBudget + time.Minute)
	account := openAIAvailabilityWaitAccount(9)
	account.RateLimitResetAt = &resetAt
	repo := &openAIAvailabilityWaitRepoStub{candidates: []Account{account}}
	svc := &OpenAIGatewayService{accountRepo: repo}

	start := time.Now()
	waited, err := svc.waitForOpenAITransientAvailability(
		context.Background(),
		nil,
		"",
		OpenAIUpstreamTransportAny,
		OpenAIEndpointCapabilityChatCompletions,
		"",
		false,
	)

	require.NoError(t, err)
	require.False(t, waited)
	require.Less(t, time.Since(start), 200*time.Millisecond)
}
