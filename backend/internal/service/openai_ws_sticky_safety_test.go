package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenAIGatewayService_PreviousResponseIDSkipsRuntimeBlockedAccountWithoutSnapshot(t *testing.T) {
	ctx := context.Background()
	groupID := int64(31)
	account := Account{
		ID:          3101,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                newOpenAIWSV2TestConfig(),
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
	}
	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_runtime_blocked", account.ID, time.Hour))

	svc.BlockAccountScheduling(&account, time.Now().Add(time.Minute), "429")
	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_runtime_blocked", "gpt-5.1", nil, false)

	require.NoError(t, err)
	require.Nil(t, selection)
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_runtime_blocked")
	require.NoError(t, getErr)
	require.Zero(t, boundAccountID)
}

func TestOpenAIGatewayService_PreviousResponseIDSkipsQuarantinedProxy(t *testing.T) {
	ctx := context.Background()
	groupID := int64(32)
	proxyID := int64(3202)
	account := Account{
		ID:          3201,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		ProxyID:     &proxyID,
		Extra: map[string]any{
			"openai_apikey_responses_websockets_v2_enabled": true,
		},
	}
	cache := &stubGatewayCache{}
	store := NewOpenAIWSStateStore(cache)
	svc := &OpenAIGatewayService{
		accountRepo:        stubOpenAIAccountRepo{accounts: []Account{account}},
		cache:              cache,
		cfg:                newOpenAIWSV2TestConfig(),
		concurrencyService: NewConcurrencyService(stubConcurrencyCache{}),
		openaiWSStateStore: store,
		openaiProxyStreamCircuit: newOpenAIProxyStreamCircuit(openAIProxyStreamCircuitSettings{
			failureThreshold: 1,
			failureWindow:    time.Minute,
			quarantineTTL:    10 * time.Minute,
			maxEntries:       16,
		}),
	}
	require.NoError(t, store.BindResponseAccount(ctx, groupID, "resp_proxy_blocked", account.ID, time.Hour))
	svc.openaiProxyStreamCircuit.recordFailure(proxyID, time.Now())

	selection, err := svc.SelectAccountByPreviousResponseID(ctx, &groupID, "resp_proxy_blocked", "gpt-5.1", nil, false)

	require.NoError(t, err)
	require.Nil(t, selection)
	boundAccountID, getErr := store.GetResponseAccount(ctx, groupID, "resp_proxy_blocked")
	require.NoError(t, getErr)
	require.Zero(t, boundAccountID)
}
