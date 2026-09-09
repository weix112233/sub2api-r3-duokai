package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestOpenAIScheduler_OAuthCacheAffinity(t *testing.T) {
	for _, tc := range []struct {
		name        string
		accountType string
		slow        bool
		failing     bool
		full        bool
		excluded    bool
		wantSticky  bool
	}{
		{name: "oauth_slow_healthy", accountType: AccountTypeOAuth, slow: true, wantSticky: true},
		{name: "setup_token_slow_healthy", accountType: AccountTypeSetupToken, slow: true, wantSticky: true},
		{name: "oauth_fast_healthy", accountType: AccountTypeOAuth, wantSticky: true},
		{name: "oauth_slow_failing", accountType: AccountTypeOAuth, slow: true, failing: true},
		{name: "setup_token_slow_failing", accountType: AccountTypeSetupToken, slow: true, failing: true},
		{name: "oauth_failing", accountType: AccountTypeOAuth, failing: true},
		{name: "oauth_slow_full", accountType: AccountTypeOAuth, slow: true, full: true},
		{name: "setup_token_slow_full", accountType: AccountTypeSetupToken, slow: true, full: true},
		{name: "oauth_slow_excluded", accountType: AccountTypeOAuth, slow: true, excluded: true},
		{name: "api_key_slow_legacy_escape", accountType: AccountTypeAPIKey, slow: true},
		{name: "api_key_fast_legacy_sticky", accountType: AccountTypeAPIKey, wantSticky: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const stickyID, otherID = int64(21701), int64(21702)
			groupID := int64(10107)
			accounts := []Account{
				{ID: stickyID, Platform: PlatformOpenAI, Type: tc.accountType, Status: StatusActive,
					Schedulable: true, Concurrency: 1, Priority: 0, GroupIDs: []int64{groupID}},
				{ID: otherID, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Status: StatusActive,
					Schedulable: true, Concurrency: 1, Priority: 1, GroupIDs: []int64{groupID}},
			}
			cache := &schedulerTestGatewayCache{
				sessionBindings: map[string]int64{"openai:cache_affinity": stickyID},
			}
			cfg := &config.Config{}
			cfg.Gateway.OpenAIScheduler.StickyEscapeEnabled = true
			cfg.Gateway.OpenAIScheduler.StickyEscapeTTFTMs = 15000
			cfg.Gateway.OpenAIScheduler.StickyEscapeErrorRate = 0.5
			var acquiredIDs []int64
			svc := &OpenAIGatewayService{
				accountRepo:      schedulerTestOpenAIAccountRepo{accounts: accounts},
				cache:            cache,
				cfg:              cfg,
				rateLimitService: newOpenAIAdvancedSchedulerRateLimitService("true"),
				concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{
					acquireResults: map[int64]bool{stickyID: !tc.full, otherID: true},
					acquiredIDs:    &acquiredIDs,
				}),
				openaiAccountStats: newOpenAIAccountRuntimeStats(),
			}
			ttft := 5000
			if tc.slow {
				ttft = 45000
			}
			for i := 0; i < 10; i++ {
				svc.openaiAccountStats.report(stickyID, !tc.failing, &ttft)
			}
			var excluded map[int64]struct{}
			if tc.excluded {
				excluded = map[int64]struct{}{stickyID: {}}
			}
			selection, decision, err := svc.SelectAccountWithScheduler(
				context.Background(), &groupID, "", "cache_affinity", "gpt-6-astra",
				excluded, OpenAIUpstreamTransportAny, false,
			)
			require.NoError(t, err)
			require.NotNil(t, selection)
			require.NotNil(t, selection.Account)
			if selection.ReleaseFunc != nil {
				defer selection.ReleaseFunc()
			}
			require.Equal(t, tc.wantSticky, decision.StickySessionHit)
			if tc.wantSticky {
				require.Equal(t, stickyID, selection.Account.ID)
				require.Equal(t, openAIAccountScheduleLayerSessionSticky, decision.Layer)
			} else {
				require.Equal(t, openAIAccountScheduleLayerLoadBalance, decision.Layer)
			}
			if tc.excluded {
				require.Equal(t, otherID, selection.Account.ID)
				require.NotContains(t, acquiredIDs, stickyID)
			} else {
				// Temporary escape preserves the original cache/session owner.
				require.Equal(t, stickyID, cache.sessionBindings["openai:cache_affinity"])
			}
			if tc.wantSticky {
				require.Equal(t, []int64{stickyID}, acquiredIDs)
			}
		})
	}
}

func TestOpenAIScheduler_CacheAffinityNeverMasksHealthFailure(t *testing.T) {
	stats := newOpenAIAccountRuntimeStats()
	const accountID = int64(21703)
	ttft := 60000
	stats.report(accountID, true, &ttft)
	scheduler := &defaultOpenAIAccountScheduler{stats: stats}
	cfg := openAIStickyEscapeConfig{
		enabled: true, ttftMs: 15000, errorRate: 0.5, preserveCacheAffinity: true,
	}

	reason, _, observedTTFT, escape := scheduler.shouldEscapeStickyAccount(accountID, cfg)
	require.False(t, escape)
	require.Empty(t, reason)
	require.Equal(t, float64(ttft), observedTTFT)
	for i := 0; i < 4; i++ {
		stats.report(accountID, false, nil)
	}
	reason, _, observedTTFT, escape = scheduler.shouldEscapeStickyAccount(accountID, cfg)
	require.True(t, escape)
	require.Equal(t, "error_rate", reason)
	require.Equal(t, float64(ttft), observedTTFT)

	cfg.enabled = false
	_, _, _, escape = scheduler.shouldEscapeStickyAccount(accountID, cfg)
	require.False(t, escape)
}
