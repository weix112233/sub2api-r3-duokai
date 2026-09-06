package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAstraAccountLongContextOptOutMatchesProductionBaseline(t *testing.T) {
	billing := NewBillingService(&config.Config{}, nil)
	resolver := NewModelPricingResolver(nil, billing)
	disabled, enabled := false, true
	for _, tier := range []string{"", "priority", "flex"} {
		for name, gate := range map[string]*bool{"disabled": &disabled, "enabled": &enabled, "other_platform": nil} {
			t.Run(name+"/"+tier, func(t *testing.T) {
				tokens := UsageTokens{InputTokens: 815, CacheReadTokens: 302592, OutputTokens: 709}
				result, err := billing.CalculateCostUnified(CostInput{
					Ctx: context.Background(), Model: "gpt-6-astra", Tokens: tokens,
					RateMultiplier: 1, ServiceTier: tier, Resolver: resolver,
					Group: &Group{LongContextPricingEnabled: true},
					LongContextBillingEnabled: gate,
				})
				require.NoError(t, err)
				expected, err := billing.calculateCostWithServiceTierPolicy(
					"gpt-6-astra", tokens, 1, tier, gate == nil || *gate,
				)
				require.NoError(t, err)
				require.InDelta(t, expected.InputCost, result.InputCost, 1e-10)
				require.InDelta(t, expected.OutputCost, result.OutputCost, 1e-10)
				require.InDelta(t, expected.CacheReadCost, result.CacheReadCost, 1e-10)
				require.InDelta(t, expected.TotalCost, result.TotalCost, 1e-10)
				require.Equal(t, expected.LongContextBillingApplied, result.LongContextBillingApplied)
				if !result.LongContextBillingApplied && tier == "" {
					// Production row 194717 previously recorded $0.674659.
					require.InDelta(t, 0.346192, result.TotalCost, 1e-10)
				}
			})
		}
	}
}

func TestAstraOAuthMissingLongContextSettingDoesNotApplyPremium(t *testing.T) {
	billing := NewBillingService(&config.Config{}, nil)
	tokens := UsageTokens{InputTokens: 278598, CacheReadTokens: 3584, OutputTokens: 1273}
	account := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	gate := openAILongContextBillingGate(account)
	require.NotNil(t, gate)
	require.False(t, *gate)
	cost, err := billing.CalculateCostUnified(CostInput{
		Ctx: context.Background(), Model: "gpt-6-astra", Tokens: tokens,
		RateMultiplier: 1, Resolver: NewModelPricingResolver(nil, billing),
		Group: &Group{LongContextPricingEnabled: true}, LongContextBillingEnabled: gate,
	})
	require.NoError(t, err)
	require.False(t, cost.LongContextBillingApplied)
	// Production row 194690 previously recorded $5.674603.
	require.InDelta(t, 2.853214, cost.TotalCost, 1e-10)
}
