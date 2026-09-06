package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenAIOAuth429NoResetCooldownGrowsAndCaps(t *testing.T) {
	svc := &OpenAIGatewayService{}
	base := 5 * time.Second
	now := time.Unix(1_800_000_000, 0)

	require.Equal(t, base, svc.nextOpenAIOAuth429NoResetCooldown(1, base, now))
	require.Equal(t, 2*base, svc.nextOpenAIOAuth429NoResetCooldown(1, base, now.Add(time.Second)))
	require.Equal(t, 4*base, svc.nextOpenAIOAuth429NoResetCooldown(1, base, now.Add(2*time.Second)))

	for i := 0; i < 20; i++ {
		require.LessOrEqual(t, svc.nextOpenAIOAuth429NoResetCooldown(1, base, now.Add(time.Duration(i+3)*time.Second)), openAIOAuth429NoResetMaxCooldown)
	}
	require.Equal(t, openAIOAuth429NoResetMaxCooldown,
		svc.nextOpenAIOAuth429NoResetCooldown(1, base, now.Add(time.Minute)))
}

func TestOpenAIOAuth429NoResetCooldownResetsAfterQuietPeriodAndClear(t *testing.T) {
	svc := &OpenAIGatewayService{}
	base := 5 * time.Second
	now := time.Unix(1_800_000_000, 0)

	require.Equal(t, base, svc.nextOpenAIOAuth429NoResetCooldown(2, base, now))
	require.Equal(t, 2*base, svc.nextOpenAIOAuth429NoResetCooldown(2, base, now.Add(time.Second)))
	require.Equal(t, base,
		svc.nextOpenAIOAuth429NoResetCooldown(2, base, now.Add(openAIOAuth429NoResetStateTTL+time.Second)))

	svc.clearOpenAIOAuth429NoResetBackoff(2)
	require.Equal(t, base,
		svc.nextOpenAIOAuth429NoResetCooldown(2, base, now.Add(2*openAIOAuth429NoResetStateTTL)))
}

func TestMarkOpenAIOAuth429RateLimitedUsesPerAccountNoResetBackoff(t *testing.T) {
	svc := &OpenAIGatewayService{
		rateLimitService: &RateLimitService{},
	}
	account := &Account{ID: 3, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	before := time.Now()
	svc.markOpenAIOAuth429RateLimited(nil, account, nil, nil)
	firstUntil := runtimeBlockUntilForTest(t, svc, account.ID)
	require.GreaterOrEqual(t, firstUntil, before.Add(5*time.Minute))

	svc.markOpenAIOAuth429RateLimited(nil, account, nil, nil)
	secondUntil := runtimeBlockUntilForTest(t, svc, account.ID)
	require.GreaterOrEqual(t, secondUntil, before.Add(10*time.Minute))
	require.Greater(t, secondUntil, firstUntil)
}

func runtimeBlockUntilForTest(t *testing.T, svc *OpenAIGatewayService, accountID int64) time.Time {
	t.Helper()
	value, ok := svc.openaiAccountRuntimeBlockUntil.Load(accountID)
	require.True(t, ok)
	until, ok := value.(time.Time)
	require.True(t, ok)
	return until
}
