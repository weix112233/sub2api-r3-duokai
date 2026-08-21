package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type revalidationCandidateStub struct {
	mu       sync.Mutex
	accounts []Account
	calls    int
}

func (s *revalidationCandidateStub) ListRateLimitedOpenAIOAuth(context.Context) ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return append([]Account(nil), s.accounts...), nil
}

type revalidationProbeStub struct {
	mu        sync.Mutex
	ids       []int64
	cleared   bool
	probeErr  error
	started   int
	active    int
	maxActive int
}

func (s *revalidationProbeStub) RevalidateOpenAIRateLimit(ctx context.Context, accountID int64) (bool, error) {
	s.mu.Lock()
	s.ids = append(s.ids, accountID)
	s.started++
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()

	select {
	case <-time.After(5 * time.Millisecond):
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return s.cleared, s.probeErr
}

func TestProviderProbeSucceededRequiresExplicitSuccessMarker(t *testing.T) {
	require.False(t, providerProbeSucceeded(nil))
	require.False(t, providerProbeSucceeded(map[string]any{"codex_7d_used_percent": 100.0}))
	require.False(t, providerProbeSucceeded(map[string]any{
		"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
	}))
	require.True(t, providerProbeSucceeded(map[string]any{
		"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
		"codex_usage_updated_at":            "2026-08-15T10:00:00Z",
		"codex_5h_used_percent":             12.5,
		"codex_5h_reset_after_seconds":      18000,
		"codex_5h_window_minutes":           300,
		"codex_7d_used_percent":             40.0,
		"codex_7d_reset_after_seconds":      604800,
		"codex_7d_window_minutes":           10080,
	}))
	require.False(t, providerProbeSucceeded(map[string]any{
		"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
		"codex_usage_updated_at":            "2026-08-15T10:00:00Z",
		"codex_5h_used_percent":             12.5,
		"codex_5h_reset_after_seconds":      18000,
		"codex_5h_window_minutes":           300,
		"codex_7d_used_percent":             100.0,
		"codex_7d_reset_after_seconds":      604800,
		"codex_7d_window_minutes":           10080,
	}))
	require.False(t, providerProbeSucceeded(map[string]any{
		"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
		"codex_usage_updated_at":            "2026-08-15T10:00:00Z",
		"codex_5h_used_percent":             "12.5",
		"codex_5h_reset_after_seconds":      18000,
		"codex_5h_window_minutes":           300,
		"codex_7d_used_percent":             40.0,
		"codex_7d_reset_after_seconds":      604800,
		"codex_7d_window_minutes":           10080,
	}))
}

func TestOpenAIRateLimitRevalidationUsesBoundedConcurrency(t *testing.T) {
	candidates := &revalidationCandidateStub{accounts: []Account{
		{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 5}, {ID: 6},
	}}
	probe := &revalidationProbeStub{cleared: true}
	svc := NewOpenAIRateLimitRevalidationService(candidates, probe)
	require.NotNil(t, svc)

	svc.revalidateOnce(context.Background())

	require.Equal(t, 1, candidates.calls)
	require.Len(t, probe.ids, 6)
	require.LessOrEqual(t, probe.maxActive, openAIRateLimitRevalidationWorkers)
}

func TestOpenAIRateLimitRevalidationLifecycleIsIdempotent(t *testing.T) {
	candidates := &revalidationCandidateStub{}
	probe := &revalidationProbeStub{}
	svc := NewOpenAIRateLimitRevalidationService(candidates, probe)
	require.NotNil(t, svc)

	svc.Start()
	svc.Start()
	time.Sleep(20 * time.Millisecond)
	svc.Stop()
	svc.Stop()

	require.Equal(t, 1, candidates.calls)
}

type openAIRateLimitRecoveryRepoStub struct {
	AccountRepository
	account          *Account
	updateExtraCalls int
	updateExtraErr   error
	clearCalls       int
	clearResult      bool
	clearErr         error
}

func (r *openAIRateLimitRecoveryRepoStub) GetByID(context.Context, int64) (*Account, error) {
	if r.account == nil {
		return nil, errors.New("account not found")
	}
	return r.account, nil
}

func (r *openAIRateLimitRecoveryRepoStub) UpdateExtra(context.Context, int64, map[string]any) error {
	r.updateExtraCalls++
	return r.updateExtraErr
}

func (r *openAIRateLimitRecoveryRepoStub) ClearOpenAIRateLimitIfObserved(context.Context, int64, time.Time, time.Time) (bool, error) {
	r.clearCalls++
	if r.clearResult && r.clearErr == nil {
		r.account.RateLimitedAt = nil
		r.account.RateLimitResetAt = nil
	}
	return r.clearResult, r.clearErr
}

func TestRevalidateOpenAIRateLimitPersistsBeforeAuthoritativeClear(t *testing.T) {
	limitedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	resetAt := time.Now().Add(6 * 24 * time.Hour).UTC().Truncate(time.Second)

	tests := []struct {
		name            string
		updates         map[string]any
		probeErr        error
		persistErr      error
		wantCleared     bool
		wantErr         bool
		wantUpdateCalls int
		wantClearCalls  int
	}{
		{
			name:            "authoritative early reset",
			updates:         authoritativeOpenAIProbeUpdates(),
			wantCleared:     true,
			wantUpdateCalls: 1,
			wantClearCalls:  1,
		},
		{
			name: "exhausted 2xx preserves future reset",
			updates: map[string]any{
				"codex_usage_updated_at":            "2026-08-15T10:00:00Z",
				"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
				"codex_5h_used_percent":             18.0,
				"codex_5h_reset_after_seconds":      18000,
				"codex_5h_window_minutes":           300,
				"codex_7d_used_percent":             100.0,
				"codex_7d_reset_after_seconds":      604800,
				"codex_7d_window_minutes":           10080,
			},
			wantUpdateCalls: 1,
		},
		{
			name:            "incomplete metrics preserve future reset",
			updates:         map[string]any{"codex_7d_used_percent": 12.0},
			wantUpdateCalls: 1,
		},
		{
			name:     "network failure",
			probeErr: errors.New("network unavailable"),
			wantErr:  true,
		},
		{
			name:            "persistence failure blocks clear",
			updates:         authoritativeOpenAIProbeUpdates(),
			persistErr:      errors.New("snapshot persistence failed"),
			wantErr:         true,
			wantUpdateCalls: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{
				ID:               42,
				Platform:         PlatformOpenAI,
				Type:             AccountTypeOAuth,
				RateLimitedAt:    &limitedAt,
				RateLimitResetAt: &resetAt,
			}
			repo := &openAIRateLimitRecoveryRepoStub{
				account:        account,
				updateExtraErr: tt.persistErr,
				clearResult:    true,
			}
			svc := &AccountUsageService{accountRepo: repo}
			probe := func(context.Context, *Account) (map[string]any, error) {
				return tt.updates, tt.probeErr
			}

			cleared, err := svc.revalidateOpenAIRateLimitWithProbe(context.Background(), account.ID, probe)

			require.Equal(t, tt.wantErr, err != nil)
			require.Equal(t, tt.wantCleared, cleared)
			require.Equal(t, tt.wantUpdateCalls, repo.updateExtraCalls)
			require.Equal(t, tt.wantClearCalls, repo.clearCalls)
			if !tt.wantCleared {
				require.NotNil(t, account.RateLimitResetAt)
				require.Equal(t, resetAt, *account.RateLimitResetAt)
			}
		})
	}
}

func TestRevalidateOpenAIRateLimitReplayIsIdempotent(t *testing.T) {
	limitedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	resetAt := time.Now().Add(6 * 24 * time.Hour).UTC().Truncate(time.Second)
	repo := &openAIRateLimitRecoveryRepoStub{
		account: &Account{
			ID:               42,
			Platform:         PlatformOpenAI,
			Type:             AccountTypeOAuth,
			RateLimitedAt:    &limitedAt,
			RateLimitResetAt: &resetAt,
		},
		clearResult: true,
	}
	svc := &AccountUsageService{accountRepo: repo}
	probeCalls := 0
	probe := func(context.Context, *Account) (map[string]any, error) {
		probeCalls++
		return authoritativeOpenAIProbeUpdates(), nil
	}

	cleared, err := svc.revalidateOpenAIRateLimitWithProbe(context.Background(), 42, probe)
	require.NoError(t, err)
	require.True(t, cleared)
	cleared, err = svc.revalidateOpenAIRateLimitWithProbe(context.Background(), 42, probe)
	require.NoError(t, err)
	require.False(t, cleared)
	require.Equal(t, 1, probeCalls)
	require.Equal(t, 1, repo.updateExtraCalls)
	require.Equal(t, 1, repo.clearCalls)
}

func TestRevalidateOpenAIRateLimitAllowsQuotaOnlyCandidate(t *testing.T) {
	resetAt := time.Now().Add(6 * 24 * time.Hour).UTC().Truncate(time.Second)
	repo := &openAIRateLimitRecoveryRepoStub{
		account: &Account{
			ID:       42,
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"codex_7d_used_percent": 100.0,
				"codex_7d_reset_at":     resetAt.Format(time.RFC3339),
			},
			// The quota-only path intentionally has no account-level
			// rate-limit generation to clear.
		},
		clearResult: true,
	}
	svc := &AccountUsageService{accountRepo: repo}

	cleared, err := svc.revalidateOpenAIRateLimitWithProbe(
		context.Background(),
		42,
		func(context.Context, *Account) (map[string]any, error) {
			return authoritativeOpenAIProbeUpdates(), nil
		},
	)

	require.NoError(t, err)
	require.True(t, cleared)
	require.Equal(t, 1, repo.updateExtraCalls)
	require.Equal(t, 0, repo.clearCalls)
}

func TestRevalidateOpenAIRateLimitKeepsQuotaOnlyCandidateWhenProviderStillExhausted(t *testing.T) {
	resetAt := time.Now().Add(6 * 24 * time.Hour).UTC().Truncate(time.Second)
	repo := &openAIRateLimitRecoveryRepoStub{
		account: &Account{
			ID:       42,
			Platform: PlatformOpenAI,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"codex_7d_used_percent": 100.0,
				"codex_7d_reset_at":     resetAt.Format(time.RFC3339),
			},
		},
		clearResult: true,
	}
	svc := &AccountUsageService{accountRepo: repo}

	cleared, err := svc.revalidateOpenAIRateLimitWithProbe(
		context.Background(),
		42,
		func(context.Context, *Account) (map[string]any, error) {
			updates := authoritativeOpenAIProbeUpdates()
			updates["codex_7d_used_percent"] = 100.0
			return updates, nil
		},
	)

	require.NoError(t, err)
	require.False(t, cleared)
	require.Equal(t, 1, repo.updateExtraCalls)
	require.Equal(t, 0, repo.clearCalls)
}

type cancelAwareRevalidationProbe struct {
	started chan struct{}
	once    sync.Once
}

func (p *cancelAwareRevalidationProbe) RevalidateOpenAIRateLimit(ctx context.Context, _ int64) (bool, error) {
	p.once.Do(func() { close(p.started) })
	<-ctx.Done()
	return false, ctx.Err()
}

func TestOpenAIRateLimitRevalidationStopCancelsAndWaits(t *testing.T) {
	candidates := &revalidationCandidateStub{accounts: []Account{{ID: 1}}}
	probe := &cancelAwareRevalidationProbe{started: make(chan struct{})}
	svc := NewOpenAIRateLimitRevalidationService(candidates, probe)
	require.NotNil(t, svc)

	svc.Start()
	select {
	case <-probe.started:
	case <-time.After(time.Second):
		t.Fatal("revalidation probe did not start")
	}

	stopped := make(chan struct{})
	go func() {
		svc.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel and wait for the active probe")
	}
}

func authoritativeOpenAIProbeUpdates() map[string]any {
	return map[string]any{
		"codex_usage_updated_at":            "2026-08-15T10:00:00Z",
		"codex_provider_probe_succeeded_at": "2026-08-15T10:00:00Z",
		"codex_5h_used_percent":             18.0,
		"codex_5h_reset_after_seconds":      18000,
		"codex_5h_window_minutes":           300,
		"codex_7d_used_percent":             42.0,
		"codex_7d_reset_after_seconds":      604800,
		"codex_7d_window_minutes":           10080,
	}
}
