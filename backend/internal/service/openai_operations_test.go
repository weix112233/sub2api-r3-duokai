//go:build unit

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/stretchr/testify/require"
)

type operationsTestRepository struct {
	OpenAIOperationsRepository
	record    *OpenAIRecoveryRecord
	completed []OpenAIRecoveryRecord
	scans     int
	buckets   []ReasoningTokenBucket
}

func (r *operationsTestRepository) RecoveryCandidates(context.Context, time.Time, int) ([]int64, error) {
	r.scans++
	return []int64{1}, nil
}
func (r *operationsTestRepository) ClaimRecovery(_ context.Context, a *Account, now time.Time) (*OpenAIRecoveryRecord, error) {
	if r.record != nil && r.record.Permanent {
		return nil, nil
	}
	record := OpenAIRecoveryRecord{AccountID: a.ID, LastAttemptAt: now, Attempts: 1}
	if r.record != nil {
		record = *r.record
		record.Attempts++
	}
	return &record, nil
}
func (r *operationsTestRepository) CompleteRecovery(_ context.Context, record OpenAIRecoveryRecord, _ string) error {
	r.record = &record
	r.completed = append(r.completed, record)
	return nil
}
func (r *operationsTestRepository) ReasoningDistribution(context.Context, time.Time, int, int64) ([]ReasoningTokenBucket, error) {
	return append([]ReasoningTokenBucket(nil), r.buckets...), nil
}

type recoveryTestAccounts struct {
	AccountRepository
	account       *Account
	beforeSave    func()
	saves         int
	cooldownCalls int
}

func (r *recoveryTestAccounts) GetByID(context.Context, int64) (*Account, error) {
	return snapshotOAuthRefreshAccount(r.account), nil
}
func (r *recoveryTestAccounts) SaveRecoveredOpenAIAccount(_ context.Context, before *Account, credentials map[string]any) (bool, error) {
	if r.beforeSave != nil {
		r.beforeSave()
	}
	r.saves++
	if r.account.Status != StatusError || !reflect.DeepEqual(r.account.Credentials, before.Credentials) {
		return false, nil
	}
	r.account.Credentials = shallowCopyMap(credentials)
	r.account.Status = StatusActive
	r.account.ErrorMessage = ""
	return true, nil
}
func (r *recoveryTestAccounts) SetOpenAIRecoveryCooldown(_ context.Context, before *Account, until time.Time) (bool, error) {
	r.cooldownCalls++
	if !reflect.DeepEqual(r.account.Credentials, before.Credentials) || r.account.Status != StatusError {
		return false, nil
	}
	r.account.RateLimitResetAt = &until
	return true, nil
}

func recoveryFixture() (*OpenAIOperationsService, *operationsTestRepository, *recoveryTestAccounts, *refreshAPIExecutorStub) {
	repo := &operationsTestRepository{}
	accounts := &recoveryTestAccounts{account: &Account{ID: 1, Platform: PlatformOpenAI,
		Type: AccountTypeOAuth, Status: StatusError, ErrorMessage: "token expired",
		Credentials: map[string]any{"refresh_token": "local-fixture"}}}
	executor := &refreshAPIExecutorStub{credentials: map[string]any{"refresh_token": "local-rotated-fixture"}}
	svc := &OpenAIOperationsService{repo: repo, accounts: accounts, refresh: NewOAuthRefreshAPI(accounts, nil), executor: executor}
	return svc, repo, accounts, executor
}

func TestOpenAIOperationsRecoveryStates(t *testing.T) {
	for _, tc := range []struct {
		name, message, upstream, outcome, classification string
		permanent, cooling                               bool
		calls                                            int
	}{
		{"success", "token expired", "", "recovered", "recoverable", false, false, 1},
		{"deactivated", "account_deactivated", "", "skipped", "permanent", true, false, 0},
		{"revoked", "refresh_token_revoked", "", "skipped", "permanent", true, false, 0},
		{"invalid grant", "refresh failed", "401 invalid_grant", "failed", "permanent", true, false, 1},
		{"network", "network error", "connection reset", "failed", "recoverable", false, false, 1},
		{"rate limited", "429", "HTTP 429", "cooling", "rate_limit", false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, accounts, executor := recoveryFixture()
			accounts.account.ErrorMessage = tc.message
			if tc.upstream != "" {
				executor.err = errors.New(tc.upstream)
			}
			cfg := DefaultOpenAIOperationsSettings().Recovery
			cfg.Enabled = true
			require.NoError(t, svc.runRecovery(t.Context(), cfg))
			require.Equal(t, tc.calls, executor.refreshCalls)
			require.Equal(t, tc.outcome, repo.record.Outcome)
			require.Equal(t, tc.classification, repo.record.Classification)
			require.Equal(t, tc.permanent, repo.record.Permanent)
			require.Equal(t, tc.cooling, accounts.account.IsRateLimited())
			if tc.outcome == "recovered" {
				require.Equal(t, StatusActive, accounts.account.Status)
				require.Empty(t, accounts.account.ErrorMessage)
			} else {
				require.Equal(t, StatusError, accounts.account.Status, "cooldown never relabels account status")
			}
			if tc.permanent {
				require.NoError(t, svc.runRecovery(t.Context(), cfg))
				require.Equal(t, tc.calls, executor.refreshCalls)
				require.Len(t, repo.completed, 1)
			}
		})
	}
}

func TestOpenAIOperationsRecoveryDisabledCooldownAndBackoff(t *testing.T) {
	svc, repo, accounts, executor := recoveryFixture()
	cfg := DefaultOpenAIOperationsSettings().Recovery
	require.NoError(t, svc.runRecovery(t.Context(), cfg))
	require.Zero(t, repo.scans)
	cfg.Enabled = true
	until := time.Now().Add(time.Hour)
	accounts.account.RateLimitResetAt = &until
	require.NoError(t, svc.runRecovery(t.Context(), cfg))
	require.Zero(t, executor.refreshCalls)
	require.Equal(t, until, repo.record.NextAttemptAt)
	accounts.account.RateLimitResetAt = nil
	repo.record.ConsecutiveFailures = cfg.FailureThreshold - 1
	repo.record.NextAttemptAt = time.Now().Add(time.Minute)
	executor.err = errors.New("429 too many requests")
	before := time.Now()
	require.NoError(t, svc.runRecovery(t.Context(), cfg))
	require.Equal(t, cfg.FailureThreshold, repo.record.ConsecutiveFailures)
	require.True(t, repo.record.NextAttemptAt.After(before.Add(time.Duration(cfg.BackoffMinutes)*time.Minute)))
	require.Equal(t, 1, accounts.cooldownCalls)
}

func TestOpenAIOperationsRecoveryStaleAndCancelled(t *testing.T) {
	for _, kind := range []string{"new credentials", "disabled", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			svc, repo, accounts, executor := recoveryFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			executor.onRefresh = func() {
				switch kind {
				case "new credentials":
					accounts.account.Credentials = map[string]any{"refresh_token": "local-reauthorized"}
				case "disabled":
					accounts.account.Status = StatusDisabled
				case "canceled":
					cancel()
				}
			}
			cfg := DefaultOpenAIOperationsSettings().Recovery
			cfg.Enabled = true
			require.NoError(t, svc.runRecovery(ctx, cfg))
			require.NotEqual(t, "recovered", repo.record.Outcome)
			require.NotEqual(t, StatusActive, accounts.account.Status)
			if kind == "canceled" {
				require.Zero(t, accounts.saves)
			}
		})
	}
}

func TestOpenAIOperationsRecoverySkipsChangedCredentialGeneration(t *testing.T) {
	svc, _, accounts, executor := recoveryFixture()
	before := snapshotOAuthRefreshAccount(accounts.account)
	accounts.account.Credentials["refresh_token"] = "local-new-generation"
	result, err := svc.refresh.RecoverOpenAIError(t.Context(), before, executor)
	require.NoError(t, err)
	require.False(t, result.Refreshed)
	require.Zero(t, executor.refreshCalls)
}

func TestOpenAIOperationsSettingsAndTemplate(t *testing.T) {
	store := &tlsDefaultsRepo{values: map[string]string{}}
	svc := &SettingService{settingRepo: store}
	cfg, err := svc.GetOpenAIOperationsSettings(t.Context())
	require.NoError(t, err)
	require.False(t, cfg.Recovery.Enabled)
	require.Nil(t, cfg.NewAccountDefaults)
	require.Empty(t, store.values, "no startup settings writes")
	proxy, profile, concurrency, enabled, mode := int64(0), int64(-1), 8, false, "machine"
	cfg.NewAccountDefaults = &OpenAINewAccountDefaults{ProxyID: &proxy, TLSFingerprintProfileID: &profile,
		Concurrency: &concurrency, EnableTLSFingerprint: &enabled, CodexFingerprintMode: &mode}
	require.NoError(t, svc.SetOpenAIOperationsSettings(t.Context(), cfg))
	loaded, err := svc.GetOpenAIOperationsSettings(t.Context())
	require.NoError(t, err)
	require.Equal(t, cfg, loaded)
	oldProxy := int64(9)
	input := &CreateAccountInput{Platform: PlatformOpenAI, ProxyID: &oldProxy, Concurrency: 3,
		Extra: map[string]any{"enable_tls_fingerprint": true, "unrelated": "kept"}}
	out := applyOpenAINewAccountDefaults(input, cfg.NewAccountDefaults)
	require.Nil(t, out.ProxyID)
	require.Equal(t, 8, out.Concurrency)
	require.Equal(t, false, out.Extra["enable_tls_fingerprint"])
	require.Equal(t, "kept", out.Extra["unrelated"])
	require.Equal(t, true, input.Extra["enable_tls_fingerprint"], "no mutation of original import or old account")
	require.Equal(t, 3, input.Concurrency)
	input.Platform = PlatformAnthropic
	require.Same(t, input, applyOpenAINewAccountDefaults(input, cfg.NewAccountDefaults))
	require.Same(t, input, applyOpenAINewAccountDefaults(input, nil))
	cfg.Recovery.IntervalMinutes = 0
	require.Error(t, svc.SetOpenAIOperationsSettings(t.Context(), cfg))
	store.values[SettingKeyOpenAIOperations] = "{broken"
	_, err = svc.GetOpenAIOperationsSettings(t.Context())
	require.Error(t, err)
}

func TestOpenAIOperationsReasoningThresholdAndCooldownSnapshot(t *testing.T) {
	repo := &operationsTestRepository{buckets: []ReasoningTokenBucket{
		{ReasoningTokens: 0, Hits: 100}, {ReasoningTokens: 123, Hits: 49}, {ReasoningTokens: 456, Hits: 50},
	}}
	svc := &OpenAIOperationsService{repo: repo}
	buckets, err := svc.Reasoning(t.Context(), 0)
	require.NoError(t, err)
	require.False(t, buckets[0].SuspectedTruncation)
	require.False(t, buckets[1].SuspectedTruncation)
	require.True(t, buckets[2].SuspectedTruncation)
	now := time.Now()
	future, past := now.Add(time.Minute), now.Add(-time.Second)
	account := &Account{ID: 1, Status: StatusActive, Schedulable: true, RateLimitResetAt: &future,
		OverloadUntil: &past, TempUnschedulableUntil: &future, TempUnschedulableReason: "error_rate"}
	state := accountOperationalState(account, now)
	require.Len(t, state.Cooldowns, 2)
	require.False(t, state.Schedulable)
	require.Empty(t, state.StickyEscapeReason, "TTFT is not invented as a cooldown")
	require.Empty(t, accountOperationalState(account, future.Add(time.Second)).Cooldowns)
}

func TestTLSProfileStableAccountSelectionAndWSCompatibility(t *testing.T) {
	profiles := &tlsDefaultProfilesRepo{profiles: map[int64]*model.TLSFingerprintProfile{
		11: {ID: 11, Name: "first"}, 12: {ID: 12, Name: "second"}, 13: {ID: 13, Name: "third"},
	}}
	svc := ProvideTLSFingerprintProfileService(profiles, nil, &tlsDefaultsRepo{values: map[string]string{}})
	seen := map[string]bool{}
	for id := int64(1); id <= 100; id++ {
		a := &Account{ID: id, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
			Extra: map[string]any{"enable_tls_fingerprint": true, "tls_fingerprint_profile_id": int64(-1)}}
		profile := svc.ResolveTLSProfile(a)
		seen[profile.Name] = true
		for repeat := 0; repeat < 20; repeat++ {
			require.Equal(t, profile.TransportKey(), svc.ResolveTLSProfile(a).TransportKey())
		}
		key := normalizeOpenAIWSHandshakeCompatibility(a, nil, profile)
		edited := profile.Clone()
		edited.ShuffleExtensions = !edited.ShuffleExtensions
		require.NotEqual(t, key, normalizeOpenAIWSHandshakeCompatibility(a, nil, edited))
		require.NotEqual(t, key, normalizeOpenAIWSHandshakeCompatibility(a, nil, nil))
	}
	require.Len(t, seen, 3)
}
