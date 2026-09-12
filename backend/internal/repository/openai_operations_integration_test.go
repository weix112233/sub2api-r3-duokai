//go:build integration

package repository

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func createRecoveryTestAccount(t *testing.T) *service.Account {
	t.Helper()
	a := mustCreateAccount(t, testEntClient(t), &service.Account{
		Name: "recovery-" + uuid.NewString(), Platform: service.PlatformOpenAI,
		Type: service.AccountTypeOAuth, Status: service.StatusError, ErrorMessage: "refresh failed",
		Credentials: map[string]any{"refresh_token": "local-recovery-fixture"},
	})
	t.Cleanup(func() { _, _ = integrationDB.Exec(`DELETE FROM accounts WHERE id=$1`, a.ID) })
	repo := NewAccountRepository(testEntClient(t), integrationDB, nil)
	current, err := repo.GetByID(t.Context(), a.ID)
	require.NoError(t, err)
	return current
}

func TestOpenAIOperationsRecoveryClaimLeaseAndCredentialGeneration(t *testing.T) {
	ctx := t.Context()
	repo := NewOpenAIOperationsRepository(integrationDB)
	accountRepo := NewAccountRepository(testEntClient(t), integrationDB, nil)
	a := createRecoveryTestAccount(t)
	now := time.Now()
	const workers = 8
	records := make([]*service.OpenAIRecoveryRecord, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			records[i], errs[i] = repo.ClaimRecovery(ctx, a, now)
		}(i)
	}
	wg.Wait()
	var winner *service.OpenAIRecoveryRecord
	for i, record := range records {
		require.NoError(t, errs[i])
		if record != nil {
			require.Nil(t, winner, "only one instance may refresh")
			winner = record
		}
	}
	require.NotNil(t, winner)
	winner.Permanent, winner.Classification, winner.Outcome = true, "permanent", "failed"
	winner.NextAttemptAt = now.Add(6 * time.Hour)
	winner.ConsecutiveFailures = 5
	require.NoError(t, repo.CompleteRecovery(ctx, *winner, "oauth_refresh"))
	require.NoError(t, repo.CompleteRecovery(ctx, *winner, "oauth_refresh"))
	events, err := repo.RecoveryEvents(ctx, a.ID, 10)
	require.NoError(t, err)
	require.Len(t, events, 1, "completion is idempotent")

	_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET name=name||'-edited', rate_limit_reset_at=now()+interval '10 minutes', updated_at=now() WHERE id=$1`, a.ID)
	require.NoError(t, err)
	a, err = accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	candidate, err := repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.Nil(t, candidate, "ordinary edits or cooldown writes cannot clear permanent/backoff state")
	ids, err := repo.RecoveryCandidates(ctx, time.Now(), 1000)
	require.NoError(t, err)
	require.NotContains(t, ids, a.ID)

	_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET credentials=jsonb_set(credentials,'{refresh_token}','"local-reauthorized"'), updated_at=now() WHERE id=$1`, a.ID)
	require.NoError(t, err)
	a, err = accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	candidate, err = repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.NotNil(t, candidate, "reauthorization resets permanent state")
	require.Zero(t, candidate.ConsecutiveFailures)
	require.Equal(t, 2, candidate.Attempts)
	require.NoError(t, repo.CompleteRecovery(ctx, *winner, "stale"))
	events, err = repo.RecoveryEvents(ctx, a.ID, 10)
	require.NoError(t, err)
	require.Len(t, events, 1, "old generation cannot complete a new lease")
	_, err = integrationDB.ExecContext(ctx, `UPDATE openai_account_recovery SET lease_until=now()-interval '1 second' WHERE account_id=$1`, a.ID)
	require.NoError(t, err)
	require.NoError(t, repo.CompleteRecovery(ctx, *candidate, "expired"))
	events, err = repo.RecoveryEvents(ctx, a.ID, 10)
	require.NoError(t, err)
	require.Len(t, events, 1, "expired lease cannot publish an outcome")
	reclaimed, err := repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.NotNil(t, reclaimed)
	require.Equal(t, 3, reclaimed.Attempts)
}

func TestOpenAIOperationsRecoveryBackoffSurvivesAccountEdits(t *testing.T) {
	ctx := t.Context()
	a := createRecoveryTestAccount(t)
	repo := NewOpenAIOperationsRepository(integrationDB)
	accountRepo := NewAccountRepository(testEntClient(t), integrationDB, nil)
	record, err := repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.NotNil(t, record)
	record.ConsecutiveFailures, record.Outcome = 5, "failed"
	record.NextAttemptAt = time.Now().Add(6 * time.Hour)
	require.NoError(t, repo.CompleteRecovery(ctx, *record, "oauth_refresh"))
	_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET updated_at=now(), temp_unschedulable_reason='429' WHERE id=$1`, a.ID)
	require.NoError(t, err)
	a, err = accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	claimed, err := repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.Nil(t, claimed)
	ids, err := repo.RecoveryCandidates(ctx, time.Now(), 1000)
	require.NoError(t, err)
	require.NotContains(t, ids, a.ID)
	_, err = integrationDB.ExecContext(ctx, `UPDATE openai_account_recovery SET next_attempt_at=now()-interval '1 second' WHERE account_id=$1`, a.ID)
	require.NoError(t, err)
	claimed, err = repo.ClaimRecovery(ctx, a, time.Now())
	require.NoError(t, err)
	require.NotNil(t, claimed)
	require.Equal(t, 5, claimed.ConsecutiveFailures)
}

func TestOpenAIOperationsRecoveryCompareAndSwap(t *testing.T) {
	ctx := t.Context()
	repo := NewAccountRepository(testEntClient(t), integrationDB, nil).(*accountRepository)
	for _, change := range []string{"credentials", "status", "error_message", "deleted_at", "none"} {
		t.Run(change, func(t *testing.T) {
			a := createRecoveryTestAccount(t)
			var err error
			switch change {
			case "credentials":
				_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET credentials='{"refresh_token":"local-new"}' WHERE id=$1`, a.ID)
			case "status":
				_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET status='disabled' WHERE id=$1`, a.ID)
			case "error_message":
				_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET error_message='account_deactivated' WHERE id=$1`, a.ID)
			case "deleted_at":
				_, err = integrationDB.ExecContext(ctx, `UPDATE accounts SET deleted_at=now() WHERE id=$1`, a.ID)
			}
			require.NoError(t, err)
			applied, err := repo.SetOpenAIRecoveryCooldown(ctx, a, time.Now().Add(time.Minute))
			require.NoError(t, err)
			require.Equal(t, change == "none", applied)
			applied, err = repo.SaveRecoveredOpenAIAccount(ctx, a, map[string]any{"refresh_token": "local-rotated"})
			require.NoError(t, err)
			require.Equal(t, change == "none", applied)
			if applied {
				current, err := repo.GetByID(ctx, a.ID)
				require.NoError(t, err)
				require.Equal(t, service.StatusActive, current.Status)
				require.Empty(t, current.ErrorMessage)
				require.NotNil(t, current.RateLimitResetAt, "recovery preserves scheduler cooldown")
			}
		})
	}
}

func TestOpenAIOperationsReasoningPersistenceAndDistribution(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	user := mustCreateUser(t, client, &service.User{Email: "reasoning-" + uuid.NewString() + "@example.test"})
	key := mustCreateApiKey(t, client, &service.APIKey{UserID: user.ID, Key: "test-reasoning-" + uuid.NewString(), Name: "reasoning"})
	account := mustCreateAccount(t, client, &service.Account{Name: "reasoning-" + uuid.NewString(), Platform: service.PlatformOpenAI})
	other := mustCreateAccount(t, client, &service.Account{Name: "reasoning-other-" + uuid.NewString(), Platform: service.PlatformAnthropic})
	repo := newUsageLogRepositoryWithSQL(client, integrationDB)
	t.Cleanup(func() {
		_, _ = integrationDB.Exec(`DELETE FROM usage_logs WHERE user_id=$1`, user.ID)
		_, _ = integrationDB.Exec(`DELETE FROM api_keys WHERE id=$1`, key.ID)
		_, _ = integrationDB.Exec(`DELETE FROM accounts WHERE id IN ($1,$2)`, account.ID, other.ID)
		_, _ = integrationDB.Exec(`DELETE FROM users WHERE id=$1`, user.ID)
	})
	// Exercise production batching, not only direct SQL fixture insertion.
	errs := make([]error, 50)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			effort := "xhigh"
			log := &service.UsageLog{UserID: user.ID, APIKeyID: key.ID, AccountID: account.ID,
				RequestID: uuid.NewString(), Model: "local-observation-model", ReasoningEffort: &effort,
				OutputTokens: 1000, ReasoningTokens: 321, TotalCost: 0.123, ActualCost: 0.123, CreatedAt: time.Now()}
			_, errs[i] = repo.Create(ctx, log)
			if errs[i] == nil {
				got, err := repo.GetByID(ctx, log.ID)
				errs[i] = err
				if err == nil && (got.ReasoningTokens != 321 || got.OutputTokens != 1000 || got.ActualCost != 0.123) {
					errs[i] = fmt.Errorf("reasoning or billing roundtrip changed")
				}
			}
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	operations := NewOpenAIOperationsRepository(integrationDB)
	buckets, err := operations.ReasoningDistribution(ctx, time.Now().Add(-time.Hour), 1000, account.ID)
	require.NoError(t, err)
	require.Equal(t, []service.ReasoningTokenBucket{{Model: "local-observation-model", ReasoningTokens: 321, Hits: 50}}, buckets)
	svc := service.NewOpenAIOperationsService(operations, nil, nil, nil, nil, nil, nil, nil)
	alerts, err := svc.Reasoning(ctx, account.ID)
	require.NoError(t, err)
	require.True(t, alerts[0].SuspectedTruncation)
	buckets, err = operations.ReasoningDistribution(ctx, time.Now().Add(-time.Hour), 49, account.ID)
	require.NoError(t, err)
	require.Equal(t, 49, buckets[0].Hits)
	buckets, err = operations.ReasoningDistribution(ctx, time.Now().Add(time.Hour), 1000, account.ID)
	require.NoError(t, err)
	require.Empty(t, buckets)
	buckets, err = operations.ReasoningDistribution(ctx, time.Now().Add(-time.Hour), 1000, other.ID)
	require.NoError(t, err)
	require.Empty(t, buckets)
}
