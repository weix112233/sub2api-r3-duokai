package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *accountRepository) SaveRecoveredOpenAIAccount(ctx context.Context, before *service.Account, credentials map[string]any) (bool, error) {
	if before == nil || before.Platform != service.PlatformOpenAI || before.Type != service.AccountTypeOAuth ||
		before.Status != service.StatusError || len(credentials) == 0 {
		return false, nil
	}
	oldJSON, err := json.Marshal(before.Credentials)
	if err != nil {
		return false, err
	}
	newJSON, err := json.Marshal(credentials)
	if err != nil {
		return false, err
	}
	// The credential CAS and durable scheduler notification commit together.
	result, err := r.sql.ExecContext(ctx, `WITH updated AS (
		UPDATE accounts SET credentials=$1::jsonb, status='active', error_message='', updated_at=now()
		WHERE id=$2 AND platform='openai' AND type='oauth' AND status='error'
		AND deleted_at IS NULL AND parent_account_id IS NULL AND credentials=$3::jsonb
		AND error_message IS NOT DISTINCT FROM $4 AND proxy_id IS NOT DISTINCT FROM $5
		RETURNING id
	) INSERT INTO scheduler_outbox (event_type,account_id,group_id,payload)
	SELECT $6,id,NULL,NULL FROM updated`, string(newJSON), before.ID, string(oldJSON),
		before.ErrorMessage, before.ProxyID, service.SchedulerOutboxEventAccountChanged)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, before.ID)
	return true, nil
}

func (r *accountRepository) SetOpenAIRecoveryCooldown(ctx context.Context, before *service.Account, until time.Time) (bool, error) {
	if before == nil || before.Platform != service.PlatformOpenAI || before.Type != service.AccountTypeOAuth ||
		before.Status != service.StatusError {
		return false, nil
	}
	oldJSON, err := json.Marshal(before.Credentials)
	if err != nil {
		return false, err
	}
	result, err := r.sql.ExecContext(ctx, `WITH updated AS (
		UPDATE accounts SET rate_limited_at=now(), rate_limit_reset_at=$1, updated_at=now()
		WHERE id=$2 AND platform='openai' AND type='oauth' AND status='error'
		AND deleted_at IS NULL AND parent_account_id IS NULL AND credentials=$3::jsonb
		AND error_message IS NOT DISTINCT FROM $4 AND proxy_id IS NOT DISTINCT FROM $5
		AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at < $1)
		RETURNING id
	) INSERT INTO scheduler_outbox (event_type,account_id,group_id,payload)
	SELECT $6,id,NULL,NULL FROM updated`, until, before.ID, string(oldJSON),
		before.ErrorMessage, before.ProxyID, service.SchedulerOutboxEventAccountChanged)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	r.syncSchedulerAccountSnapshotDetached(ctx, before.ID)
	return true, nil
}
