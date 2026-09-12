package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type openAIOperationsRepository struct{ db *sql.DB }

func NewOpenAIOperationsRepository(db *sql.DB) service.OpenAIOperationsRepository {
	return &openAIOperationsRepository{db: db}
}

func (r *openAIOperationsRepository) ReasoningDistribution(ctx context.Context, since time.Time, limit int, accountID int64) ([]service.ReasoningTokenBucket, error) {
	rows, err := r.db.QueryContext(ctx, `WITH sample AS (
		SELECT COALESCE(NULLIF(u.upstream_response_model,''), NULLIF(u.upstream_model,''),u.model) AS model, u.reasoning_tokens
		FROM usage_logs u JOIN accounts a ON a.id = u.account_id
		WHERE a.platform = 'openai' AND u.created_at >= $1 AND u.reasoning_effort = 'xhigh'
		AND ($2::bigint = 0 OR u.account_id = $2) ORDER BY u.created_at DESC, u.id DESC LIMIT $3
	) SELECT model, reasoning_tokens, count(*) FROM sample GROUP BY model, reasoning_tokens
	ORDER BY count(*) DESC, model, reasoning_tokens`, since, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]service.ReasoningTokenBucket, 0)
	for rows.Next() {
		var b service.ReasoningTokenBucket
		if err := rows.Scan(&b.Model, &b.ReasoningTokens, &b.Hits); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (r *openAIOperationsRepository) RecoveryCandidates(ctx context.Context, now time.Time, limit int) ([]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT a.id FROM accounts a LEFT JOIN openai_account_recovery r ON r.account_id=a.id
		WHERE a.platform='openai' AND a.type='oauth' AND a.status='error' AND a.deleted_at IS NULL
		AND a.parent_account_id IS NULL AND (r.account_id IS NULL OR
			(r.lease_until <= $1 AND (NOT r.permanent OR r.credential_fingerprint <> `+recoveryCredentialFingerprint("a")+`)
			AND (r.next_attempt_at <= $1 OR r.credential_fingerprint <> `+recoveryCredentialFingerprint("a")+`)))
		ORDER BY COALESCE(r.next_attempt_at, '-infinity'::timestamptz), a.id LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

const recoveryColumns = `account_id, attempts, consecutive_failures, last_attempt_at, next_attempt_at, classification, outcome, permanent`

// Changes to display names, cooldowns and quota metadata must not reset retry
// policy. This comparison stays in PostgreSQL and is never returned by the API.
func recoveryCredentialFingerprint(alias string) string {
	return `md5(jsonb_build_array(` + alias + `.credentials->>'refresh_token', ` + alias + `.credentials->>'client_id')::text)`
}

func scanRecovery(row interface{ Scan(...any) error }) (*service.OpenAIRecoveryRecord, error) {
	var v service.OpenAIRecoveryRecord
	err := row.Scan(&v.AccountID, &v.Attempts, &v.ConsecutiveFailures, &v.LastAttemptAt, &v.NextAttemptAt,
		&v.Classification, &v.Outcome, &v.Permanent)
	return &v, err
}

func (r *openAIOperationsRepository) ClaimRecovery(ctx context.Context, account *service.Account, now time.Time) (*service.OpenAIRecoveryRecord, error) {
	row := r.db.QueryRowContext(ctx, `INSERT INTO openai_account_recovery
		(account_id, attempts, last_attempt_at, next_attempt_at, lease_until, credential_fingerprint, outcome)
		SELECT id, 1, $2::timestamptz, $2::timestamptz, $2::timestamptz + interval '2 minutes', `+recoveryCredentialFingerprint("accounts")+`, 'running' FROM accounts
		WHERE id=$1 AND status='error' AND platform='openai' AND type='oauth' AND deleted_at IS NULL
			AND parent_account_id IS NULL AND updated_at=$3
		ON CONFLICT (account_id) DO UPDATE SET attempts=openai_account_recovery.attempts+1,
			consecutive_failures=CASE WHEN EXCLUDED.credential_fingerprint <> openai_account_recovery.credential_fingerprint
				THEN 0 ELSE openai_account_recovery.consecutive_failures END,
			last_attempt_at=$2::timestamptz, lease_until=$2::timestamptz + interval '2 minutes',
			credential_fingerprint=EXCLUDED.credential_fingerprint, permanent=false,
			next_attempt_at=$2, classification='', outcome='running'
		WHERE openai_account_recovery.lease_until <= $2
			AND (NOT openai_account_recovery.permanent OR EXCLUDED.credential_fingerprint <> openai_account_recovery.credential_fingerprint)
			AND (openai_account_recovery.next_attempt_at <= $2 OR EXCLUDED.credential_fingerprint <> openai_account_recovery.credential_fingerprint)
		RETURNING `+recoveryColumns, account.ID, now, account.UpdatedAt)
	record, err := scanRecovery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return record, err
}

func (r *openAIOperationsRepository) CompleteRecovery(ctx context.Context, v service.OpenAIRecoveryRecord, action string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE openai_account_recovery SET consecutive_failures=$3,
		next_attempt_at=$4, classification=$5, outcome=$6, permanent=$7, lease_until=now()
		WHERE account_id=$1 AND attempts=$2 AND outcome='running' AND lease_until > now()`, v.AccountID, v.Attempts, v.ConsecutiveFailures,
		v.NextAttemptAt, v.Classification, v.Outcome, v.Permanent)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO openai_account_recovery_events
		(account_id, attempt, classification, action, outcome) VALUES ($1,$2,$3,$4,$5)`,
		v.AccountID, v.Attempts, v.Classification, action, v.Outcome)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *openAIOperationsRepository) RecoveryEvents(ctx context.Context, accountID int64, limit int) ([]service.OpenAIRecoveryEvent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, account_id, attempt, classification, action, outcome, created_at
		FROM openai_account_recovery_events WHERE ($1::bigint=0 OR account_id=$1) ORDER BY id DESC LIMIT $2`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]service.OpenAIRecoveryEvent, 0)
	for rows.Next() {
		var v service.OpenAIRecoveryEvent
		if err := rows.Scan(&v.ID, &v.AccountID, &v.Attempt, &v.Classification, &v.Action, &v.Outcome, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *openAIOperationsRepository) RecoveryRecords(ctx context.Context, ids []int64) ([]service.OpenAIRecoveryRecord, error) {
	out := make([]service.OpenAIRecoveryRecord, 0)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+recoveryColumns+` FROM openai_account_recovery WHERE account_id=ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		record, err := scanRecovery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *record)
	}
	return out, rows.Err()
}
