-- Manual rollback for 223_force_account_fingerprint_defaults.sql.
-- Run only after stopping new account edits or during a maintenance window.
-- The backup table is intentionally retained after rollback for audit evidence.

UPDATE accounts AS account
SET extra = CASE
    WHEN COALESCE((backup.original_keys->>'had_codex_fingerprint_mode')::boolean, false)
    THEN jsonb_set(
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END,
        '{codex_fingerprint_mode}',
        backup.original_keys->'codex_fingerprint_mode',
        true
    )
    ELSE (
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END
    ) - 'codex_fingerprint_mode'
END
FROM account_fingerprint_defaults_20260901_backup AS backup
WHERE account.id = backup.account_id
  AND backup.platform = 'openai'
  AND backup.account_type = 'oauth';

UPDATE accounts AS account
SET extra = CASE
    WHEN COALESCE((backup.original_keys->>'had_codex_fingerprint_seed')::boolean, false)
    THEN jsonb_set(
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END,
        '{codex_fingerprint_seed}',
        backup.original_keys->'codex_fingerprint_seed',
        true
    )
    ELSE (
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END
    ) - 'codex_fingerprint_seed'
END
FROM account_fingerprint_defaults_20260901_backup AS backup
WHERE account.id = backup.account_id
  AND backup.platform = 'openai'
  AND backup.account_type = 'oauth';

UPDATE accounts AS account
SET extra = CASE
    WHEN COALESCE((backup.original_keys->>'had_enable_tls_fingerprint')::boolean, false)
    THEN jsonb_set(
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END,
        '{enable_tls_fingerprint}',
        backup.original_keys->'enable_tls_fingerprint',
        true
    )
    ELSE (
        CASE
            WHEN jsonb_typeof(account.extra) = 'object' THEN account.extra
            ELSE '{}'::jsonb
        END
    ) - 'enable_tls_fingerprint'
END
FROM account_fingerprint_defaults_20260901_backup AS backup
WHERE account.id = backup.account_id
  AND backup.platform = 'anthropic'
  AND backup.account_type IN ('oauth', 'setup-token');
