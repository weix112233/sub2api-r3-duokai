-- Field-level rollback for 224_enable_openai_oauth_tls_fingerprint.sql.
-- Keep the backup table for audit and repeatable rollback evidence.
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
FROM account_openai_tls_fingerprint_20260901_backup AS backup
WHERE account.id = backup.account_id
  AND account.deleted_at IS NULL
  AND account.platform = 'openai'
  AND account.type = 'oauth';
