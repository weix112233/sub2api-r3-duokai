-- Force the approved fingerprint defaults onto all existing eligible accounts.
-- The backup table stores only the keys this migration overwrites so rollback
-- does not replace unrelated account configuration.
CREATE TABLE IF NOT EXISTS account_fingerprint_defaults_20260901_backup (
    account_id BIGINT PRIMARY KEY,
    platform TEXT NOT NULL,
    account_type TEXT NOT NULL,
    original_keys JSONB NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO account_fingerprint_defaults_20260901_backup (
    account_id,
    platform,
    account_type,
    original_keys
)
SELECT
    id,
    platform,
    type,
    jsonb_build_object(
        'had_codex_fingerprint_mode', COALESCE(extra ? 'codex_fingerprint_mode', false),
        'codex_fingerprint_mode', extra -> 'codex_fingerprint_mode',
        'had_codex_fingerprint_seed', COALESCE(extra ? 'codex_fingerprint_seed', false),
        'codex_fingerprint_seed', extra -> 'codex_fingerprint_seed',
        'had_enable_tls_fingerprint', COALESCE(extra ? 'enable_tls_fingerprint', false),
        'enable_tls_fingerprint', extra -> 'enable_tls_fingerprint'
    )
FROM accounts
WHERE deleted_at IS NULL
  AND (
      (platform = 'openai' AND type = 'oauth')
      OR (platform = 'anthropic' AND type IN ('oauth', 'setup-token'))
  )
ON CONFLICT (account_id) DO NOTHING;

UPDATE accounts
SET extra = jsonb_set(
    jsonb_set(
        CASE
            WHEN jsonb_typeof(extra) = 'object' THEN extra
            ELSE '{}'::jsonb
        END,
        '{codex_fingerprint_mode}',
        '"machine"'::jsonb,
        true
    ),
    '{codex_fingerprint_seed}',
    CASE
        WHEN (
            extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
        )
        THEN to_jsonb(extra->>'codex_fingerprint_seed')
        ELSE to_jsonb(gen_random_uuid()::text)
    END,
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth';

UPDATE accounts
SET extra = jsonb_set(
    CASE
        WHEN jsonb_typeof(extra) = 'object' THEN extra
        ELSE '{}'::jsonb
    END,
    '{enable_tls_fingerprint}',
    'true'::jsonb,
    true
)
WHERE deleted_at IS NULL
  AND platform = 'anthropic'
  AND type IN ('oauth', 'setup-token');
