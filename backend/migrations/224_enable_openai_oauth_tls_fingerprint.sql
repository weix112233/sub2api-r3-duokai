-- Enable the approved TLS fingerprint default for existing OpenAI OAuth
-- accounts. The backup stores only the overwritten key for field-level
-- rollback and remains retained as migration evidence.
CREATE TABLE IF NOT EXISTS account_openai_tls_fingerprint_20260901_backup (
    account_id BIGINT PRIMARY KEY,
    platform TEXT NOT NULL,
    account_type TEXT NOT NULL,
    original_keys JSONB NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO account_openai_tls_fingerprint_20260901_backup (
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
        'had_enable_tls_fingerprint', COALESCE(extra ? 'enable_tls_fingerprint', false),
        'enable_tls_fingerprint', extra -> 'enable_tls_fingerprint'
    )
FROM accounts
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
ON CONFLICT (account_id) DO NOTHING;

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
  AND platform = 'openai'
  AND type = 'oauth';
