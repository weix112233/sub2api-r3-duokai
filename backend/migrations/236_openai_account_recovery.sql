CREATE TABLE IF NOT EXISTS openai_account_recovery (
    account_id bigint PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    attempts integer NOT NULL DEFAULT 0,
    consecutive_failures integer NOT NULL DEFAULT 0,
    last_attempt_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    lease_until timestamptz NOT NULL,
    credential_fingerprint text NOT NULL,
    classification text NOT NULL DEFAULT '',
    outcome text NOT NULL DEFAULT '',
    permanent boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_openai_account_recovery_due ON openai_account_recovery(next_attempt_at);
CREATE TABLE IF NOT EXISTS openai_account_recovery_events (
    id bigserial PRIMARY KEY,
    account_id bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    attempt integer NOT NULL,
    classification text NOT NULL,
    action text NOT NULL,
    outcome text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_openai_recovery_events_account ON openai_account_recovery_events(account_id, id DESC);
