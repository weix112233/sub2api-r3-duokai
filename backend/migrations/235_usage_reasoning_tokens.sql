ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS reasoning_tokens integer NOT NULL DEFAULT 0;
