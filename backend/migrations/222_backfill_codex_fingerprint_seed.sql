-- Backfill system-managed Codex fingerprint seeds for OpenAI OAuth accounts.
-- Idempotent: valid canonical seeds are preserved on rerun.
-- 与上游 225 的差异：上游缺省模式为 off（仅显式 device/session/full 的账号回填）；
-- 本基线缺省模式为 session（所有 OpenAI OAuth 账号默认收敛），因此除显式 off 外
-- 全部回填，保证存量账号在 seed 化收敛（v2 派生）下继续收敛而不是退化为透传。
UPDATE accounts
SET extra = jsonb_set(
    COALESCE(extra, '{}'::jsonb),
    '{codex_fingerprint_seed}',
    to_jsonb(gen_random_uuid()::text),
    true
)
WHERE deleted_at IS NULL
  AND platform = 'openai'
  AND type = 'oauth'
  AND COALESCE(extra->>'codex_fingerprint_mode', '') <> 'off'
  AND (
      extra->>'codex_fingerprint_seed' IS NULL
      OR btrim(extra->>'codex_fingerprint_seed') = ''
      OR NOT (
          extra->>'codex_fingerprint_seed' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND extra->>'codex_fingerprint_seed' <> '00000000-0000-0000-0000-000000000000'
      )
  );
