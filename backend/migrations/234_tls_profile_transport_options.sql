ALTER TABLE tls_fingerprint_profiles
    ADD COLUMN IF NOT EXISTS shuffle_extensions BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS http2 JSONB;

-- Before this version, both NULL and [] meant "inherit default ALPN".
-- Preserve those records; explicit [] written after this migration means no ALPN.
UPDATE tls_fingerprint_profiles
SET alpn_protocols = NULL
WHERE alpn_protocols = '[]'::jsonb;
