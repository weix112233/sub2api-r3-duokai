//go:build integration

package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	dbmigrations "github.com/Wei-Shaw/sub2api/migrations"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMigration223ForcesExistingAccountFingerprintDefaultsAndRollsBack(t *testing.T) {
	tx := testTx(t)
	ctx := context.Background()

	migrationSQL, err := dbmigrations.FS.ReadFile("223_force_account_fingerprint_defaults.sql")
	require.NoError(t, err)
	rollbackSQL, err := os.ReadFile(filepath.Join(
		"..",
		"..",
		"migrations",
		"rollback",
		"223_restore_account_fingerprint_defaults.sql",
	))
	require.NoError(t, err)

	type fixture struct {
		name        string
		platform    string
		accountType string
		extra       string
		deleted     bool
	}
	fixtures := []fixture{
		{
			name:        "migration-223-openai-missing",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{}`,
		},
		{
			name:        "migration-223-openai-explicit-off",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{"codex_fingerprint_mode":"off","codex_fingerprint_seed":"11111111-1111-4111-8111-111111111111"}`,
		},
		{
			name:        "migration-223-openai-invalid-seed",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{"codex_fingerprint_mode":"device","codex_fingerprint_seed":"BAD"}`,
		},
		{
			name:        "migration-223-openai-apikey",
			platform:    "openai",
			accountType: "apikey",
			extra:       `{"codex_fingerprint_mode":"off"}`,
		},
		{
			name:        "migration-223-anthropic-oauth-off",
			platform:    "anthropic",
			accountType: "oauth",
			extra:       `{"enable_tls_fingerprint":false}`,
		},
		{
			name:        "migration-223-anthropic-setup-missing",
			platform:    "anthropic",
			accountType: "setup-token",
			extra:       `{}`,
		},
		{
			name:        "migration-223-anthropic-apikey",
			platform:    "anthropic",
			accountType: "apikey",
			extra:       `{"enable_tls_fingerprint":false}`,
		},
		{
			name:        "migration-223-deleted-openai",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{"codex_fingerprint_mode":"off"}`,
			deleted:     true,
		},
	}

	ids := make(map[string]int64, len(fixtures))
	allIDs := make([]int64, 0, len(fixtures))
	for _, fixture := range fixtures {
		var id int64
		require.NoError(t, tx.QueryRowContext(ctx, `
INSERT INTO accounts (name, platform, type, extra, deleted_at)
VALUES ($1, $2, $3, $4::jsonb, CASE WHEN $5 THEN NOW() ELSE NULL END)
RETURNING id
`, fixture.name, fixture.platform, fixture.accountType, fixture.extra, fixture.deleted).Scan(&id))
		ids[fixture.name] = id
		allIDs = append(allIDs, id)
	}

	_, err = tx.ExecContext(ctx, string(migrationSQL))
	require.NoError(t, err)

	readExtraString := func(name, key string) string {
		t.Helper()
		var value string
		require.NoError(t, tx.QueryRowContext(
			ctx,
			`SELECT COALESCE(extra->>$2, '') FROM accounts WHERE id = $1`,
			ids[name],
			key,
		).Scan(&value))
		return value
	}

	for _, name := range []string{
		"migration-223-openai-missing",
		"migration-223-openai-explicit-off",
		"migration-223-openai-invalid-seed",
	} {
		require.Equal(t, "machine", readExtraString(name, "codex_fingerprint_mode"))
		requireCanonicalUUIDString(t, readExtraString(name, "codex_fingerprint_seed"))
	}
	require.Equal(
		t,
		"11111111-1111-4111-8111-111111111111",
		readExtraString("migration-223-openai-explicit-off", "codex_fingerprint_seed"),
	)
	require.Equal(t, "off", readExtraString("migration-223-openai-apikey", "codex_fingerprint_mode"))
	require.Equal(t, "off", readExtraString("migration-223-deleted-openai", "codex_fingerprint_mode"))

	require.Equal(t, "true", readExtraString("migration-223-anthropic-oauth-off", "enable_tls_fingerprint"))
	require.Equal(t, "true", readExtraString("migration-223-anthropic-setup-missing", "enable_tls_fingerprint"))
	require.Equal(t, "false", readExtraString("migration-223-anthropic-apikey", "enable_tls_fingerprint"))

	var backupRows int
	require.NoError(t, tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM account_fingerprint_defaults_20260901_backup
WHERE account_id = ANY($1)
`, pq.Array(allIDs)).Scan(&backupRows))
	require.Equal(t, 5, backupRows)

	seedsAfterFirstRun := map[string]string{
		"migration-223-openai-missing":      readExtraString("migration-223-openai-missing", "codex_fingerprint_seed"),
		"migration-223-openai-explicit-off": readExtraString("migration-223-openai-explicit-off", "codex_fingerprint_seed"),
		"migration-223-openai-invalid-seed": readExtraString("migration-223-openai-invalid-seed", "codex_fingerprint_seed"),
	}
	_, err = tx.ExecContext(ctx, string(migrationSQL))
	require.NoError(t, err)
	for name, seed := range seedsAfterFirstRun {
		require.Equal(t, seed, readExtraString(name, "codex_fingerprint_seed"))
	}

	_, err = tx.ExecContext(ctx, string(rollbackSQL))
	require.NoError(t, err)
	require.Empty(t, readExtraString("migration-223-openai-missing", "codex_fingerprint_mode"))
	require.Empty(t, readExtraString("migration-223-openai-missing", "codex_fingerprint_seed"))
	require.Equal(t, "off", readExtraString("migration-223-openai-explicit-off", "codex_fingerprint_mode"))
	require.Equal(
		t,
		"11111111-1111-4111-8111-111111111111",
		readExtraString("migration-223-openai-explicit-off", "codex_fingerprint_seed"),
	)
	require.Equal(t, "device", readExtraString("migration-223-openai-invalid-seed", "codex_fingerprint_mode"))
	require.Equal(t, "BAD", readExtraString("migration-223-openai-invalid-seed", "codex_fingerprint_seed"))
	require.Equal(t, "false", readExtraString("migration-223-anthropic-oauth-off", "enable_tls_fingerprint"))
	require.Empty(t, readExtraString("migration-223-anthropic-setup-missing", "enable_tls_fingerprint"))
}
