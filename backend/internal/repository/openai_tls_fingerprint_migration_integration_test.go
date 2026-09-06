//go:build integration

package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	dbmigrations "github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestMigration224EnablesOpenAIOAuthTLSFingerprintAndRollsBack(t *testing.T) {
	tx := testTx(t)
	ctx := context.Background()

	migrationSQL, err := dbmigrations.FS.ReadFile("224_enable_openai_oauth_tls_fingerprint.sql")
	require.NoError(t, err)
	rollbackSQL, err := os.ReadFile(filepath.Join(
		"..",
		"..",
		"migrations",
		"rollback",
		"224_restore_openai_oauth_tls_fingerprint.sql",
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
			name:        "migration-224-openai-missing",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{}`,
		},
		{
			name:        "migration-224-openai-explicit-off",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{"enable_tls_fingerprint":false}`,
		},
		{
			name:        "migration-224-openai-apikey",
			platform:    "openai",
			accountType: "apikey",
			extra:       `{"enable_tls_fingerprint":false}`,
		},
		{
			name:        "migration-224-deleted-openai",
			platform:    "openai",
			accountType: "oauth",
			extra:       `{"enable_tls_fingerprint":false}`,
			deleted:     true,
		},
	}

	ids := make(map[string]int64, len(fixtures))
	for _, fixture := range fixtures {
		var id int64
		require.NoError(t, tx.QueryRowContext(ctx, `
INSERT INTO accounts (name, platform, type, extra, deleted_at)
VALUES ($1, $2, $3, $4::jsonb, CASE WHEN $5 THEN NOW() ELSE NULL END)
RETURNING id
`, fixture.name, fixture.platform, fixture.accountType, fixture.extra, fixture.deleted).Scan(&id))
		ids[fixture.name] = id
	}

	readExtra := func(name string) string {
		t.Helper()
		var value string
		require.NoError(t, tx.QueryRowContext(
			ctx,
			`SELECT COALESCE(extra->>'enable_tls_fingerprint', '') FROM accounts WHERE id = $1`,
			ids[name],
		).Scan(&value))
		return value
	}

	_, err = tx.ExecContext(ctx, string(migrationSQL))
	require.NoError(t, err)
	require.Equal(t, "true", readExtra("migration-224-openai-missing"))
	require.Equal(t, "true", readExtra("migration-224-openai-explicit-off"))
	require.Equal(t, "false", readExtra("migration-224-openai-apikey"))
	require.Equal(t, "false", readExtra("migration-224-deleted-openai"))

	_, err = tx.ExecContext(ctx, string(migrationSQL))
	require.NoError(t, err)
	require.Equal(t, "true", readExtra("migration-224-openai-missing"))
	require.Equal(t, "true", readExtra("migration-224-openai-explicit-off"))

	_, err = tx.ExecContext(ctx, string(rollbackSQL))
	require.NoError(t, err)
	require.Empty(t, readExtra("migration-224-openai-missing"))
	require.Equal(t, "false", readExtra("migration-224-openai-explicit-off"))
	require.Equal(t, "false", readExtra("migration-224-openai-apikey"))
	require.Equal(t, "false", readExtra("migration-224-deleted-openai"))
}
