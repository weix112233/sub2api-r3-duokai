//go:build integration

// Package profileacceptance exercises the production repository against an
// explicitly provisioned, disposable PostgreSQL database without Docker.
package profileacceptance

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/Wei-Shaw/sub2api/ent/runtime"
	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	dbmigrations "github.com/Wei-Shaw/sub2api/migrations"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestTLSProfileNativePersistence(t *testing.T) {
	socketDir := os.Getenv("SUB2API_TEST_POSTGRES_SOCKET")
	if socketDir == "" {
		t.Skip("set SUB2API_TEST_POSTGRES_SOCKET to a disposable local PostgreSQL socket directory")
	}
	require.True(t, filepath.IsAbs(socketDir), "only an absolute local socket directory is accepted")
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	dsn := url.URL{Scheme: "postgres", Path: "/sub2api_test"}
	dsn.RawQuery = url.Values{"host": {socketDir}, "sslmode": {"disable"}, "TimeZone": {"UTC"}}.Encode()
	db, err := sql.Open("postgres", dsn.String())
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.PingContext(ctx))
	require.NoError(t, repository.ApplyMigrations(ctx, db))
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	tx, err := client.Tx(ctx)
	require.NoError(t, err)
	defer tx.Rollback()
	repo := repository.NewTLSFingerprintProfileRepository(tx.Client())
	p, err := repo.Create(ctx, &model.TLSFingerprintProfile{
		Name: "local-transport-roundtrip", ShuffleExtensions: true, ALPNProtocols: []string{"h2"},
		HTTP2: &tlsfingerprint.HTTP2Config{
			InitialWindowSize: new(uint32), ConnectionWindowUpdate: new(uint32),
			MaxHeaderListSize: new(uint32), EnablePush: new(bool),
		},
	})
	require.NoError(t, err)
	got, err := repo.GetByID(ctx, p.ID)
	require.NoError(t, err)
	require.True(t, got.ShuffleExtensions)
	require.Equal(t, p.HTTP2, got.HTTP2)
	got.HTTP2 = nil
	got.ShuffleExtensions = false
	got.ALPNProtocols = []string{}
	_, err = repo.Update(ctx, got)
	require.NoError(t, err)
	got, err = repo.GetByID(ctx, p.ID)
	require.NoError(t, err)
	require.Nil(t, got.HTTP2)
	require.False(t, got.ShuffleExtensions)
	require.NotNil(t, got.ALPNProtocols)
	require.Empty(t, got.ALPNProtocols)
	got.ALPNProtocols = nil
	_, err = repo.Update(ctx, got)
	require.NoError(t, err)
	got, err = repo.GetByID(ctx, p.ID)
	require.NoError(t, err)
	require.Nil(t, got.ALPNProtocols)
	require.NoError(t, tx.Rollback())

	sqlTx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer sqlTx.Rollback()
	_, err = sqlTx.ExecContext(ctx, `INSERT INTO tls_fingerprint_profiles (name, alpn_protocols) VALUES ('legacy-alpn-empty', '[]'::jsonb), ('legacy-alpn-explicit', '["h2"]'::jsonb)`)
	require.NoError(t, err)
	migration, err := dbmigrations.FS.ReadFile("234_tls_profile_transport_options.sql")
	require.NoError(t, err)
	_, err = sqlTx.ExecContext(ctx, string(migration))
	require.NoError(t, err)
	var inherited bool
	require.NoError(t, sqlTx.QueryRowContext(ctx, `SELECT alpn_protocols IS NULL FROM tls_fingerprint_profiles WHERE name = 'legacy-alpn-empty'`).Scan(&inherited))
	require.True(t, inherited)
	var explicit string
	require.NoError(t, sqlTx.QueryRowContext(ctx, `SELECT alpn_protocols::text FROM tls_fingerprint_profiles WHERE name = 'legacy-alpn-explicit'`).Scan(&explicit))
	require.Equal(t, `["h2"]`, explicit)
}
