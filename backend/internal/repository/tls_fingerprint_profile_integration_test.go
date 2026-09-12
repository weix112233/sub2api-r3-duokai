//go:build integration

package repository

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	dbmigrations "github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestTLSProfileTransportPersistence(t *testing.T) {
	tx := testEntTx(t)
	repo := NewTLSFingerprintProfileRepository(tx.Client())
	p, err := repo.Create(t.Context(), &model.TLSFingerprintProfile{
		Name: "transport-roundtrip", ShuffleExtensions: true, ALPNProtocols: []string{"h2"},
		HTTP2: &tlsfingerprint.HTTP2Config{
			InitialWindowSize: new(uint32), ConnectionWindowUpdate: new(uint32),
			MaxHeaderListSize: new(uint32), EnablePush: new(bool),
		},
	})
	require.NoError(t, err)
	got, err := repo.GetByID(t.Context(), p.ID)
	require.NoError(t, err)
	require.True(t, got.ShuffleExtensions)
	require.Equal(t, p.HTTP2, got.HTTP2)
	got.HTTP2 = nil
	got.ShuffleExtensions = false
	got.ALPNProtocols = []string{}
	_, err = repo.Update(t.Context(), got)
	require.NoError(t, err)
	got, err = repo.GetByID(t.Context(), p.ID)
	require.NoError(t, err)
	require.Nil(t, got.HTTP2)
	require.False(t, got.ShuffleExtensions)
	require.NotNil(t, got.ALPNProtocols)
	require.Empty(t, got.ALPNProtocols)
	got.ALPNProtocols = nil
	_, err = repo.Update(t.Context(), got)
	require.NoError(t, err)
	got, err = repo.GetByID(t.Context(), p.ID)
	require.NoError(t, err)
	require.Nil(t, got.ALPNProtocols)
}

func TestMigration234PreservesLegacyALPN(t *testing.T) {
	tx := testTx(t)
	_, err := tx.ExecContext(t.Context(), `INSERT INTO tls_fingerprint_profiles (name, alpn_protocols) VALUES ('legacy-alpn-empty', '[]'::jsonb), ('legacy-alpn-explicit', '["h2"]'::jsonb)`)
	require.NoError(t, err)
	migration, err := dbmigrations.FS.ReadFile("234_tls_profile_transport_options.sql")
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), string(migration))
	require.NoError(t, err)
	var inherited bool
	err = tx.QueryRowContext(t.Context(), `SELECT alpn_protocols IS NULL FROM tls_fingerprint_profiles WHERE name = 'legacy-alpn-empty'`).Scan(&inherited)
	require.NoError(t, err)
	require.True(t, inherited)
	var explicit string
	err = tx.QueryRowContext(t.Context(), `SELECT alpn_protocols::text FROM tls_fingerprint_profiles WHERE name = 'legacy-alpn-explicit'`).Scan(&explicit)
	require.NoError(t, err)
	require.Equal(t, `["h2"]`, explicit)
}
