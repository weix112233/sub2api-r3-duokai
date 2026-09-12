package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/stretchr/testify/require"
)

type tlsDefaultsRepo struct {
	SettingRepository
	values map[string]string
	err    error
}

func (r *tlsDefaultsRepo) GetValue(_ context.Context, key string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	value, ok := r.values[key]
	if !ok {
		return "", ErrSettingNotFound
	}
	return value, nil
}

func (r *tlsDefaultsRepo) Set(_ context.Context, key, value string) error {
	if r.err != nil {
		return r.err
	}
	r.values[key] = value
	return nil
}

type tlsDefaultProfilesRepo struct {
	TLSFingerprintProfileRepository
	profiles map[int64]*model.TLSFingerprintProfile
}

func (r *tlsDefaultProfilesRepo) List(context.Context) ([]*model.TLSFingerprintProfile, error) {
	profiles := make([]*model.TLSFingerprintProfile, 0, len(r.profiles))
	for _, p := range r.profiles {
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func (r *tlsDefaultProfilesRepo) GetByID(_ context.Context, id int64) (*model.TLSFingerprintProfile, error) {
	p, ok := r.profiles[id]
	if !ok {
		return nil, errors.New("profile missing")
	}
	return p, nil
}

func (r *tlsDefaultProfilesRepo) Delete(_ context.Context, id int64) error {
	delete(r.profiles, id)
	return nil
}

func TestTLSProfileDefaultResolutionBoundaries(t *testing.T) {
	settings := &tlsDefaultsRepo{values: map[string]string{}}
	profiles := &tlsDefaultProfilesRepo{profiles: map[int64]*model.TLSFingerprintProfile{
		11: {ID: 11, Name: "operational-default", ALPNProtocols: []string{}},
		12: {ID: 12, Name: "explicit"},
	}}
	svc := ProvideTLSFingerprintProfileService(profiles, nil, settings)
	defaults, err := svc.GetDefaults(t.Context())
	require.NoError(t, err)
	require.Zero(t, defaults.OpenAIOAuthDefaultTLSProfileID)
	require.Empty(t, settings.values, "startup must not install an operational default")
	require.NoError(t, svc.SetDefaults(t.Context(), TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: 11}))
	for _, tc := range []struct {
		name, platform, kind string
		enabled              bool
		id                   int64
		want                 string
	}{
		{"unbound OAuth", PlatformOpenAI, AccountTypeOAuth, true, 0, "operational-default"},
		{"explicit", PlatformOpenAI, AccountTypeOAuth, true, 12, "explicit"},
		{"deleted explicit", PlatformOpenAI, AccountTypeOAuth, true, 99, "Built-in Default (Node.js 24.x)"},
		{"Anthropic", PlatformAnthropic, AccountTypeOAuth, true, 0, "Built-in Default (Node.js 24.x)"},
		{"API key", PlatformOpenAI, AccountTypeAPIKey, true, 0, ""},
		{"disabled", PlatformOpenAI, AccountTypeOAuth, false, 0, ""},
		{"disabled explicit", PlatformOpenAI, AccountTypeOAuth, false, 12, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &Account{Platform: tc.platform, Type: tc.kind, Extra: map[string]any{
				"enable_tls_fingerprint": tc.enabled, "tls_fingerprint_profile_id": tc.id,
			}}
			got := svc.ResolveTLSProfile(account)
			if tc.want == "" {
				require.Nil(t, got)
			} else {
				require.Equal(t, tc.want, got.Name)
				if tc.id == 0 && tc.platform == PlatformOpenAI && tc.kind == AccountTypeOAuth {
					require.NotNil(t, got.ALPNProtocols)
					require.Empty(t, got.ALPNProtocols)
				}
			}
			require.Equal(t, tc.id, account.Extra["tls_fingerprint_profile_id"])
			require.Equal(t, tc.enabled, account.Extra["enable_tls_fingerprint"])
		})
	}
	require.Nil(t, svc.ResolveTLSProfile(nil))
	require.Error(t, svc.Delete(t.Context(), 11))
	require.Error(t, svc.SetDefaults(t.Context(), TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: -1}))
	require.Error(t, svc.SetDefaults(t.Context(), TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: 99}))
	require.NoError(t, svc.SetDefaults(t.Context(), TLSProfileDefaults{}))
	require.NoError(t, svc.Delete(t.Context(), 11))
}

func TestTLSProfileDefaultsReloadAndFailures(t *testing.T) {
	settings := &tlsDefaultsRepo{values: map[string]string{SettingKeyOpenAIOAuthDefaultTLSProfileID: "11"}}
	profiles := &tlsDefaultProfilesRepo{profiles: map[int64]*model.TLSFingerprintProfile{
		11: {ID: 11, Name: "first"}, 12: {ID: 12, Name: "second"},
	}}
	svc := ProvideTLSFingerprintProfileService(profiles, nil, settings)
	account := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{"enable_tls_fingerprint": true}}
	require.Equal(t, "first", svc.ResolveTLSProfile(account).Name)
	settings.values[SettingKeyOpenAIOAuthDefaultTLSProfileID] = "12"
	require.NoError(t, svc.refreshLocalCache(t.Context()))
	require.Equal(t, "second", svc.ResolveTLSProfile(account).Name)
	settings.err = errors.New("storage unavailable")
	require.Error(t, svc.refreshLocalCache(t.Context()))
	require.Equal(t, "Built-in Default (Node.js 24.x)", svc.ResolveTLSProfile(account).Name)
	require.Error(t, svc.SetDefaults(t.Context(), TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: 11}))
	settings.err = nil
	for _, raw := range []string{"-1", "not-an-id", "9223372036854775808"} {
		settings.values[SettingKeyOpenAIOAuthDefaultTLSProfileID] = raw
		_, err := svc.GetDefaults(t.Context())
		require.Error(t, err)
	}
}
