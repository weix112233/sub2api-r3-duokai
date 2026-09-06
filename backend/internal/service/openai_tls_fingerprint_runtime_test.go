package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/stretchr/testify/require"
)

type recordingTLSProfileRepo struct {
	profile *model.TLSFingerprintProfile
}

func (r *recordingTLSProfileRepo) List(context.Context) ([]*model.TLSFingerprintProfile, error) {
	return []*model.TLSFingerprintProfile{r.profile}, nil
}
func (r *recordingTLSProfileRepo) GetByID(context.Context, int64) (*model.TLSFingerprintProfile, error) {
	return r.profile, nil
}
func (r *recordingTLSProfileRepo) Create(context.Context, *model.TLSFingerprintProfile) (*model.TLSFingerprintProfile, error) {
	return r.profile, nil
}
func (r *recordingTLSProfileRepo) Update(context.Context, *model.TLSFingerprintProfile) (*model.TLSFingerprintProfile, error) {
	return r.profile, nil
}
func (r *recordingTLSProfileRepo) Delete(context.Context, int64) error { return nil }

type recordingTLSProfileCache struct{}

func (recordingTLSProfileCache) Get(context.Context) ([]*model.TLSFingerprintProfile, bool) {
	return nil, false
}
func (recordingTLSProfileCache) Set(context.Context, []*model.TLSFingerprintProfile) error {
	return nil
}
func (recordingTLSProfileCache) Invalidate(context.Context) error         { return nil }
func (recordingTLSProfileCache) NotifyUpdate(context.Context) error       { return nil }
func (recordingTLSProfileCache) SubscribeUpdates(context.Context, func()) {}

type recordingTLSUpstream struct {
	profile *tlsfingerprint.Profile
}

func (u *recordingTLSUpstream) Do(_ *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return nil, nil
}
func (u *recordingTLSUpstream) DoWithTLS(
	_ *http.Request,
	_ string,
	_ int64,
	_ int,
	profile *tlsfingerprint.Profile,
) (*http.Response, error) {
	u.profile = profile
	return nil, nil
}

func TestOpenAIOAuthTLSFingerprintResolvesAndUsesProfile(t *testing.T) {
	profile := &model.TLSFingerprintProfile{ID: 42, Name: "test"}
	profileService := NewTLSFingerprintProfileService(
		&recordingTLSProfileRepo{profile: profile},
		recordingTLSProfileCache{},
	)
	upstream := &recordingTLSUpstream{}
	svc := &OpenAIGatewayService{httpUpstream: upstream}
	svc.SetTLSFingerprintProfileService(profileService)

	account := &Account{
		ID:       7,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"enable_tls_fingerprint":     true,
			"tls_fingerprint_profile_id": int64(42),
		},
	}

	_, _ = svc.doHTTPUpstream(&http.Request{}, "", account)
	require.NotNil(t, upstream.profile)
	require.Equal(t, "test", upstream.profile.Name)
}
