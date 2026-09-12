//go:build unit

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/stretchr/testify/require"
)

type profileContextOAuthClient struct {
	OpenAIOAuthClient
	profile *tlsfingerprint.Profile
	present bool
}

func (c *profileContextOAuthClient) RefreshTokenWithClientID(ctx context.Context, _, _, _ string) (*openai.TokenResponse, error) {
	c.profile, c.present = tlsfingerprint.ProfileFromContext(ctx)
	return nil, errors.New("local profile capture only")
}

func (c *profileContextOAuthClient) ExchangeCode(ctx context.Context, _, _, _, _, _ string) (*openai.TokenResponse, error) {
	c.profile, c.present = tlsfingerprint.ProfileFromContext(ctx)
	return nil, errors.New("local profile capture only")
}

func TestTLSProfileOAuthAccountAndLegacyPaths(t *testing.T) {
	settings := &tlsDefaultsRepo{values: map[string]string{}}
	profiles := &tlsDefaultProfilesRepo{profiles: map[int64]*model.TLSFingerprintProfile{
		11: {ID: 11, Name: "platform", ALPNProtocols: []string{}},
		12: {ID: 12, Name: "account", ALPNProtocols: []string{"h2", "http/1.1"}},
	}}
	resolver := ProvideTLSFingerprintProfileService(profiles, nil, settings)
	require.NoError(t, resolver.SetDefaults(t.Context(), TLSProfileDefaults{OpenAIOAuthDefaultTLSProfileID: 11}))
	client := &profileContextOAuthClient{}
	svc := ProvideOpenAIOAuthService(nil, client, nil, resolver)
	t.Cleanup(svc.Stop)
	for _, enabled := range []bool{true, false} {
		account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
			Credentials: map[string]any{"refresh_token": t.Name()},
			Extra:       map[string]any{"enable_tls_fingerprint": enabled, "tls_fingerprint_profile_id": int64(12)}}
		_, err := svc.RefreshAccountToken(t.Context(), account)
		require.Error(t, err)
		require.True(t, client.present)
		if enabled {
			require.Equal(t, resolver.ResolveTLSProfile(account).TransportKey(), client.profile.TransportKey())
		} else {
			require.Nil(t, client.profile, "disabled accounts must not inherit the platform default")
		}
	}
	_, err := svc.RefreshToken(t.Context(), t.Name(), "")
	require.Error(t, err)
	require.True(t, client.present)
	require.Equal(t, "platform", client.profile.Name)
	explicitDisabled := tlsfingerprint.WithProfile(t.Context(), nil)
	_, err = svc.RefreshToken(explicitDisabled, t.Name(), "")
	require.Error(t, err)
	require.Nil(t, client.profile)
	auth, err := svc.GenerateAuthURL(t.Context(), nil, "", "")
	require.NoError(t, err)
	session, ok := svc.sessionStore.Get(auth.SessionID)
	require.True(t, ok)
	_, err = svc.ExchangeCode(t.Context(), &OpenAIExchangeCodeInput{
		SessionID: auth.SessionID, Code: t.Name(), State: session.State,
	})
	require.ErrorContains(t, err, "local profile capture only")
	require.True(t, client.present)
	require.Equal(t, "platform", client.profile.Name, "code exchange must forward the platform profile")
}

func TestTLSProfileWSWireAndCache(t *testing.T) {
	for _, protocols := range [][]string{{"h2", "http/1.1"}, {}} {
		t.Run(strings.Join(protocols, "_"), func(t *testing.T) {
			hellos := make(chan *tls.ClientHelloInfo, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("untrusted test certificate must not complete the request")
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				hellos <- hello
				return nil, nil
			}}
			server.StartTLS()
			defer server.Close()
			profile := &tlsfingerprint.Profile{
				CipherSuites:      []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
				SupportedVersions: []uint16{tls.VersionTLS12},
				ALPNProtocols:     protocols,
			}
			dialer := &coderOpenAIWSClientDialer{}
			first, err := dialer.proxyHTTPClient("", profile)
			require.NoError(t, err)
			defer first.CloseIdleConnections()
			again, err := dialer.proxyHTTPClient("", profile.Clone())
			require.NoError(t, err)
			require.Same(t, first, again)
			edited := profile.Clone()
			edited.ShuffleExtensions = true
			changed, err := dialer.proxyHTTPClient("", edited)
			require.NoError(t, err)
			defer changed.CloseIdleConnections()
			require.NotSame(t, first, changed)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, _, _, err = dialer.Dial(tlsfingerprint.WithProfile(ctx, profile),
				"wss"+strings.TrimPrefix(server.URL, "https"), nil, "")
			require.Error(t, err, "certificate validation remains enabled")
			select {
			case hello := <-hellos:
				require.Equal(t, profile.CipherSuites, hello.CipherSuites)
				require.Equal(t, profile.SupportedVersions, hello.SupportedVersions)
				if len(protocols) == 0 {
					require.Empty(t, hello.SupportedProtos)
				} else {
					require.Equal(t, []string{"http/1.1"}, hello.SupportedProtos)
				}
			case <-ctx.Done():
				t.Fatal("WS dial did not use the profile transport")
			}
			require.Equal(t, protocols, profile.ALPNProtocols, "WS must not mutate the HTTP profile")
		})
	}
}

func TestTLSProfileWSPoolReplacesEditedAndDisabledConnections(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 1
	cfg.Gateway.OpenAIWS.MinIdlePerAccount = 0
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 1
	var current atomic.Pointer[tlsfingerprint.Profile]
	current.Store(&tlsfingerprint.Profile{ALPNProtocols: []string{}})
	pool := newOpenAIWSConnPool(cfg, func(*Account) *tlsfingerprint.Profile { return current.Load() })
	defer pool.Close()
	dialer := &openAIWSCountingDialer{}
	pool.setClientDialerForTest(dialer)
	req := openAIWSAcquireRequest{Account: &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth},
		WSURL: "wss://127.0.0.1/responses"}
	lease, err := pool.Acquire(t.Context(), req)
	require.NoError(t, err)
	firstID := lease.ConnID()
	lease.Release()
	same, err := pool.Acquire(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, firstID, same.ConnID())
	same.Release()
	for _, profile := range []*tlsfingerprint.Profile{
		{ShuffleExtensions: true, ALPNProtocols: []string{}}, nil,
	} {
		current.Store(profile)
		next, err := pool.Acquire(t.Context(), req)
		require.NoError(t, err)
		require.False(t, next.Reused())
		require.NotEqual(t, firstID, next.ConnID())
		firstID = next.ConnID()
		next.Release()
	}
	require.Equal(t, 3, dialer.DialCount())
}

type defaultTemplateAccounts struct {
	AccountRepository
	created []*Account
}

func (r *defaultTemplateAccounts) Create(_ context.Context, account *Account) error {
	account.ID = int64(len(r.created) + 1)
	r.created = append(r.created, snapshotOAuthRefreshAccount(account))
	return nil
}

func TestOpenAIOperationsTemplateCreationConsumers(t *testing.T) {
	for _, entry := range []string{"admin", "account", "crs"} {
		t.Run(entry, func(t *testing.T) {
			settings := &SettingService{settingRepo: &tlsDefaultsRepo{values: map[string]string{}}}
			cfg := DefaultOpenAIOperationsSettings()
			concurrency, enabled, profile, proxy := 7, false, int64(-1), int64(0)
			cfg.NewAccountDefaults = &OpenAINewAccountDefaults{Concurrency: &concurrency,
				EnableTLSFingerprint: &enabled, TLSFingerprintProfileID: &profile, ProxyID: &proxy}
			require.NoError(t, settings.SetOpenAIOperationsSettings(t.Context(), cfg))
			repo := &defaultTemplateAccounts{}
			create := func(platform string) {
				t.Helper()
				input := &CreateAccountInput{Name: t.Name(), Platform: platform, Type: AccountTypeAPIKey,
					Concurrency: 2, Extra: map[string]any{"enable_tls_fingerprint": true}, SkipDefaultGroupBind: true}
				switch entry {
				case "admin":
					_, err := (&adminServiceImpl{accountRepo: repo, settingService: settings}).CreateAccount(t.Context(), input)
					require.NoError(t, err)
				case "account":
					_, err := ProvideAccountService(repo, nil, settings).Create(t.Context(), CreateAccountRequest{
						Name: input.Name, Platform: platform, Type: input.Type, Concurrency: input.Concurrency, Extra: input.Extra,
					})
					require.NoError(t, err)
				case "crs":
					svc := ProvideCRSSyncService(repo, nil, nil, nil, nil, &config.Config{}, settings)
					require.NoError(t, svc.createImportedAccount(t.Context(), &Account{
						Name: input.Name, Platform: platform, Type: input.Type, Concurrency: input.Concurrency, Extra: input.Extra,
					}))
				}
				require.Equal(t, true, input.Extra["enable_tls_fingerprint"])
			}
			create(PlatformOpenAI)
			require.Equal(t, 7, repo.created[0].Concurrency)
			require.Equal(t, false, repo.created[0].Extra["enable_tls_fingerprint"])
			require.Equal(t, int64(-1), repo.created[0].Extra["tls_fingerprint_profile_id"])
			require.Nil(t, repo.created[0].ProxyID)
			concurrency = 11
			require.NoError(t, settings.SetOpenAIOperationsSettings(t.Context(), cfg))
			create(PlatformOpenAI)
			require.Equal(t, 11, repo.created[1].Concurrency)
			require.Equal(t, 7, repo.created[0].Concurrency, "changing defaults must not update old accounts")
			create(PlatformAnthropic)
			require.Equal(t, 2, repo.created[2].Concurrency)
			require.Equal(t, true, repo.created[2].Extra["enable_tls_fingerprint"])
		})
	}
}

func TestOpenAIOperationsRecoveryLockAndInvalidation(t *testing.T) {
	for _, lockError := range []bool{false, true} {
		svc, repo, accounts, _ := recoveryFixture()
		cache := &refreshAPICacheStub{lockResult: true}
		if lockError {
			cache.lockErr = errors.New("local cache unavailable")
		}
		svc.refresh.tokenCache = cache
		cfg := DefaultOpenAIOperationsSettings().Recovery
		cfg.Enabled = true
		require.NoError(t, svc.runRecovery(t.Context(), cfg))
		if lockError {
			require.Zero(t, accounts.saves)
			require.Zero(t, cache.deleteCalls)
			require.Equal(t, "failed", repo.record.Outcome)
		} else {
			require.Equal(t, StatusActive, accounts.account.Status)
			require.Equal(t, 1, cache.deleteCalls)
			require.Equal(t, OpenAITokenCacheKey(accounts.account), cache.deleteKey)
			require.NoError(t, cache.deleteCtxErr)
			require.Equal(t, 1, cache.releaseCalls)
		}
	}
}
