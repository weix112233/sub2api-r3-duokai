package repository

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestTLSProfileOAuthUsesSharedWireTransport(t *testing.T) {
	for _, alpn := range [][]string{{}, {"http/1.1"}, {"h2", "http/1.1"}} {
		t.Run(strings.Join(alpn, "_"), func(t *testing.T) {
			hellos := make(chan *tls.ClientHelloInfo, 4)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("an untrusted certificate must not reach HTTP")
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
				ALPNProtocols:     alpn,
			}
			client, err := createOpenAIReqClient("", profile)
			require.NoError(t, err)
			defer client.GetClient().CloseIdleConnections()
			same, err := createOpenAIReqClient("", profile.Clone())
			require.NoError(t, err)
			require.Same(t, client, same)
			edited := profile.Clone()
			edited.ShuffleExtensions = true
			changed, err := createOpenAIReqClient("", edited)
			require.NoError(t, err)
			defer changed.GetClient().CloseIdleConnections()
			require.NotSame(t, client, changed)
			plain, err := createOpenAIReqClient("")
			require.NoError(t, err)
			require.NotSame(t, client, plain, "disabled TLS cannot reuse a profiled OAuth client")
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err = client.R().SetContext(ctx).Get(server.URL)
			require.Error(t, err, "the actual req.Client path must verify certificates")
			select {
			case hello := <-hellos:
				require.Equal(t, profile.CipherSuites, hello.CipherSuites)
				require.Equal(t, profile.SupportedVersions, hello.SupportedVersions)
				require.Equal(t, len(alpn), len(hello.SupportedProtos))
				for i, protocol := range alpn {
					require.Equal(t, protocol, hello.SupportedProtos[i])
				}
			case <-ctx.Done():
				t.Fatal("OAuth req.Client did not use the profile dialer")
			}
		})
	}
}

func TestTLSProfileTransportProtocolCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		alpn   []string
		proxy  string
		wantH2 bool
	}{
		{name: "inherited"},
		{name: "no ALPN", alpn: []string{}},
		{name: "HTTP1", alpn: []string{"http/1.1"}},
		{name: "HTTP2 direct", alpn: []string{"h2", "http/1.1"}, wantH2: true},
		{name: "HTTP2 CONNECT", alpn: []string{"h2"}, proxy: "http://127.0.0.1:1080", wantH2: true},
		{name: "HTTP2 SOCKS", alpn: []string{"h2"}, proxy: "socks5h://127.0.0.1:1080", wantH2: true},
		{name: "HTTPS proxy fallback", alpn: []string{"h2"}, proxy: "https://127.0.0.1:1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewHTTPUpstream(nil).(*httpUpstreamService)
			p := &tlsfingerprint.Profile{ALPNProtocols: tc.alpn}
			entry, err := s.getClientEntryWithTLS(tc.proxy, 902, 1, p, service.HTTPUpstreamProfileDefault, false, true)
			require.NoError(t, err)
			defer entry.client.CloseIdleConnections()
			if tc.wantH2 {
				require.IsType(t, &tlsfingerprint.Transport{}, entry.client.Transport)
			} else {
				require.IsType(t, &http.Transport{}, entry.client.Transport)
			}
		})
	}
}

func TestTLSProfileTransportRecreatedAfterEdit(t *testing.T) {
	s := NewHTTPUpstream(nil).(*httpUpstreamService)
	p := &tlsfingerprint.Profile{Name: "custom"}
	a, err := s.getClientEntryWithTLS("", 901, 1, p, service.HTTPUpstreamProfileDefault, false, true)
	require.NoError(t, err)
	defer a.client.CloseIdleConnections()
	p.Name = "renamed"
	same, err := s.getClientEntryWithTLS("", 901, 1, p, service.HTTPUpstreamProfileDefault, false, true)
	require.NoError(t, err)
	require.Same(t, a, same)
	p.ALPNProtocols = []string{}
	b, err := s.getClientEntryWithTLS("", 901, 1, p, service.HTTPUpstreamProfileDefault, false, true)
	require.NoError(t, err)
	defer b.client.CloseIdleConnections()
	require.NotSame(t, a, b, "explicit no ALPN must retire inherited ALPN transport")
	p.ShuffleExtensions = true
	c, err := s.getClientEntryWithTLS("", 901, 1, p, service.HTTPUpstreamProfileDefault, false, true)
	require.NoError(t, err)
	defer c.client.CloseIdleConnections()
	require.NotSame(t, b, c)
}
