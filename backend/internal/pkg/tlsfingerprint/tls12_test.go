package tlsfingerprint

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

func TestProfileTLS12OnlyWithoutALPN(t *testing.T) {
	profile := &Profile{CipherSuites: []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SupportedVersions: []uint16{utls.VersionTLS12}, ALPNProtocols: []string{},
		Extensions: []uint16{0, 23, 65281, 10, 11, 13}}
	require.NoError(t, profile.Validate())
	spec := buildClientHelloSpecFromProfile(profile)
	require.Equal(t, uint16(utls.VersionTLS12), spec.TLSVersMax)
	require.Equal(t, uint16(utls.VersionTLS12), spec.TLSVersMin)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS12 || r.TLS.NegotiatedProtocol != "" || r.ProtoMajor != 1 {
			t.Error("TLS1.2/no-ALPN profile did not reach HTTP/1.1")
		}
		_, _ = w.Write([]byte("local-tls12"))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	tr, _ := testProfileTransport(t, server, profile)
	resp, err := (&http.Client{Transport: tr}).Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "local-tls12", string(body))
	for _, versions := range [][]uint16{{0x0300}, {0x0a0a}, {0x0304}} {
		invalid := profile.Clone()
		invalid.SupportedVersions = versions
		require.Error(t, invalid.Validate())
	}
}
