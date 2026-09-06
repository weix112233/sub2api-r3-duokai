package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyutil"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestFingerprintCONNECTGatewayFailureIsSharedTransport(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodConnect, r.Method)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	dialer := tlsfingerprint.NewHTTPProxyDialer(nil, proxyURL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer.DialTLSContext(ctx, "tcp", "upstream.example:443")
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	require.True(t, isOpenAIProxyChainTransportError(err), "actual fingerprint CONNECT error: %v", err)
}

func TestStandardHTTPProxyCONNECTGatewayFailureIsSharedTransport(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodConnect, r.Method)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	transport := &http.Transport{}
	require.NoError(t, proxyutil.ConfigureTransportProxy(transport, proxyURL))
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	resp, err := client.Get("https://upstream.example/test")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	require.True(t, isOpenAIProxyChainTransportError(err), "actual net/http CONNECT error: %v", err)
}

func TestProxyCONNECTErrorVariantsDoNotMatchProviderErrors(t *testing.T) {
	for _, message := range []string{
		"proxy CONNECT failed: 502 Bad Gateway",
		"proxy CONNECT failed: 503 Service Unavailable",
		"proxy CONNECT failed: 504 Gateway Timeout",
	} {
		require.True(t, isOpenAIProxyChainTransportError(errors.New(message)), message)
	}
	for _, message := range []string{
		"upstream returned 502 Bad Gateway",
		"proxy CONNECT failed: 407 Proxy Authentication Required",
		"proxy CONNECT failed: 200 Connection Established",
		"TLS handshake failed: EOF",
	} {
		require.False(t, isOpenAIProxyChainTransportError(errors.New(message)), message)
	}
}

func TestSharedProxyFailureDoesNotDisableAccount(t *testing.T) {
	svc := &OpenAIGatewayService{}
	proxyID := int64(93)
	account := &Account{ID: 301, Platform: PlatformOpenAI, ProxyID: &proxyID}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	err := svc.handleOpenAIUpstreamTransportError(c.Request.Context(), c, account,
		errors.New("proxy CONNECT failed: 502 Bad Gateway"), false)
	var failover *UpstreamFailoverError
	require.ErrorAs(t, err, &failover)
	require.False(t, failover.ShouldRetryNextAccount())
	require.False(t, failover.ShouldReportAccountScheduleFailure())
	require.Equal(t, http.StatusServiceUnavailable, failover.ClientStatusCode)
	require.False(t, svc.isOpenAIAccountRuntimeBlocked(account))
	require.True(t, svc.isOpenAIProxyStreamQuarantined(c.Request.Context(), account))
	require.False(t, svc.getOpenAIProxyStreamCircuit().isBlocked(proxyID, time.Now().Add(6*time.Second)),
		"a shared CONNECT blip must not leave the pool blocked for ten minutes")
	require.Empty(t, recorder.Body.String())
}
