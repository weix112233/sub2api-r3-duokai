package proxyutil

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigureProxyPreservesExistingConnectCallback(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:12345")
	require.NoError(t, err)
	expected := errors.New("existing callback refusal")
	transport := &http.Transport{OnProxyConnectResponse: func(context.Context, *url.URL, *http.Request, *http.Response) error {
		return expected
	}}
	require.NoError(t, ConfigureTransportProxy(transport, proxyURL))
	require.ErrorIs(t, transport.OnProxyConnectResponse(context.Background(), proxyURL, nil,
		&http.Response{StatusCode: http.StatusBadGateway}), expected)
}

func TestConnectErrorOnlyUsesCanonicalStatusText(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:12345")
	require.NoError(t, err)
	transport := &http.Transport{}
	require.NoError(t, ConfigureTransportProxy(transport, proxyURL))
	err = transport.OnProxyConnectResponse(context.Background(), proxyURL, nil,
		&http.Response{StatusCode: http.StatusBadGateway, Status: "502 untrusted response content"})
	var connectErr *ConnectError
	require.ErrorAs(t, err, &connectErr)
	require.EqualError(t, err, "proxy CONNECT failed: 502 Bad Gateway")
	require.NoError(t, transport.OnProxyConnectResponse(context.Background(), proxyURL, nil,
		&http.Response{StatusCode: http.StatusOK}))
}
