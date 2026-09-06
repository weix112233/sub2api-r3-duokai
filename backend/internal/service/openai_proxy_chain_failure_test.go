package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOpenAIProxyChainFailureRequiresInternalMarker(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Sub2API-Proxy-Chain-Error", "connect_failed")
	require.True(t, isOpenAIProxyChainFailure(http.StatusBadGateway, headers))
	require.False(t, isOpenAIProxyChainFailure(http.StatusServiceUnavailable, headers))
	require.False(t, isOpenAIProxyChainFailure(http.StatusBadGateway, http.Header{}))
}

func TestOpenAIProxyChainFailureStopsAccountFailover(t *testing.T) {
	err := newOpenAIProxyChainFailoverError(http.StatusBadGateway, http.Header{
		"Retry-After": []string{"5"},
	})

	require.True(t, err.IsProxyChainFailure())
	require.Equal(t, GatewayFailureScopeProvider, err.Scope)
	require.Equal(t, GatewayFailureReasonProxyChainUnavailable, err.Reason)
	require.Equal(t, NextAccountStop, err.NextAccountAction)
	require.False(t, err.ShouldRetryNextAccount())
	require.False(t, err.ShouldReportAccountScheduleFailure())
	require.Equal(t, http.StatusServiceUnavailable, err.ClientStatusCode)
	require.Equal(t, openAIProxyChainClientMessage, err.ClientMessage)
	require.Equal(t, "5", err.ResponseHeaders.Get("Retry-After"))
}
