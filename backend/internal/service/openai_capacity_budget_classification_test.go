package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCapacityBudgetIsAssignedBySharedErrorConstructor(t *testing.T) {
	for _, payload := range []string{
		`{"error":{"code":"server_is_overloaded","message":"overloaded"}}`,
		`{"response":{"error":{"code":"slow_down","message":"slow down"}}}`,
		`{"error":{"message":"Our servers are currently overloaded."}}`,
	} {
		for _, status := range []int{400, 502, 503} {
			body := []byte(payload)
			err := newOpenAIUpstreamFailoverError(status, nil, body, "", false)
			require.Equal(t, 1, err.SameAccountRetryMax, "%d %s", status, payload)
			require.True(t, err.IsOpenAICapacityShed())
			require.True(t, err.RetryableOnSameAccount)
		}
	}
}

func TestCapacityBudgetPreservesQuotaAndAuthSemantics(t *testing.T) {
	body := []byte(`{"error":{"message":"Our servers are currently overloaded."}}`)
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		err := newOpenAIUpstreamFailoverError(status, nil, body, "", false)
		require.Zero(t, err.SameAccountRetryMax)
		require.False(t, err.RequestScopedTransient)
		require.False(t, err.RetryableOnSameAccount)
	}
	for _, body := range []string{
		`{"error":{"code":"workspace_suspended","message":"Our servers are currently overloaded."}}`,
		`{"error":{"code":"server_error","message":"temporary processing error"}}`,
		`{"error":{"code":"rate_limit_exceeded","message":"try again in 30s"}}`,
	} {
		err := newOpenAIUpstreamFailoverError(503, nil, []byte(body), "", false)
		require.Zero(t, err.SameAccountRetryMax)
	}
}
