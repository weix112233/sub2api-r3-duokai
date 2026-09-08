package service

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectedModelCapacityUsesRequestBudget(t *testing.T) {
	for name, payload := range map[string]string{
		"http_error": `{"error":{"type":"invalid_request_error","message":"Selected model is at capacity. Please try a different model."}}`,
		"sse_failed": `{"type":"response.failed","response":{"error":{"type":"invalid_request_error","message":"Selected model is at capacity. Please try a different model."}}}`,
		"ws_error":   `{"type":"error","error":{"message":"Selected model is at capacity. Please try a different model."}}`,
		"plain_text": "Selected model is at capacity. Please try a different model.",
	} {
		for _, status := range []int{400, 502, 503} {
			t.Run(fmt.Sprintf("%s/%d", name, status), func(t *testing.T) {
				err := newOpenAIUpstreamFailoverError(status, nil, []byte(payload), "", false)
				require.Equal(t, 1, err.SameAccountRetryMax)
				require.True(t, err.IsOpenAICapacityShed())
				require.True(t, err.RetryableOnSameAccount)
				require.Equal(t, http.StatusServiceUnavailable, err.ClientStatusCode)
			})
		}
	}
}

func TestSelectedModelCapacityPreservesAuthoritativeErrorBoundaries(t *testing.T) {
	const message = "Selected model is at capacity. Please try a different model."
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		err := newOpenAIUpstreamFailoverError(status, nil, []byte(message), "", false)
		require.False(t, err.RequestScopedTransient)
		require.False(t, err.RetryableOnSameAccount)
		require.Zero(t, err.SameAccountRetryMax)
	}
	for _, body := range []string{
		`{"error":{"code":"rate_limit_exceeded","message":"Selected model is at capacity."}}`,
		`{"error":{"code":"workspace_suspended","message":"Selected model is at capacity."}}`,
		`{"error":{"message":"invalid input"},"request":{"input":"Selected model is at capacity."}}`,
		`{"response":{"error":{"message":"invalid input"}},"message":"Selected model is at capacity."}`,
		`{"code":"rate_limit_exceeded","message":"Selected model is at capacity."}`,
		`{"code":"permission_denied","message":"Selected model is at capacity."}`,
	} {
		err := newOpenAIUpstreamFailoverError(503, nil, []byte(body), "", false)
		require.False(t, err.RequestScopedTransient, body)
		require.Zero(t, err.SameAccountRetryMax, body)
		require.False(t, isOpenAIRequestScopedCapacityShed(message, []byte(body)), body)
	}
	require.True(t, isOpenAICapacityShedMessage("  SELECTED MODEL IS AT CAPACITY.  "))
	require.False(t, isOpenAICapacityShedMessage("model capacity information"))
}

func TestSelectedModelCapacityTopLevelCodes(t *testing.T) {
	for _, code := range []string{"server_is_overloaded", "slow_down"} {
		body := []byte(fmt.Sprintf(`{"code":%q,"message":"retry later"}`, code))
		err := newOpenAIUpstreamFailoverError(http.StatusServiceUnavailable, nil, body, "", false)
		require.True(t, err.RequestScopedTransient)
		require.Equal(t, 1, err.SameAccountRetryMax)
	}
}

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
