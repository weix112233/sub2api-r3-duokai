package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func boundedCapacityError() *service.UpstreamFailoverError {
	return &service.UpstreamFailoverError{
		StatusCode:             http.StatusServiceUnavailable,
		ResponseBody:           []byte(`{"error":{"code":"server_is_overloaded"}}`),
		RetryableOnSameAccount: true,
		RequestScopedTransient: true,
		SameAccountRetryMax:    1,
		SameAccountRetryDelay:  time.Nanosecond,
		ClientStatusCode:       http.StatusServiceUnavailable,
		ClientMessage:          "Upstream service is temporarily overloaded",
	}
}

func TestCapacityRetryBudgetDoesNotResetOnAccountSwitchOrMixedErrors(t *testing.T) {
	var budget openAICapacityRetryBudget
	require.False(t, budget.exhausted(nil))
	require.False(t, budget.exhausted(boundedCapacityError()))
	require.False(t, budget.exhausted(&service.UpstreamFailoverError{StatusCode: 429}))
	require.False(t, budget.exhausted(boundedCapacityError()))
	require.True(t, budget.exhausted(boundedCapacityError()))
	require.True(t, budget.exhausted(boundedCapacityError()))
	var nextRequest openAICapacityRetryBudget
	require.False(t, nextRequest.exhausted(boundedCapacityError()))
}

func TestFailoverStateCapacityStopsAtThirdFailureWithoutAccountEviction(t *testing.T) {
	state := NewFailoverState(10, false)
	err := boundedCapacityError()
	require.Equal(t, FailoverContinue, state.HandleFailoverError(context.Background(), nil, 1, service.PlatformOpenAI, 10, err))
	require.Equal(t, 1, state.SameAccountRetryCount[1])
	require.Equal(t, FailoverContinue, state.HandleFailoverError(context.Background(), nil, 1, service.PlatformOpenAI, 10, err))
	require.Equal(t, 1, state.SwitchCount)
	require.Equal(t, FailoverExhausted, state.HandleFailoverError(context.Background(), nil, 2, service.PlatformOpenAI, 10, err))
	require.Zero(t, state.SameAccountRetryCount[2])
	require.Equal(t, FailoverExhausted, state.HandleSelectionExhausted(context.Background()))
}

func TestFailoverStateCapacityCancellationDoesNotSpendBudget(t *testing.T) {
	state := NewFailoverState(10, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, FailoverCanceled, state.HandleFailoverError(ctx, nil, 1, service.PlatformOpenAI, 10, boundedCapacityError()))
	require.Zero(t, state.capacityRetryBudget.failures)
}

func TestCapacityTerminalPreservesCodeForHTTPAndCommittedResponsesSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "sse"}[streaming], func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			if streaming {
				c.Header("Content-Type", "text/event-stream")
				c.Writer.WriteHeaderNow()
			}
			(&OpenAIGatewayHandler{}).handleFailoverExhausted(c, boundedCapacityError(), streaming)
			body := rec.Body.String()
			if streaming {
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, 1, strings.Count(body, "event: response.failed"))
				body = strings.TrimSpace(strings.SplitN(body, "data: ", 2)[1])
			} else {
				require.Equal(t, http.StatusServiceUnavailable, rec.Code)
			}
			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(body), &payload))
			if streaming {
				payload = payload["response"].(map[string]any)
			}
			require.Equal(t, "server_is_overloaded", payload["error"].(map[string]any)["code"])
		})
	}
}
