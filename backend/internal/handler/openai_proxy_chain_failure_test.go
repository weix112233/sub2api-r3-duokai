package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestHandleFailoverExhaustedProxyChainReturnsRetryable503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	handler := &OpenAIGatewayHandler{}
	failoverErr := &service.UpstreamFailoverError{
		StatusCode:        http.StatusBadGateway,
		Reason:            service.GatewayFailureReasonProxyChainUnavailable,
		Scope:             service.GatewayFailureScopeProvider,
		NextAccountAction: service.NextAccountStop,
		ClientStatusCode:  http.StatusServiceUnavailable,
		ClientMessage:     "Outbound proxy temporarily unavailable",
		ResponseHeaders:   http.Header{"Retry-After": []string{"5"}},
	}

	handler.handleFailoverExhausted(ctx, failoverErr, false)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Equal(t, "5", recorder.Header().Get("Retry-After"))
	require.Contains(t, recorder.Body.String(), "Outbound proxy temporarily unavailable")
}
