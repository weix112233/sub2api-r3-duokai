package service

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestSelectedModelCapacitySSEBeforeAndAfterOutput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, passthrough := range []bool{false, true} {
		for _, committed := range []bool{false, true} {
			name := map[bool]string{false: "native", true: "passthrough"}[passthrough] +
				"/" + map[bool]string{false: "before_output", true: "after_output"}[committed]
			t.Run(name, func(t *testing.T) {
				stream := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_capacity\"}}\n\n"
				if committed {
					stream += "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
				}
				stream += "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\",\"message\":\"Selected model is at capacity. Please try a different model.\"}}\n\n"
				stream += "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_capacity\",\"status\":\"failed\",\"error\":{\"message\":\"Selected model is at capacity. Please try a different model.\"}}}\n\n"
				svc := &OpenAIGatewayService{cfg: &config.Config{
					Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
				}}
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
				response := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(stream)),
				}
				account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
				var err error
				if passthrough {
					_, err = svc.handleStreamingResponsePassthrough(c.Request.Context(), response, c, account, time.Now(), "gpt-6-astra", "gpt-6-astra")
				} else {
					_, err = svc.handleStreamingResponse(c.Request.Context(), response, c, account, time.Now(), "gpt-6-astra", "gpt-6-astra")
				}
				require.Error(t, err)
				var failover *UpstreamFailoverError
				if !committed {
					require.ErrorAs(t, err, &failover)
					require.True(t, failover.RequestScopedTransient)
					require.True(t, failover.IsOpenAICapacityShed())
					require.Equal(t, 1, failover.SameAccountRetryMax)
					require.False(t, c.Writer.Written())
					require.Empty(t, recorder.Body.String())
				} else {
					require.False(t, errors.As(err, &failover))
					body := recorder.Body.String()
					require.Contains(t, body, "partial")
					require.Equal(t, 1, strings.Count(body, "event: response.failed"))
					require.NotContains(t, body, "event: error")
					require.Contains(t, body, `"code":"server_is_overloaded"`)
					require.Contains(t, body, "Selected model is at capacity")
				}
			})
		}
	}
}
