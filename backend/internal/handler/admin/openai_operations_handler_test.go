package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestOpenAIOperationsHandlerRejectsInvalidSettings(t *testing.T) {
	handler := NewOpenAIOperationsHandler(nil)
	for _, body := range []string{"null", "[]", `{"unknown":1}`, `{} {}`, `{"recovery":{"interval_minutes":0}}`, strings.Repeat(" ", 65<<10)} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		handler.SetSettings(ctx)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}

func TestOpenAIOperationsHandlerIDs(t *testing.T) {
	for _, raw := range []string{"-1", "abc", "9223372036854775808"} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/?account_id="+raw, nil)
		_, ok := optionalOperationsID(ctx, "account_id")
		require.False(t, ok)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}
