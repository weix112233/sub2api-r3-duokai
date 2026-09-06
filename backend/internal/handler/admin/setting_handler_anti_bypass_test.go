package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestUpdateSettingsAntiBypassRoundTrip(t *testing.T) {
	h, repo := newStepUpSwitchTestHandler(t, map[string]string{
		service.SettingKeyAntiBypassEnabled: "false",
	})

	for _, enabled := range []bool{true, false} {
		rec := doUpdateSettings(t, h, map[string]any{
			"anti_bypass_enabled": enabled,
		}, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, map[bool]string{true: "true", false: "false"}[enabled], repo.values[service.SettingKeyAntiBypassEnabled])

		var updateResponse response.Response
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updateResponse))
		updateData, ok := updateResponse.Data.(map[string]any)
		require.True(t, ok)
		require.Equal(t, enabled, updateData["anti_bypass_enabled"])

		recGet := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recGet)
		c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings", nil)
		h.GetSettings(c)
		require.Equal(t, http.StatusOK, recGet.Code)

		var getResponse response.Response
		require.NoError(t, json.Unmarshal(recGet.Body.Bytes(), &getResponse))
		getData, ok := getResponse.Data.(map[string]any)
		require.True(t, ok)
		require.Equal(t, enabled, getData["anti_bypass_enabled"])

		if enabled {
			omitted := doUpdateSettings(t, h, map[string]any{
				"registration_enabled": true,
			}, nil)
			require.Equal(t, http.StatusOK, omitted.Code)
			require.Equal(t, "true", repo.values[service.SettingKeyAntiBypassEnabled])
		}
	}
}
