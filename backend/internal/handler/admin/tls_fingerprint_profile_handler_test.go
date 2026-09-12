package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/model"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type tlsProfileHandlerRepo struct {
	service.TLSFingerprintProfileRepository
	profile *model.TLSFingerprintProfile
}

func (r *tlsProfileHandlerRepo) List(context.Context) ([]*model.TLSFingerprintProfile, error) {
	if r.profile == nil {
		return nil, nil
	}
	return []*model.TLSFingerprintProfile{r.profile}, nil
}
func (r *tlsProfileHandlerRepo) GetByID(context.Context, int64) (*model.TLSFingerprintProfile, error) {
	return r.profile, nil
}
func (r *tlsProfileHandlerRepo) Create(_ context.Context, p *model.TLSFingerprintProfile) (*model.TLSFingerprintProfile, error) {
	p.ID = 1
	r.profile = p
	return p, nil
}
func (r *tlsProfileHandlerRepo) Update(_ context.Context, p *model.TLSFingerprintProfile) (*model.TLSFingerprintProfile, error) {
	r.profile = p
	return p, nil
}

func tlsProfileTestRouter() (*gin.Engine, *tlsProfileHandlerRepo) {
	repo := &tlsProfileHandlerRepo{}
	h := NewTLSFingerprintProfileHandler(service.NewTLSFingerprintProfileService(repo, nil))
	r := gin.New()
	r.POST("/profiles", h.Create)
	r.PUT("/profiles/:id", h.Update)
	r.POST("/parse-yaml", h.ParseYAML)
	r.PUT("/defaults", h.SetDefaults)
	return r, repo
}

func tlsProfileJSONRequest(r http.Handler, method, url, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTLSProfileCRUDOptionalTransportFields(t *testing.T) {
	router, repo := tlsProfileTestRouter()
	w := tlsProfileJSONRequest(router, http.MethodPost, "/profiles", `{"name":"custom","alpn_protocols":["h2"],"shuffle_extensions":true,"http2":{"initial_window_size":0,"connection_window_update":0,"max_header_list_size":0,"enable_push":false}}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.True(t, repo.profile.ShuffleExtensions)
	require.NotNil(t, repo.profile.HTTP2.EnablePush)
	require.False(t, *repo.profile.HTTP2.EnablePush)
	require.Zero(t, *repo.profile.HTTP2.ConnectionWindowUpdate)
	w = tlsProfileJSONRequest(router, http.MethodPut, "/profiles/1", `{"name":"renamed"}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, repo.profile.ShuffleExtensions)
	require.Equal(t, []string{"h2"}, repo.profile.ALPNProtocols)
	require.NotNil(t, repo.profile.HTTP2)
	w = tlsProfileJSONRequest(router, http.MethodPut, "/profiles/1", `{"shuffle_extensions":false,"alpn_protocols":[],"http2":null}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.False(t, repo.profile.ShuffleExtensions)
	require.NotNil(t, repo.profile.ALPNProtocols)
	require.Empty(t, repo.profile.ALPNProtocols)
	require.Nil(t, repo.profile.HTTP2)
	w = tlsProfileJSONRequest(router, http.MethodPut, "/profiles/1", `{"alpn_protocols":null}`)
	require.Equal(t, http.StatusOK, w.Code)
	require.Nil(t, repo.profile.ALPNProtocols)
}

func TestTLSProfileCRUDRejectsInvalidTransportFields(t *testing.T) {
	for _, body := range []string{
		`{"name":"bad","http2":{"ignored":1}}`,
		`{"name":"bad","alpn_protocols":["h2"],"http2":{"initial_window_size":-1}}`,
		`{"name":"bad","alpn_protocols":["h2"],"http2":{"initial_window_size":2147483648}}`,
		`{"name":"bad","alpn_protocols":["h2"],"http2":{"connection_window_update":2147418113}}`,
		`{"name":"bad","alpn_protocols":[],"http2":{"enable_push":true}}`,
		`{"name":"bad","alpn_protocols":["other"]}`,
	} {
		router, repo := tlsProfileTestRouter()
		w := tlsProfileJSONRequest(router, http.MethodPost, "/profiles", body)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		require.Nil(t, repo.profile)
	}
	router, repo := tlsProfileTestRouter()
	repo.profile = &model.TLSFingerprintProfile{ID: 1, Name: "unchanged"}
	for _, body := range []string{`{"http2":{"unknown":1}}`, `{"alpn_protocols":42}`, `{"alpn_protocols":[],"http2":{"enable_push":true}}`} {
		w := tlsProfileJSONRequest(router, http.MethodPut, "/profiles/1", body)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Nil(t, repo.profile.HTTP2)
		require.Nil(t, repo.profile.ALPNProtocols)
	}
}

func TestTLSProfileYAMLAPI(t *testing.T) {
	router, _ := tlsProfileTestRouter()
	body, err := json.Marshal(map[string]string{"yaml": "custom:\n  name: local\n  shuffle_extensions: true\n  alpn_protocols: []\n"})
	require.NoError(t, err)
	w := tlsProfileJSONRequest(router, http.MethodPost, "/parse-yaml", string(body))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var result struct {
		Data struct {
			Shuffle bool     `json:"shuffle_extensions"`
			ALPN    []string `json:"alpn_protocols"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.True(t, result.Data.Shuffle)
	require.NotNil(t, result.Data.ALPN)
	w = tlsProfileJSONRequest(router, http.MethodPost, "/parse-yaml", `{"yaml":"name: bad\nshuffle_extensions: maybe"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	for _, body := range []string{`{}`, `{"openai_oauth_default_tls_profile_id":null}`, `{"openai_oauth_default_tls_profile_id":-1}`} {
		w = tlsProfileJSONRequest(router, http.MethodPut, "/defaults", body)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}
