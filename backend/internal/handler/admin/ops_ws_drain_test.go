package admin

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/wsdrain"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestQPSManagementWebSocketDrainsBeforeDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &OpsHandler{opsService: &service.OpsService{}}
	router := gin.New()
	router.GET("/qps", handler.QPSWSHandler)
	registry := wsdrain.New()
	server := httptest.NewServer(registry.Handler(router))
	defer server.Close()
	defer func() {
		cancelQPSWSIdleStop()
		qpsWSCache.Stop()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/qps", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.Eventually(t, func() bool { return registry.Count() == 1 }, time.Second, time.Millisecond)
	registry.BeginDrain()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	for {
		_, _, err = conn.ReadMessage()
		if err != nil {
			break
		}
	}
	var closed *websocket.CloseError
	require.ErrorAs(t, err, &closed)
	require.Equal(t, websocket.CloseServiceRestart, closed.Code)
	require.NoError(t, registry.Wait(ctx))
	require.Zero(t, registry.Count())
	require.Equal(t, int32(0), wsConnCount.Load())
}
