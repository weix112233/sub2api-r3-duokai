package tlsfingerprint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHTTPProxyCONNECTReadHonorsCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	defer close(release)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, dialErr := NewHTTPProxyDialer(nil, proxyURL).DialTLSContext(ctx, "tcp", "upstream.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		result <- dialErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("CONNECT not received")
	}
	cancel()
	select {
	case dialErr := <-result:
		require.True(t, errors.Is(dialErr, context.Canceled))
	case <-time.After(time.Second):
		t.Fatal("proxy response reader ignored cancellation")
	}
}
