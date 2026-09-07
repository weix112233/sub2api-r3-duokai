package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/wsdrain"
)

// Preserve the legacy default; production explicitly opts into longer draining.
func shutdownTimeout(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 5 * time.Second, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > time.Hour {
		return 0, fmt.Errorf("SERVER_SHUTDOWN_TIMEOUT must be a positive duration no greater than 1h")
	}
	return duration, nil
}

func shutdownHTTPServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return server.Shutdown(ctx)
}

func shutdownApplication(server *http.Server, sockets *wsdrain.Registry, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sockets.BeginDrain()
	httpErr := server.Shutdown(ctx)
	wsErr := sockets.Wait(ctx)
	if httpErr != nil {
		_ = server.Close()
		return httpErr
	}
	return wsErr
}
