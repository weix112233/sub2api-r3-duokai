package main

import (
	"testing"
	"time"
)

func TestServerShutdownTimeout(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want time.Duration
	}{
		{name: "default", want: defaultServerShutdownTimeout},
		{name: "configured", env: "90s", want: 90 * time.Second},
		{name: "invalid uses default", env: "not-a-duration", want: defaultServerShutdownTimeout},
		{name: "too short uses default", env: "1s", want: defaultServerShutdownTimeout},
		{name: "too long is capped", env: "24h", want: maxServerShutdownTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env == "" {
				t.Setenv("SERVER_SHUTDOWN_TIMEOUT", "")
			} else {
				t.Setenv("SERVER_SHUTDOWN_TIMEOUT", tt.env)
			}
			if got := serverShutdownTimeout(); got != tt.want {
				t.Fatalf("serverShutdownTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
}
