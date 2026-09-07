package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShutdownTimeoutHonorsProductionEnvironment(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  time.Duration
	}{
		{"", 5 * time.Second}, {"55m", 55 * time.Minute},
		{" 30s ", 30 * time.Second}, {"1h", time.Hour},
	} {
		got, err := shutdownTimeout(tc.input)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
	for _, value := range []string{"0", "-1s", "61m", "forever", "999999999999999999h"} {
		_, err := shutdownTimeout(value)
		require.Error(t, err)
	}
}

func TestShutdownWaitsForActiveResponse(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("complete"))
	}))
	defer server.Close()
	var once sync.Once
	releaseRequest := func() { once.Do(func() { close(release) }) }
	defer releaseRequest()
	done := make(chan string, 1)
	go func() {
		response, err := http.Get(server.URL)
		if err != nil {
			done <- "request_failed"
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		done <- string(body)
	}()
	<-entered
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- shutdownHTTPServer(server.Config, 2*time.Second) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before response completed: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseRequest()
	require.Equal(t, "complete", <-done)
	require.NoError(t, <-shutdownDone)
}

func TestShutdownDeadlineIsBounded(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}))
	defer server.Close()
	var once sync.Once
	releaseRequest := func() { once.Do(func() { close(release) }) }
	defer releaseRequest()
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, err := http.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
	}()
	<-entered
	err := shutdownHTTPServer(server.Config, 20*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	releaseRequest()
	<-done
}
