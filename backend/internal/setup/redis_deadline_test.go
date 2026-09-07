package setup

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisserver "github.com/alicebob/miniredis/v2/server"
	"github.com/stretchr/testify/require"
)

func TestRedisConnectionDeadline(t *testing.T) {
	server := miniredis.RunT(t)
	host, portText, err := net.SplitHostPort(server.Addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	cfg := &RedisConfig{Host: host, Port: port}
	require.NoError(t, TestRedisConnection(cfg))
	server.Server().SetPreHook(func(_ *redisserver.Peer, command string, _ ...string) bool {
		if command == "PING" {
			time.Sleep(6 * time.Second)
		}
		return false
	})
	started := time.Now()
	require.Error(t, TestRedisConnection(cfg))
	require.Less(t, time.Since(started), 5500*time.Millisecond)
}
