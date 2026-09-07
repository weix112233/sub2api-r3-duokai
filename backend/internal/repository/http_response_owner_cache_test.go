package repository

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	redisserver "github.com/alicebob/miniredis/v2/server"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func ownerCacheFixture(t *testing.T) (*miniredis.Miniredis, *redis.Client, service.GatewayCache) {
	t.Helper()
	server := miniredis.RunT(t)
	host, portText, err := net.SplitHostPort(server.Addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	client := InitRedis(&config.Config{Redis: config.RedisConfig{
		Host: host, Port: port, DialTimeoutSeconds: 2,
		ReadTimeoutSeconds: 10, WriteTimeoutSeconds: 10, PoolSize: 4,
	}})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())
	return server, client, NewGatewayCache(client)
}

func TestHTTPResponseOwnerAtomicBinding(t *testing.T) {
	server, _, cache := ownerCacheFixture(t)
	ctx := context.Background()
	writer := service.NewOpenAIWSStateStore(cache)
	require.NoError(t, writer.BindHTTPResponseOwner(ctx, 11, "resp_atomic", 21, 31, time.Minute))
	reader := service.NewOpenAIWSStateStore(cache)
	user, key, found, err := reader.GetHTTPResponseOwner(ctx, 11, "resp_atomic")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(21), user)
	require.Equal(t, int64(31), key)

	require.ErrorIs(t, writer.BindHTTPResponseOwner(ctx, 11, "resp_atomic", 22, 32, time.Minute), service.ErrHTTPResponseOwnerConflict)
	user, key, found, err = reader.GetHTTPResponseOwner(ctx, 11, "resp_atomic")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(21), user)
	require.Equal(t, int64(31), key)

	require.NoError(t, writer.BindHTTPResponseOwner(ctx, 11, "resp_atomic", 21, 33, time.Minute))
	user, key, found, err = reader.GetHTTPResponseOwner(ctx, 11, "resp_atomic")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(21), user)
	require.Equal(t, int64(33), key)
	_, _, found, err = reader.GetHTTPResponseOwner(ctx, 12, "resp_atomic")
	require.ErrorIs(t, err, service.ErrStickySessionNotFound)
	require.False(t, found)

	server.FastForward(2 * time.Minute)
	_, _, found, err = reader.GetHTTPResponseOwner(ctx, 11, "resp_atomic")
	require.ErrorIs(t, err, service.ErrStickySessionNotFound)
	require.False(t, found, "an earlier successful read must not authorize an expired owner")
}

func TestHTTPResponseOwnerFailedRebindPreservesWholePair(t *testing.T) {
	server, _, cache := ownerCacheFixture(t)
	ctx := context.Background()
	store := service.NewOpenAIWSStateStore(cache)
	require.NoError(t, store.BindHTTPResponseOwner(ctx, 11, "resp_failure", 21, 31, time.Minute))
	server.Server().SetPreHook(func(peer *redisserver.Peer, command string, _ ...string) bool {
		if command == "EVAL" || command == "EVALSHA" {
			peer.WriteError("ERR injected owner transaction failure")
			return true
		}
		return false
	})
	require.Error(t, store.BindHTTPResponseOwner(ctx, 11, "resp_failure", 21, 32, time.Minute))
	for _, reader := range []service.OpenAIWSStateStore{store, service.NewOpenAIWSStateStore(cache)} {
		user, key, found, err := reader.GetHTTPResponseOwner(ctx, 11, "resp_failure")
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, int64(21), user)
		require.Equal(t, int64(31), key)
	}
}

func TestHTTPResponseOwnerLegacyPairCompatibility(t *testing.T) {
	_, client, raw := ownerCacheFixture(t)
	cache := raw.(service.OpenAIHTTPResponseOwnerCache)
	ctx := context.Background()
	require.NoError(t, client.MSet(ctx, buildSessionKey(11, "legacy-user"), "21", buildSessionKey(11, "legacy-key"), "31").Err())
	user, key, err := cache.GetHTTPResponseOwnerPair(ctx, 11, "legacy-user", "legacy-key")
	require.NoError(t, err)
	require.Equal(t, int64(21), user)
	require.Equal(t, int64(31), key)
	require.NoError(t, client.Del(ctx, buildSessionKey(11, "legacy-user")).Err())
	_, _, err = cache.GetHTTPResponseOwnerPair(ctx, 11, "legacy-user", "legacy-key")
	require.ErrorIs(t, err, service.ErrStickySessionNotFound)
	require.ErrorIs(t, cache.SetHTTPResponseOwner(ctx, 11, "legacy-user", "legacy-key", 22, 32, time.Minute), service.ErrHTTPResponseOwnerConflict)
}

func TestHTTPResponseOwnerConcurrentUsersHaveOneWinner(t *testing.T) {
	_, _, cache := ownerCacheFixture(t)
	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = service.NewOpenAIWSStateStore(cache).BindHTTPResponseOwner(context.Background(), 11, "resp_race", int64(21+i), int64(31+i), time.Minute)
		}(i)
	}
	close(start)
	wg.Wait()
	winner := 0
	if errs[0] != nil {
		winner = 1
	}
	require.NoError(t, errs[winner])
	require.ErrorIs(t, errs[1-winner], service.ErrHTTPResponseOwnerConflict)
	user, key, found, err := service.NewOpenAIWSStateStore(cache).GetHTTPResponseOwner(context.Background(), 11, "resp_race")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(21+winner), user)
	require.Equal(t, int64(31+winner), key)
}

func TestHTTPResponseOwnerRealClientRespectsPersistenceBudget(t *testing.T) {
	server, client, cache := ownerCacheFixture(t)
	require.True(t, client.Options().ContextTimeoutEnabled)
	store := service.NewOpenAIWSStateStore(cache)
	require.NoError(t, store.BindHTTPResponseOwner(context.Background(), 11, "resp_warm", 21, 31, time.Minute))
	server.Server().SetPreHook(func(_ *redisserver.Peer, command string, _ ...string) bool {
		if command == "EVALSHA" {
			time.Sleep(4 * time.Second)
		}
		return false
	})
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := store.BindHTTPResponseOwner(parent, 11, "resp_slow", 21, 31, time.Minute)
	require.Error(t, err)
	require.Less(t, time.Since(started), 3500*time.Millisecond)
}

func TestRedisProductionClientHonorsReadDeadline(t *testing.T) {
	server, client, _ := ownerCacheFixture(t)
	server.Server().SetPreHook(func(_ *redisserver.Peer, command string, _ ...string) bool {
		if command == "GET" {
			time.Sleep(500 * time.Millisecond)
		}
		return false
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.Error(t, client.Get(ctx, "deadline-fixture").Err())
	require.Less(t, time.Since(started), 400*time.Millisecond)
}
