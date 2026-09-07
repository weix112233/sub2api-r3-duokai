package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type ownerPersistenceProbe struct {
	stubGatewayCache
	t        *testing.T
	cancel   context.CancelFunc
	setCalls int
	failAt   int
	err      error
	contexts []context.Context
}

func (c *ownerPersistenceProbe) SetHTTPResponseOwner(ctx context.Context, groupID int64, userKey, apiKeyKey string, userID, apiKeyID int64, ttl time.Duration) error {
	c.setCalls++
	c.contexts = append(c.contexts, ctx)
	deadline, ok := ctx.Deadline()
	require.True(c.t, ok)
	require.LessOrEqual(c.t, time.Until(deadline), openAIWSStateStoreRedisTimeout)
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.cancel != nil && c.setCalls == 1 {
		c.cancel()
	}
	if c.setCalls == c.failAt {
		return c.err
	}
	return c.stubGatewayCache.SetHTTPResponseOwner(ctx, groupID, userKey, apiKeyKey, userID, apiKeyID, ttl)
}

func TestOpenAIHTTPResponseOwner_PersistsAfterRequestCancellation(t *testing.T) {
	for _, mode := range []string{"already_canceled", "during_write", "expired_deadline", "nil_parent"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probe := &ownerPersistenceProbe{t: t}
			switch mode {
			case "already_canceled":
				cancel()
			case "during_write":
				probe.cancel = cancel
			case "expired_deadline":
				var expiredCancel context.CancelFunc
				ctx, expiredCancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer expiredCancel()
			case "nil_parent":
				ctx = nil
			}
			writer := NewOpenAIWSStateStore(probe)
			require.NoError(t, writer.BindHTTPResponseOwner(ctx, 8, "resp_completed_owner", 201, 301, time.Minute))
			require.Equal(t, 1, probe.setCalls)
			for _, persistedCtx := range probe.contexts {
				require.ErrorIs(t, persistedCtx.Err(), context.Canceled, "the bounded persistence context must be released")
			}

			reader := NewOpenAIWSStateStore(probe)
			userID, apiKeyID, found, err := reader.GetHTTPResponseOwner(context.Background(), 8, "resp_completed_owner")
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, int64(201), userID)
			require.Equal(t, int64(301), apiKeyID)
			_, _, found, err = reader.GetHTTPResponseOwner(context.Background(), 9, "resp_completed_owner")
			require.Error(t, err)
			require.False(t, found)
		})
	}
}

func TestOpenAIHTTPResponseOwner_PersistenceFailureRemainsFailClosed(t *testing.T) {
	unavailable := errors.New("owner persistence unavailable")
	probe := &ownerPersistenceProbe{t: t, failAt: 1, err: unavailable}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := NewOpenAIWSStateStore(probe)
	require.ErrorIs(t, writer.BindHTTPResponseOwner(ctx, 8, "resp_partial_owner", 201, 301, time.Minute), unavailable)
	require.Equal(t, 1, probe.setCalls)
	for _, reader := range []OpenAIWSStateStore{writer, NewOpenAIWSStateStore(probe)} {
		_, _, found, err := reader.GetHTTPResponseOwner(context.Background(), 8, "resp_partial_owner")
		require.Error(t, err)
		require.False(t, found, "failed persistence must not publish a local or remote owner")
	}
}

func TestOpenAIHTTPResponseOwner_UnsupportedCacheFailsClosed(t *testing.T) {
	store := NewOpenAIWSStateStore(&openAIWSStateStoreTimeoutProbeCache{})
	require.ErrorIs(t, store.BindHTTPResponseOwner(context.Background(), 8, "resp_unsupported", 201, 301, time.Minute), ErrHTTPResponseOwnerCacheUnsupported)
	_, _, found, err := store.GetHTTPResponseOwner(context.Background(), 8, "resp_unsupported")
	require.ErrorIs(t, err, ErrHTTPResponseOwnerCacheUnsupported)
	require.False(t, found)
}

func TestOpenAIHTTPResponseOwner_LocalOnlyOwnerIsImmutable(t *testing.T) {
	store := NewOpenAIWSStateStore(nil)
	require.NoError(t, store.BindHTTPResponseOwner(context.Background(), 8, "resp_local", 201, 301, time.Minute))
	require.ErrorIs(t, store.BindHTTPResponseOwner(context.Background(), 8, "resp_local", 202, 302, time.Minute), ErrHTTPResponseOwnerConflict)
	user, key, found, err := store.GetHTTPResponseOwner(context.Background(), 8, "resp_local")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(201), user)
	require.Equal(t, int64(301), key)
}

func TestOpenAIHTTPResponseOwner_ReadStillHonorsCancellation(t *testing.T) {
	probe := &ownerPersistenceProbe{t: t}
	store := NewOpenAIWSStateStore(probe)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, found, err := store.GetHTTPResponseOwner(ctx, 8, "resp_uncached")
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, found)
}

func TestOpenAIHTTPResponseOwner_PersistencePreservesContextValues(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "audit_value")
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	probe := &ownerPersistenceProbe{t: t}
	store := NewOpenAIWSStateStore(probe)
	require.NoError(t, store.BindHTTPResponseOwner(ctx, 8, "resp_context_owner", 201, 301, time.Minute))
	for _, persistedCtx := range probe.contexts {
		require.Equal(t, "audit_value", persistedCtx.Value(contextKey{}))
	}
}
