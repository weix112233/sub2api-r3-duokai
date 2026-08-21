package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type timeSensitiveRefreshCache struct {
	SchedulerCache
	refreshes chan []Account
}

func (c *timeSensitiveRefreshCache) GetSnapshot(context.Context, SchedulerBucket) ([]*Account, bool, error) {
	return []*Account{{ID: 1}}, true, nil
}

func (c *timeSensitiveRefreshCache) CaptureBucketWriteToken(_ context.Context, bucket SchedulerBucket) (SchedulerBucketWriteToken, error) {
	return SchedulerBucketWriteToken{Bucket: bucket, Epoch: 1}, nil
}

func (c *timeSensitiveRefreshCache) SetSnapshot(_ context.Context, _ SchedulerBucket, _ SchedulerBucketWriteToken, accounts []Account) error {
	select {
	case c.refreshes <- accounts:
	default:
	}
	return nil
}

type timeSensitiveRefreshAccountRepo struct {
	AccountRepository
	calls atomic.Int32
}

func (r *timeSensitiveRefreshAccountRepo) ListSchedulableByPlatform(_ context.Context, _ string) ([]Account, error) {
	r.calls.Add(1)
	return []Account{{ID: 395}}, nil
}

func TestSchedulerSnapshotRefreshesTimeSensitiveMembershipOffHotPath(t *testing.T) {
	cache := &timeSensitiveRefreshCache{refreshes: make(chan []Account, 1)}
	repo := &timeSensitiveRefreshAccountRepo{}
	svc := NewSchedulerSnapshotService(
		cache,
		nil,
		repo,
		nil,
		&config.Config{RunMode: config.RunModeSimple},
	)

	started := time.Now()
	accounts, useMixed, err := svc.ListSchedulableAccounts(context.Background(), nil, PlatformOpenAI, false)
	require.NoError(t, err)
	require.False(t, useMixed)
	require.Len(t, accounts, 1)
	require.Less(t, time.Since(started), time.Second)

	select {
	case refreshed := <-cache.refreshes:
		require.Len(t, refreshed, 1)
		require.EqualValues(t, 395, refreshed[0].ID)
	case <-time.After(time.Second):
		t.Fatal("time-sensitive snapshot refresh did not run")
	}

	_, _, err = svc.ListSchedulableAccounts(context.Background(), nil, PlatformOpenAI, false)
	require.NoError(t, err)
	time.Sleep(25 * time.Millisecond)
	require.EqualValues(t, 1, repo.calls.Load(), "refreshes must be rate-limited per bucket")
}
