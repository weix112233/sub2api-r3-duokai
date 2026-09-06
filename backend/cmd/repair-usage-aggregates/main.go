// This maintenance command is explicitly scoped to the 2026-09-05 fee repair.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

func main() {
	apply := flag.Bool("apply-fees", false, "Apply the prepared fee correction before recomputing")
	flag.Parse()
	if err := run(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(apply bool) error {
	data, err := os.ReadFile("/Users/liyunlong/Library/Application Support/Sub2API/secrets/sub2api.env")
	if err != nil {
		return errors.New("production connection configuration unavailable")
	}
	secrets := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && (key == "DATABASE_PASSWORD" || key == "REDIS_PASSWORD") {
			secrets[key] = value
		}
	}
	if secrets["DATABASE_PASSWORD"] == "" || secrets["REDIS_PASSWORD"] == "" {
		return errors.New("production database or Redis credential missing")
	}
	dsn := url.URL{Scheme: "postgres", Host: "127.0.0.1:15432", Path: "/sub2api",
		User: url.UserPassword("sub2api_admin", secrets["DATABASE_PASSWORD"])}
	params := url.Values{"sslmode": []string{"disable"}, "application_name": []string{"astra_fee_correction"}}
	dsn.RawQuery = params.Encode()
	db, err := sql.Open("postgres", dsn.String())
	if err != nil {
		return errors.New("database connection initialization failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16379", Username: "default",
		Password: secrets["REDIS_PASSWORD"], DialTimeout: 5 * time.Second})
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if db.PingContext(ctx) != nil || rdb.Ping(ctx).Err() != nil {
		return errors.New("database or Redis health check failed")
	}
	lock := repository.NewLeaderLockCache(rdb)
	const lockKey = "dashboard:aggregation:leader"
	owner := "fee-correction-" + uuid.NewString()
	acquired := false
	for attempt := 0; attempt < 15; attempt++ {
		acquired, err = lock.TryAcquireLeaderLock(ctx, lockKey, owner, 5*time.Minute)
		if err != nil {
			return errors.New("aggregation lock check failed")
		}
		if acquired {
			break
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return errors.New("aggregation lock wait timed out")
		}
	}
	if !acquired {
		return errors.New("existing aggregation writer is busy; no fees changed")
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_ = lock.ReleaseLeaderLock(releaseCtx, lockKey, owner)
	}()
	if apply {
		cmd := exec.CommandContext(ctx, "python3",
			"/Users/liyunlong/Documents/Codex/2026-09-05/wen/repair_historical_fees.py", "apply")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if cmd.Run() != nil {
			return errors.New("fee correction did not complete; inspect its receipt before retrying")
		}
	}
	if err := timezone.Init("Asia/Shanghai"); err != nil {
		return errors.New("aggregation timezone initialization failed")
	}
	start, _ := time.Parse(time.RFC3339, "2026-09-05T10:00:00+08:00")
	end, _ := time.Parse(time.RFC3339, "2026-09-05T13:00:00+08:00")
	aggregator := repository.NewDashboardAggregationRepository(db)
	if err := aggregator.RecomputeRange(ctx, start, end); err != nil {
		return errors.New("fee rows may be corrected but aggregate recomputation failed; rerun this command without --apply-fees")
	}
	if err := repository.NewDashboardCache(rdb, nil).DeleteDashboardStats(ctx); err != nil {
		return errors.New("aggregate recomputation succeeded but dashboard display cache invalidation failed")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"aggregate_recompute": "passed", "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339),
		"dashboard_display_cache_invalidated": true, "model_caches_untouched": true,
		"balance_and_provider_billing_untouched": true,
	})
}
