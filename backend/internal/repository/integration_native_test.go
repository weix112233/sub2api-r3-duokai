//go:build integration

package repository

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	redisclient "github.com/redis/go-redis/v9"
)

// Native mode is opt-in and Unix-socket-only. The preprovisioned sub2api_test
// database anchors a disposable cluster; each run creates and removes its own
// database so fixtures from a prior run cannot affect repository assertions.
// The default Docker/CI path is unchanged.
func runNativeIntegration(m *testing.M) (exitCode int) {
	pgSocket := os.Getenv("SUB2API_TEST_POSTGRES_SOCKET")
	redisSocket := os.Getenv("SUB2API_TEST_REDIS_SOCKET")
	for _, socket := range []string{pgSocket, redisSocket} {
		if !filepath.IsAbs(socket) {
			log.Print("native integration requires absolute PostgreSQL and Redis socket paths")
			return 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dsn := url.URL{Scheme: "postgres", Path: "/sub2api_test"}
	dsn.RawQuery = url.Values{"host": {pgSocket}, "sslmode": {"disable"}, "TimeZone": {"UTC"}}.Encode()
	var err error
	controlDB, err := openSQLWithRetry(ctx, dsn.String(), 5*time.Second)
	if err != nil {
		log.Print("native integration PostgreSQL connection failed")
		return 1
	}
	defer controlDB.Close()
	var database string
	if err := controlDB.QueryRowContext(ctx, "SELECT current_database()").Scan(&database); err != nil || database != "sub2api_test" {
		log.Print("native integration refused a non-test database")
		return 1
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		log.Print("native integration database name generation failed")
		return 1
	}
	runDatabase := fmt.Sprintf("sub2api_test_%x", suffix)
	if _, err := controlDB.ExecContext(ctx, "CREATE DATABASE "+runDatabase+" TEMPLATE template0"); err != nil {
		log.Print("native integration disposable database creation failed")
		return 1
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := controlDB.ExecContext(cleanupCtx, "DROP DATABASE "+runDatabase); err != nil {
			log.Printf("native integration database cleanup failed: %s", runDatabase)
			exitCode = 1
		}
	}()
	dsn.Path = "/" + runDatabase
	integrationDB, err = openSQLWithRetry(ctx, dsn.String(), 5*time.Second)
	if err != nil {
		log.Print("native integration disposable database connection failed")
		return 1
	}
	defer integrationDB.Close()
	if err := ApplyMigrations(ctx, integrationDB); err != nil {
		log.Printf("native integration migration failed: %v", err)
		return 1
	}
	integrationEntClient = dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, integrationDB)))
	defer integrationEntClient.Close()
	integrationRedis = redisclient.NewClient(&redisclient.Options{
		Network: "unix", Addr: redisSocket, DB: 0,
	})
	defer integrationRedis.Close()
	if err := integrationRedis.Ping(ctx).Err(); err != nil {
		log.Print("native integration Redis connection failed")
		return 1
	}
	fmt.Println("integration services: explicit local Unix sockets, fresh per-run test database")
	return m.Run()
}
