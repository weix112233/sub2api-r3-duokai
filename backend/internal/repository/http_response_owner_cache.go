package repository

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

var _ service.OpenAIHTTPResponseOwnerCache = (*gatewayCache)(nil)

// Keep the existing keys for R9 compatibility, but commit both values together.
var bindHTTPResponseOwnerScript = redis.NewScript(`
local existing = redis.call('MGET', KEYS[1], KEYS[2])
if existing[1] and existing[1] ~= ARGV[1] then
  return 0
end
if not existing[1] and existing[2] then
  return 0
end
redis.call('MSET', KEYS[1], ARGV[1], KEYS[2], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
`)

func (c *gatewayCache) SetHTTPResponseOwner(ctx context.Context, groupID int64, userKey, apiKeyKey string, userID, apiKeyID int64, ttl time.Duration) error {
	if userID <= 0 || apiKeyID <= 0 || ttl.Milliseconds() <= 0 || userKey == apiKeyKey {
		return fmt.Errorf("invalid response owner binding")
	}
	result, err := bindHTTPResponseOwnerScript.Run(ctx, c.rdb,
		[]string{buildSessionKey(groupID, userKey), buildSessionKey(groupID, apiKeyKey)},
		strconv.FormatInt(userID, 10), strconv.FormatInt(apiKeyID, 10), ttl.Milliseconds()).Int64()
	if err != nil {
		return err
	}
	if result != 1 {
		return service.ErrHTTPResponseOwnerConflict
	}
	return nil
}

func (c *gatewayCache) GetHTTPResponseOwnerPair(ctx context.Context, groupID int64, userKey, apiKeyKey string) (int64, int64, error) {
	values, err := c.rdb.MGet(ctx, buildSessionKey(groupID, userKey), buildSessionKey(groupID, apiKeyKey)).Result()
	if err != nil {
		return 0, 0, err
	}
	if len(values) != 2 || values[0] == nil || values[1] == nil {
		return 0, 0, service.ErrStickySessionNotFound
	}
	userText, userOK := values[0].(string)
	keyText, keyOK := values[1].(string)
	userID, userErr := strconv.ParseInt(userText, 10, 64)
	apiKeyID, keyErr := strconv.ParseInt(keyText, 10, 64)
	if !userOK || !keyOK || userErr != nil || keyErr != nil || userID <= 0 || apiKeyID <= 0 {
		return 0, 0, fmt.Errorf("invalid persisted response owner")
	}
	return userID, apiKeyID, nil
}
