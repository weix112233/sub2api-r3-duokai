package service

import (
	"context"
	"fmt"
	"time"
)

func (c *stubGatewayCache) SetHTTPResponseOwner(ctx context.Context, groupID int64, userKey, apiKeyKey string, userID, apiKeyID int64, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.sessionBindings == nil {
		c.sessionBindings = make(map[string]int64)
	}
	u := fmt.Sprintf("%d:%s", groupID, userKey)
	k := fmt.Sprintf("%d:%s", groupID, apiKeyKey)
	if previous := c.sessionBindings[u]; previous > 0 && previous != userID {
		return ErrHTTPResponseOwnerConflict
	}
	c.sessionBindings[u], c.sessionBindings[k] = userID, apiKeyID
	return nil
}

func (c *stubGatewayCache) GetHTTPResponseOwnerPair(ctx context.Context, groupID int64, userKey, apiKeyKey string) (int64, int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	userID := c.sessionBindings[fmt.Sprintf("%d:%s", groupID, userKey)]
	apiKeyID := c.sessionBindings[fmt.Sprintf("%d:%s", groupID, apiKeyKey)]
	if userID <= 0 || apiKeyID <= 0 {
		return 0, 0, ErrStickySessionNotFound
	}
	return userID, apiKeyID, nil
}
