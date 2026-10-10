package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/mohit-bhandari45/bastion/internal/config"
)

type Limiter struct {
	rdb    *redis.Client
	cfg    *config.RateLimitConfig
	prefix string
}

func New(rdb *redis.Client, cfg *config.RateLimitConfig) *Limiter {
	return &Limiter{
		rdb:    rdb,
		cfg:    cfg,
		prefix: "bastion:rl:",
	}
}

// Allow uses a simple fixed-window counter in Redis.
// Returns allowed (bool), remaining requests, and retry-after seconds.
func (l *Limiter) Allow(ctx context.Context, key string) (bool, int, int, error) {
	if !l.cfg.Enabled {
		return true, l.cfg.RequestsPerMinute, 0, nil
	}

	fullKey := l.prefix + key
	now := time.Now()
	window := now.Truncate(time.Minute)
	windowKey := fmt.Sprintf("%s:%d", fullKey, window.Unix())

	pipe := l.rdb.Pipeline()
	incr := pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, 2*time.Minute)
	_, err := pipe.Exec(ctx)
	if err != nil {
		// Fail open on Redis errors (or change to fail closed in high-security setups)
		return true, l.cfg.RequestsPerMinute, 0, err
	}

	count := int(incr.Val())
	remaining := l.cfg.RequestsPerMinute - count
	if remaining < 0 {
		remaining = 0
	}

	if count > l.cfg.RequestsPerMinute {
		retryAfter := int(60 - now.Second())
		if retryAfter <= 0 {
			retryAfter = 1
		}
		return false, remaining, retryAfter, nil
	}

	return true, remaining, 0, nil
}
