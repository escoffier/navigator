package util

import (
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultLimiterCacheExpireAt = time.Minute * 3
)

type limiterWrapper struct {
	key string
	lmt *rate.Limiter
}

type limiter struct {
	limit rate.Limit
	burst int
	cache cache.Store
}

func NewLimiter(r rate.Limit, b int) *limiter {
	return &limiter{
		limit: r,
		burst: b,
		cache: cache.NewTTLStore(func(obj interface{}) (string, error) { return obj.(*limiterWrapper).key, nil }, defaultLimiterCacheExpireAt),
	}
}

func (l *limiter) AllowKey(key string) bool {
	item, found, _ := l.cache.GetByKey(key)
	if !found {
		// create limiter
		item = &limiterWrapper{key: key, lmt: rate.NewLimiter(l.limit, l.burst)}
		_ = l.cache.Add(item)
	}

	return item.(*limiterWrapper).lmt.Allow()
}
