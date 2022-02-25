package nodeinfo

import (
	"strings"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"gitlab.com/security-rd/go-pkg/logging"
)

type ownerRefCache struct {
	maxSize    int
	defaultTTL time.Duration
	cache      *ttlcache.Cache // namespace/kind/name -> Resource
}

func newOwnerRefCache(maxSize int, ttl time.Duration) *ownerRefCache {
	cache := ttlcache.NewCache()
	cache.SetCacheSizeLimit(maxSize)
	if err := cache.SetTTL(ttl); err != nil {
		logging.Get().Warn().Msgf("the ttl cache is errored: %v", err)
	}
	c := &ownerRefCache{
		maxSize: maxSize,
		cache:   cache,
	}
	return c
}

func getKey(elements ...string) string {
	return strings.Join(elements, "/")
}

func (c *ownerRefCache) GetOwnerFrom(name, kind, namespace string) (Resource, bool) {
	key := getKey(namespace, kind, name)
	o, err := c.cache.Get(key)
	if err == ttlcache.ErrNotFound {
		return Resource{}, false
	}
	if r, ok := o.(Resource); ok {
		// to implement read ttl
		_ = c.cache.SetWithTTL(key, r, c.defaultTTL)
		return r, true
	}
	return Resource{}, false
}

func (c *ownerRefCache) Put(name, kind, namespace string, owner Resource) error {
	return c.cache.SetWithTTL(getKey(namespace, kind, name), owner, c.defaultTTL)
}
