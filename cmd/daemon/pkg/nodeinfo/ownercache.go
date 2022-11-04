package nodeinfo

import (
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type ownerRefCache struct {
	maxSize    uint64
	defaultTTL time.Duration
	cache      *ttlcache.Cache[string, Resource] // namespace/kind/name -> Resource
}

func newOwnerRefCache(maxSize uint64, ttl time.Duration) *ownerRefCache {
	cache := ttlcache.New[string, Resource](
		ttlcache.WithCapacity[string, Resource](maxSize),
		ttlcache.WithTTL[string, Resource](ttl),
	)
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
	item := c.cache.Get(key)
	if item == nil {
		return Resource{}, false
	}

	c.cache.Set(key, item.Value(), c.defaultTTL)
	return Resource{}, false
}

func (c *ownerRefCache) Put(name, kind, namespace string, owner Resource) error {
	c.cache.Set(getKey(namespace, kind, name), owner, c.defaultTTL)
	return nil
}
