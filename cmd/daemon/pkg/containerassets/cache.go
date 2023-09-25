package containerassets

import (
	"github.com/jellydator/ttlcache/v3"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"time"
)

type Store interface {
	add(namespace, name string, obj interface{}) error
	get(key string) (*model.TensorRawContainer, bool)
}

type cache struct {
	store    *ttlcache.Cache[string, assets.TensorRawContainer]
	maxLimit int
}

func newCache(limit int) *cache {
	c := ttlcache.New[string, assets.TensorRawContainer](
		ttlcache.WithCapacity[string, assets.TensorRawContainer](uint64(limit)),
		ttlcache.WithTTL[string, assets.TensorRawContainer](time.Second*60))

	return &cache{
		store:    c,
		maxLimit: limit,
	}
}

func (c *cache) add(namespace, name string, value assets.TensorRawContainer) error {
	c.store.Set(keyFunc(namespace, name), value, time.Second*60)
	return nil
}

func (c *cache) get(key string) (assets.TensorRawContainer, bool) {
	obj := c.store.Get(key)
	if obj == nil {
		return assets.TensorRawContainer{}, false
	}
	return obj.Value(), true
}

func (c *cache) remove(namespace, name string) error {
	c.store.Delete(keyFunc(namespace, name))
	return nil
}

func keyFunc(namespace, name string) string {
	return namespace + "/" + name
}
