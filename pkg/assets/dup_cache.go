package assets

import (
	"crypto/md5"
	"encoding/hex"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	maxUnMd5Length = 32
)

type IdentifiableItem interface {
	IdentityString() string
	KeyName() string
	SetDuplicatedChecked(checked bool)
	DuplicatedChecked() bool
}
type DuplicationCheckingCache struct {
	cache *ttlcache.Cache[string, string]
	ttl   time.Duration
}

func NewDuplicationCheckingCache(ttl time.Duration, maxSize int) *DuplicationCheckingCache {
	cache := ttlcache.New[string, string](
		ttlcache.WithTTL[string, string](ttl),
		ttlcache.WithCapacity[string, string](uint64(maxSize)),
	)
	return &DuplicationCheckingCache{
		cache: cache,
		ttl:   ttl,
	}
}

func getMD5(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

func (c *DuplicationCheckingCache) Put(item IdentifiableItem) {
	keyName := item.KeyName()
	if len(keyName) > maxUnMd5Length {
		keyName = getMD5(keyName)
	}
	idStr := item.IdentityString()
	if len(idStr) > maxUnMd5Length {
		idStr = getMD5(idStr)
	}
	c.cache.Set(keyName, idStr, c.ttl)
}

func (c *DuplicationCheckingCache) Check(item IdentifiableItem) bool {
	keyName := item.KeyName()
	if len(keyName) > maxUnMd5Length {
		keyName = getMD5(keyName)
	}

	v := c.cache.Get(keyName)
	if v == nil {
		return false
	}

	idStr := item.IdentityString()
	if len(idStr) > maxUnMd5Length {
		idStr = getMD5(idStr)
	}
	return idStr == v.Value()
}
