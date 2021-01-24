package alert

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var (
	checkInterval = 1 * time.Minute
)

type cacheItem struct {
	Val           primitive.ObjectID
	CreateStamp   int64
	lastReadStamp int64
}

func (c *cacheItem) LastReadStamp() int64 {
	return atomic.LoadInt64(&c.lastReadStamp)
}

func (c *cacheItem) setLastReadStamp(stamp int64) {
	atomic.StoreInt64(&c.lastReadStamp, stamp)
}

type AlertAggrCache struct {
	sync.RWMutex
	cache   map[string]*cacheItem // ruleID to Mongo alerts Collection ObjectID
	wTTLSec int64
	rTTLSec int64
}

func NewAlertAggrCache(predictSize int, rTTLSec, wTTLSec int64) *AlertAggrCache {
	c := new(AlertAggrCache)
	c.cache = make(map[string]*cacheItem, predictSize)
	c.wTTLSec = wTTLSec
	c.rTTLSec = rTTLSec

	c.asyncLoop()
	return c
}

func (c *AlertAggrCache) GetByKey(key string, rtimestamp int64) (*primitive.ObjectID, bool) {
	c.RLock()
	defer c.RUnlock()
	item, exist := c.cache[key]
	if exist {
		item.setLastReadStamp(rtimestamp)
		return &item.Val, true
	}
	return nil, false
}

func (c *AlertAggrCache) Put(key string, oid primitive.ObjectID, wtimestamp, rtimestamp int64) {
	item := &cacheItem{oid, wtimestamp, rtimestamp}

	c.Lock()
	defer c.Unlock()

	c.cache[key] = item
}

func (c *AlertAggrCache) ttlCheck(now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Fatal().Msgf("Panic when checking ttl: %v. stack: %s", r, debug.Stack())
		}
	}()

	toDel := make([]string, 0, 2)
	nowStamp := now.Unix()
	for key, item := range c.cache {
		logging.GetLogger().Info().Msgf("alerts aggr cache cached item: %s -> %+v", key, item)
		if nowStamp-item.LastReadStamp() > c.rTTLSec {
			toDel = append(toDel, key)
		} else if nowStamp-item.CreateStamp > c.wTTLSec {
			toDel = append(toDel, key)
		}
	}

	if len(toDel) > 0 {
		func() {
			c.Lock()
			for _, delKey := range toDel {
				delete(c.cache, delKey)
			}

			c.Unlock()
		}()

	}
}
func (c *AlertAggrCache) asyncLoop() {
	go func() {
		ticker := time.NewTicker(checkInterval)

		for t := range ticker.C {
			c.ttlCheck(t)
		}
	}()
}
