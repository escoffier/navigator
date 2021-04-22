package util

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	MongoTimeout         = time.Second * 20
	RedisTimeout         = time.Second * 5
	CacheRefreshInterval = time.Second * 30
	RedisExpiration      = time.Hour * 24
	FinishedAtKey        = "FinishedAt"
	CreatedAtKey         = "CreatedAt"
	TimestampKey         = "Timestamp"
)

type CacheHelper struct {
	keyPrefix                    string
	redisClient                  *redis.Client
	ctx                          context.Context
	mu                           sync.Mutex
	getNewestEntryTimestamp      func() (int64, error)
	redisNewestEntryTimestampKey string
	registry                     map[string]func() ([]model.CacheEntry, error)
}

func NewCacheHelper(
	ctx context.Context,
	keyPrefix string,
	redisClient *redis.Client,
	getNewestEntryTimestamp func() (int64, error),
	redisNewestEntryTimestampKey string,
) *CacheHelper {
	c := CacheHelper{
		ctx:                          ctx,
		keyPrefix:                    keyPrefix,
		redisClient:                  redisClient,
		getNewestEntryTimestamp:      getNewestEntryTimestamp,
		redisNewestEntryTimestampKey: redisNewestEntryTimestampKey,
		registry:                     make(map[string]func() ([]model.CacheEntry, error)),
	}
	go c.bgSync()
	return &c
}

func (c *CacheHelper) RemoveFromRegistry(keyElements ...string) error {
	key := c.KeyFrom(keyElements...)
	if _, ok := c.registry[key]; !ok {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Key doesnt exist in cache", key))
	}
	redisCtx, redisCtxCancel := context.WithTimeout(c.ctx, RedisTimeout)
	defer redisCtxCancel()
	err := c.redisClient.Del(redisCtx, key).Err()
	if err != nil {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Failed to remove layer from cache: %w", err))
	}
	delete(c.registry, key)
	return nil
}

func (c *CacheHelper) ExistsInRegistry(keyElements ...string) bool {
	key := c.KeyFrom(keyElements...)
	if _, ok := c.registry[key]; ok {
		return true
	}
	return false
}

func (c *CacheHelper) AddToRegistry(dataPuller func() ([]model.CacheEntry, error), keyElements ...string) error {
	key := c.KeyFrom(keyElements...)
	if _, ok := c.registry[key]; ok {
		return NewAnError(http.StatusInternalServerError, fmt.Errorf("Cache controller for %s already registered", key))
	}
	c.registry[key] = dataPuller
	return nil
}

func (c *CacheHelper) KeyFrom(keyElements ...string) string {
	return c.keyPrefix + "_" + strings.Join(keyElements, "_")
}

func (c *CacheHelper) bgSync() {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
		}
	}()

	for {
		select {
		case <-time.After(CacheRefreshInterval):
			err := c.CheckVersionAndSyncData()
			if err != nil {
				logging.GetLogger().Error().Err(err).Str("name", c.keyPrefix).Msg("Failed pagination cache sync")
			}
		}
	}
}

func (c *CacheHelper) CheckVersionAndSyncData() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ok, err := c.CheckVersion()
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("checkVersion error: %w", err))
	}
	if ok {
		return nil
	}

	for redisKey, dataPuller := range c.registry {
		ids, err := dataPuller()
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("GetMongo and flush to redis error: %w", err))
		}
		err = c.flushToRedis(redisKey, ids)
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("redis flush error: %w", err))
		}
	}
	maxEntryTimestamp, err := c.getNewestEntryTimestamp()
	if err != nil {
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("getNewestEntryTimestamp error:%w", err))
	}

	err = c.SetCachedTimestamp(maxEntryTimestamp)
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("SetCachedTimestamp error: %w", err))
	}

	return nil
}

func (c *CacheHelper) SetCachedTimestamp(maxEntryTimestamp int64) error {
	if maxEntryTimestamp == -1 {
		return nil
	}

	redisCtx, redisCtxCancel := context.WithTimeout(c.ctx, RedisTimeout)
	defer redisCtxCancel()

	err := c.redisClient.Set(redisCtx, c.redisNewestEntryTimestampKey, strconv.FormatInt(maxEntryTimestamp, 10), 0).Err()
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Set redis maxEntryTimestamp error: %w", err))
	}
	return nil
}

func (c *CacheHelper) Lock() {
	c.mu.Lock()
}

func (c *CacheHelper) Unlock() {
	c.mu.Unlock()
}

func (c *CacheHelper) CheckVersion() (bool, error) {

	newestEntryTimestamp, err := c.getNewestEntryTimestamp()
	if err != nil {
		return false, NewMongoError(http.StatusInternalServerError, fmt.Errorf("getMongoMaxThresholdVal error: %w ", err))
	}
	cachedTimestamp, err := c.GetCachedTimestamp()
	if err != nil {
		return false, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("getMongoMaxThresholdVal error: %w ", err))
	}
	if newestEntryTimestamp != -1 && cachedTimestamp != -1 && newestEntryTimestamp == cachedTimestamp {
		return true, nil
	}
	return false, nil
}

func (c *CacheHelper) GetCachedTimestamp() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, RedisTimeout)
	defer cancel()

	val, err := c.redisClient.Get(ctx, c.redisNewestEntryTimestampKey).Result()
	if err != nil {
		if err == redis.Nil {
			// key not found
			return -1, nil
		}
		return -1, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Get redis MaxThresholdVal error: %w", err))
	}

	val64, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return -1, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Redis ParseInt [val:%s] error: %w", val, err))
	}

	return val64, nil
}

func (c *CacheHelper) reverse(s []model.CacheEntry) []model.CacheEntry {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func (c *CacheHelper) GetItems(offset int64, limit int64, sortOrder string, keyElements ...string) ([]model.CacheEntry, int64, error) {
	key := c.KeyFrom(keyElements...)
	c.mu.Lock()
	defer c.mu.Unlock()

	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}

	ctx, cancel := context.WithTimeout(c.ctx, RedisTimeout)
	defer cancel()
	var result []string

	//gen len
	length, err := c.redisClient.LLen(ctx, key).Result()
	ids := make([]model.CacheEntry, 0)
	if err != nil {
		return ids, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("get length redis %s cache error: %w", key, err))
	}
	start := offset

	end := offset + limit - 1
	if end > length-1 {
		end = length - 1
	}
	if sortOrder == "desc" {
		start = length - offset - limit
		if start < 0 {
			start = 0
		}
		end = length - offset - 1
	}

	result, err = c.redisClient.LRange(c.ctx, key, start, end).Result()
	if err == redis.Nil {
		return ids, 0, nil
	}
	if err != nil {
		return ids, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("get redis %s cache error: %w", key, err))
	}

	for _, v := range result {
		r := model.CacheEntry{}
		err := json.Unmarshal([]byte(v), &r)
		if err != nil {
			return ids, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("json  unmarshal error:%w", err))
		}
		ids = append(ids, r)
	}
	if sortOrder != "asc" {
		return c.reverse(ids), length, nil
	}
	return ids, length, nil
}

func (c *CacheHelper) flushToRedis(key string, idsList []model.CacheEntry) error {
	ctx, cancel := context.WithTimeout(c.ctx, RedisTimeout)
	defer cancel()
	err := c.redisClient.LTrim(ctx, key, 1, 0).Err()
	if err != nil {
		return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("redis %s trim error: %w", key, err))
	}
	for _, id := range idsList {
		data, err := json.Marshal(id)
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("json marshal error: %w", err))
		}
		err = c.redisClient.RPush(ctx, key, data).Err()
		if err != nil {
			return NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Redis set %s data error %w", key, err))
		}
	}

	return nil
}
