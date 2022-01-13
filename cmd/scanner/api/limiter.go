package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
)

// 常规计数器限流
type TokenLimiter struct {
	redisClient *redis.Client
	key         string // 限流桶的类别
	burst       int64  // 桶大小
}

func RateLimitMiddleware(redisClient *redis.Client, burst int64) gin.HandlerFunc {
	bucket := NewTokenLimiter(redisClient, burst)
	return func(c *gin.Context) {
		key := fmt.Sprintf("scanner-limit-%s:%s", c.Request.Method, c.FullPath())
		allow, err := bucket.Allow(key)
		if err != nil {
			// 内部组件出错，不阻断请求
			logging.GetLogger().Error().Err(err).Msg(bucket.Msg())
		} else if !allow {
			c.PureJSON(http.StatusTooManyRequests, response.HTTPEnvelope{
				ApiVersion: "1.0",
				Error:      &response.HTTPError{Message: bucket.Msg()},
			})
			c.Abort() // 后续操作不再执行
			return
		}
		c.Next()
	}
}

func NewTokenLimiter(redisClient *redis.Client, burst int64) *TokenLimiter {
	tl := &TokenLimiter{
		redisClient: redisClient,
		burst:       burst,
		// key:         fmt.Sprintf("scanner-limit-:%s", key),
	}
	return tl
}

func (tl *TokenLimiter) Msg() string {
	msg := "您使用频率过高，请一分钟后再重试"
	return msg
}

var script = redis.NewScript(`
local exist = redis.call('setnx', KEYS[1], 1) 
   redis.call('expire', KEYS[1], tonumber(ARGV[2]))
  if  exist > 0 then
     return exist
   end
   local current = tonumber(redis.call('get', KEYS[1]))
if (current == nil) then
  local result = redis.call('incr', KEYS[1])
  redis.call('expire', KEYS[1], tonumber(ARGV[2]))
  return result
end
if (current >= tonumber(ARGV[1])) then
  return 0
end
local result = redis.call('incr', KEYS[1])
return result    
`)

func (tl *TokenLimiter) Allow(key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := script.Run(ctx, tl.redisClient, []string{key}, tl.burst, 60).Result()
	if err != nil {
		return true, err
	}
	allow, ok := result.(int64)
	if !ok {
		logging.GetLogger().Error().Err(fmt.Errorf("assertion error")).Interface("result", result).Str("type", fmt.Sprintf("%T", result))
		return true, nil
	}

	return allow > 0, nil
}
