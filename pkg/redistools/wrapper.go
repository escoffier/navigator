package redistools

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func NewTensorRedisClient(opt *redis.FailoverOptions) (*redis.Client, error) {
	redisClient := redis.NewFailoverClient(opt)
	rt, rc := context.WithTimeout(context.Background(), 1*time.Second)
	defer rc()
	res, err := redisClient.Ping(rt).Result()
	if err != nil {
		logging.GetLogger().Error().Msgf("connect redis err:%v", err)
		return nil, fmt.Errorf("connect redis err:%v", err)
	}
	logging.GetLogger().Debug().Msgf("redis client ping %s", res)
	return redisClient, nil
}
