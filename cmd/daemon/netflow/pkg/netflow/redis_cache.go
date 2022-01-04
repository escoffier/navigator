package netflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
)

func RedisInit() (*redis.Client, error) {
	var redisAddr string
	clusterType := os.Getenv("IS_MAIN_CLUSTER")
	redisPwd := os.Getenv("REDIS_PASSWORD")
	if clusterType == "true" {
		redisAddr = os.Getenv("REDIS_CLUSTER_URL")
	} else {
		redisAddr = os.Getenv("REDIS_SINGLE_URL")
	}
	if redisAddr == "" || redisPwd == "" {
		return nil, errors.Errorf("get redis address or redis password is nil")
	}
	//print debug log
	//logging.GetLogger().Info().Msgf("redis addr : %v, redis password : %v, cluster type : %v", redisAddr, redisPwd, clusterType)
	//connect redis
	var err error
	var redisClient *redis.Client
	if clusterType == "true" {
		//redisPwd = "Redis12345"
		//redisAddr = "tensorsec-redis-ha-announce-0:26379,tensorsec-redis-ha-announce-1:26379,tensorsec-redis-ha-announce-2:26379"
		sa := strings.Split(redisAddr, ",")
		redisClient, err = redistools.NewTensorRedisClient(&redis.FailoverOptions{
			MasterName:    "mymaster",
			SentinelAddrs: sa,
			Password:      redisPwd,
			DB:            0,
		})

		if err != nil {
			return nil, errors.Errorf("connect redis failed, %v", err)
		}
	} else {
		redisClient, err = ConnectRedis(redisAddr, redisPwd)
		if err != nil {
			return nil, errors.Errorf("connect redis failed, %v", err)
		}
	}

	logging.GetLogger().Info().Msgf("connect redis success!")
	return redisClient, nil
}

func ConnectRedis(addr, pwd string) (*redis.Client, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: pwd,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		return nil, errors.Errorf("redis ping error, %v", err)
	}

	return redisClient, nil
}

func redisGet(ctx context.Context, redisClient *redis.Client, key string) (*model.TensorNetworkFlow, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()

	ret, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		return nil, errors.Errorf("get %v failed, %v", key, err)
	}

	var netflow model.TensorNetworkFlow
	err = json.Unmarshal([]byte(ret), &netflow)
	if err != nil {
		return nil, errors.Errorf("json unmarshal failed, key : %v, %v", key, err)
	}

	return &netflow, nil
}

func redisSetIfNotExists(ctx context.Context, redisClient *redis.Client, key string, netflow *model.TensorNetworkFlow) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()

	value, err := json.Marshal(netflow)
	if err != nil {
		return false, errors.Errorf("json marshal failed, %v", err)
	}
	res := redisClient.SetNX(ctx, key, value, 60*time.Second)
	return res.Result()
}

func redisSaveOrUpdate(ctx context.Context, redisClient *redis.Client, addrType int, netflow *model.TensorNetworkFlow) (bool, error) {
	if len(netflow.SrcProcess) > 0 && len(netflow.DstProcess) > 0 {
		return true, nil
	}

	key := fmt.Sprintf("%v", netflow.AssocKey)

	newValueSetted, err := redisSetIfNotExists(ctx, redisClient, key, netflow)
	if err != nil {
		return false, errors.Errorf("setnx redis failed for key %s. value: %+v", key, netflow)
	}

	if newValueSetted {
		return false, nil
	}
	net, err := redisGet(ctx, redisClient, key)
	if err != nil {
		return false, errors.Errorf("get netflow info from redis failed, %v", err)
	}

	switch addrType {
	case daemon.SND_ADDR:
		netflow.DstContainerName = net.DstContainerName
		netflow.DstProcess = net.DstProcess
	case daemon.RCV_ADDR:
		netflow.SrcContainerName = net.SrcContainerName
		netflow.SrcProcess = net.SrcProcess
	}

	return true, nil
}
