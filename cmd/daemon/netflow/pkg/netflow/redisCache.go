package netflow

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/redistools"
	"os"
	"strings"
	"time"
)

func RedisInit(clusterName string) (*redis.Client, error) {
	redisAddr := os.Getenv("REDIS_ADDR")
	redisPwd := os.Getenv("REDIS_PASSWORD")
	if redisAddr == "" || redisPwd == "" {
		return nil, errors.Errorf("get redis address or redis password is nil")
	}
	//print debug log
	log.Infof("redis addr : %v, redis password : %v, cluster name : %v", redisAddr, redisPwd, clusterName)
	//connect redis
	var err error
	var redisClient *redis.Client
	if clusterName == "default" {
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

	log.Infof("connect redis success!")
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

func RedisGet(redisClient *redis.Client, key string) (*model.TensorNetworkFlow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
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

func RedisSet(redisClient *redis.Client, key string, netflow *model.TensorNetworkFlow) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	value, err := json.Marshal(netflow)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}

	err = redisClient.Set(ctx, key, value, time.Second*60).Err()
	if err != nil {
		return errors.Errorf("set %v failed, %v", key, err)
	}
	return nil
}

func RedisKeyIsExist(redisClient *redis.Client, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	keyNum, err := redisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, errors.Errorf("get %v exists failed, %v", key, err)
	}

	return (keyNum > 0), nil
}

func RedisSaveOrUpdate(redisClient *redis.Client, addrType int, netflow *model.TensorNetworkFlow) (bool, error) {
	if len(netflow.SrcProcess) > 0 && len(netflow.DstProcess) > 0 {
		return true, nil
	}

	key := fmt.Sprintf("%v", netflow.AssocKey)

	ok, err := RedisKeyIsExist(redisClient, key)
	if err != nil {
		return false, errors.Errorf("get redis key is exist failed, %v", err)
	}

	if !ok {
		return false, RedisSet(redisClient, key, netflow)
	}

	net, err := RedisGet(redisClient, key)
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
