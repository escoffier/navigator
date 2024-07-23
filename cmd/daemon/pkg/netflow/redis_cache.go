package netflow

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/cache"
	"time"

	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/model"
)

type RedisClient struct {
	redisClient *redis.Client
}

func NewRedisClient() (*RedisClient, error) {
	redisClient, err := cache.NewRedis()
	if err != nil {
		return nil, errors.Errorf("redis init failed, %v", err)
	}

	rc := &RedisClient{
		redisClient: redisClient,
	}

	return rc, nil
}

func (rc RedisClient) IsExists(key string) (bool, error) {
	if rc.redisClient == nil {
		return false, errors.Errorf("argument point is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	ret, err := rc.redisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, errors.Errorf("get %v failed, %v", key, err)
	}

	if ret == 1 {
		return true, nil
	}

	return false, errors.Errorf("query result is : %+v", ret)
}

func (rc RedisClient) RedisSetKey(key, value string, timeout int64) bool {
	if rc.redisClient == nil || len(key) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	res := rc.redisClient.SetNX(ctx, key, value, time.Second*time.Duration(timeout))
	ok, err := res.Result()
	if err != nil {
		return false
	}
	return ok
}

func (rc RedisClient) RedisDelKey(key string) (bool, error) {
	if rc.redisClient == nil || len(key) == 0 {
		return false, errors.Errorf("argument point is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	_, err := rc.redisClient.Del(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis del key : %+v failed, %+v", key, err)
	}

	return true, nil
}

func (rc RedisClient) RedisGetValue(key string) (string, error) {
	if rc.redisClient == nil {
		return "", errors.Errorf("argument point is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	ret, err := rc.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", errors.Errorf("get %v failed, %v", key, err)
	}

	return ret, nil
}

func (rc RedisClient) RedisGet(key string) (*model.TensorNetworkFlow, error) {
	if rc.redisClient == nil {
		return nil, errors.Errorf("argument point is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	ret, err := rc.redisClient.Get(ctx, key).Result()
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

func (rc RedisClient) RedisSetIfNotExists(key string, netflow *model.TensorNetworkFlow) (bool, error) {
	if rc.redisClient == nil || netflow == nil {
		return false, errors.Errorf("argument point is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	value, err := json.Marshal(netflow)
	if err != nil {
		return false, errors.Errorf("json marshal failed, %v", err)
	}

	res := rc.redisClient.SetNX(ctx, key, value, 60*time.Second)

	return res.Result()
}

func (rc *RedisClient) RedisSaveOrUpdate(addrType int, netflow *model.TensorNetworkFlow) (bool, error) {
	if rc.redisClient == nil || netflow == nil {
		return false, errors.Errorf("argument point is nil")
	}

	if len(netflow.SrcPodName) > 0 && len(netflow.DstPodName) > 0 {
		return true, nil
	}

	key := fmt.Sprintf("%v", netflow.AssocKey)

	exist, err := rc.RedisSetIfNotExists(key, netflow)
	if err != nil {
		return false, errors.Errorf("setnx redis failed for key %s, err : %+v. value: %+v", key, err, *netflow)
	}

	if exist {
		return false, nil
	}

	net, err := rc.RedisGet(key)
	if err != nil {
		return false, errors.Errorf("get netflow info from redis failed, %v", err)
	}

	switch addrType {
	case daemon.SND_ADDR:
		netflow.DstContainerID = net.DstContainerID
		netflow.DstContainerName = net.DstContainerName
		netflow.DstProcess = net.DstProcess
		netflow.DstPid = net.DstPid
		netflow.DstOwnerName = net.DstOwnerName
		netflow.DstPodName = net.DstPodName
		netflow.DstPodUid = net.DstPodUid
		netflow.DstNamespace = net.DstNamespace
		netflow.DstKind = net.DstKind
		netflow.DstCluster = net.DstCluster
	case daemon.RCV_ADDR:
		netflow.SrcContainerID = net.SrcContainerID
		netflow.SrcContainerName = net.SrcContainerName
		netflow.SrcProcess = net.SrcProcess
		netflow.SrcPid = net.SrcPid
		netflow.SrcOwnerName = net.SrcOwnerName
		netflow.SrcPodName = net.SrcPodName
		netflow.SrcPodUid = net.SrcPodUid
		netflow.SrcNamespace = net.SrcNamespace
		netflow.SrcKind = net.SrcKind
		netflow.SrcCluster = net.SrcCluster
	case daemon.UNKNOWN_ADDR:
		if len(net.SrcPodName) != 0 {
			netflow.SrcContainerID = net.SrcContainerID
			netflow.SrcContainerName = net.SrcContainerName
			netflow.SrcProcess = net.SrcProcess
			netflow.SrcPid = net.SrcPid
			netflow.SrcOwnerName = net.SrcOwnerName
			netflow.SrcPodName = net.SrcPodName
			netflow.SrcPodUid = net.SrcPodUid
			netflow.SrcNamespace = net.SrcNamespace
			netflow.SrcKind = net.SrcKind
			netflow.SrcCluster = net.SrcCluster
		} else if len(net.DstPodName) != 0 {
			netflow.DstContainerID = net.DstContainerID
			netflow.DstContainerName = net.DstContainerName
			netflow.DstProcess = net.DstProcess
			netflow.DstPid = net.DstPid
			netflow.DstOwnerName = net.DstOwnerName
			netflow.DstPodName = net.DstPodName
			netflow.DstPodUid = net.DstPodUid
			netflow.DstNamespace = net.DstNamespace
			netflow.DstKind = net.DstKind
			netflow.DstCluster = net.DstCluster
		}
	}

	if len(netflow.SrcPodName) == 0 && len(netflow.DstPodName) == 0 {
		logging.GetLogger().Warn().Msgf("not find pod info, addr type : %v, %+v", addrType, *netflow)
		return false, nil
	}

	return true, nil
}
