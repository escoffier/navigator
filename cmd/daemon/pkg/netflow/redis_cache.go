package netflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func redisGet(redisClient *redis.Client, key string) (*model.TensorNetworkFlow, error) {
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

func redisSetIfNotExists(redisClient *redis.Client, key string, netflow *model.TensorNetworkFlow) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	value, err := json.Marshal(netflow)
	if err != nil {
		return false, errors.Errorf("json marshal failed, %v", err)
	}
	res := redisClient.SetNX(ctx, key, value, 60*time.Second)
	return res.Result()
}

func redisSaveOrUpdate(redisClient *redis.Client, addrType int, netflow *model.TensorNetworkFlow) (bool, error) {
	if len(netflow.SrcPodName) > 0 && len(netflow.DstPodName) > 0 {
		return true, nil
	}

	key := fmt.Sprintf("%v", netflow.AssocKey)

	newValueSetted, err := redisSetIfNotExists(redisClient, key, netflow)
	if err != nil {
		return false, errors.Errorf("setnx redis failed for key %s. value: %+v", key, *netflow)
	}

	if newValueSetted {
		return false, nil
	}

	net, err := redisGet(redisClient, key)
	if err != nil {
		return false, errors.Errorf("get netflow info from redis failed, %v", err)
	}

	switch addrType {
	case daemon.SND_ADDR:
		netflow.DstContainerName = net.DstContainerName
		netflow.DstProcess = net.DstProcess
		netflow.DstPid = net.DstPid
		netflow.DstOwnerName = net.DstOwnerName
		netflow.DstPodName = net.DstPodName
		netflow.DstNamespace = net.DstNamespace
		netflow.DstKind = net.DstKind
	case daemon.RCV_ADDR:
		netflow.SrcContainerName = net.SrcContainerName
		netflow.SrcProcess = net.SrcProcess
		netflow.SrcPid = net.SrcPid
		netflow.SrcOwnerName = net.SrcOwnerName
		netflow.SrcPodName = net.SrcPodName
		netflow.SrcNamespace = net.SrcNamespace
		netflow.SrcKind = net.SrcKind
	}

	if len(netflow.SrcProcess) == 0 || len(netflow.DstProcess) == 0 {
		return false, errors.Errorf("net data is nil, addr type : %v, %+v", addrType, *netflow)
	}

	return true, nil
}
