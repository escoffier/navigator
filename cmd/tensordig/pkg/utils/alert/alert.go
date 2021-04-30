package alert

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"time"

	log "github.com/sirupsen/logrus"
)

type SeccompEventArg struct {
	Cluster     string
	PodName     string
	PodUID      string
	ContainerID string
	ProfileName string
	Syscall     string
	Phase       string
	Action      string
}

func GenerateSeccompEvent(uuidGenerator *uuid.Generator, arg *SeccompEventArg) *pb.SendNotificationReq {
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   model.AlertModuleContainerSecurity,
			Category: string(model.AlertKindSeccompProfile),
			Name:     "seccompProfile",
		},
		NotifyContext: &pb.Context{
			Cluster: arg.Cluster,
			PodName: arg.PodName,
			PodUID:  arg.PodUID,
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: arg.ContainerID},
						"zh": {Key: "容器id", Value: arg.ContainerID},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "profileName", Value: arg.ProfileName},
						"zh": {Key: "名称", Value: arg.ProfileName},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "syscall", Value: arg.Syscall},
						"zh": {Key: "系统调用", Value: arg.Syscall},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "phase", Value: arg.Phase},
						"zh": {Key: "阶段", Value: arg.Phase},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "action", Value: arg.Action},
						"zh": {Key: "行为", Value: arg.Action},
					},
				},
			},
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
	}

	return req
}

func NotifyEventWithRetry(cli pb.EventsCenterCollectionServiceClient, req *pb.SendNotificationReq) {
	log.Infof("NotifyEventWithRetry req:%s", req)
	var err error
	var retryDelay = time.Millisecond * 200
	var maxRetryDelay = time.Second * 3
	var maxRetryCount = 10
	var retryCount int
	for {
		err = NotifyEvent(cli, req)
		if err == nil {
			break
		}

		log.Errorf("notifyEvent fail, err:%s", err.Error())
		if retryCount > maxRetryCount {
			log.Errorf("notifyEvent exceed maxRetryCount, retryCount:%d", retryCount)
			return
		}

		time.Sleep(retryDelay)
		retryDelay *= 2
		retryCount++
		if retryDelay > maxRetryDelay {
			retryDelay = maxRetryDelay
		}
	}
}

func NotifyEvent(cli pb.EventsCenterCollectionServiceClient, req *pb.SendNotificationReq) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	_, err := cli.SendNotification(ctx, req)
	return err
}
