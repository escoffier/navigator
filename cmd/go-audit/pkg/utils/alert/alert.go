package alert

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/pb"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"

	log "github.com/sirupsen/logrus"
)

type EventArg struct {
	Cluster     string
	PodName     string
	PodUID      string
	ContainerID string
	Filepath    string
	Operation   string
	Syscall     string
	ProfileName string
	Action      string
	Pid         string
}

func GenerateEvent(uuidGenerator *uuid.Generator, arg *EventArg, category model.AlertKind) *pb.SendNotificationReq {
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   model.AlertModuleContainerSecurity,
			Category: string(category),
			Name:     string(category),
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
						"en": {Key: "action", Value: arg.Action},
						"zh": {Key: "行为", Value: arg.Action},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "filePath", Value: arg.Filepath},
						"zh": {Key: "文件路径", Value: arg.Filepath},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: arg.Pid},
						"zh": {Key: "进程号", Value: arg.Pid},
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
