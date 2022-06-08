package dp

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type Reporter struct {
	uuidGenerator *uuid.Generator
	cli           pb.EventsCenterCollectionServiceClient
}

type EventArg struct {
	Cluster       string
	Namespace     string
	PodName       string
	PodUID        string
	ContainerID   string
	ContainerName string
	FilePath      string
	Syscall       string
	Action        string
	crc32Expected string
	crc32Actual   string
	ImageRepoTags string
	ImageDigest   string
	reason        string
	reasonCN      string
}

func sendEventByKafka(ctx context.Context, mq mq.Writer, eventArgs *EventArg, req *pb.SendNotificationReq) {
	if req == nil {
		logging.Get().Error().Msg("sendEventByKafka: req is nil")
		return
	}

	logging.Get().Info().Msgf("sendEventByKafka: %v", req)

	ebyptes, err := proto.Marshal(req)
	if err != nil {
		logging.Get().Error().Err(err).Msg("eventArg marshal fail")
		return
	}

	msgKey, ok := rtdetect.GetKeyOfSignal(eventArgs.Cluster)
	if !ok {
		msgKey = []byte(strconv.FormatInt(rand.Int63(), 10))
	}
	err = mq.Write(ctx, model.MQTopicPalacePodContainerEvents, kafka.Message{
		Topic: model.MQTopicPalacePodContainerEvents,
		Key:   msgKey,
		Value: ebyptes,
		Headers: []kafka.Header{{
			Key:   model.MHeaderKeyEventType,
			Value: []byte(model.MEventTypeHolmes),
		}},
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("sendEventByKafka fail")
	}

}

func generateEvent(uuid uint64, arg *EventArg, category, name model.AlertKind, npw *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo) *pb.SendNotificationReq {
	podInfo, err := npw.GetPodByUID(arg.PodUID)
	if err != nil {
		logging.Get().Error().Err(err).Msg("get pod info fail")
		return nil
	}
	logging.Get().Debug().Msgf("generateEvent: %v", podInfo)

	containerName := ""

	for _, cName := range podInfo.Containers {
		if strings.Contains(arg.ContainerName, cName) {
			containerName = cName
			break
		}
	}

	resKeyType, ok := podResInfo.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.Get().Error().Msgf("get pod res info fail, pod:%s/%s", podInfo.Namespace, podInfo.Name)
		return nil
	}

	logging.Get().Debug().Msgf("generateEvent: %v", resKeyType)

	actionZh := ""
	if arg.Action == resultBlock {
		actionZh = "阻断"
	} else {
		actionZh = "告警"
	}

	expectStr := ""
	expectStrZh := ""
	if arg.crc32Expected != "" {
		expectStr = arg.crc32Expected
		expectStrZh = arg.crc32Expected
	} else {
		expectStr = "none"
		expectStrZh = "无"
	}

	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   model.AlertModuleContainerSecurity,
			Category: string(category),
			Name:     string(name),
		},
		NotifyContext: &pb.Context{
			Cluster:   podInfo.ClusterKey,
			PodName:   podInfo.Name,
			PodUID:    arg.PodUID,
			Namespace: podInfo.Namespace,
			ServiceID: fmt.Sprintf("%s/%s", resKeyType.Kind, resKeyType.Name),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "规则类型", Value: string(category)},
						"zh": {Key: "规则类型", Value: "偏移防御"},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: arg.ContainerID},
						"zh": {Key: "容器id", Value: arg.ContainerID},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerName", Value: containerName},
						"zh": {Key: "容器名称", Value: containerName},
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
						"en": {Key: "crc32Expected", Value: expectStr},
						"zh": {Key: "预期的校验值", Value: expectStrZh},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "crc32Actual", Value: arg.crc32Actual},
						"zh": {Key: "实际的校验值", Value: arg.crc32Actual},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "action", Value: arg.Action},
						"zh": {Key: "行为", Value: actionZh},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "filePath", Value: arg.FilePath},
						"zh": {Key: "文件路径", Value: arg.FilePath},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "Cluster", Value: podInfo.ClusterKey},
						"zh": {Key: "所属集群", Value: podInfo.ClusterKey},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "NameSpace", Value: podInfo.Namespace},
						"zh": {Key: "命名空间", Value: podInfo.Namespace},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "PodName", Value: podInfo.Name},
						"zh": {Key: "Pod名称", Value: podInfo.Name},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "ImageRepoTags", Value: arg.ImageRepoTags},
						"zh": {Key: "关联镜像", Value: arg.ImageRepoTags},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "reason", Value: arg.reason},
						"zh": {Key: "原因", Value: arg.reasonCN},
					},
				},
			},
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuid,
	}

	return req
}

func NewClientFromEnv() (pb.EventsCenterCollectionServiceClient, error) {
	c, err := credentials.NewClientTLSFromFile(
		GetEnvWithDefault("GRPC_CERT_PATH", "/auth/server/tls.crt"),
		GetEnvWithDefault("GRPC_CERT_SERVER_NAME", "eventcenter"))
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(
		GetEnvWithDefault("EVENT_GRPC_URL", "eventcenter:9090"),
		grpc.WithTransportCredentials(c))
	if err != nil {
		return nil, err
	}
	return pb.NewEventsCenterCollectionServiceClient(conn), nil
}

func GetEnvWithDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func notifyEventWithRetry(req *pb.SendNotificationReq) {

	cli, err := NewClientFromEnv()
	if err != nil {
		logging.Get().Error().Err(err).Msg("eventcenter_helper.NewClientFromEnv fail")
	}

	logging.Get().Debug().Msgf("notifyEventWithRetry: %v", req)
	if req == nil {
		return
	}

	var retryDelay = time.Millisecond * 200
	var maxRetryDelay = time.Second * 3
	var maxRetryCount = 10
	var retryCount int
	for {
		err = NotifyEvent(cli, req)
		if err == nil {
			break
		}

		logging.Get().Error().Str("notifyEvent fail, err:", err.Error())
		if retryCount > maxRetryCount {
			logging.Get().Error().Int("notifyEvent exceed maxRetryCount, retryCount:%d", retryCount)
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
