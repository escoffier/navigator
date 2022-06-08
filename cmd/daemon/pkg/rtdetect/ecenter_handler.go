package rtdetect

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/proto"
)

var (
	filteredOutRulesSet = map[string]struct{}{
		"File Integrity Management":          {},
		"Command whitelist":                  {},
		"Seccomp":                            {},
		"Falco internal: syscall event drop": {},
	}
)

type EventsOutputHandler struct {
	myNodeName string

	mqWriter      mq.Writer
	containerInfo nodeinfo.ContainerInfoManager
	podResInfo    *nodeinfo.PodResInfo
}

func NewEventsOutputHandler(myNodeName string, mqWriter mq.Writer, containerInfo nodeinfo.ContainerInfoManager, podResInfo *nodeinfo.PodResInfo) *EventsOutputHandler {
	return &EventsOutputHandler{
		myNodeName:    myNodeName,
		mqWriter:      mqWriter,
		containerInfo: containerInfo,
		podResInfo:    podResInfo,
	}
}

func (ec *EventsOutputHandler) getOwnerInfo(data *outputs.Response) (*nodeinfo.Resource, string, bool) {
	podName, exist := data.OutputFields[rtdetect.FieldK8sPodName]
	if !exist {
		return nil, "", false
	}
	namespace, exist := data.OutputFields[rtdetect.FieldK8sNsName]
	if !exist {
		return nil, "", false
	}

	res, exist := ec.podResInfo.GetPod(namespace, podName)
	if exist && res != nil {
		return res, namespace, true
	}
	return nil, "", false
}
func (ec *EventsOutputHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, e := range events {
		if isEventItemWhitelisted(e.data, ec.containerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
			continue
		}

		e.data.Hostname = ec.myNodeName
		e.data.OutputFields[rtdetect.KeyUuid] = "0"
		e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
		ownerRes, _, exist := ec.getOwnerInfo(e.data)
		if exist {
			e.data.OutputFields[rtdetect.KeyOwnerResName] = ownerRes.Name
			e.data.OutputFields[rtdetect.KeyOwnerResKind] = ownerRes.Kind
		}
		ebytes, err := proto.Marshal(e.data)
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
			continue
		}

		keyBytes, ok := GetKeyOfSignal(e.clusterKey)
		if !ok { // if the key is empty, generate random key to prevent consumer load unbalance
			keyBytes = []byte(strconv.FormatInt(rand.Int63(), 10))
		}

		err = ec.mqWriter.Write(ctx, model.MQTopicPalacePodContainerEvents, kafka.Message{
			Topic: model.MQTopicPalacePodContainerEvents,
			Key:   keyBytes,
			Value: ebytes,
			Headers: []kafka.Header{{
				Key:   model.MHeaderKeyEventType,
				Value: []byte(model.MEventTypeHolmes),
			}},
		})
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "publish pod container events error. data: %s", string(ebytes))
		}
	}

	return nil
}
func (ec *EventsOutputHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
