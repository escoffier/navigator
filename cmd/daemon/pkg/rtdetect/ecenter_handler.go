package rtdetect

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
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

const (
	subjectOfPodContainerEvents = "ivan_podcontainer_events"
)

type EventsOutputHandler struct {
	mqWriter   mq.Writer
	dockerInfo *nodeinfo.DockerInfoManager
	podResInfo *nodeinfo.PodResInfo
}

func NewEventsOutputHandler(mqWriter mq.Writer, dockerInfo *nodeinfo.DockerInfoManager, podResInfo *nodeinfo.PodResInfo) *EventsOutputHandler {
	return &EventsOutputHandler{
		mqWriter:   mqWriter,
		dockerInfo: dockerInfo,
		podResInfo: podResInfo,
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
		if isEventItemWhitelisted(e.data, ec.dockerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
			continue
		}

		e.data.OutputFields[rtdetect.KeyUuid] = strconv.FormatInt(e.uuid, 10)
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

		keyBytes, ok := getKeyOfPodContainerEvent(e.clusterKey, e.data)
		if !ok { // if the key is empty, generate random key to prevent consumer load unbalance
			keyBytes = []byte(strconv.FormatInt(rand.Int63n(10000000000), 10))
		}

		err = ec.mqWriter.Write(ctx, subjectOfPodContainerEvents, kafka.Message{
			Topic: subjectOfPodContainerEvents,
			Key:   keyBytes,
			Value: ebytes,
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
