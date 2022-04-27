package rtdetect

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/proto"
)

const (
	subjectOfAssocationEvents = "ivan_podcontainer_events"
)

type AssociatedEventsHandler struct {
	mqWriter   mq.Writer
	dockerInfo *nodeinfo.DockerInfoManager
}

func NewAssociatedEventsHandler(mqWriter mq.Writer, dockerInfo *nodeinfo.DockerInfoManager) *AssociatedEventsHandler {
	return &AssociatedEventsHandler{
		mqWriter:   mqWriter,
		dockerInfo: dockerInfo,
	}
}

func (ih *AssociatedEventsHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, e := range events {
		if isEventItemWhitelisted(e.data, ih.dockerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
			continue
		}

		e.data.OutputFields[rtdetect.KeyUuid] = strconv.FormatInt(e.uuid, 10)
		e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
		ebytes, err := proto.Marshal(e.data)
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
			continue
		}

		keyBytes, ok := getKeyOfPodContainerEvent(e.clusterKey, e.data)
		if !ok { // if the key is empty, generate random key to prevent consumer load unbalance
			keyBytes = []byte(strconv.FormatInt(rand.Int63n(10000000000), 10))
		}
		err = ih.mqWriter.Write(ctx, subjectOfAssocationEvents, kafka.Message{
			Topic: subjectOfAssocationEvents,
			Key:   keyBytes,
			Value: ebytes,
		})
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "publish pod container events error. data: %s", string(ebytes))
		}
	}

	return nil
}
func (ih *AssociatedEventsHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
