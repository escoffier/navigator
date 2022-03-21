package rtdetect

import (
	"context"
	"strconv"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/mqtools"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/proto"
)

const (
	subjectOfAssocationEvents = "tensorsec_podcontainer_events"
)

type AssociatedEventsHandler struct {
	stanConn   *mqtools.StanConn
	dockerInfo *nodeinfo.DockerInfoManager
}

func NewAssociatedEventsHandler(stanConn *mqtools.StanConn, dockerInfo *nodeinfo.DockerInfoManager) *AssociatedEventsHandler {
	return &AssociatedEventsHandler{
		stanConn:   stanConn,
		dockerInfo: dockerInfo,
	}
}

func (ih *AssociatedEventsHandler) Handle(ctx context.Context, events []eventItem) error {
	tctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	for _, e := range events {
		if isEventItemWhitelisted(e.data, ih.dockerInfo) {
			logging.Get().Info().Msgf("Filter out container creation post events. data: %v.", e.data)
			continue
		}

		stanconn, ok := ih.stanConn.Conn()
		if !ok {
			logging.Get().WithContext(ctx).Errorf(nil, "stan connection not avaiable. data: %+v", e)
			continue
		}
		e.data.OutputFields[rtdetect.KeyUuid] = strconv.FormatInt(e.uuid, 10)
		e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
		ebytes, err := proto.Marshal(e.data)
		if err != nil {
			logging.Get().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
			continue
		}

		err = util.RetryWithBackoff(tctx, func() error {
			return stanconn.Publish(subjectOfAssocationEvents, ebytes)
		}, retry.Attempts(2))
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
