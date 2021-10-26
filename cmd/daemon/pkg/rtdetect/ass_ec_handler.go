package rtdetect

import (
	"context"
	"strconv"
	"time"

	"github.com/avast/retry-go"
	"github.com/golang/protobuf/proto"
	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	subjectOfAssocationEvents = "tensorsec_associated_events"
)

type AssociatedEventsHandler struct {
	stanConn stan.Conn
}

func NewAssociatedEventsHandler(stanConn stan.Conn) *AssociatedEventsHandler {
	return &AssociatedEventsHandler{stanConn}
}

func (ih *AssociatedEventsHandler) Handle(ctx context.Context, events []eventItem) error {
	tctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	for _, e := range events {
		e.data.OutputFields[rtdetect.KeyUuid] = strconv.FormatUint(e.uuid, 10)
		e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
		ebytes, err := proto.Marshal(e.data)
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
			continue
		}

		err = util.RetryWithBackoff(tctx, func() error {
			return ih.stanConn.Publish(subjectOfAssocationEvents, ebytes)
		}, retry.Attempts(2))
		if err != nil {
			logging.GetLogger().WithContext(ctx).Errorf(err, "publish immune events error. data: %s", string(ebytes))
		}
	}

	return nil
}
func (ih *AssociatedEventsHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := filteredOutRulesSet[event.data.Rule]
	return !exist
}
