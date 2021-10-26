package rtdetect

import (
	"context"
	"time"

	"github.com/avast/retry-go"
	"github.com/golang/protobuf/proto"
	"github.com/nats-io/stan.go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	immuneRules = map[string]string{
		"file integrity management": "falco.warning.file_integrity_management",
		"command whitelist":         "falco.warning.command_whitelist",
		"seccomp":                   "falco.warning.seccomp",
	}
)

type ImmuneHandler struct {
	stanConn stan.Conn
}

func NewImmuneHandler(stanConn stan.Conn) *AssociatedEventsHandler {
	return &AssociatedEventsHandler{stanConn}
}
func (ih *ImmuneHandler) Handle(ctx context.Context, events []eventItem) error {
	tctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	for _, e := range events {
		subject, ok := immuneRules[e.data.Rule]
		if ok {
			e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
			ebytes, err := proto.Marshal(e.data)
			if err != nil {
				logging.GetLogger().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
				continue
			}
			err = util.RetryWithBackoff(tctx, func() error {
				return ih.stanConn.Publish(subject, ebytes)
			}, retry.Attempts(3))
			if err != nil {
				logging.GetLogger().WithContext(ctx).Errorf(err, "publish immune events error. data: %s", string(ebytes))
			}
		}
	}

	return nil
}
func (ih *ImmuneHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := immuneRules[event.data.Rule]
	return exist
}
