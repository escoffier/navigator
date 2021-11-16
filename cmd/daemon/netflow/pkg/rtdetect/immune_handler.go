package rtdetect

import (
	"context"
	"time"

	"github.com/avast/retry-go"
	"github.com/golang/protobuf/proto"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/mqtools"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	immuneRules = map[string]string{
		"File Integrity Management": "falco.warning.file_integrity_management",
		"Command whitelist":         "falco.warning.command_whitelist",
		"Seccomp":                   "falco.warning.seccomp",
	}
)

type ImmuneHandler struct {
	stanConn *mqtools.StanConn
}

func NewImmuneHandler(stanConn *mqtools.StanConn) *ImmuneHandler {
	return &ImmuneHandler{
		stanConn: stanConn,
	}
}
func (ih *ImmuneHandler) Handle(ctx context.Context, events []eventItem) error {
	tctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	for _, e := range events {
		subject, ok := immuneRules[e.data.Rule]
		if ok {
			stanconn, ok := ih.stanConn.Conn()
			if !ok {
				logging.GetLogger().WithContext(ctx).Errorf(nil, "stan connection not avaiable. data: %+v", e)
				continue
			}
			e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
			ebytes, err := proto.Marshal(e.data)
			if err != nil {
				logging.GetLogger().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
				continue
			}

			err = util.RetryWithBackoff(tctx, func() error {
				return stanconn.Publish(subject, ebytes)
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
