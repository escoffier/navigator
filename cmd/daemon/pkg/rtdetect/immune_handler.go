package rtdetect

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"google.golang.org/protobuf/proto"
)

var (
	immuneRules = map[string]string{
		"File Integrity Management": "falco.warning.file_integrity_management",
		"Command whitelist":         "falco.warning.command_whitelist",
		"Seccomp":                   "falco.warning.seccomp",
	}
)

// Deprecated
type ImmuneHandler struct {
	mqWriter mq.Writer
}

func NewImmuneHandler(mqWriter mq.Writer) *ImmuneHandler {
	return &ImmuneHandler{
		mqWriter: mqWriter,
	}
}
func (ih *ImmuneHandler) Handle(ctx context.Context, events []eventItem) error {
	for _, e := range events {
		subject, ok := immuneRules[e.data.Rule]
		if ok {
			e.data.OutputFields[rtdetect.KeyClusterKey] = e.clusterKey
			ebytes, err := proto.Marshal(e.data)
			if err != nil {
				logging.Get().WithContext(ctx).Errorf(err, "failed to marshal data: %v", e)
				continue
			}

			keyBytes, ok := GetKeyOfSignal(e.clusterKey)
			if !ok { // if the key is empty, generate random key to prevent consumer load unbalance
				keyBytes = []byte(strconv.FormatInt(rand.Int63n(10000000000), 10))
			}

			err = ih.mqWriter.Write(ctx, subject, kafka.Message{
				Topic: model.MQTopicPalacePodContainerEvents,
				Key:   keyBytes,
				Value: ebytes,
			})
			if err != nil {
				logging.Get().WithContext(ctx).Errorf(err, "publish immune events error. data: %s", string(ebytes))
			}
		}
	}

	return nil
}
func (ih *ImmuneHandler) CheckTarget(ctx context.Context, event eventItem) bool {
	_, exist := immuneRules[event.data.Rule]
	return exist
}
