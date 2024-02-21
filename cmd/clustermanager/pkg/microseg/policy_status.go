package microseg

import (
	"context"
	"encoding/json"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/mq"
)

type PolicyStatusWatcher struct {
	consumer mq.Reader
	topic    string
	groupID  string
	db       *databases.RDBInstance
}

func NewWatcher(reader mq.Reader, topic, groupID string, rdb *databases.RDBInstance) *PolicyStatusWatcher {
	return &PolicyStatusWatcher{
		consumer: reader,
		topic:    topic,
		groupID:  groupID,
		db:       rdb,
	}
}

func (w *PolicyStatusWatcher) Run(stopCh <-chan struct{}) {
	w.consumer.Subscribe(w.topic, w.groupID, w.process)
	<-stopCh
}

func (w *PolicyStatusWatcher) process(ctx context.Context, message kafka.Message) error {
	policyStatus := &model.PolicyStatus{}
	err := json.Unmarshal(message.Value, policyStatus)
	if err != nil {
		return err
	}
	logging.Get().Debug().Msg(string(message.Value))
	return nil
}
