package microseg

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

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
	logging.Get().Info().Msgf("policy status %s", string(message.Value))
	idStr, found := strings.CutPrefix(policyStatus.Policy, "policy-")
	if found {
		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			log.Err(err).Msgf("invalid policy name %s", idStr)
			return nil
		}
		err = w.db.Get().WithContext(ctx).Table("ivan_microseg_rules").Where("id = ?", id).Update("status", policyStatus.Status).Error
		if err != nil {
			log.Err(err).Msgf("update policy (%s) status", idStr)
			return nil
		}
	}
	return nil
}
