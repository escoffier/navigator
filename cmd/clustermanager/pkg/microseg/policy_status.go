package microseg

import (
	"context"
	"encoding/json"
	"strconv"

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
	// idStr, found := strings.CutPrefix(policyStatus.Policy, "policy-")
	// if found {
	name := policyStatus.Policy
	// result := strings.SplitN(name, "-", 2)
	// if len(result) < 2 {
	// 	logging.Get().Error().Msgf("invalid policy name %s", name)
	// 	return nil
	// }
	// idStr := result[0]

	id, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		log.Err(err).Msgf("invalid policy name %s", name)
		return nil
	}
	err = w.db.Get().WithContext(ctx).Table("ivan_microseg_rules").Where("id = ? and enable = true", id).Updates(map[string]interface{}{
		"status":        policyStatus.Status,
		"status_detail": policyStatus.Detail,
	}).Error
	if err != nil {
		log.Err(err).Msgf("update policy (%s) status", name)
		return nil
	}
	// }
	return nil
}
