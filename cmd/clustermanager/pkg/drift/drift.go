package drift

import (
	"context"
	"fmt"
	"time"

	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

type DriftSupportWatcher struct {
	rdb      *databases.RDBInstance
	mqReader mq.Reader
	topic    string
	groupID  string
}

func (dsw *DriftSupportWatcher) handleDriftSupportEvent(ctx context.Context, m kafka.Message) error {
	var data model.DriftSupportInfo
	err := json.Unmarshal(m.Value, &data)
	if err != nil {
		logging.Get().Err(err).Msg("json decode fail")
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	logging.Get().Info().Str("receive msg:", fmt.Sprintf("%+v", data)).Msg("handleDriftSupportEvent")
	err = updateReasonSupportInfo(ctx, dsw.rdb, data)
	if err != nil {
		logging.Get().Err(err).Msg("update fail")
	}
	return err
}

func NewDriftSupport(rdb *databases.RDBInstance,
	mqReader mq.Reader,
	topic, groupID string) *DriftSupportWatcher {
	return &DriftSupportWatcher{
		rdb:      rdb,
		mqReader: mqReader,
		topic:    topic,
		groupID:  groupID,
	}
}

func (dsw *DriftSupportWatcher) Start(stopCh <-chan struct{}) {
	logging.Get().Info().Msg("drift support watcher start")
	err := dsw.mqReader.Subscribe(
		dsw.topic,
		dsw.groupID,
		dsw.handleDriftSupportEvent,
	)
	if err != nil {
		logging.Get().Err(err).Msg("subscribe error")
	}
	<-stopCh
}

func updateReasonSupportInfo(ctx context.Context, db *databases.RDBInstance, data model.DriftSupportInfo) error {
	if data.ScannerStatus > 0 {
		return dal.UpdateResourceScannerStatus(ctx, db.Get(), data)
	}
	time.Sleep(time.Second * 3)
	return dal.UpdateResourceSupportInfo(ctx, db.Get(), data)
}
