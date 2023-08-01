package imagesecReport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanInstanceReport struct {
	ScanInstanceDal imagesecStore.ScanInstanceDal
	mqReader        mq.Reader
	MqWriter        mq.Writer
}

func NewScanInstanceReport(
	ScanInstanceDal imagesecStore.ScanInstanceDal,
	mqReader mq.Reader,
	mqWriter mq.Writer,
) *ScanInstanceReport {
	return &ScanInstanceReport{
		ScanInstanceDal: ScanInstanceDal,
		mqReader:        mqReader,
		MqWriter:        mqWriter,
	}
}

func (s *ScanInstanceReport) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("ScanInstanceReport")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport finished")
		}
	}()

	logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport receive kafka started end")

	return nil
}

func (s *ScanInstanceReport) ReceiveAssetReport(ctx context.Context, msg kafka.Message) error {

	var imageReport imagesecModel.ScannerInstanceInfo
	err := json.Unmarshal(msg.Value, &imageReport)

	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport failed to unmarshal ScannerInstanceInfo msg")
		return err
	}

	logging.Get().Debug().Str("module", "KafkaReport").
		Interface("imageReport", imageReport).
		Msg("receive scan instance report")

	_, err = s.ScanInstanceDal.CreateAndReplace(ctx, imageReport)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport CreateAndReplace")
	}
	return nil
}

func (s *ScanInstanceReport) handleMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(model.ScanInstanceTopic, model.ScanInstanceGroup, s.ReceiveAssetReport)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport failed to sub message queue")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport sub message queue ok")
	<-stopCh
	logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport sub message queue end")

	return fmt.Errorf("ScanInstanceReport quit message handler")
}

func (s *ScanInstanceReport) ReportScanInstance(ctx context.Context) error {
	// 执行上报scanner的信息
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msg("ScanInstanceReport recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()

		for {
			scannerVersion := os.Getenv("SOFT_VERSION")
			if global.ScannerInstance == "" {
				logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport global ScannerInstance is empty")
				continue
			}
			info := imagesecModel.ScannerInstanceInfo{
				ClusterKey:      global.ClusterKey,
				ClusterName:     global.ClusterName,
				ScannerPodID:    global.ScannerPodID,
				ScannerVersion:  scannerVersion,
				ScannerInstance: global.ScannerInstance,
			}
			_ = s.sendToKafka(ctx, info)

			<-ticker.C
		}
	}()

	return nil
}

func (s *ScanInstanceReport) sendToKafka(ctx context.Context, report imagesecModel.ScannerInstanceInfo) error {

	bys, err := json.Marshal(report)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport Marshal")
		return err
	}
	msg := kafka.Message{
		Topic: model.ScanInstanceTopic,
		Key:   []byte(model.ScanInstanceKey),
		Value: bys,
	}

	if err := s.MqWriter.Write(ctx, msg.Topic, msg); err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("ScanInstanceReport SendToMq")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Msg("ScanInstanceReport send kafka")
	return nil
}
