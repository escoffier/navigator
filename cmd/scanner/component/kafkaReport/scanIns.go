package imagesecReport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanInstanceReport struct {
	ScanInstanceDal imagesecStore.ScanInstanceDal
	mqReader        mq.Reader
	MqWriter        mq.Writer
	Log             *scannerUtils.LogEvent
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
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanInstance"),
			scannerUtils.WithModule(consts.ModuleKafkaReport),
		),
	}
}

func (s *ScanInstanceReport) ReceiveReport(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("scanner in slave cluster,ignore handle kafka msg")
		return nil
	}

	s.Log.Info().Msg("scanner in main cluster,ready to handle kafka msg")

	ch := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Stack().Msg("ScanInstanceReport")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			s.Log.Err(err).Msg("finished")
		}
	}()

	s.Log.Info().Msg("receive kafka started end")

	return nil
}

func (s *ScanInstanceReport) ReceiveAssetReport(ctx context.Context, msg kafka.Message) error {

	var ir imagesecModel.ScannerInstanceInfo
	err := json.Unmarshal(msg.Value, &ir)
	if err != nil {
		s.Log.Err(err).Msg("failed to unmarshal ScannerInstanceInfo msg")
		return nil
	}

	s.Log.Debug().
		Interface("imageReport", ir).
		Msg("receive scan instance report")

	_, err = s.ScanInstanceDal.CreateAndReplace(ctx, ir)
	if err != nil {
		s.Log.Err(err).Msg("CreateAndReplace")
	}
	return nil
}

func (s *ScanInstanceReport) handleMsg(stopCh <-chan struct{}) error {
	err := s.mqReader.Subscribe(consts.ScanInstanceTopic, consts.ScanInstanceGroup, s.ReceiveAssetReport)
	if err != nil {
		s.Log.Err(err).Msg("failed to sub message queue")
		return err
	}
	s.Log.Info().Msg("sub message queue ok")
	<-stopCh
	s.Log.Info().Msg("sub message queue end")

	return fmt.Errorf("quit message handler")
}

type ClusterKey struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Instance string `json:"instance"`
}

func (s *ScanInstanceReport) GetCluster(ctx context.Context) (ClusterKey, error) {

	clusterURL := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterURL == "" {
		return ClusterKey{}, fmt.Errorf("not get CLUSTER_MANAGER_URL")
	}
	url := fmt.Sprintf("%s%s", clusterURL, "/internal/cluster")
	timeOutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(timeOutCtx, http.MethodGet, url, nil)
	if err != nil {
		return ClusterKey{}, err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return ClusterKey{}, err
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return ClusterKey{}, err
	}
	cluster := ClusterKey{}

	if err := json.Unmarshal(content, &cluster); err != nil {
		return cluster, err
	}

	cluster.Instance = fmt.Sprintf("scan-%s", cluster.Key)

	return cluster, err
}

func (s *ScanInstanceReport) ReportScanInstance(ctx context.Context) error {
	// 执行上报scanner的信息
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msg("recover")
			}
		}()
		ticker := time.NewTicker(time.Minute * 5)
		defer ticker.Stop()

		for {
			cluster, err := s.GetCluster(ctx)
			if err != nil {
				s.Log.Err(err).Msg("ReportScanInstance")
				continue
			}

			scannerVersion := os.Getenv("SOFT_VERSION")

			global.ScannerInstance = cluster.Instance

			info := imagesecModel.ScannerInstanceInfo{
				ClusterKey:      cluster.Key,
				ClusterName:     cluster.Name,
				ScannerPodID:    global.ScannerPodID,
				ScannerVersion:  scannerVersion,
				ScannerInstance: cluster.Instance,
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
		s.Log.Err(err).Msg("Marshal")
		return err
	}
	msg := kafka.Message{
		Topic: consts.ScanInstanceTopic,
		Key:   []byte(consts.ScanInstanceKey),
		Value: bys,
	}

	if err := s.MqWriter.Write(ctx, msg.Topic, msg); err != nil {
		s.Log.Err(err).Msg("SendToMq")
		return err
	}
	s.Log.Info().Msg("send scan instance kafka")
	return nil
}
