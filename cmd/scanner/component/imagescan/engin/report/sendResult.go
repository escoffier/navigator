package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/modify"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type SendResult struct {
	MqWriter mq.Writer
	Log      *scannerUtils.LogEvent
}

func (s *SendResult) Send(ctx context.Context, pre *imagesecTypes.PrepareScan, result *imagesecTypes.ReportScanResult) error {
	start := time.Now().Unix()
	s.logScanStart(pre)
	defer s.logScanEnd(start, pre)

	sendData, err := json.Marshal(result)
	if err != nil {
		s.Log.Err(err).Str("subtask", pre.Subtask.LogStr()).Msg("send to kafka")
		return err
	}
	sendData2 := scannerUtils.ZipByteSlice(sendData)

	s.Log.Debug().Int("preZip", len(sendData)).Int("afterZip", len(sendData2)).Msg("ZipByteSlice")

	outCtx, cancelFunc := context.WithTimeout(ctx, time.Second*20)
	defer cancelFunc()

	err = s.MqWriter.Write(outCtx, consts.NodeImageScanResultTopic, kafka.Message{
		Key:   []byte(consts.NodeImageScanResultKey),
		Value: sendData2,
	})
	if err != nil {
		s.Log.Err(err).Str("subtask", pre.Subtask.LogStr()).Int("dataSize", len(sendData2)).Msg("send to kafka failed")
		if strings.Contains(err.Error(), "Message Size Too Large") {
			mo := modify.NewResultModify()
			err2 := fmt.Errorf("kafka [Message Size Too Large] data size:%d", len(sendData))
			result.Errors = append(result.Errors, err2)
			_ = mo.ConvertScanStatus(ctx, result)
			// 再发一次，不然主集群中的扫描任务会一直卡着
			// 消息已经精简，所以不会进入死循环
			if err3 := s.Send(ctx, pre, result); err3 != nil {
				s.Log.Err(err3).Str("subtask", pre.Subtask.LogStr()).Int("dataSize", len(sendData2)).
					Msg("kafka [Message Size Too Large] resend to kafka failed")
				return fmt.Errorf("kafka [Message Size Too Large] resend result failed")
			}
			return nil
		}

		s.Log.Err(err).Int("dataSize", len(sendData2)).Msg("send scan result to kafka failed")
		return err
	}
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Msg("send to kafka success")
	return nil
}

func (s *SendResult) logScanEnd(start int64, pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).
		Int64("cost", time.Now().Unix()-start).Msg("scan job end")
}

func (s *SendResult) logScanStart(pre *imagesecTypes.PrepareScan) {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Msg("scan job start")
}

var sendResultSinge *SendResult

func NewSendResult(mqWriter mq.Writer) *SendResult {
	if sendResultSinge != nil {
		return sendResultSinge
	}
	sendResultSinge = &SendResult{
		MqWriter: mqWriter,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("SendResult"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}

	return sendResultSinge
}
