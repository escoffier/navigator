package report

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type SendFile struct {
	MqWriter         mq.Writer
	MaxSingeFileSize int64
	Log              *scannerUtils.LogEvent
}

func (s *SendFile) Send(ctx context.Context, pre *imagesecTypes.PrepareScan, result *imagesecTypes.ReportScanResult) error {
	startAt := time.Now().Unix()
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "SendFile").Msg("scan job start")
	defer s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "SendFile").
		Int64("cost", time.Now().Unix()-startAt).Msg("scan job end")

	need := make(map[string]*imagesecTypes.SaveFileToKafka)

	for i := range result.SaveFileToKafka {
		sed := result.SaveFileToKafka[i]
		need[sed.FileMd5] = &sed
	}

	outer := s.AddNeedSendFile(ctx, result)
	for i := range outer {
		need[outer[i].FileMd5] = outer[i]
	}

	s.Log.Info().Str("image", pre.Subtask.RegImageMeta.ImageName()).Int("sendfileCnt", len(need)).Msg("sendFile")

	wg := &sync.WaitGroup{}
	out := make(chan error)
	defer close(out)

	for i := range need {
		param := need[i]
		wg.Add(1)
		// 耗时的操作
		go func(param *imagesecTypes.SaveFileToKafka, wg *sync.WaitGroup) {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error().Str("Stack", string(debug.Stack())).Msg("SendFileToKafka")
				}
			}()
			_ = s.SendFileToKafka(ctx, param, wg)
		}(param, wg)
	}

	wg.Wait()
	return nil
}

func (s *SendFile) SendFileToKafka(ctx context.Context, param *imagesecTypes.SaveFileToKafka, wg *sync.WaitGroup) error {
	defer wg.Done()
	if param == nil {
		return nil
	}
	if len(param.Data) == 0 {
		// 尝试读取文件
		f, err := os.Open(param.Filename)
		if err != nil {
			s.Log.Err(err).Str("file", param.LopStr()).Msg("Open file")
			return err
		}
		defer func() { _ = f.Close() }()

		content, err := io.ReadAll(f)
		if err != nil {
			s.Log.Err(err).Str("Filename", param.Filename).Msg("ReadAll")
			return err
		}
		param.Data = content
	}

	// 如果 md5 为空，得先计算 md5
	if param.FileMd5 == "" && len(param.Data) > 0 {
		param.FileMd5 = scannerUtils.GetContentMd5(param.Data)
	}

	param.Data = scannerUtils.ZipByteSlice(param.Data)

	if err := param.Check(); err != nil {
		s.Log.Err(err).Str("file", param.LopStr()).Msg("send file incorrect,not send")
		return err
	}

	if s.MaxSingeFileSize > 0 && int64(len(param.Data)) > s.MaxSingeFileSize {
		s.Log.Info().Str("file", param.LopStr()).Msg("send file is too big")
		return nil
	}

	bys, err := json.Marshal(param)
	if err != nil {
		s.Log.Err(err).Str("file", param.LopStr()).Msg("Marshal")
		return err
	}

	err = s.MqWriter.Write(context.Background(), consts.WebshellKafkaTopic, kafka.Message{
		Key:   []byte(consts.WebshellKafkaKey),
		Value: bys,
	})
	if err != nil {
		s.Log.Err(err).Str("file", param.LopStr()).Int("dataSize", len(bys)).Msg("SendFileToKafka")
		return err
	}
	s.Log.Debug().Str("file", param.LopStr()).Msg("SendFileToKafka")
	return nil
}

var sendFileSinge *SendFile

func NewSendFile(mqWriter mq.Writer, maxSingeFileSize int64) *SendFile {
	if sendFileSinge != nil {
		return sendFileSinge
	}
	sendFileSinge = &SendFile{
		MqWriter: mqWriter,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("SendFile"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
		MaxSingeFileSize: maxSingeFileSize,
	}

	return sendFileSinge
}

func (s *SendFile) AddNeedSendFile(ctx context.Context, result *imagesecTypes.ReportScanResult) []*imagesecTypes.SaveFileToKafka {

	all := make([]*imagesecTypes.SaveFileToKafka, 0)

	for i := range result.Sensitives.SensitiveFiles {
		ses := result.Sensitives.SensitiveFiles[i]
		param := &imagesecTypes.SaveFileToKafka{
			Layer:    ses.Layer,
			FileMd5:  ses.MD5,
			Filename: ses.Filename,
		}
		all = append(all, param)

	}
	for i := range result.Webshell.HmWebshells {
		ses := result.Webshell.HmWebshells[i]
		param := &imagesecTypes.SaveFileToKafka{
			Layer:    ses.Layer,
			FileMd5:  ses.MD5,
			Filename: ses.Filename,
		}
		all = append(all, param)
	}

	for i := range result.Malware.AviraScanResults {
		ses := result.Malware.AviraScanResults[i]
		param := &imagesecTypes.SaveFileToKafka{
			Layer:    ses.Layer,
			FileMd5:  ses.MD5,
			Filename: ses.Filename,
		}
		all = append(all, param)
	}

	for i := range result.Malware.ClamAvScanResults {
		ses := result.Malware.ClamAvScanResults[i]
		param := &imagesecTypes.SaveFileToKafka{
			Layer:    ses.Layer,
			FileMd5:  ses.MD5,
			Filename: ses.Filename,
		}
		all = append(all, param)
	}

	for i := range result.License {
		ses := result.License[i]
		param := &imagesecTypes.SaveFileToKafka{
			Data:     ses.Content,
			Layer:    ses.Layer,
			FileMd5:  ses.MD5,
			Filename: ses.Filename,
		}
		all = append(all, param)
	}

	return all
}
