package imagesecReport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	scannerUtils2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type FileUploadSrv struct {
	FileRootPath      string
	MQReader          mq.Reader
	FileExpirationDay int64
}

func (s *FileUploadSrv) saveFile(ctx context.Context, msg kafka.Message) error {
	var dst imagesecModel.WebshellKafkaInfo
	err := json.Unmarshal(msg.Value, &dst)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("FileUploadSrv failed to unmarshal msg")
		return nil
	}

	filename := fmt.Sprintf("%s/%s", s.FileRootPath, dst.FileMd5)

	logging.Get().Debug().Str("module", "KafkaReport").Str("md5", dst.FileMd5).Str("filename", filename).Int("data", len(dst.Data)).
		Msg("FileUploadSrv Save kafka file")

	if scannerUtils2.FileExist(filename) {
		return nil
	}

	wbf, err := os.Create(filename)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("mdg", dst.FileMd5).Str("filename", filename).Msg("FileUploadSrv create file")
		return nil
	}
	_, err = io.Copy(wbf, bytes.NewReader(dst.Data))
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Str("mdg", dst.FileMd5).Str("filename", filename).Msg("FileUploadSrv create file")
	} else {
		logging.Get().Debug().Str("module", "KafkaReport").Str("mdg", dst.FileMd5).Str("filename", filename).Msg("FileUploadSrv Save file success")
	}
	return nil
}

// 定时删除保存的文件
func (s *FileUploadSrv) DeleteExpirationFile(ctx context.Context) error {
	if !scannerUtils2.MainCluster() {
		logging.Get().Info().Str("module", "KafkaReport").Msg("not in main cluster")
		return nil
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("FileUploadSrv panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			fns, err := scannerUtils2.GetDirAllFilename(s.FileRootPath)
			if err != nil {
				logging.Get().Err(err).Str("module", "KafkaReport").Str("FileRootPath", s.FileRootPath).Msg("FileUploadSrv GetDirAllFilename")
				continue
			}
			for i := range fns {
				stat, err := os.Stat(fns[i])
				if err != nil {
					logging.Get().Err(err).Str("module", "KafkaReport").Str("WebshellFilename", fns[i]).Msg("FileUploadSrv GetDirAllFilename Stat")
					continue
				}
				if time.Now().Unix()-stat.ModTime().Unix() <= (s.FileExpirationDay * 24 * 60 * 60) {
					continue
				}
				_ = os.Remove(fns[i])

				logging.Get().Info().Str("module", "KafkaReport").Str("filename", fns[i]).Msg("FileUploadSrv remove file success")
			}
		}
	}()
	return nil
}

func (s *FileUploadSrv) ReceiveKafkaReport(ctx context.Context) error {
	if !scannerUtils2.MainCluster() {
		logging.Get().Info().Str("module", "KafkaReport").Msg("FileUploadSrv not in main cluster")
		return nil
	}

	logging.Get().Info().Str("module", "KafkaReport").Msg("FileUploadSrv in main cluster")

	ch := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Stack().Msg("FileUploadSrv")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			logging.Get().Err(err).Str("module", "KafkaReport").Msg("FileUploadSrv")
		}
	}()

	logging.Get().Error().Msg("FileUploadSrv receive kafka started successfully")

	return nil
}

func (s *FileUploadSrv) handleMsg(stopCh chan struct{}) error {
	err := s.MQReader.Subscribe(scannermodel.WebshellKafkaTopic, scannermodel.WebshellKafkaGroupID, s.saveFile)
	if err != nil {
		logging.Get().Err(err).Str("module", "KafkaReport").Msg("FileUploadSrv reader subscribe error")
		return err
	}
	logging.Get().Info().Str("module", "KafkaReport").Msg("FileUploadSrv Subscribe ok")
	<-stopCh
	return nil
}

func NewFileUploadSrv(
	mqReader mq.Reader,
) *FileUploadSrv {
	s := &FileUploadSrv{
		FileRootPath:      global.PVCPath + "/" + consts.WebshellFileDir,
		MQReader:          mqReader,
		FileExpirationDay: consts.DefaultFileExpirationDay,
	}
	if n, err := strconv.Atoi(os.Getenv("FILE_EXPIRATION_PER_DAY")); err == nil && n > 0 {
		s.FileExpirationDay = int64(n)
	}

	return s

}
