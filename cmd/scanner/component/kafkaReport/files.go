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
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type FileUploadSrv struct {
	FileRootPath      string
	MQReader          mq.Reader
	FileExpirationDay int64
	Log               *scannerUtils.LogEvent
}

func (s *FileUploadSrv) saveFile(ctx context.Context, msg kafka.Message) error {
	var dst imagesecModel.WebshellKafkaInfo
	err := json.Unmarshal(msg.Value, &dst)
	if err != nil {
		s.Log.Err(err).Msg(" failed to unmarshal msg")
		return nil
	}

	filename := fmt.Sprintf("%s/%s", s.FileRootPath, dst.FileMd5)

	s.Log.Debug().Str("md5", dst.FileMd5).Str("filename", filename).Int("data", len(dst.Data)).
		Msg(" Save kafka file")

	if scannerUtils.FileExist(filename) {
		return nil
	}

	wbf, err := os.Create(filename)
	if err != nil {
		s.Log.Err(err).Str("mdg", dst.FileMd5).Str("filename", filename).Msg(" create file")
		return nil
	}
	_, err = io.Copy(wbf, bytes.NewReader(dst.Data))
	if err != nil {
		s.Log.Err(err).Str("mdg", dst.FileMd5).Str("filename", filename).Msg(" create file")
	} else {
		s.Log.Debug().Str("mdg", dst.FileMd5).Str("filename", filename).Msg(" Save file success")
	}
	return nil
}

// 定时删除保存的文件
func (s *FileUploadSrv) DeleteExpirationFile(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster")
		return nil
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msgf(" panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			fns, err := scannerUtils.GetDirAllFilename(s.FileRootPath)
			if err != nil {
				s.Log.Err(err).Str("FileRootPath", s.FileRootPath).Msg(" GetDirAllFilename")
				continue
			}
			for i := range fns {
				stat, err := os.Stat(fns[i])
				if err != nil {
					s.Log.Err(err).Str("WebshellFilename", fns[i]).Msg(" GetDirAllFilename Stat")
					continue
				}
				if time.Now().Unix()-stat.ModTime().Unix() <= (s.FileExpirationDay * 24 * 60 * 60) {
					continue
				}
				_ = os.Remove(fns[i])

				s.Log.Info().Str("filename", fns[i]).Msg(" remove file success")
			}
		}
	}()
	return nil
}

func (s *FileUploadSrv) ReceiveKafkaReport(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg(" not in main cluster")
		return nil
	}

	s.Log.Info().Msg(" in main cluster")

	ch := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Stack().Msg("")
			}
		}()

		if err := s.handleMsg(ch); err != nil {
			s.Log.Err(err).Msg("")
		}
	}()

	s.Log.Error().Msg(" receive kafka started successfully")

	return nil
}

func (s *FileUploadSrv) handleMsg(stopCh chan struct{}) error {
	err := s.MQReader.Subscribe(scannermodel.WebshellKafkaTopic, scannermodel.WebshellKafkaGroupID, s.saveFile)
	if err != nil {
		s.Log.Err(err).Msg(" reader subscribe error")
		return err
	}
	s.Log.Info().Msg(" Subscribe ok")
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
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("FileUpload"),
			scannerUtils.WithModule(consts.ModuleKafkaReport),
		),
	}
	if n, err := strconv.Atoi(os.Getenv("FILE_EXPIRATION_PER_DAY")); err == nil && n > 0 {
		s.FileExpirationDay = int64(n)
	}

	return s

}
