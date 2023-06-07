package scanwebshell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/security-rd/go-pkg/mq"
)

const (
	serviceName = "scanner-webshell"
)

type Config struct {
}

type ScannerWebshellService struct {
	mqReader mq.Reader
	Num      int
	PvcPath  string
	// config      Config
}

func (s *ScannerWebshellService) CreateHmBack(n int) {
	for i := 1; i <= n; i++ {
		str := consts.WebshellDir + fmt.Sprintf("%d", i)
		cmd := exec.Command("cp", "-r", consts.WebshellDir, str)
		err := cmd.Run()
		if err != nil {
			panic(fmt.Sprintf("create hm back error %v", err))
		}
	}
}

func (s *ScannerWebshellService) DeleteHmBack(n int) {
	for i := 1; i <= n; i++ {
		str := consts.WebshellDir + fmt.Sprintf("%d", i)
		cmd := exec.Command("rm", "-rf", str)
		err := cmd.Run()
		if err != nil {
			panic(fmt.Sprintf("delete hm back error %v", err))
		}
	}
}

func (s *ScannerWebshellService) PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func (s *ScannerWebshellService) saveHandle(ctx context.Context, msg kafka.Message) error {
	var dst scannermodel.WebshellSaveInfo
	err := json.Unmarshal(msg.Value, &dst)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to unmarshal webShell msg")
		return err
	}
	logging.GetLogger().Info().Msgf("Save kafka file %v", dst.FileMd5)
	dstPath := filepath.Join(filepath.Join(s.PvcPath, "webshell"), dst.FileMd5)
	if s.PathExists(dstPath) {
		return nil
	}
	tmpFs, err := s.createFile(dstPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("create webshell file error")
		return err
	}
	_, err = io.Copy(tmpFs, bytes.NewReader(dst.Data))
	if err != nil {
		logging.GetLogger().Err(err).Msg("copy webshell file error")
		return err
	}
	return nil
}

func (s *ScannerWebshellService) DeleteFile() {
	isMain := os.Getenv("IS_MAIN_CLUSTER")
	if isMain == "true" {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			var day int64
			day = 30
			str := os.Getenv("WEBSHELL_DELETE")
			if str != "" {
				tmp, err := strconv.ParseInt(str, 10, 64)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("WEBSHELL_DELETE str IS ERROR")
				} else {
					day = tmp
				}
			}
			expire := time.Now().Add(time.Hour * time.Duration(day) * 24 * -1).UnixMilli()
			filepath.Walk(filepath.Join(s.PvcPath, "webshell"), func(path string, info fs.FileInfo, err error) error {
				if info.ModTime().UnixMilli() < expire {
					err := os.Remove(path)
					if err != nil {
						logging.GetLogger().Err(err).Msgf("remove error")
					}
					logging.GetLogger().Info().Msgf("remove webshell file %v", info.Name())
				}
				return nil
			})
		}
	}
}

func (s *ScannerWebshellService) SaveWebshell(mqReader mq.Reader) {
	err := mqReader.Subscribe(scannermodel.WebshellKafkaTopic, scannermodel.WebshellKafkaGroupID, s.saveHandle)
	if err != nil {
		logging.GetLogger().Err(err).Msg("webshell init mq consumer error")
	}
	logging.GetLogger().Info().Msg("Subscribe ok")
}
func (s *ScannerWebshellService) handleMsg(stopCh <-chan struct{}) {
	err := s.mqReader.Subscribe(scannermodel.WebshellKafkaTopic, scannermodel.WebshellKafkaGroupID, s.saveHandle)
	if err != nil {
		logging.GetLogger().Err(err).Msg("reader subscribe error")
		return
	}
	logging.GetLogger().Info().Msg("Subscribe ok")
	<-stopCh
}
func (s *ScannerWebshellService) Start(ctx context.Context) error {
	s.CreateHmBack(s.Num)
	go s.DeleteFile()
	ch := make(chan struct{})
	s.handleMsg(ch)
	return nil
}

func (s *ScannerWebshellService) createFile(name string) (*os.File, error) {
	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
	if err != nil {
		return nil, err
	}
	return os.Create(name)
}

func (s *ScannerWebshellService) Stop(ctx context.Context) error {
	s.DeleteHmBack(s.Num)
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	s := &ScannerWebshellService{}
	s.PvcPath = config.Options.PvcPath
	numStr := os.Getenv("WebshellNum")
	num, err := strconv.Atoi(numStr)
	if err != nil {
		s.Num = 5
		logging.GetLogger().Warn().Msgf("failed to get websehllNum env,set worker num to default value")
	} else {
		s.Num = num
	}

	mqReader, err := mq.GetClientFactory().Reader(context.Background())
	if err != nil {
		logging.GetLogger().Err(err).Msg("Init mq error")
		return nil, err
	}
	s.mqReader = mqReader
	return s, nil
}
