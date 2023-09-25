package hm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
)

type ScanHM struct {
	MQReader          mq.Reader
	MqWriter          mq.Writer
	BinCnt            int64
	HM                []*HmMeta
	SendEnginChan     chan int64
	UsedEnginChan     chan int64
	HmRootPath        string // /opt/webshell/hm
	WebshellFilePath  string // 保存webshell文件的路径 /host/path/webshell
	ScanTimeout       time.Duration
	MaxSingeFileSize  int64
	FileExpirationDay int64 // webshell文件最大保存天数
}

type HmMeta struct {
	HmRootPath  string // /opt/webshell/hm
	BinFilename string // hm 的二制制执行文件
	DbFilename  string // hm 扫描后会把结果果保存在当前目录的data.db文件中,这是一个sqlite文件
	CsvFilename string // hm 扫描后会把结果果保存在当前目录的result.csv文件中,这是一个csv文件
}

func (s *ScanHM) GenEnginChan(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("GenEnginChan panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		var start int64 = 0
		for {
			<-s.UsedEnginChan
			s.SendEnginChan <- start
			start++
		}
	}()
}

func NewScanHM() (*ScanHM, error) {
	s := &ScanHM{
		HM:               make([]*HmMeta, 0),
		HmRootPath:       "/opt/webshell",
		ScanTimeout:      10 * time.Minute,
		MaxSingeFileSize: (1 << 20) * 10,
	}
	cnt, err := strconv.Atoi(os.Getenv("HM_ENGIN_CNT"))
	if err != nil || cnt <= 0 {
		cnt = consts.DefaultHmEnginCnt
	}

	if err := s.createHmBack(context.Background(), cnt); err != nil {
		return nil, err
	}
	s.BinCnt = int64(len(s.HM))
	s.SendEnginChan = make(chan int64, len(s.HM))
	s.UsedEnginChan = make(chan int64)

	s.GenEnginChan(context.Background())

	return s, nil
}

func (s *ScanHM) createHmBack(ctx context.Context, n int) error {
	toCtx, cancelFunc := context.WithTimeout(ctx, time.Minute*10)
	defer cancelFunc()

	for i := 0; i < n; i++ {
		str := s.HmRootPath + fmt.Sprintf("%d", i)
		cmd := exec.CommandContext(toCtx, "cp", "-r", s.HmRootPath, str)
		err := cmd.Run()
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("CreateHmBack error")
			return err
		}
		s.HM = append(s.HM, &HmMeta{
			HmRootPath:  str,
			BinFilename: fmt.Sprintf("%s/%s", str, "hm"),
			DbFilename:  fmt.Sprintf("%s/%s", str, "data.db"),
			CsvFilename: fmt.Sprintf("%s/%s", str, "result.csv"),
		})
	}
	return nil
}

func (s *ScanHM) GetHMEngin(ctx context.Context) (*HmMeta, error) {
	str := s.HmRootPath + fmt.Sprintf("%d", 2)
	return &HmMeta{
		HmRootPath:  str,
		BinFilename: fmt.Sprintf("%s/%s", str, "hm"),
		DbFilename:  fmt.Sprintf("%s/%s", str, "data.db"),
		CsvFilename: fmt.Sprintf("%s/%s", str, "result.csv"),
	}, nil

	// timeout, cancelFunc := context.WithTimeout(ctx, s.ScanTimeout)
	// defer cancelFunc()
	//
	// select {
	// case <-timeout.Done():
	// 	return nil, fmt.Errorf("can not get hm engin")
	// case en := <-s.SendEnginChan:
	// 	if int64(len(s.HM)) < en%s.BinCnt && en%s.BinCnt >= 0 {
	// 		return s.HM[en%s.BinCnt], nil
	// 	}
	// 	return nil, fmt.Errorf("can not get hm engin,idex :%d", en)
	// }
}

func (s *ScanHM) ScanWebshell(ctx context.Context, scanPath string) ([]imagesecModel.Webshell, error) {
	logging.Get().Info().Str("module", "imagescan").Str("scanPath", scanPath).Msg("ScanWebshell")
	en, err := s.GetHMEngin(ctx)

	if err != nil {
		return nil, err
	}
	defer func() { s.UsedEnginChan <- 0 }()
	// defer func() { _ = en.removeWhDb(ctx, en.DbFilename) }()
	logging.Get().Info().Str("module", "imagescan").Interface("HmMeta", en).Msg("GetHMEngin")

	err = en.cmdScan(ctx, scanPath, consts.DefaultScanTimeout)
	if err != nil {
		return nil, err
	}

	res, err := en.parseWhDb(ctx, en.DbFilename)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *ScanHM) SendWebshell(ctx context.Context, wbs imagesecModel.Webshell) error {
	cont, err := os.ReadFile(s.WebshellFilePath + "/" + wbs.MD5)
	if err != nil {
		return err
	}

	saveInfo := imagesecModel.WebshellKafkaInfo{
		FileMd5:  wbs.MD5,
		Data:     cont,
		Filename: s.WebshellFilePath + "/" + wbs.MD5,
	}

	saveByte, err := json.Marshal(saveInfo)
	if err != nil {
		return err
	}

	err = s.MqWriter.Write(
		context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
			Topic: scannermodel.WebshellKafkaTopic,
			Key:   []byte(wbs.MD5),
			Value: saveByte,
		})
	return err
}

func (s *HmMeta) parseWhDb(ctx context.Context, dbFilename string) ([]imagesecModel.Webshell, error) {
	res := make([]imagesecModel.Webshell, 0)
	if !scannerUtils.FileExist(dbFilename) {
		return res, fmt.Errorf("not find db file:%s", dbFilename)
	}

	db, err := gorm.Open(sqlite.Open(dbFilename), &gorm.Config{})
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("open hm sqlite error")
		return nil, err
	}
	resB := make([]imagesecModel.CertainWebshell, 0)

	err = db.Model(&imagesecModel.CertainWebshell{}).Select("*").Find(&resB).Error
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("get hm tbl_b error")
		return nil, err
	}
	resS := make([]imagesecModel.MaybeWebshell, 0)

	err = db.Model(&imagesecModel.MaybeWebshell{}).Select("*").Find(&resS).Error
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("get hm tbl_s error")
		return nil, err
	}
	for _, wbb := range resB {
		fileSize, _ := scannerUtils.FileSize(wbb.Filepath)
		wb := imagesecModel.Webshell{
			Filename:    wbb.Filepath,
			Size:        fileSize,
			MD5:         wbb.Md5Hash,
			FileMod:     "",
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelCertain,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	for _, wbb := range resS {
		fileSize, _ := scannerUtils.FileSize(wbb.Filepath)
		wb := imagesecModel.Webshell{
			Filename:    wbb.Filepath,
			Size:        fileSize,
			MD5:         wbb.Md5Hash,
			FileMod:     "",
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelMaybe,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	return res, nil
}

func (s *HmMeta) removeWhDb(ctx context.Context, dbFilename string) error {
	if !scannerUtils.FileExist(dbFilename) {
		return nil
	}

	return os.Remove(dbFilename)
}

func (s *HmMeta) cmdScan(ctx context.Context, scanPath string, to int64) error {
	// 每一次扫描都会在所扫描的目录下生成  data.db文件，这个文件是一个sqlite数据文件
	timeout, cancelFunc := context.WithTimeout(ctx, time.Minute*time.Duration(to))
	defer cancelFunc()

	if scannerUtils.FileExist(s.DbFilename) {
		// 先删除上一次扫描的结果文件
		if err := os.Remove(s.DbFilename); err != nil {
			return fmt.Errorf("can not remore pre scan db")
		}
	}
	cmd := exec.CommandContext(timeout, s.BinFilename, "scan", scanPath)
	_, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(s.DbFilename)
		return err
	}
	return nil
}

func (s *ScanHM) DetectWebshellFile(ctx context.Context, dir string) ([]imagesecModel.WebshellKafkaInfo, error) {
	// filename, err := utils.GetDirAllFilename(dir)
	// if err != nil {
	// 	return nil, err
	// }
	// for i := range filename {
	// 	if !utils.WebshellFileExt(filename[i]) {
	// 		continue
	// 	}
	// 	fd, err := os.Stat(filename[i])
	// 	if err != nil {
	// 		continue
	// 	}
	// 	if fd.Size() > s.MaxSingeFileSize {
	// 		continue
	// 	}
	//
	// 	cont, err := os.ReadFile(filename[i])
	// 	if err != nil {
	// 		continue
	// 	}
	// 	fileMd5, err := w.FileMD5(bytes.NewReader(fileByte))
	// 	if err != nil {
	// 		logging.GetLogger().Err(err).Msg("generate md5 failed")
	// 		continue
	// 	}
	//
	// }
	//
	// if w.webshellFileExt(filepath.Ext(header.Name)) {
	// 	if header.Size > scannermodel.WebshellSize {
	// 		continue
	// 	}
	// 	fileByte, err := io.ReadAll(tarReader)
	// 	if err != nil {
	// 		logging.GetLogger().Err(err).Msgf("copy from tarReader error")
	// 	}
	// 	fileMd5, err := w.FileMD5(bytes.NewReader(fileByte))
	// 	if err != nil {
	// 		logging.GetLogger().Err(err).Msg("generate md5 failed")
	// 		continue
	// 	}
	// 	tmpPath := filepath.Join(digestPath, fileMd5)
	// 	tmpfs, err := os.Create(tmpPath)
	// 	if err != nil {
	// 		logging.GetLogger().Err(err).Msg("generate tmpFile failed")
	// 		continue
	// 	}
	// 	// logging.GetLogger().Info().Msgf("name :%v,size:%v", header.Name, header.Size)
	// 	_, err = io.Copy(tmpfs, bytes.NewReader(fileByte))
	// 	if err != nil {
	// 		logging.GetLogger().Err(err).Msg("copy tmpFile failed")
	// 		continue
	// 	}
	//
	// 	tmpfs.Close()
	// 	tmpInfo := scannermodel.WebshellFileInfo{}
	// 	tmpInfo.FilePath = tmpPath
	// 	tmpInfo.FileName = header.Name
	// 	tmpInfo.Size = header.Size
	// 	tmpInfo.LayerDigest = digest
	// 	tmpInfo.ModeTime = header.ModTime.UnixMilli()
	// 	tmpInfo.Mode = header.FileInfo().Mode().String()
	// 	mp[fileMd5] = append(mp[fileMd5], tmpInfo)
	// 	count++
	// }
	return nil, nil
}
