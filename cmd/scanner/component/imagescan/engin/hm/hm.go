package hm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanHM struct {
	BinCnt      int64
	EnginBack   []*EnginMeta
	WG          sync.Locker // 主要用于获取引擎
	HmRootPath  string      // /opt/webshell/hm
	ScanTimeout int64       // 单位：秒
	DebugLog    *zerolog.Event
	InfoLog     *zerolog.Event
}

type EnginMeta struct {
	Using       bool // 是否在使用中
	EnginNO     int64
	HmRootPath  string // /opt/webshell/hm
	BinFilename string // hm 的二制制执行文件
	DbFilename  string // hm 扫描后会把结果果保存在当前目录的data.db文件中,这是一个sqlite文件
	CsvFilename string // hm 扫描后会把结果果保存在当前目录的result.csv文件中,这是一个csv文件
}

type SingleHMSrv struct {
	ScanHM *ScanHM
	WG     sync.Locker
}

// 这样才保险
func init() {
	singleHmMeta = &SingleHMSrv{
		ScanHM: nil,
		WG:     &sync.Mutex{},
	}
}

var singleHmMeta *SingleHMSrv

// 单例
func NewScanHM() (*ScanHM, error) {
	singleHmMeta.WG.Lock()
	defer singleHmMeta.WG.Unlock()

	if singleHmMeta.ScanHM != nil {
		return singleHmMeta.ScanHM, nil
	}
	s := &ScanHM{
		HmRootPath:  "/opt/webshell/hm",
		ScanTimeout: 10 * 60,
		WG:          &sync.Mutex{},
		BinCnt:      consts.DefaultHmEnginCnt,
		InfoLog:     consts.ImageScanInfo().Str("scanEngin", "hm"),
		DebugLog:    consts.ImageScanDebug().Str("scanEngin", "hm"),
	}
	cnt, err := strconv.Atoi(os.Getenv("HM_ENGIN_CNT"))
	if err == nil && cnt > 0 {
		s.BinCnt = int64(cnt)
	}

	if err := s.createHmBack(context.Background(), int(s.BinCnt)); err != nil {
		return nil, err
	}

	singleHmMeta.ScanHM = s

	return singleHmMeta.ScanHM, nil
}

func (s *ScanHM) createHmBack(ctx context.Context, n int) error {
	toCtx, cancelFunc := context.WithTimeout(ctx, time.Minute*10)
	defer cancelFunc()

	for i := 0; i < n; i++ {
		// 因为要拼接，所有 s.HmRootPath不能是/opt/webshell/hm/ 后面不能有斜杠
		str := fmt.Sprintf("%s%d", s.HmRootPath, i)
		cmd := exec.CommandContext(toCtx, "cp", "-r", s.HmRootPath, str)
		err := cmd.Run()
		if err != nil {
			logging.Get().Err(err).Str("module", "imagescan").Msg("CreateHmBack error")
			return err
		}
		en := &EnginMeta{
			EnginNO:     int64(i),
			HmRootPath:  str,
			BinFilename: fmt.Sprintf("%s/%s", str, "hm"),
			DbFilename:  fmt.Sprintf("%s/%s", str, "data.db"),
			CsvFilename: fmt.Sprintf("%s/%s", str, "result.csv"),
		}
		s.EnginBack = append(s.EnginBack, en)
	}
	return nil
}

// 获取引擎
func (s *ScanHM) GetHMEngin(ctx context.Context) (*EnginMeta, error) {
	start := time.Now().Unix()
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		s.WG.Lock()
		for i := range s.EnginBack {
			en := s.EnginBack[i]
			if !en.Using {
				s.EnginBack[i].Using = true
				en.Using = true
				s.WG.Unlock()
				logging.Get().Info().Str("model", "imagescan").Interface("engin", en).Msg("GetHMEngin")
				return en, nil
			}
		}
		s.WG.Unlock()
		logging.Get().Info().Str("model", "imagescan").Msg("GetHMEngin not get hm engin and wait next")

		if time.Now().Unix()-start > s.ScanTimeout {
			err := fmt.Errorf("get hm engin timeout")
			logging.Get().Err(err).Str("model", "imagescan").Msg("GetHMEngin get engin timeout")
			return nil, err
		}
		<-ticker.C
	}
}

// 归还引擎
func (s *ScanHM) BackHMEngin(ctx context.Context, eng *EnginMeta) {
	s.DebugLog.Interface("engin", eng).Msg("BackHMEngin start")

	s.WG.Lock()
	defer s.WG.Unlock()
	for i := range s.EnginBack {
		en := s.EnginBack[i]
		if en.EnginNO == eng.EnginNO {
			s.EnginBack[i].Using = false
			en.Using = false
		}
	}
	s.InfoLog.Interface("engin", eng).Msg("BackHMEngin end")
}

func (s *ScanHM) ScanWebshell(ctx context.Context, scanPath string) ([]imagesecTypes.HmWebshell, error) {
	logging.Get().Debug().Str("module", "imagescan").Str("scanPath", scanPath).Msg("ScanWebshell")

	en, err := s.GetHMEngin(ctx)

	if err != nil {
		logging.Get().Info().Str("module", "imagescan").Str("scanPath", scanPath).Msg("ScanWebshell GetHMEngin")
		return nil, err
	}

	defer func() { s.BackHMEngin(ctx, en) }()
	defer func() { _ = en.removeWhDb(ctx, en.DbFilename) }()
	defer func() { _ = en.removeWhDb(ctx, en.CsvFilename) }()

	logging.Get().Info().Str("module", "imagescan").Interface("EnginMeta", en).Msg("ScanWebshell GetHMEngin")

	err = en.cmdScan(ctx, scanPath, consts.DefaultScanTimeout)
	if err != nil {
		logging.Get().Info().Str("module", "imagescan").Str("scanPath", scanPath).Msg("ScanWebshell cmdScan")
		return nil, err
	}

	pre, err := en.parseWhDb(ctx, en.DbFilename)
	if err != nil {
		logging.Get().Info().Str("module", "imagescan").Str("scanPath", scanPath).Msg("ScanWebshell parseWhDb")
		return nil, err
	}
	return pre, nil
}

func (s *EnginMeta) parseWhDb(ctx context.Context, dbFilename string) ([]imagesecTypes.HmWebshell, error) {
	res := make([]imagesecTypes.HmWebshell, 0)

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
		wb := imagesecTypes.HmWebshell{
			Filename:    wbb.Filepath,
			Size:        fileSize,
			MD5:         wbb.Md5Hash,
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelCertain,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	for _, wbb := range resS {
		fileSize, _ := scannerUtils.FileSize(wbb.Filepath)
		wb := imagesecTypes.HmWebshell{
			Filename:    wbb.Filepath,
			MD5:         wbb.Md5Hash,
			Size:        fileSize,
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelMaybe,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	return res, nil
}

func (s *EnginMeta) removeWhDb(ctx context.Context, dbFilename string) error {
	if !scannerUtils.FileExist(dbFilename) {
		return nil
	}

	return os.Remove(dbFilename)
}

func (s *EnginMeta) cmdScan(ctx context.Context, scanPath string, to int64) error {
	// 每一次扫描都会在hm 扫描器所在的目录下生成  data.db文件，这个文件是一个sqlite数据文件
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
