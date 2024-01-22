package imagesec

import (
	"context"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type Cleaner struct {
	FileCleanConfig FileCleanConfig
	ScanResultDal   imagesecStore.ScanResultDal
	Log             *scannerUtils.LogEvent
}

type FileCleanConfig struct {
	FileRootPath      string // 保存文件的根路径
	FileExpirationDay int64  // 文件最长保存天数
}

// 定时删除保存的文件
// 加入的缓存
func (s *Cleaner) DeleteExpirationFile(ctx context.Context, config FileCleanConfig) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster")
		return nil
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.Log.Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			<-ticker.C
			fns, err := scannerUtils.GetDirAllFilename(s.FileCleanConfig.FileRootPath)
			if err != nil {
				s.Log.Err(err).Str("FileRootPath", s.FileCleanConfig.FileRootPath).Msg("GetDirAllFilename")
				continue
			}
			for i := range fns {
				// 检测是否在缓存中
				stat, err := os.Stat(fns[i])
				if err != nil {
					s.Log.Err(err).Str("WebshellFilename", fns[i]).Msg("GetDirAllFilename Stat")
					continue
				}
				if time.Now().Unix()-stat.ModTime().Unix() <= (s.FileCleanConfig.FileExpirationDay * 24 * 60 * 60) {
					continue
				}
				// 删除缓存
				split := strings.Split(stat.Name(), string(os.PathSeparator))
				if len(split) == 0 || split[len(split)-1] == "" {
					continue
				}

				if err := s.ScanResultDal.DeleteScanLayerData(ctx, imagesecModel.SearchScanLayerParam{FileM5d: split[len(split)-1]}); err != nil {
					s.Log.Err(err).Str("fileMD5", split[len(split)-1]).Msg("delete scan layer cache")
					continue
				}

				_ = os.Remove(fns[i])

				s.Log.Info().Str("filename", fns[i]).Msg("remove file success")
			}
		}
	}()
	return nil
}

func NewCleaner(scanResultDal imagesecStore.ScanResultDal) *Cleaner {

	cl := &Cleaner{
		FileCleanConfig: FileCleanConfig{
			FileRootPath:      global.ScannerOpts.PvcPath + "/" + consts.WebshellFileDir,
			FileExpirationDay: consts.DefaultFileExpirationDay,
		},
		ScanResultDal: scanResultDal,
		Log:           scannerUtils.NewLogEvent(scannerUtils.WithModule(consts.ModuleImagesecSrv), scannerUtils.WithSubModule("cleaner")),
	}

	_ = os.MkdirAll(cl.FileCleanConfig.FileRootPath, os.ModePerm)

	if n, err := strconv.Atoi(os.Getenv("FILE_EXPIRATION_PER_DAY")); err == nil && n > 0 {
		cl.FileCleanConfig.FileExpirationDay = int64(n)
	}
	_ = os.MkdirAll(cl.FileCleanConfig.FileRootPath, os.ModePerm)

	return cl
}
