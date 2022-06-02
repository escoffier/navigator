package export

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ClearFile struct {
	fileDir       string
	expiration    int64 // 多少天前过期
	exportTaskDal store.ExportTaskDal
}

func NewClearFile(fileDir string, expiration int64, exportTaskDal store.ExportTaskDal) *ClearFile {
	return &ClearFile{
		fileDir:       fileDir,
		expiration:    expiration,
		exportTaskDal: exportTaskDal,
	}
}

func (s *ClearFile) DeleteExpiredFiles(ctx context.Context) error {
	err := filepath.Walk(s.fileDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			logging.GetLogger().Info().Msg("not find file,the f is nil")
			return err
		}
		if path == s.fileDir {
			return nil
		}
		expirationDate := getExpirationDate(s.expiration)
		if f.ModTime().Before(expirationDate) {
			logging.GetLogger().Info().Str("filename", path).Msg("file has expired")
			if !f.IsDir() {
				if err := os.Remove(path); err != nil {
					logging.GetLogger().Err(err).Str("filename", path).Msg("Remove")
				}
			}
		}
		return nil
	})
	if err != nil {
		logging.GetLogger().Err(err).Str("rootDir", s.fileDir).Msg("DeleteExpiredFiles")
		return err
	}
	return nil
}

func (s *ClearFile) DeleteExpiredExportRecord(ctx context.Context) error {

	expirationDate := getExpirationDate(s.expiration)
	if err := s.exportTaskDal.DeleteExportTensorTask(ctx, store.SearchExportTensorTask{ExpirationDate: expirationDate}); err != nil {
		logging.GetLogger().Err(err).Time("expirationDate", expirationDate).Msg("DeleteExpiredExportRecord")
		return err
	}
	return nil
}

func (s *ClearFile) Run(ctx context.Context) {
	if err := s.DeleteExpiredFiles(ctx); err != nil {
		logging.GetLogger().Err(err).Str("rootDir", s.fileDir).Msg("DeleteExpiredFiles")
	}

	if err := s.DeleteExpiredExportRecord(ctx); err != nil {
		logging.GetLogger().Err(err).Str("rootDir", s.fileDir).Msg("DeleteExpiredFiles")
	}
}

func getExpirationDate(expirationDay int64) time.Time {
	year, month, day := time.Now().Date()
	zeroDate := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)

	expiration := zeroDate.AddDate(0, 0, -int(expirationDay))
	return expiration
}
