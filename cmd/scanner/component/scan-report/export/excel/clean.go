package excel

import (
	"context"
	"os"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ClearFileAndRecord struct {
	FileDir       string
	Expiration    int64 // 多少天前过期
	ExportTaskDal store.ExportTaskDal
}

func NewClearFile(fileDir string, expiration int64, exportTaskDal store.ExportTaskDal) *ClearFileAndRecord {
	return &ClearFileAndRecord{
		FileDir:       fileDir,
		Expiration:    expiration,
		ExportTaskDal: exportTaskDal,
	}
}

func (s *ClearFileAndRecord) Run(ctx context.Context) {

	expirationDate := getExpirationDate(s.Expiration)

	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExpirationDate: expirationDate}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Time("expirationDate", expirationDate).Msg("SearchExportTensorTask")
		return
	}
	for i := range tasks {
		// 删除中间目录,任务可能出错，所以不能直接取数据库中的数据
		filePath := strings.ReplaceAll(tasks[i].FilePath, ".zip", "")
		filePath = strings.ReplaceAll(filePath, s.FileDir+"/", "")
		if filePath != "" && s.FileDir != "" && s.FileDir != "/" {
			if err := os.RemoveAll(s.FileDir + "/" + filePath); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Str("filePath", s.FileDir+"/"+filePath).Msg("RemoveAll")
			}
		}
		// 删除文件
		filePath = strings.ReplaceAll(filePath, s.FileDir+"/", "")
		if filePath != "" && s.FileDir != "" && s.FileDir != "/" {
			if err := os.RemoveAll(s.FileDir + "/" + filePath); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Str("filePath", s.FileDir+"/"+filePath).Msg("RemoveAll")
			}
		}

		if tasks[i].FilePath != "" && strings.Contains(tasks[i].FilePath, s.FileDir) && strings.Contains(tasks[i].FilePath, ".zip") {
			if err := os.Remove(tasks[i].FilePath); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Str("fileName", tasks[i].FilePath).Msg("Remove file")
			}
		}

		if err := s.ExportTaskDal.DeleteExportVulnImage(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportVulnImage")
		}
		if err := s.ExportTaskDal.DeleteExportTaskImage(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportTaskImage")
		}
		if err := s.ExportTaskDal.DeleteExportTensorTask(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportTensorTask")
		}

	}

	return
}

func getExpirationDate(expirationDay int64) time.Time {
	year, month, day := time.Now().Date()
	zeroDate := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)

	expiration := zeroDate.AddDate(0, 0, -int(expirationDay))
	return expiration
}
