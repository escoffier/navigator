package common

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ClearFileAndRecord struct {
	FileDir                 string
	Expiration              int64 // 多少天前过期
	ExportTaskDal           imagesecStore.ExportTaskDal
	IdempotentDal           imagesecStore.IdempotentDal
	ExportTaskTimeoutSecond int64
}

func NewClearFile(
	fileDir string,
	expiration int64,
	exportTaskDal imagesecStore.ExportTaskDal,
	idempotentDal imagesecStore.IdempotentDal,
) *ClearFileAndRecord {
	s := &ClearFileAndRecord{
		FileDir:       fileDir,
		Expiration:    expiration,
		ExportTaskDal: exportTaskDal,
		IdempotentDal: idempotentDal,
	}

	getenv, err := strconv.Atoi(os.Getenv("TASK_TIMEOUT_SECOND"))
	if err == nil && getenv > 0 {
		s.ExportTaskTimeoutSecond = int64(getenv)
	} else {
		s.ExportTaskTimeoutSecond = 4 * 60 * 60 // 4个小时
	}
	return s
}

func (s *ClearFileAndRecord) Run(ctx context.Context) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanReport")
			}
		}()

		tick := time.NewTicker(time.Minute * 5)
		defer tick.Stop()
		for {
			s.Clean(ctx)
			logging.Get().Debug().Msg("finish ClearFileAndRecord job")
			<-tick.C
		}
	}()
}

func (s *ClearFileAndRecord) Clean(ctx context.Context) {

	expirationDate := getExpirationDate(s.Expiration)

	tasks, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesecModel.SearchExportTaskParam{ExpirationDate: expirationDate})
	if err != nil {
		logging.Get().Err(err).Time("expirationDate", expirationDate).Msg("SearchExportTask")
		return
	}
	for i := range tasks {
		// 删除中间目录,任务可能出错，所以不能直接取数据库中的数据
		filePath := strings.ReplaceAll(tasks[i].FilePath, ".zip", "")
		filePath = strings.ReplaceAll(filePath, s.FileDir+"/", "")
		if filePath != "" && s.FileDir != "" && s.FileDir != "/" {
			if err := os.RemoveAll(s.FileDir + "/" + filePath); err != nil {
				logging.Get().Err(err).Int64("taskID", tasks[i].ID).Str("filePath", s.FileDir+"/"+filePath).Msg("RemoveAll")
			}
		}
		// 删除文件
		filePath = strings.ReplaceAll(filePath, s.FileDir+"/", "")
		if filePath != "" && s.FileDir != "" && s.FileDir != "/" {
			if err := os.RemoveAll(s.FileDir + "/" + filePath); err != nil {
				logging.Get().Err(err).Int64("taskID", tasks[i].ID).Str("filePath", s.FileDir+"/"+filePath).Msg("RemoveAll")
			}
		}

		if tasks[i].FilePath != "" && strings.Contains(tasks[i].FilePath, s.FileDir) && strings.Contains(tasks[i].FilePath, ".zip") {
			if err := os.Remove(tasks[i].FilePath); err != nil {
				logging.Get().Err(err).Int64("taskID", tasks[i].ID).Str("fileName", tasks[i].FilePath).Msg("Remove file")
			}
		}

		if err := s.ExportTaskDal.DeleteExportVulnImage(ctx, tasks[i].ID); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportVulnImage")
		}
		if err := s.ExportTaskDal.DeleteExportTaskImage(ctx, tasks[i].ID); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportTaskImage")
		}
		if err := s.ExportTaskDal.DeleteExportTask(ctx, tasks[i].ID); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteExportTask")
		}
		// if err := s.IdempotentDal.DeleteIdempotent(ctx, store.SearchIdempotentParam{
		//	TableId: tasks[i].ID, TableNAME: new(model.ExportTensorTask).TableName()}); err != nil {
		//	logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("DeleteIdempotent")
		// }
	}

	tasks2, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesecModel.SearchExportTaskParam{Finished: consts.FalseString})
	if err != nil {
		logging.Get().Err(err).Time("expirationDate", expirationDate).Msg("SearchExportTask")
		return
	}
	for i := range tasks2 {
		if tasks2[i].StartAt > 0 && tasks2[i].StartAt != consts.ExportHtmlReady &&
			time.Now().Unix()-tasks2[i].StartAt > s.ExportTaskTimeoutSecond {
			updater := map[string]interface{}{
				"finish_at": time.Now().Unix(),
				"err_msg":   imagesecModel.TaskFailedReasonTimeout,
			}

			if err := s.ExportTaskDal.UpdateExportTask(ctx, fmt.Sprintf("id = %d", tasks2[i].ID),
				updater, nil); err != nil {
				logging.Get().Err(err).Int64("taskID", tasks2[i].ID).Msg("ClearFileAndRecord update task timeout")
				continue
			}
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
