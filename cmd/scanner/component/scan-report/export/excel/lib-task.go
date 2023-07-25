package excel

import (
	"context"
	"runtime/debug"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type LibImageScanTaskExport struct {
	ExcelExportService types.ExcelExportService
	ScanTaskDal        store.ScanTaskDal
	UpdateTask         types.UpdateExportTask
}

func NewLibScanTaskExport(
	excelExportService types.ExcelExportService,
	scanTaskDal store.ScanTaskDal,
	updateTask types.UpdateExportTask,
) *LibImageScanTaskExport {
	return &LibImageScanTaskExport{
		ExcelExportService: excelExportService,
		ScanTaskDal:        scanTaskDal,
		UpdateTask:         updateTask,
	}
}

func (s *LibImageScanTaskExport) Run(ctx context.Context) {
	go s.ExcelExportService.RunExport(ctx, consts.ExportLibTask, s.GenImageChan, common.ConvertData)
}

func (s *LibImageScanTaskExport) GenImageChan(ctx context.Context, task model.ExportTensorTask) chan imagesecModel.Image {
	out := make(chan imagesecModel.Image, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("LibImageScanTaskExport")
			}
		}()

		defer close(out)

		var lastID int64
		var completed int64
		param := types.TaskExportParma{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageChan Unmarshal")
			return
		}
		// 前端传过来的是groupID
		scanTasks, _, err := s.ScanTaskDal.GetTaskList(ctx, store.SearchTaskParam{GroupID: param.ScanTaskID}, nil)
		if err != nil {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageChan GetTaskList")
			return
		}

		taskIds := make([]int64, 0)
		for i := range scanTasks {
			taskIds = append(taskIds, scanTasks[i].ID)
		}
		if len(taskIds) == 0 {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageChan not fond task")
			return
		}

		for {
			scanTask, cnt, err := s.ScanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
				TaskIds: taskIds, Statuses: []int{consts.ImageScanSuccess}, StartID: lastID},
				&model.Filter{Limit: consts.DefaultBathSize, SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("GenImageChan Export.GetSubTasks")
				return
			}
			if len(scanTask) == 0 {
				logging.Get().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).
					Int64("completed", completed).Msg("GenImageChan all image completed")
				break
			}
			_ = s.UpdateTask.SetRedisAll(ctx, task.ID, cnt)

			lastID = scanTask[len(scanTask)-1].ID
			for i := range scanTask {
				out <- imagesecModel.Image{
					ID:            scanTask[i].ImageID,
					ImageFromType: imagesecModel.ImageFromRegistry,
				}
			}
			completed += int64(len(scanTask))
			logging.Get().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).
				Msg("GenImageChan.partially completed")
		}
	}()

	return out
}
