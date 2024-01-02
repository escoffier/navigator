package excel

import (
	"context"
	"runtime/debug"

	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ImageScanTaskExport struct {
	ExcelExportService types.ExcelExportService
	ScanTaskDal        imagesecStore.ScanTaskDal
	UpdateTask         types.UpdateExportTask
}

func NewNodeImageScanTaskExport(
	excelExportService types.ExcelExportService,
	scanTaskDal imagesecStore.ScanTaskDal,
	updateTask types.UpdateExportTask,
) *ImageScanTaskExport {
	return &ImageScanTaskExport{
		ExcelExportService: excelExportService,
		ScanTaskDal:        scanTaskDal,
		UpdateTask:         updateTask,
	}
}

func (s *ImageScanTaskExport) Run(ctx context.Context) {
	go s.ExcelExportService.RunExport(ctx, consts.ExportScanTask, s.GenImageChan, common.ConvertData)
}

func (s *ImageScanTaskExport) GenImageChan(ctx context.Context, task imagesecModel.ExportTensorTask) chan imagesecModel.Image {
	out := make(chan imagesecModel.Image, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageScanTaskExport")
			}
		}()

		defer close(out)

		var completed int64
		var lastID int64
		param := types.TaskExportParma{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageChan Unmarshal")
			return
		}

		filter := imagesecModel.EmptyFilter().SetSortFiledByID().SetSortAsc().SetLimit(consts.DefaultMaxLimit)
		for {
			scanTask, cnt, err := s.ScanTaskDal.SearchScanSubtask(ctx, imagesecModel.SearchTaskParam{
				TaskID:  param.ScanTaskID,
				StartID: lastID,
				Filter:  filter,
			})
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
					UniqueID:      scanTask[i].ImageUniqueID,
					ImageFromType: param.ImageFromType,
				}
			}
			completed += int64(len(scanTask))
			logging.Get().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).
				Int64("completed", completed).Msg("GenImageChan.partially completed")
		}
	}()

	return out
}
