package excel

import (
	"context"
	"encoding/json"
	"runtime/debug"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

/*
根据筛选条件导出镜像结果
*/

type LibImageSearchExportExcel struct {
	ExcelExportService types.ExcelExportService
	UpdateTask         types.UpdateExportTask
	LibImageSrv        types.ImageSrvInterface
}

func NewLibImageSearchExportExcel(
	excelExportService types.ExcelExportService,
	updateTask types.UpdateExportTask,
	libImageSrv types.ImageSrvInterface,
) *LibImageSearchExportExcel {
	return &LibImageSearchExportExcel{
		ExcelExportService: excelExportService,
		UpdateTask:         updateTask,
		LibImageSrv:        libImageSrv,
	}
}

func (s *LibImageSearchExportExcel) GenImageChan(ctx context.Context, task model.ExportTensorTask) chan imagesecModel.Image {
	out := make(chan imagesecModel.Image, 1)

	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("LibImageSearchExportExcel")
			}
		}()

		defer close(out)
		var lastID int64
		var completed int64
		param := imagesecModel.ImageListParam{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ImageListParam", task.Parameter).Msg("GenImageChan Unmarshal")
			return
		}
		param.JustReturnImage = true

		var startID int64
		// 批量查询
		param.Filter = &model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
		for {
			param.StartID = startID
			images, cnt, err := s.LibImageSrv.ListImageWithScanInfo(ctx, param)

			if err != nil {
				return
			}
			if len(images) == 0 {
				break
			}
			_ = s.UpdateTask.SetRedisAll(ctx, task.ID, cnt)
			startID = images[len(images)-1].ID
			for i := range images {
				out <- imagesecModel.Image{
					ID:            images[i].ID,
					ImageFromType: images[i].ImageFromType,
				}
			}
			completed += int64(len(images))
			logging.Get().Info().Int64("taskID", task.ID).Int64("lastImageID", lastID).
				Int64("completed", completed).Msg("GenImageChan partially")
		}

		logging.Get().Info().Int64("taskID", task.ID).Int64("lastImageID", lastID).
			Int64("completed", completed).Msg("GenImageChan completed")
	}()

	return out
}

func (s *LibImageSearchExportExcel) Run(ctx context.Context) {
	go s.ExcelExportService.RunExport(ctx, consts.ExportLibImageSearch, s.GenImageChan, nil)
}
