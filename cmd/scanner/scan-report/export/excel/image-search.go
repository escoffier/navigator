package excel

import (
	"context"
	"encoding/json"
	"runtime/debug"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

/*
根据筛选条件导出镜像结果
*/

type ImageSearchExportExcel struct {
	ExcelExportService types.ExcelExportService
	UpdateTask         types.UpdateExportTask
	ImageSrv           types.ImageSrvInterface
}

func NewImageSearchExportExcel(
	excelExportService types.ExcelExportService,
	updateTask types.UpdateExportTask,
	nodeImageSrv types.ImageSrvInterface,
) *ImageSearchExportExcel {
	return &ImageSearchExportExcel{
		ExcelExportService: excelExportService,
		UpdateTask:         updateTask,
		ImageSrv:           nodeImageSrv,
	}
}

func (s *ImageSearchExportExcel) Run(ctx context.Context) {
	go s.ExcelExportService.RunExport(ctx, consts.ExportImageSearch, s.GenImageChan, common.ConvertData)
}

func (s *ImageSearchExportExcel) GenImageChan(ctx context.Context, task model.ExportTensorTask) chan imagesecModel.Image {
	out := make(chan imagesecModel.Image, 1)

	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageSearchExportExcel")
			}
		}()

		defer close(out)
		var lastID int64
		var completed int64
		param := imagesecModel.ImageSearchApiParam{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ImageSearchApiParam", task.Parameter).Msg("GenImageChan Unmarshal")
			return
		}
		param.JustReturnImage = true

		var startID int64
		// 批量查询
		param.Filter = &model.Filter{Limit: consts.DefaultMaxLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
		for {
			param.StartID = startID
			images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, param)

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
