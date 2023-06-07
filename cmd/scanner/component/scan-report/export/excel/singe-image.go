package excel

import (
	"context"
	"encoding/json"
	"runtime/debug"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type SingeImageExport struct {
	ExcelExportService types.ExcelExportService
}

func NewSingeImageExport(
	excelExportService types.ExcelExportService,
) *SingeImageExport {
	return &SingeImageExport{
		ExcelExportService: excelExportService,
	}
}

func (s *SingeImageExport) GenImageChan(ctx context.Context, task model.ExportTensorTask) chan imagesecModel.Image {
	out := make(chan imagesecModel.Image, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("SingeImageExportParam")
			}
		}()

		defer close(out)
		ima := types.SingeImageExportParam{}
		if err := json.Unmarshal([]byte(task.Parameter), &ima); err != nil {
			logging.Get().Err(err).Interface("task", task).Msg("GenImageChan")
			return
		}
		if ima.ImageID <= 0 {
			logging.Get().Info().Interface("task", task).Msg("GenImageChan get get image")
			return
		}
		out <- imagesecModel.Image{ID: ima.ImageID, ImageFromType: ima.ImageFromType}
	}()
	return out
}

// 对于单个镜像的导出，不需要镜像名称和仓库来源两列
func (s *SingeImageExport) ConvertData(res map[string]chan []string) map[string]chan []string {

	ans := make(map[string]chan []string)

	for key, value := range res {
		if key == common.GenImageTypeInfoMeta().SheetName || key == common.GenImageBaseInfoMeta().SheetName {
			ans[key] = value
		} else {
			out := make(chan []string, 1)
			go func(value chan []string) {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageExport")
					}
				}()

				defer close(out)

				for data := range value {
					data = data[2:]
					out <- data
				}
			}(value)
			ans[key] = out
		}
	}
	return ans
}

func (s *SingeImageExport) Run(ctx context.Context) {
	go s.ExcelExportService.RunExport(ctx, consts.ExportSingleImage, s.GenImageChan, s.ConvertData)
}
