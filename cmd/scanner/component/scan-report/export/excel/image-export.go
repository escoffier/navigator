package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageExport struct {
	ExportTaskDal store.ExportTaskDal
	ImageSrv      common.ImageInterface
	FileDir       string // 文件存储的决对路径
	UpdateTask    common.UpdateExportTask
}

type ImageExportInterface interface {
	GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error)
	ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error
	GetExcelData(ctx context.Context, imageID int64, vulnCol *atomic.Int32) (map[string]chan []string, error)
}

func NewImageExport(
	exportTaskDal store.ExportTaskDal,
	imageSrv common.ImageInterface,
	fileDir string,
	updateTask common.UpdateExportTask,
) *ImageExport {
	return &ImageExport{
		ExportTaskDal: exportTaskDal,
		ImageSrv:      imageSrv,
		FileDir:       fileDir,
		UpdateTask:    updateTask,
	}
}

type ImageExportParma struct {
	ImageID int64 `json:"imageID"`
}

func (s *ImageExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	task, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		TaskType:    model.ExportExcel,
		ExecuteType: []string{executeType},
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: n})
	if err != nil {
		logging.Get().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return task, nil
}

func (s *ImageExport) Export(ctx context.Context, task model.ExportTensorTask, executeType string) chan *excelize.File {

	out := make(chan *excelize.File, 1)

	go func(task model.ExportTensorTask) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageExport")
			}
		}()
		defer close(out)

		param := ImageExportParma{}

		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Export.Unmarshal")
			return
		}
		logging.Get().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export Parse parameters")

		filename := strings.Replace(task.FilePath, ".zip", "", 1)
		logging.Get().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Str("filename", filename).Msg("Export createExcelFile")

		excelData := make(map[string][]chan []string)

		data, err := s.GetExcelData(ctx, param.ImageID, nil)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Export.GetExcelData")
			return
		}
		data = s.ConvertData(data)
		for sheetName, dataChan := range data {
			if excelData[sheetName] == nil {
				excelData[sheetName] = make([]chan []string, 0)
			}
			excelData[sheetName] = append(excelData[sheetName], dataChan)
		}
		logging.Get().Debug().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export.GetExcelData")

		sheets := GetImageSheetInfo(executeType)

		excelFile, err := common.WriteToExcel(filename, sheets, excelData)

		if err != nil {
			logging.Get().Err(err).Msg("Export.WriteToExcel")
			return
		}

		out <- excelFile
		logging.Get().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Str("filename", filename).Msg("Export GetExcelData")
	}(task)

	return out
}

func (s *ImageExport) GetExcelData(ctx context.Context, imageID int64, vulnCol *atomic.Int32) (map[string]chan []string, error) {
	// 获取镜像详情
	logging.Get().Info().Int64("imageID", imageID).Msg("GetExcelData GetImageDetail start")
	data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{
		ImageId:         imageID,
		VulnEnable:      true,
		VirusEnable:     true,
		EnvEnable:       true,
		SoftwareEnable:  true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		ContainerEnable: true,
		SubtaskEnable:   true,
		RegistryEnable:  true,
		BaseImageEnable: true,
		AppImageEnable:  true,
	})
	if err != nil {
		logging.Get().Err(err).Int64("ImageID", imageID).Msg("GetDataAndCreateExcelFile.GetImageDetail")
		return nil, err
	}

	baseImage := data.ToImageBaseResponse()

	res := make(map[string]chan []string)
	// 写入数据
	res[GenImageBaseInfoMeta().SheetName] = GenBaseInfoChan(*data)
	res[GenImageVulnInfoMeta().SheetName] = GenVulnInfoChan(baseImage, data.Vuln)
	res[GenImageSensitiveFileInfoMeta().SheetName] = GenSensitiveFileChan(baseImage, data.Sensitive)
	res[GenImageVirusInfoMeta().SheetName] = GenVirusChan(baseImage, data.Virus)
	res[GenImageWebshellInfoMeta().SheetName] = GenWebShellChan(baseImage, data.Webshell)
	res[GenImageEnvInfoMeta().SheetName] = GenEnvChan(baseImage, data.Env)
	res[GenImageResourcesInfoMeta().SheetName] = GenImageResourceChan(baseImage, data.Container)

	if model.ExistFlag(baseImage.Flag, model.FlagBaseImage) {
		res[GenImageTypeInfoMeta().SheetName] = GenAppOrBaseImageChan(data.AppImages)
	}
	if !model.ExistFlag(baseImage.Flag, model.FlagBaseImage) {
		res[GenImageTypeInfoMeta().SheetName] = GenAppOrBaseImageChan(data.BaseImages)
	}
	if vulnCol != nil {
		vulnCol.Add(int32(len(data.Vuln)))
	}

	logging.Get().Info().Int64("imageID", imageID).Int("vulnCount", len(data.Vuln)).Msg("GetExcelData GetImageDetail end")
	return res, nil
}

// 对于单个镜像的导出，不需要镜像名称和仓库来源两列
func (s *ImageExport) ConvertData(res map[string]chan []string) map[string]chan []string {

	ans := make(map[string]chan []string)

	for key, value := range res {
		if key == GenImageTypeInfoMeta().SheetName || key == GenImageBaseInfoMeta().SheetName {
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

func (s *ImageExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {

	file, err := common.ZipExcelFile(files)
	if err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.WriteToExcel")
		return err
	}
	if err := common.SaveFile(file, s.FileDir+"/"+filename); err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.Get().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile success")
	return nil
}

func (s *ImageExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportSingleImage, consts.DefaultExportBathSize)
	if err != nil {
		return
	}
	for i := range tasks {
		task := tasks[i]

		// 支持横向扩展
		created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, task.ID)
		if err != nil {
			logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv CreateExportIdempotent")
			return
		}
		if !created {
			continue
		}

		if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Run.Start")
			continue
		}

		filename := strings.ReplaceAll(task.FilePath, ".zip", "")

		excelChan := s.Export(ctx, tasks[i], consts.ExportSingleImage)

		if err := s.ZipAndSave(ctx, filename, excelChan); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")

			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
			}
			continue
		}
		logging.Get().Info().Int64("taskID", task.ID).Str("filename", filename).Msg("export task success")
		// 成功之后更新任务
		if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, filename)); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
	}
	return
}
