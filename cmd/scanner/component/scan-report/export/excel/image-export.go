package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/xuri/excelize/v2"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageExport struct {
	ResourceDal   store.ResourceDal
	ExportTaskDal store.ExportTaskDal
	ImageSrv      ImageInterface
	Interval      time.Duration

	ExportingMap *sync.Map // 正在执行的任务
	FileDir      string    // 文件存储的决对路径
	UpdateTask   export.UpdateTask
}

type ImageExportInterface interface {
	GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error)
	ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error
	GetExcelData(ctx context.Context, imageID int64, vulnCol *atomic.Int32) (map[string]chan []string, error)
}

func NewImageExport(
	resourceDal store.ResourceDal,
	exportTaskDal store.ExportTaskDal,
	imageSrv ImageInterface,
	fileDir string,
	interval time.Duration,
	UpdateTask export.UpdateTask,
) *ImageExport {
	return &ImageExport{
		ResourceDal:   resourceDal,
		ExportTaskDal: exportTaskDal,
		ImageSrv:      imageSrv,
		ExportingMap:  &sync.Map{},
		FileDir:       fileDir,
		Interval:      interval,
		UpdateTask:    UpdateTask,
	}
}

type ImageInterface interface {
	ListBaseImageOfApp(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error)
	ListAppImageOfBase(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error)
	GetImageDetail(ctx context.Context, imgID int64) (*model.ImageList, error)
}

type ImageExportParma struct {
	ImageID int64 `json:"imageID"`
}

type ImageExportData struct {
	BaseDetail []string
}

func (s *ImageExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	task, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		TaskType:    model.ExportExcel,
		ExecuteType: []string{executeType},
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: n})
	if err != nil {
		logging.GetLogger().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return task, nil
}

func (s *ImageExport) Export(ctx context.Context, task model.ExportTensorTask, executeType string) chan *excelize.File {

	out := make(chan *excelize.File, 1)

	go func(task model.ExportTensorTask) {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ImageExport")
			}
		}()
		defer close(out)

		param := ImageExportParma{}

		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.Unmarshal")
			return
		}
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export Parse parameters")

		filename := task.FilePath
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Str("filename", filename).Msg("Export createExcelFile")

		excelData := make(map[string][]chan []string)

		data, err := s.GetExcelData(ctx, param.ImageID, nil)
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.GetExcelData")
			return
		}
		data = s.ConvertData(data)
		for sheetName, dataChan := range data {
			if excelData[sheetName] == nil {
				excelData[sheetName] = make([]chan []string, 0)
			}
			excelData[sheetName] = append(excelData[sheetName], dataChan)
		}
		logging.GetLogger().Debug().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export.GetExcelData")

		sheets := GetImageSheetInfo(executeType)

		excelFile, err := WriteToExcel(filename, sheets, excelData)

		if err != nil {
			logging.GetLogger().Err(err).Msg("Export.WriteToExcel")
			return
		}

		out <- excelFile
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Str("filename", filename).Msg("Export GetExcelData")
	}(task)

	return out
}

func (s *ImageExport) GetExcelData(ctx context.Context, imageID int64, vulnCol *atomic.Int32) (map[string]chan []string, error) {
	// 获取镜像详情
	imageDetail, err := s.ImageSrv.GetImageDetail(ctx, imageID)
	if err != nil {
		logging.GetLogger().Err(err).Int64("ImageID", imageID).Msg("GetDataAndCreateExcelFile.GetImageDetail")
		return nil, err
	}
	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData GetImageDetail")

	if imageDetail.Registry != nil {
		imageDetail.Library = imageDetail.Registry.Url
	}

	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData GetScanOneStatus")

	// 获取关联容器
	// resources, err := s.ResourceDal.SearchResources(ctx, []uint32{imageDetail.ImageUUID})
	// if err != nil {
	// 	logging.GetLogger().Err(err).Int64("imageID", imageID).Uint32("ImageUUID", imageDetail.ImageUUID).Msg("GetDataAndCreateExcelFile.SearchResources")
	// 	return nil, err
	// }
	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData SearchResources")

	res := make(map[string]chan []string)
	// 写入数据
	res[GenImageBaseInfoMeta().SheetName] = GenBaseInfoChan(*imageDetail)
	res[GenImageVulnInfoMeta().SheetName] = GenVulnInfoChan(*imageDetail, vulnCol)
	res[GenImageSensitiveFileInfoMeta().SheetName] = GenSensitiveFileChan(*imageDetail)
	res[GenImageVirusInfoMeta().SheetName] = GenVirusChan(*imageDetail)
	res[GenImageWebshellInfoMeta().SheetName] = GenWebShellChan(*imageDetail)
	res[GenImageEnvInfoMeta().SheetName] = GenEnvChan(*imageDetail)
	// res[GenImageResourcesInfoMeta().SheetName] = GenImageResourceChan(*imageDetail, resources)

	if model.ExistFlag(imageDetail.Flag, model.FlagBaseImage) {
		images, _, err := s.ImageSrv.ListAppImageOfBase(ctx, imageID, nil)
		if err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("GetDataAndCreateExcelFile.WriteToExcel")
			return res, nil
		}
		res[GenImageTypeInfoMeta().SheetName] = GenAppOrBaseImageChan(images)
	}
	if !model.ExistFlag(imageDetail.Flag, model.FlagBaseImage) {
		images, _, err := s.ImageSrv.ListAppImageOfBase(ctx, imageID, nil)
		if err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("GetDataAndCreateExcelFile.WriteToExcel")
			return res, nil
		}
		res[GenImageTypeInfoMeta().SheetName] = GenAppOrBaseImageChan(images)
	}
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
						logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ImageExport")
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

	file, err := ZipExcelFile(files)
	if err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.WriteToExcel")
		return err
	}
	if err := SaveFile(file, s.FileDir+"/"+filename); err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.GetLogger().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile success")
	return nil
}

func (s *ImageExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportSingleImage, consts.DefaultExportBathSize)
	if err != nil {
		return
	}
	for i := range tasks {
		task := tasks[i]
		if ex, ok := s.ExportingMap.Load(task.ID); ok {
			if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
				logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
				continue
			}
		}
		s.ExportingMap.Store(task.ID, consts.TaskExporting)
		if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Run.Start")
			continue
		}

		filename := strings.ReplaceAll(task.FilePath, ".zip", "")

		excelChan := s.Export(ctx, tasks[i], consts.ExportSingleImage)

		if err := s.ZipAndSave(ctx, filename, excelChan); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
			s.ExportingMap.Delete(task.ID)

			if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
			}

			continue
		}
		logging.GetLogger().Info().Int64("taskID", task.ID).Str("filename", filename).Msg("export task success")
		s.ExportingMap.Delete(task.ID)
		// 成功之后更新任务
		if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, filename)); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
	}
	return
}
