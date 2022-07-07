package export

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xuri/excelize/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ImageExport struct {
	resourceDal   store.ResourceDal
	exportTaskDal store.ExportTaskDal
	imageSrv      ImageInterface
	Interval      time.Duration

	exportingMap *sync.Map // 正在执行的任务
	fileDir      string    // 文件存储的决对路径
}

type ImageExportInterface interface {
	GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error)
	ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error
	GetExcelData(ctx context.Context, imageID int64) (map[string]chan []string, error)
}

type UpdateTask interface {
	Start(ctx context.Context, id int64) error
	Success(ctx context.Context, id int64, filePath string) error
	Failure(ctx context.Context, id int64, msg string) error
}

func NewImageExport(
	resourceDal store.ResourceDal,
	exportTaskDal store.ExportTaskDal,
	imageSrv ImageInterface,
	fileDir string,
	interval time.Duration,
) *ImageExport {
	return &ImageExport{
		resourceDal:   resourceDal,
		exportTaskDal: exportTaskDal,
		imageSrv:      imageSrv,
		exportingMap:  &sync.Map{},
		fileDir:       fileDir,
		Interval:      interval,
	}
}

type ImageInterface interface {
	ListBaseImageOfApp(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error)
	ListAppImageOfBase(ctx context.Context, imageID int64, filter *model.Filter) ([]model.ImageList, int64, error)
	GetImageDetail(ctx context.Context, imgID int64) (*model.ImageList, error)
	GetScanOneStatus(ctx context.Context, imgID int64) (*model.ImageResponse, error)
}

type ImageExportParma struct {
	ImageID int64 `json:"imageID"`
}

type ImageExportData struct {
	BaseDetail []string
}

func (s *ImageExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	task, _, err := s.exportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		ExecuteType: executeType,
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: n})
	if err != nil {
		logging.GetLogger().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return task, nil
}

func (s *ImageExport) Export(ctx context.Context, task model.ExportTensorTask, executeType consts.ExportType) chan *excelize.File {

	out := make(chan *excelize.File)

	go func(task model.ExportTensorTask) {

		defer close(out)

		param := ImageExportParma{}

		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.Unmarshal")
			return
		}
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export Parse parameters")

		filename, err := s.genFilename(ctx, task)
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.genFilename")
			return
		}
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Str("filename", filename).Msg("Export createExcelFile")

		excelData := make(map[string][]chan []string)

		data, err := s.GetExcelData(ctx, param.ImageID)
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
		logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", param.ImageID).Msg("Export.GetExcelData")

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

func (s *ImageExport) GetExcelData(ctx context.Context, imageID int64) (map[string]chan []string, error) {
	// 获取镜像详情
	imageDetail, err := s.imageSrv.GetImageDetail(ctx, imageID)
	if err != nil {
		logging.GetLogger().Err(err).Int64("ImageID", imageID).Msg("GetDataAndCreateExcelFile.GetImageDetail")
		return nil, err
	}
	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData GetImageDetail")

	if imageDetail.Registry != nil {
		imageDetail.Library = imageDetail.Registry.Url
	}

	imageStatus, err := s.imageSrv.GetScanOneStatus(ctx, imageID)
	if err != nil {
		logging.GetLogger().Err(err).Int64("ImageID", imageID).Msg("GetDataAndCreateExcelFile.GetImageDetail")
		return nil, err
	}
	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData GetScanOneStatus")

	// 获取关联容器
	resources, err := s.resourceDal.SearchResources(ctx, imageDetail.ImageUUID)
	if err != nil {
		logging.GetLogger().Err(err).Int64("imageID", imageID).Uint32("ImageUUID", imageDetail.ImageUUID).Msg("GetDataAndCreateExcelFile.SearchResources")
		return nil, err
	}
	logging.GetLogger().Debug().Int64("imageID", imageID).Msg("GetExcelData SearchResources")

	res := make(map[string]chan []string)
	// 写入数据
	res[GenImageBaseInfoMeta().SheetName] = GenBaseInfoChan(*imageDetail, *imageStatus)
	res[GenImageVulnInfoMeta().SheetName] = GenVulnInfoChan(*imageDetail)
	res[GenImageSensitiveFileInfoMeta().SheetName] = GenSensitiveFileChan(*imageDetail)
	res[GenImageVirusInfoMeta().SheetName] = GenVirusChan(*imageDetail)
	res[GenImageWebshellInfoMeta().SheetName] = GenWebShellChan(*imageDetail)
	res[GenImageEnvInfoMeta().SheetName] = GenEnvChan(*imageDetail)
	res[GenImageResourcesInfoMeta().SheetName] = GenImageResourceChan(*imageDetail, resources)

	if model.ExistFlag(imageDetail.Flag, model.FlagBaseImage) {
		images, _, err := s.imageSrv.ListAppImageOfBase(ctx, imageID, nil)
		if err != nil {
			logging.GetLogger().Err(err).Int64("imageID", imageID).Msg("GetDataAndCreateExcelFile.WriteToExcel")
			return res, nil
		}
		res[GenImageTypeInfoMeta().SheetName] = GenAppOrBaseImageChan(images)
	}
	if !model.ExistFlag(imageDetail.Flag, model.FlagBaseImage) {
		images, _, err := s.imageSrv.ListAppImageOfBase(ctx, imageID, nil)
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
			out := make(chan []string)
			go func(value chan []string) {
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

func (s *ImageExport) genFilename(ctx context.Context, task model.ExportTensorTask) (string, error) {
	searchParam := ImageExportParma{}
	if err := json.Unmarshal([]byte(task.Parameter), &searchParam); err != nil {
		return "", err
	}

	imageDetail, err := s.imageSrv.GetImageDetail(ctx, searchParam.ImageID)
	if err != nil {
		return "", err
	}

	fileName := fmt.Sprintf("%s_%s_%d", strings.ReplaceAll(imageDetail.FullRepoName, "/", "_"),
		imageDetail.Tags, task.CreatedAt.Unix())
	return fileName, nil
}

func (s *ImageExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {

	file, err := ZipExcelFile(files)
	if err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.WriteToExcel")
		return err
	}
	if err := SaveFile(file, s.fileDir+"/"+filename); err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.GetLogger().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile success")
	return nil
}

func (s *ImageExport) Success(ctx context.Context, id int64, filePath string) error {

	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := s.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil

}

func (s *ImageExport) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (s *ImageExport) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}

func (s *ImageExport) Run(ctx context.Context) {
	// // 检测当查正在执行的任务数
	// runningTaskCount := CountRunningTask(s.exportingMap)
	//
	// if runningTaskCount >= s.ParallelTaskNum {
	// 	logging.GetLogger().Info().Int64("runningTaskCount", runningTaskCount).Int64("ParallelTaskNum", s.ParallelTaskNum).Msg("ImageExport export task in progress")
	// 	return
	// }

	tasks, err := s.GetTensorTask(ctx, string(consts.ExportImage), consts.DefaultExportBathSize)
	if err != nil {
		return
	}
	for i := range tasks {
		task := tasks[i]
		if ex, ok := s.exportingMap.Load(task.ID); ok {
			if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
				logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
				continue
			}
		}
		s.exportingMap.Store(task.ID, consts.TaskExporting)
		if err := s.Start(ctx, task.ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Run.Start")
			continue
		}

		filename, err := s.genFilename(ctx, task)
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("genFilename")
			s.exportingMap.Delete(task.ID)
			if err := s.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure genFilename")
			}
			continue
		}

		excelChan := s.Export(ctx, tasks[i], consts.ExportImage)

		if err := s.ZipAndSave(ctx, filename, excelChan); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
			s.exportingMap.Delete(task.ID)

			if err := s.Failure(ctx, task.ID, err.Error()); err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
			}

			continue
		}
		logging.GetLogger().Info().Int64("taskID", task.ID).Str("filename", filename).Msg("export task success")
		s.exportingMap.Delete(task.ID)
		// 成功之后更新任务
		if err := s.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.fileDir, filename)); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
	}
	return
}
