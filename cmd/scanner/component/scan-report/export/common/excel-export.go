package common

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"time"

	"go.uber.org/atomic"

	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ExcelExportSrv struct {
	ExportTaskDal store.ExportTaskDal
	LibImageSrv   types.ImageSrvInterface
	NodeImageSrv  types.ImageSrvInterface
	FileDir       string // 文件存储的决对路径
	UpdateTask    types.UpdateExportTask
	MaxVulnCol    int64
}

func NewExcelExportSrv(
	exportTaskDal store.ExportTaskDal,
	libImageSrv types.ImageSrvInterface,
	nodeImageSrv types.ImageSrvInterface,
	fileDir string, // 文件存储的决对路径
	updateTask types.UpdateExportTask,
	maxVulnCol int64,
) *ExcelExportSrv {
	return &ExcelExportSrv{
		ExportTaskDal: exportTaskDal,
		LibImageSrv:   libImageSrv,
		NodeImageSrv:  nodeImageSrv,
		FileDir:       fileDir,
		UpdateTask:    updateTask,
		MaxVulnCol:    maxVulnCol,
	}
}

func (s *ExcelExportSrv) GenExcelFileChan(ctx context.Context, dataChan chan types.ExcelDataWithMeta) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenExcelFileChan")
			}
		}()

		defer close(out)
		var idx int64

		for excelData := range dataChan {
			idx++
			excelFile, err := WriteToExcel(fmt.Sprintf("%s_%d", excelData.Filepath, idx),
				excelData.ExcelMeta, excelData.ExcelExportImageData)
			if err != nil {
				logging.Get().Err(err).Msg("Export.WriteToExcel")
				continue
			}
			out <- excelFile
			logging.Get().Info().Str("excelFile", excelFile.Path).Msg("GenExcelFileChan Send excel file")
		}
	}()

	return out
}

func (s *ExcelExportSrv) GenExcelDataChan(ctx context.Context, excelData types.ExcelDataWithMeta,
	imageChan chan imagesecModel.Image, convertDataFunc types.ConvertDataFunc) chan types.ExcelDataWithMeta {

	out := make(chan types.ExcelDataWithMeta, 1)

	go func(imageIdChan chan imagesecModel.Image) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenExcelFileChan")
			}
		}()
		defer close(out)

		vulnCol := atomic.NewInt32(0)

		for ima := range imageIdChan {

			_ = s.UpdateTask.IncrRedisFinished(ctx, excelData.ExportTask.ID)

			data, err := s.GetExcelData(ctx, ima, vulnCol, excelData.ExportTask)
			if err != nil {
				logging.Get().Err(err).Int64("imageId", ima.ID).Uint64("imageUniqueID", ima.UniqueID).Msg("Export.GetExcelData")
				continue
			}
			logging.Get().Info().Int64("imageId", ima.ID).Uint64("imageUniqueID", ima.UniqueID).Msg("Export.GetExcelData")

			if convertDataFunc != nil {
				data = convertDataFunc(data, excelData.ExportTask.Lang)
			}

			for sheetName, dataChan := range data {
				if excelData.ExcelExportImageData[sheetName] == nil {
					excelData.ExcelExportImageData[sheetName] = make([]chan []string, 0)
				}
				excelData.ExcelExportImageData[sheetName] = append(excelData.ExcelExportImageData[sheetName], dataChan)
			}

			if vulnCol.Load() > int32(s.MaxVulnCol) {
				out <- excelData
				vulnCol = atomic.NewInt32(0)
				excelData.ExcelExportImageData = make(types.ExcelExportImageData)
			}
		}

		if len(excelData.ExcelExportImageData) > 0 {
			out <- excelData
		}

	}(imageChan)

	return out
}

// 取一个任务来执行
func (s *ExcelExportSrv) Export(ctx context.Context, excelData types.ExcelDataWithMeta, imageChan chan imagesecModel.Image,
	convertDataFunc types.ConvertDataFunc) error {

	excelDataChan := s.GenExcelDataChan(ctx, excelData, imageChan, convertDataFunc)
	excelFileChan := s.GenExcelFileChan(ctx, excelDataChan)

	if err := s.ZipAndSave(ctx, excelData.Filepath, excelFileChan); err != nil {
		logging.Get().Err(err).Int64("taskID", excelData.ExportTask.ID).Msg("ZipAndSave")

		if err := s.UpdateTask.Failure(ctx, excelData.ExportTask.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", excelData.ExportTask.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, excelData.ExportTask.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, excelData.Filepath)); err != nil {
		logging.Get().Err(err).Int64("taskID", excelData.ExportTask.ID).Msg("Success export task success update task")
	}

	_ = s.UpdateTask.DeleteRedisData(ctx, excelData.ExportTask.ID)
	return nil
}

func (s *ExcelExportSrv) RunExport(ctx context.Context, executeType string, imageChanFunc types.GenImageChanFunc,
	convertDataFunc types.ConvertDataFunc) {

	taskChan := s.GenTensorExportTaskChan(ctx, executeType)

	for task := range taskChan {

		if err := s.UpdateTask.Start(ctx, task.ID); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Clean Start")
			continue
		}

		excelData := types.ExcelDataWithMeta{
			ExcelExportImageData: make(types.ExcelExportImageData),
			Filepath:             task.GenFilenamePrefix(),
			ExcelMeta:            GetImageSheetInfo(task),
			ExportTask:           task,
		}

		if err := s.Export(ctx, excelData, imageChanFunc(ctx, task), convertDataFunc); err != nil {
			logging.Get().Err(err).Interface("task", task).Msg("Export fail")
			continue
		}
		logging.Get().Info().Interface("task", task).Msg("Export succeed")
	}
}

func (s *ExcelExportSrv) GetExcelData(ctx context.Context, image imagesecModel.Image, vulnCol *atomic.Int32, task model.ExportTensorTask) (
	map[types.SheetName]chan []string, error) {
	// 获取镜像详情
	logging.Get().Info().Int64("imageID", image.ID).Uint64("ImageUniqueID", image.UniqueID).
		Msg("GetExcelData GetImageDetail start")

	data, err := s.getImageSrv(ctx, image.ImageFromType).GetImageCorrelateData(ctx, imagesecModel.GetImageAssociateDataParam{
		ImageUniqueID:   image.UniqueID,
		ImageId:         image.ID,
		VulnEnable:      true,
		MalwareEnable:   true,
		EnvEnable:       true,
		PkgEnable:       true,
		SensitiveEnable: true,
		WebshellEnable:  true,
		ContainerEnable: true,
		SubtaskEnable:   true,
		RegistryEnable:  true,
		BaseImageEnable: true,
		AppImageEnable:  true,
	})
	if err != nil {
		logging.Get().Info().Int64("imageID", image.ID).Uint64("ImageUniqueID", image.UniqueID).
			Msg("GetDataAndCreateExcelFile.GetImageDetail")
		return nil, err
	}

	baseImage := data.ToImageBaseResponse()

	baseImage.AdaptI18(context.WithValue(ctx, model.AcceptLanguage, task.Lang))
	for i := range data.Vuln {
		data.Vuln[i].AdaptI18(context.WithValue(ctx, model.AcceptLanguage, task.Lang))
	}

	res := make(map[types.SheetName]chan []string)
	// 写入数据
	res[GenImageBaseInfoMeta(task.Lang).SheetName] = GenBaseInfoChan(baseImage, task.Lang)
	res[GenImageVulnInfoMeta(task.Lang).SheetName] = GenVulnInfoChan(baseImage, data.Vuln, task.Lang)
	res[GenImageSensitiveFileInfoMeta(task.Lang).SheetName] = GenSensitiveFileChan(baseImage, data.Sensitive)
	res[GenImageVirusInfoMeta(task.Lang).SheetName] = GenMalwareChan(baseImage, data.Malware)
	res[GenImageWebshellInfoMeta(task.Lang).SheetName] = GenWebShellChan(baseImage, data.Webshell)
	res[GenImageEnvInfoMeta(task.Lang).SheetName] = GenEnvChan(baseImage, data.Env)
	res[GenImageResourcesInfoMeta(task.Lang).SheetName] = GenImageResourceChan(baseImage, data.Container)

	if model.ExistFlag(baseImage.Flag, model.FlagBaseImage) {
		res[GenImageTypeInfoMeta(task.Lang).SheetName] = GenAppOrBaseImageChan(data.AppImages)
	}
	if !model.ExistFlag(baseImage.Flag, model.FlagBaseImage) {
		res[GenImageTypeInfoMeta(task.Lang).SheetName] = GenAppOrBaseImageChan(data.BaseImages)
	}
	if vulnCol != nil {
		vulnCol.Add(int32(len(data.Vuln)))
	}

	logging.Get().Info().Int64("imageID", image.ID).Uint64("ImageUniqueID", image.UniqueID).
		Int("vulnCount", len(data.Vuln)).Msg("GetExcelData GetImageDetail end")

	return res, nil
}

// 压缩并写入文件，filename 路径名
func (s *ExcelExportSrv) ZipAndSave(ctx context.Context, filename string, excelFileChan chan *excelize.File) error {

	// 先保存所有的excel文件
	filePath := s.FileDir + "/" + filename
	defer func() {
		if filePath != "" {
			if err := os.RemoveAll(filePath); err != nil {
				logging.Get().Err(err).Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
			}
			logging.Get().Info().Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
		}
	}()

	if err := util.MkdirIfNotExist(filePath, true); err != nil {
		logging.Get().Info().Str("filePath", filePath).Msg("ZipAndSave MkdirIfNotExist")
		return err
	}

	for file := range excelFileChan {
		// 检测目录是否存在
		if err := file.SaveAs(filePath + "/" + file.Path); err != nil {
			logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave")
			continue
		}
		logging.Get().Info().Str("filePath", filePath).Str("excelFile", file.Path).Msg("ZipAndSave save excel file")
		if err := file.Close(); err != nil {
			logging.Get().Info().Str("filePath", filePath).Str("excelFile", file.Path).Msg("ZipAndSave close excel file")
		}
		file = nil // For GC
	}
	logging.Get().Info().Str("filePath", filePath).Msg("ZipAndSave save all  excel file start zip files")

	if filePath != "" {
		// 调用用命令进行压缩
		zipFilename := filePath + ".zip"
		logging.Get().Info().Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ZipAndSave use zip start zip")

		cmd := exec.Command("zip", "-j", "-r", zipFilename, filePath)
		if err := cmd.Run(); err != nil {
			logging.Get().Err(err).Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ZipAndSave use zip")
			return err
		}
	}

	return nil
}

func (s *ExcelExportSrv) GenTensorExportTaskChan(ctx context.Context, executeType string) chan model.ExportTensorTask {
	out := make(chan model.ExportTensorTask, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("GenTensorExportTaskChan")
			}
		}()
		defer close(out)

		tick := time.NewTicker(time.Second * 10)
		defer tick.Stop()

		for {
			<-tick.C

			task, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
				TaskType:    model.ExportExcel,
				ExecuteType: []string{executeType},
				Finished:    consts.FalseString,
				Failure:     consts.FalseString,
			}, &model.Filter{Limit: 1})
			if err != nil {

				logging.Get().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
				continue
			}
			for i := range task {
				out <- task[i]
			}
		}
	}()
	return out
}

func (s *ExcelExportSrv) getImageSrv(ctx context.Context, imageFromType string) types.ImageSrvInterface {
	if imageFromType == imagesecModel.ImageFromNode {
		return s.NodeImageSrv
	}
	return s.LibImageSrv
}

func ConvertData(res map[types.SheetName]chan []string, lang string) map[types.SheetName]chan []string {

	if lang == model.LangZh || lang == "" {
		return res
	}

	ans := make(map[types.SheetName]chan []string)

	for key, value := range res {
		out := make(chan []string)
		go func(key string, value chan []string) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageExport")
				}
			}()

			defer close(out)

			for data := range value {
				data = ReplaceToEN(data)
				out <- data
			}
		}(key.String(), value)
		ans[key] = out
	}
	return ans
}
