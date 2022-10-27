package excel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"

	json "github.com/json-iterator/go"
	"github.com/xuri/excelize/v2"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ScanTaskExport struct {
	ImageExport             ImageExportInterface
	ExportTaskDal           store.ExportTaskDal
	ScanTaskDal             store.ScanTaskDal
	ExportingMap            *sync.Map // 正在执行的任务
	FileDir                 string    // 文件存储的决对路径
	UpdateTask              export.UpdateTask
	MaxVulnCol              int64
	MaxImageByOneExportTask int64
}

func NewScanTaskExport(
	imageExport ImageExportInterface,
	exportTaskDal store.ExportTaskDal,
	scanTaskDal store.ScanTaskDal,
	fileDir string, // 文件存储的决对路径
	updateTask export.UpdateTask,
	maxVulnCol int64,
	maxImageByOneExportTask int64,
) *ScanTaskExport {
	return &ScanTaskExport{
		ImageExport:             imageExport,
		ExportTaskDal:           exportTaskDal,
		ScanTaskDal:             scanTaskDal,
		ExportingMap:            &sync.Map{},
		FileDir:                 fileDir,
		UpdateTask:              updateTask,
		MaxVulnCol:              maxVulnCol,
		MaxImageByOneExportTask: maxImageByOneExportTask,
	}
}

type TaskExportParma struct {
	ScanTaskID int64 `json:"scanTaskId"`
}

func (s *ScanTaskExport) GenExcelFileChan(ctx context.Context, dataChan chan ExcelDataWithMeta) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()

		defer close(out)

		for excelData := range dataChan {
			excelFile, err := WriteToExcel(excelData.Filename, excelData.ExcelMetaData, excelData.ExcelData)
			if err != nil {
				logging.GetLogger().Err(err).Msg("Export.WriteToExcel")
				continue
			}
			// 没有基础镜像和应用镜像这一张表,删除
			excelFile.DeleteSheet(GenImageTypeInfoMeta().SheetName)
			out <- excelFile
			logging.GetLogger().Info().Str("excelFile", excelFile.Path).Msg("GenExcelFileChan Send excel file")
		}
	}()

	return out
}

type ExcelData map[string][]chan []string // key：excel sheet name

type ExcelDataWithMeta struct {
	ExcelData     ExcelData
	Filename      string
	ExcelMetaData []ExcelMetaData
}

func (s *ScanTaskExport) GenExcelDataChan(ctx context.Context, imageIdChan chan int64, filenamePrefix string) chan ExcelDataWithMeta {
	out := make(chan ExcelDataWithMeta, 1)

	go func(scanTaskChan chan int64) {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()
		defer close(out)

		vulnCol := atomic.NewInt32(0)
		index := 0

		excelData := ExcelDataWithMeta{
			ExcelData:     make(ExcelData),
			Filename:      fmt.Sprintf("%s_%d", filenamePrefix, index),
			ExcelMetaData: GetImageSheetInfo(consts.ExportScanResult),
		}

		for imageId := range scanTaskChan {
			data, err := s.ImageExport.GetExcelData(ctx, imageId, vulnCol)
			if err != nil {
				logging.GetLogger().Err(err).Int64("imageId", imageId).Msg("Export.GetExcelData")
			} else {
				for sheetName, dataChan := range data {
					if excelData.ExcelData[sheetName] == nil {
						excelData.ExcelData[sheetName] = make([]chan []string, 0)
					}
					excelData.ExcelData[sheetName] = append(excelData.ExcelData[sheetName], dataChan)
				}
			}

			if vulnCol.Load() > int32(s.MaxVulnCol) {
				out <- excelData
				index++
				vulnCol = atomic.NewInt32(0)
				excelData = ExcelDataWithMeta{
					ExcelData:     make(ExcelData),
					Filename:      fmt.Sprintf("%s_%d", filenamePrefix, index),
					ExcelMetaData: GetImageSheetInfo(consts.ExportScanResult),
				}
			}
		}

		if len(excelData.ExcelData) > 0 {
			out <- excelData
		}

	}(imageIdChan)

	return out
}

func (s *ScanTaskExport) GenImageIdChan(ctx context.Context, task model.ExportTensorTask) chan int64 {
	out := make(chan int64, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()

		defer close(out)

		var lastID int64
		var completed int64
		param := TaskExportParma{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.GetLogger().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan Unmarshal")
			return
		}
		// 前端传过来的是groupID
		scanTasks, _, err := s.ScanTaskDal.GetTaskList(ctx, store.SearchTaskParam{GroupID: param.ScanTaskID}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan GetTaskList")
			return
		}
		taskIds := make([]int64, 0)
		for i := range scanTasks {
			taskIds = append(taskIds, scanTasks[i].ID)
		}
		if len(taskIds) == 0 {
			logging.GetLogger().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan not fond task")
			return
		}

		for {
			scanTask, _, err := s.ScanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
				TaskIds: taskIds, Statuses: []int{consts.ImageScanSuccess}, LastID: lastID},
				&model.Filter{Limit: Min(consts.DefaultBathSize, s.MaxImageByOneExportTask-completed), SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("GenImageIdChan Export.GetSubTasks")
				return
			}
			if len(scanTask) == 0 {
				logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageIdChan all image completed")
				break
			}
			lastID = scanTask[len(scanTask)-1].ID
			for i := range scanTask {
				out <- scanTask[i].ImageID
			}
			completed += int64(len(scanTask))
			logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageIdChan.partially completed")
		}
	}()

	return out
}

// 压缩并写入文件，filename 路径名
func (s *ScanTaskExport) ZipAndSave(ctx context.Context, filename string, excelFileChan chan *excelize.File) error {

	// 先保存所有的excel文件
	var filePath string
	defer func() {
		if filePath != "" {
			if err := os.RemoveAll(filePath); err != nil {
				logging.GetLogger().Err(err).Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
			}
			logging.GetLogger().Info().Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
		}
	}()
	remove := true

	for file := range excelFileChan {
		filePath = s.FileDir + "/" + filename
		// 检测目录是否存在
		if err := utils.MkdirIfNotExist(filePath, remove); err != nil {
			logging.GetLogger().Err(err).Str("filePath", filePath).Msg("ZipAndSave MkdirIfNotExist")
			return err
		}
		remove = false
		if err := file.SaveAs(filePath + "/" + file.Path); err != nil {
			logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave")
			continue
		}
		logging.GetLogger().Info().Str("filePath", filePath).Str("excelFile", file.Path).Msg("ZipAndSave save excel file")
		if err := file.Close(); err != nil {
			logging.GetLogger().Info().Str("filePath", filePath).Str("excelFile", file.Path).Msg("ZipAndSave close excel file")
		}
		file = nil // GC
	}
	logging.GetLogger().Info().Str("filePath", filePath).Msg("ZipAndSave save all  excel file start zip files")

	if filePath != "" {
		// 调用用命令进行压缩
		zipFilename := filePath + ".zip"
		logging.GetLogger().Info().Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ZipAndSave use zip start zip")

		cmd := exec.Command("zip", "-j", "-r", zipFilename, filePath)
		if err := cmd.Run(); err != nil {
			logging.GetLogger().Err(err).Str("zipFilename", zipFilename).Str("filePath", filePath).Msg("ZipAndSave use zip")
			return err
		}
	}
	return nil
}

// 取一个任务来执行
func (s *ScanTaskExport) worker(ctx context.Context, task model.ExportTensorTask) error {
	// 检查同样的任务是否已经做过,且文件存在，就不再执行
	tensorTask, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: []string{consts.ExportScanResult}, TaskType: task.TaskType, Parameter: task.Parameter, NotIds: []int64{task.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("SearchExportTensorTask")
		return err
	}
	if len(tensorTask) > 0 && tensorTask[0].FinishAt > 0 {
		// 如果上一次执行成功了,成功之后更新任务
		file := tensorTask[0].FilePath
		stat, err := os.Stat(file)
		if err == nil && !stat.IsDir() {
			err := s.UpdateTask.Success(ctx, task.ID, tensorTask[0].FilePath)
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
			} else {
				return nil
			}
		}
	}

	if ex, ok := s.ExportingMap.Load(task.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
			logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
			return nil
		}
	}

	s.ExportingMap.Store(task.ID, consts.TaskExporting)

	filename := task.FilePath
	subTaskChan := s.GenImageIdChan(ctx, task)
	excelDataChan := s.GenExcelDataChan(ctx, subTaskChan, filename)
	excelFileChan := s.GenExcelFileChan(ctx, excelDataChan)

	if err := s.ZipAndSave(ctx, filename, excelFileChan); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
		s.ExportingMap.Delete(task.ID)

		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	s.ExportingMap.Delete(task.ID)
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, filename)); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}
	return nil
}

func (s *ScanTaskExport) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		TaskType:    model.ExportExcel,
		ExecuteType: []string{consts.ExportScanResult},
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: consts.DefaultExportBathSize})
	if err != nil {
		logging.GetLogger().Err(err).Str("ExecuteType", consts.ExportScanResult).Msg("GetTensorTask")
		return
	}

	for i := range tasks {
		if err := s.UpdateTask.Start(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("Run.Start")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			logging.GetLogger().Err(err).Msg("worker")
		}
	}
}
