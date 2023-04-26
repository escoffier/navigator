package excel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"

	json "github.com/json-iterator/go"
	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanTaskExport struct {
	ImageExport   ImageExportInterface
	ExportTaskDal store.ExportTaskDal
	ScanTaskDal   store.ScanTaskDal
	FileDir       string // 文件存储的决对路径
	UpdateTask    common.UpdateExportTask
	MaxVulnCol    int64
}

func NewScanTaskExport(
	imageExport ImageExportInterface,
	exportTaskDal store.ExportTaskDal,
	scanTaskDal store.ScanTaskDal,
	fileDir string, // 文件存储的决对路径
	updateTask common.UpdateExportTask,
	maxVulnCol int64,
) *ScanTaskExport {
	return &ScanTaskExport{
		ImageExport:   imageExport,
		ExportTaskDal: exportTaskDal,
		ScanTaskDal:   scanTaskDal,
		FileDir:       fileDir,
		UpdateTask:    updateTask,
		MaxVulnCol:    maxVulnCol,
	}
}

type TaskExportParma struct {
	ScanTaskID int64 `json:"scanTaskId"`
}

func (s *ScanTaskExport) GenExcelFileChan(ctx context.Context, dataChan chan common.ExcelDataWithMeta) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()

		defer close(out)

		for excelData := range dataChan {
			excelFile, err := common.WriteToExcel(excelData.Filename, excelData.ExcelMetaData, excelData.ExcelData)
			if err != nil {
				logging.Get().Err(err).Msg("Export.WriteToExcel")
				continue
			}
			// 没有基础镜像和应用镜像这一张表,删除
			excelFile.DeleteSheet(GenImageTypeInfoMeta().SheetName)
			out <- excelFile
			logging.Get().Info().Str("excelFile", excelFile.Path).Msg("GenExcelFileChan Send excel file")
		}
	}()

	return out
}

func (s *ScanTaskExport) GenExcelDataChan(ctx context.Context, task model.ExportTensorTask,
	imageIdChan chan int64) chan common.ExcelDataWithMeta {
	out := make(chan common.ExcelDataWithMeta, 1)

	go func(imageIdChan chan int64) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()
		defer close(out)

		vulnCol := atomic.NewInt32(0)
		index := 0

		excelData := common.ExcelDataWithMeta{
			ExcelData:     make(common.ExcelData),
			Filename:      fmt.Sprintf("%s_%d", task.GenFilenamePrefix(), index),
			ExcelMetaData: GetImageSheetInfo(consts.ExportScanResult),
		}

		for imageId := range imageIdChan {

			_ = s.UpdateTask.IncrRedisFinished(ctx, task)

			data, err := s.ImageExport.GetExcelData(ctx, imageId, vulnCol)
			if err != nil {
				logging.Get().Err(err).Int64("imageId", imageId).Msg("Export.GetExcelData")
			} else {
				logging.Get().Info().Int64("imageId", imageId).Msg("Export.GetExcelData")
				for sheetName, dataChan := range data {
					if excelData.ExcelData[sheetName] == nil {
						excelData.ExcelData[sheetName] = make([]chan []string, 0)
					}
					excelData.ExcelData[sheetName] = append(excelData.ExcelData[sheetName], dataChan)
				}
			}

			if vulnCol.Load() > int32(s.MaxVulnCol) {
				logging.Get().Info().Str("filename", excelData.Filename).Int32("vulnCol", vulnCol.Load()).Msg("Export.GenExcelDataChan send excelData")
				out <- excelData
				index++
				vulnCol = atomic.NewInt32(0)
				excelData = common.ExcelDataWithMeta{
					ExcelData:     make(common.ExcelData),
					Filename:      fmt.Sprintf("%s_%d", task.GenFilenamePrefix(), index),
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
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ScanTaskExport")
			}
		}()

		defer close(out)

		var lastID int64
		var completed int64
		param := TaskExportParma{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan Unmarshal")
			return
		}
		// 前端传过来的是groupID
		scanTasks, _, err := s.ScanTaskDal.GetTaskList(ctx, store.SearchTaskParam{GroupID: param.ScanTaskID}, nil)
		if err != nil {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan GetTaskList")
			return
		}

		taskIds := make([]int64, 0)
		for i := range scanTasks {
			taskIds = append(taskIds, scanTasks[i].ID)
		}
		if len(taskIds) == 0 {
			logging.Get().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageIdChan not fond task")
			return
		}

		for {
			scanTask, cnt, err := s.ScanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
				TaskIds: taskIds, Statuses: []int{consts.ImageScanSuccess}, LastID: lastID},
				&model.Filter{Limit: consts.DefaultBathSize, SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("GenImageIdChan Export.GetSubTasks")
				return
			}
			if len(scanTask) == 0 {
				logging.Get().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageIdChan all image completed")
				break
			}
			_ = s.UpdateTask.SetRedisAll(ctx, task, cnt)

			lastID = scanTask[len(scanTask)-1].ID
			for i := range scanTask {
				out <- scanTask[i].ImageID
			}
			completed += int64(len(scanTask))
			logging.Get().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageIdChan.partially completed")
		}
	}()

	return out
}

// 压缩并写入文件，filename 路径名
func (s *ScanTaskExport) ZipAndSave(ctx context.Context, filename string, excelFileChan chan *excelize.File) error {

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

// 取一个任务来执行
func (s *ScanTaskExport) worker(ctx context.Context, task model.ExportTensorTask) error {
	// 检查同样的任务是否已经做过,且文件存在，就不再执行
	tensorTask, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: []string{consts.ExportScanResult}, TaskType: task.TaskType, Parameter: task.Parameter, NotIds: []int64{task.ID}}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("SearchExportTensorTask")
		return err
	}
	if len(tensorTask) > 0 && tensorTask[0].FinishAt > 0 {
		// 如果上一次执行成功了,成功之后更新任务
		file := tensorTask[0].FilePath
		stat, err := os.Stat(file)
		if err == nil && !stat.IsDir() {
			err := s.UpdateTask.Success(ctx, task.ID, tensorTask[0].FilePath)
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
			} else {
				return nil
			}
		}
	}

	filename := task.GenFilenamePrefix()

	subTaskChan := s.GenImageIdChan(ctx, task)
	excelDataChan := s.GenExcelDataChan(ctx, task, subTaskChan)
	excelFileChan := s.GenExcelFileChan(ctx, excelDataChan)

	if err := s.ZipAndSave(ctx, filename, excelFileChan); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")

		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, filename)); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}

	_ = s.UpdateTask.DeleteRedisData(ctx, task)
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
		logging.Get().Err(err).Str("ExecuteType", consts.ExportScanResult).Msg("GetTensorTask")
		return
	}

	for i := range tasks {
		// 支持横向扩展
		created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, tasks[i].ID)
		if err != nil {
			logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("ExportImageHtmlSrv CreateExportIdempotent")
			return
		}
		if !created {
			continue
		}

		if err := s.UpdateTask.Start(ctx, tasks[i].ID); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("Run.Start")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			logging.Get().Err(err).Msg("worker")
		}
	}
}
