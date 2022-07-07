package export

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	json "github.com/json-iterator/go"
	"github.com/xuri/excelize/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ScanTaskExport struct {
	BatchImage              int64
	imageExport             ImageExportInterface
	exportTaskDal           store.ExportTaskDal
	scanTaskDal             store.ScanTaskDal
	exportingMap            *sync.Map // 正在执行的任务
	fileDir                 string    // 文件存储的决对路径
	Interval                time.Duration
	updateTask              UpdateTask
	maxImageByOneExportTask int64
}

func NewScanTaskExport(
	imageExport ImageExportInterface,
	exportTaskDal store.ExportTaskDal,
	scanTaskDal store.ScanTaskDal,
	fileDir string, // 文件存储的决对路径
	interval time.Duration,
	updateTask UpdateTask,
	batchImage int64,
	maxImageByOneExportTask int64,
) *ScanTaskExport {
	return &ScanTaskExport{
		imageExport:             imageExport,
		exportTaskDal:           exportTaskDal,
		scanTaskDal:             scanTaskDal,
		exportingMap:            &sync.Map{},
		fileDir:                 fileDir,
		Interval:                interval,
		updateTask:              updateTask,
		BatchImage:              batchImage,
		maxImageByOneExportTask: maxImageByOneExportTask,
	}
}

func (s *ScanTaskExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
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

type TaskExportParma struct {
	ScanTaskID int64 `json:"scanTaskId"`
}

func (s *ScanTaskExport) Export(ctx context.Context, task model.ExportTensorTask) chan *excelize.File {
	out := make(chan *excelize.File)

	go func(task model.ExportTensorTask) {
		defer close(out)
		param := TaskExportParma{}
		index := 0
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			return
		}
		var lastID int64
		var completed int64
		for {
			filename, err := s.genFilename(ctx, task, index)
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.genFilename")
				return
			}
			logging.GetLogger().Info().Int64("taskID", task.ID).Str("filename", filename).Msg("Export.genFilename")

			if completed >= s.maxImageByOneExportTask {
				logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("Export.partially completed")
				break
			}

			scanTask, _, err := s.scanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
				TaskIds: []int64{param.ScanTaskID}, Statuses: []int{consts.ImageScanSuccess}, LastID: lastID},
				&model.Filter{Limit: Min(s.BatchImage, s.maxImageByOneExportTask-completed), SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.GetSubTasks")
				return
			}
			logging.GetLogger().Info().Int64("taskID", task.ID).Int64("scanTaskID", param.ScanTaskID).Int("scan subtask length", len(scanTask)).Msg("Export.GetSubTasks")
			if len(scanTask) == 0 || completed >= s.maxImageByOneExportTask {
				logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("Export.partially completed")
				break
			}
			lastID = scanTask[len(scanTask)-1].ID
			excelData := make(map[string][]chan []string)

			for i := range scanTask {
				data, err := s.imageExport.GetExcelData(ctx, scanTask[i].ImageID)
				if err != nil {
					logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.GetExcelData")
					return
				}
				for sheetName, dataChan := range data {
					if excelData[sheetName] == nil {
						excelData[sheetName] = make([]chan []string, 0)
					}
					excelData[sheetName] = append(excelData[sheetName], dataChan)
				}
				logging.GetLogger().Info().Int64("taskID", task.ID).Int64("imageID", scanTask[i].ImageID).Msg("Export.GetExcelData")
			}

			sheets := GetImageSheetInfo(consts.ExportScanResult)

			excelFile, err := WriteToExcel(filename, sheets, excelData)
			if err != nil {
				logging.GetLogger().Err(err).Msg("Export.WriteToExcel")
				continue
			}
			// 没有基础镜像和应用镜像这一张表,删除
			excelFile.DeleteSheet(GenImageTypeInfoMeta().SheetName)

			out <- excelFile

			index++
			completed += int64(len(scanTask))
			logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("Export.partially completed")
		}
	}(task)

	return out
}

func (s *ScanTaskExport) genFilename(ctx context.Context, task model.ExportTensorTask, suffix int) (string, error) {
	searchParam := TaskExportParma{}

	if err := json.Unmarshal([]byte(task.Parameter), &searchParam); err != nil {
		return "", err
	}
	scanTasks, _, err := s.scanTaskDal.GetTasks(ctx, store.SearchTaskParam{Ids: []int64{searchParam.ScanTaskID}, Statuses: []int8{consts.End}}, nil)
	if err != nil {
		return "", err
	}
	if len(scanTasks) == 0 {
		return "", fmt.Errorf("not fond the scan task:%d", searchParam.ScanTaskID)
	}
	if suffix > 0 {
		fileName := fmt.Sprintf("%s_scan_result_export_%d", FormatTime(scanTasks[0].CreatedAt.UnixMilli(), consts.ExportTimeFormatForFilename), suffix)
		return fileName, nil
	}
	fileName := fmt.Sprintf("%s_scan_result_export", FormatTime(scanTasks[0].CreatedAt.UnixMilli(), consts.ExportTimeFormatForFilename))
	return fileName, nil
}

// 压缩并写入文件，filename 路径名
func (s *ScanTaskExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {

	// 先保存所有的excel文件
	var filePath string
	for file := range files {
		filePath = s.fileDir + "/" + filename
		// 检测目录是否存在
		if err := MkdirIfNotExist(filePath); err != nil {
			logging.GetLogger().Err(err).Str("filePath", filePath).Msg("ZipAndSave MkdirIfNotExist")
			return err
		}
		if err := file.SaveAs(filePath + "/" + file.Path); err != nil {
			logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave")
			continue
		}
		logging.GetLogger().Info().Str("filePath", filePath).Str("excelFile", file.Path).Msg("ZipAndSave save excel file")
	}
	logging.GetLogger().Info().Str("filePath", filePath).Msg("ZipAndSave save all  excel file start zip files")
	defer func() {
		if filePath != "" {
			if err := os.RemoveAll(filePath); err != nil {
				logging.GetLogger().Err(err).Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
			}
			logging.GetLogger().Info().Str("filePath", filePath).Msg("ZipAndSave defer RemoveAll")
		}
	}()

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
	// 检查同样的任务是否已经做过
	tensorTask, _, err := s.exportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: string(consts.ExportScanResult), Parameter: task.Parameter, NotIds: []int64{task.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("SearchExportTensorTask")
		return err
	}
	if len(tensorTask) > 0 && tensorTask[0].FinishAt > 0 {
		// 如果上一次执行成功了,成功之后更新任务
		if err := s.updateTask.Success(ctx, task.ID, tensorTask[0].FilePath); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
		return err
	}

	if ex, ok := s.exportingMap.Load(task.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
			logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
			return nil
		}
	}

	s.exportingMap.Store(task.ID, consts.TaskExporting)

	filename, err := s.genFilename(ctx, task, 0)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("genFilename")
		s.exportingMap.Delete(task.ID)

		if err := s.updateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure genFilename")
		}
		return err
	}

	excelChan := s.Export(ctx, task)

	if err := s.ZipAndSave(ctx, filename, excelChan); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
		s.exportingMap.Delete(task.ID)

		if err := s.updateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	s.exportingMap.Delete(task.ID)
	// 成功之后更新任务
	if err := s.updateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.fileDir, filename)); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}
	return nil
}

func (s *ScanTaskExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, string(consts.ExportScanResult), consts.DefaultExportBathSize)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchExportTensorTask")
		return
	}

	for i := range tasks {
		if err := s.updateTask.Start(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("Run.Start")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			logging.GetLogger().Err(err).Msg("worker")
		}
	}
}
