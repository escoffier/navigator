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
	"go.uber.org/atomic"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ScanTaskExport struct {
	imageExport             ImageExportInterface
	exportTaskDal           store.ExportTaskDal
	scanTaskDal             store.ScanTaskDal
	exportingMap            *sync.Map // 正在执行的任务
	fileDir                 string    // 文件存储的决对路径
	Interval                time.Duration
	updateTask              UpdateTask
	maxVulnCol              int64
	maxImageByOneExportTask int64
}

func NewScanTaskExport(
	imageExport ImageExportInterface,
	exportTaskDal store.ExportTaskDal,
	scanTaskDal store.ScanTaskDal,
	fileDir string, // 文件存储的决对路径
	interval time.Duration,
	updateTask UpdateTask,
	maxVulnCol int64,
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
		maxVulnCol:              maxVulnCol,
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

func (s *ScanTaskExport) GenExcelFileChan(ctx context.Context, dataChan chan ExcelDataWithMeta) chan *excelize.File {
	out := make(chan *excelize.File)

	go func() {
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

func (s *ScanTaskExport) WriteToExcel(ctx context.Context, data ExcelDataWithMeta, vulnColChan chan int) (*excelize.File, error) {
	if data.ExcelData == nil {
		return nil, fmt.Errorf("WriteToExcel  data is nil")
	}
	if data.Filename == "" {
		return nil, fmt.Errorf("filename is nil")
	}
	start := time.Now().UnixMilli()
	file := excelize.NewFile()
	file.Path = data.Filename + ".xlsx"
	logging.GetLogger().Info().Str("excelPath", file.Path).Msg("WriteToExcel")

	vulnCount := 0
	for i := range data.ExcelMetaData {
		// 写入数据，用流式方式
		idx := file.NewSheet(data.ExcelMetaData[i].SheetName)
		file.SetActiveSheet(idx)

		// 先写头数据
		streamWriter, err := file.NewStreamWriter(data.ExcelMetaData[i].SheetName)
		if err != nil {
			return nil, err
		}

		data2 := make([]interface{}, len(data.ExcelMetaData[i].Header))
		for j := range data.ExcelMetaData[i].Header {
			data2[j] = data.ExcelMetaData[i].Header[j]
		}

		cell, err := excelize.CoordinatesToCellName(1, 1)
		if err != nil {
			return nil, err
		}
		if err := streamWriter.SetRow(cell, data2); err != nil {
			return nil, err
		}
		// 再写数据
		col := 2

		sheetDataSlice := data.ExcelData[data.ExcelMetaData[i].SheetName]

		for j := range sheetDataSlice {
			sheetDataChan := sheetDataSlice[j]
			for sheetData := range sheetDataChan {
				data3 := make([]interface{}, len(sheetData))
				for k := range sheetData {
					data3[k] = sheetData[k]
					if data.ExcelMetaData[i].SheetName == GenImageVulnInfoMeta().SheetName {
						vulnCount++
					}
				}

				cell, err := excelize.CoordinatesToCellName(1, col)
				if err != nil {
					return nil, err
				}
				if err := streamWriter.SetRow(cell, data3); err != nil {
					return nil, err
				}
				col++
			}
		}
		// 刷新数据
		if err := streamWriter.Flush(); err != nil {
			return nil, err
		}
	}
	file.DeleteSheet("Sheet1")
	file.SetActiveSheet(0)

	// 发送漏洞的条数
	go func() {
		vulnColChan <- vulnCount
	}()

	logging.GetLogger().Info().Int64("cost", time.Now().UnixMilli()-start).Msg("WriteToExcel")

	return file, nil
}

type ExcelData map[string][]chan []string // key：excel sheet name

type ExcelDataWithMeta struct {
	ExcelData     ExcelData
	Filename      string
	ExcelMetaData []ExcelMetaData
}

func (s *ScanTaskExport) GenExcelDataChan(ctx context.Context, scanTaskChan chan model.SubTask, filenamePrefix string) chan ExcelDataWithMeta {
	out := make(chan ExcelDataWithMeta)

	go func(scanTaskChan chan model.SubTask) {
		defer close(out)

		vulnCol := atomic.NewInt32(0)
		index := 0

		excelData := ExcelDataWithMeta{
			ExcelData:     make(ExcelData),
			Filename:      fmt.Sprintf("%s_%d", filenamePrefix, index),
			ExcelMetaData: GetImageSheetInfo(consts.ExportScanResult),
		}

		for scanTask := range scanTaskChan {
			data, err := s.imageExport.GetExcelData(ctx, scanTask.ImageID, vulnCol)
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", scanTask.ID).Msg("Export.GetExcelData")
			} else {
				for sheetName, dataChan := range data {
					if excelData.ExcelData[sheetName] == nil {
						excelData.ExcelData[sheetName] = make([]chan []string, 0)
					}
					excelData.ExcelData[sheetName] = append(excelData.ExcelData[sheetName], dataChan)
				}
			}

			if vulnCol.Load() > int32(s.maxVulnCol) {
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

	}(scanTaskChan)

	return out
}

func (s *ScanTaskExport) GenImageChan(ctx context.Context, task model.ExportTensorTask) chan model.SubTask {
	out := make(chan model.SubTask)

	go func() {
		defer close(out)

		var lastID int64
		var completed int64
		param := TaskExportParma{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.GetLogger().Err(err).Str("ExportTensorTask", task.Parameter).Msg("GenImageChan Unmarshal")
			return
		}

		for {
			scanTask, _, err := s.scanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
				TaskIds: []int64{param.ScanTaskID}, Statuses: []int{consts.ImageScanSuccess}, LastID: lastID},
				&model.Filter{Limit: Min(consts.DefaultBathSize, s.maxImageByOneExportTask-completed), SortFiled: "id", SortBy: consts.SortByAsc})
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Export.GetSubTasks")
				return
			}
			if len(scanTask) == 0 {
				logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageChan all image completed")
				break
			}
			lastID = scanTask[len(scanTask)-1].ID
			for i := range scanTask {
				out <- scanTask[i]
			}
			completed += int64(len(scanTask))
			logging.GetLogger().Info().Int64("taskID", task.ID).Int64("lastScanSubtaskID", lastID).Int64("completed", completed).Msg("GenImageChan.partially completed")
		}
	}()

	return out
}

func (s *ScanTaskExport) genFilenamePrefix(ctx context.Context, task model.ExportTensorTask) (string, error) {
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
	fileName := fmt.Sprintf("%s_scan_result_export", FormatTime(scanTasks[0].CreatedAt.UnixMilli(), consts.ExportTimeFormatForFilename))
	return fileName, nil
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
		filePath = s.fileDir + "/" + filename
		// 检测目录是否存在
		if err := MkdirIfNotExist(filePath, remove); err != nil {
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
	// 检查同样的任务是否已经做过,且文件存在，就不再
	tensorTask, _, err := s.exportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: string(consts.ExportScanResult), Parameter: task.Parameter, NotIds: []int64{task.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("SearchExportTensorTask")
		return err
	}
	if len(tensorTask) > 0 && tensorTask[0].FinishAt > 0 {
		// 如果上一次执行成功了,成功之后更新任务
		file := tensorTask[0].FilePath
		stat, err := os.Stat(file)
		if err == nil && !stat.IsDir() {
			err := s.updateTask.Success(ctx, task.ID, tensorTask[0].FilePath)
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
			} else {
				return nil
			}
		}
	}

	if ex, ok := s.exportingMap.Load(task.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
			logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
			return nil
		}
	}

	s.exportingMap.Store(task.ID, consts.TaskExporting)

	filename, err := s.genFilenamePrefix(ctx, task)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("genFilenamePrefix")
		s.exportingMap.Delete(task.ID)

		if err := s.updateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure genFilenamePrefix")
		}
		return err
	}

	subTaskChan := s.GenImageChan(ctx, task)
	excelDataChan := s.GenExcelDataChan(ctx, subTaskChan, filename)
	excelFileChan := s.GenExcelFileChan(ctx, excelDataChan)

	if err := s.ZipAndSave(ctx, filename, excelFileChan); err != nil {
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
	tasks, err := s.GetTensorTask(ctx, consts.ExportScanResult, consts.DefaultExportBathSize)
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
