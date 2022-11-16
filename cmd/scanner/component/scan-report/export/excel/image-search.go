package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

/*
根据筛选条件导出镜像结果
*/

type ExportImageInterface interface {
	GenExcelDataChan(ctx context.Context, task model.ExportTensorTask, imageIdChan chan int64) chan ExcelDataWithMeta
	ZipAndSave(ctx context.Context, filename string, excelFileChan chan *excelize.File) error
	GenExcelFileChan(ctx context.Context, dataChan chan ExcelDataWithMeta) chan *excelize.File
}

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
}

type ImageSearchSrv struct {
	ExportImageInterface ExportImageInterface
	ExportTaskDal        store.ExportTaskDal
	ExportingMap         *sync.Map // 正在执行的任务
	FileDir              string    // 文件存储的决对路径
	UpdateTask           export.UpdateTask
	ImageSrv             ImageSrvInterface
}

func NewImageSearchSrv(
	exportImageInterface ExportImageInterface,
	exportTaskDal store.ExportTaskDal,
	fileDir string, // 文件存储的决对路径
	updateTask export.UpdateTask,
	imageSrv ImageSrvInterface,
) *ImageSearchSrv {
	return &ImageSearchSrv{
		ExportImageInterface: exportImageInterface,
		ExportTaskDal:        exportTaskDal,
		ExportingMap:         &sync.Map{},
		FileDir:              fileDir,
		UpdateTask:           updateTask,
		ImageSrv:             imageSrv,
	}
}

func (s *ImageSearchSrv) GenImageIdChan(ctx context.Context, task model.ExportTensorTask) chan int64 {
	out := make(chan int64, 1)

	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("ImageSearchSrv")
			}
		}()

		defer close(out)
		var lastID int64
		var completed int64
		param := model.ImageListParam{}
		if err := json.Unmarshal([]byte(task.Parameter), &param); err != nil {
			logging.Get().Err(err).Str("ImageListParam", task.Parameter).Msg("GenImageIdChan Unmarshal")
			return
		}
		param.JustReturnImage = true

		var startID int64
		// 批量查询
		filter := model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
		for {
			param.StartID = startID
			images, cnt, err := s.ImageSrv.ListImageWithScanInfo(ctx, param, &filter)

			if err != nil {
				return
			}
			if len(images) == 0 {
				break
			}
			_ = s.UpdateTask.SetRedisAll(ctx, task, cnt)
			startID = images[len(images)-1].ID
			for i := range images {
				out <- images[i].ID
			}
			completed += int64(len(images))
			logging.Get().Info().Int64("taskID", task.ID).Int64("lastImageID", lastID).Int64("completed", completed).Msg("GenImageIdChan.partially completed")
		}
		logging.Get().Info().Int64("taskID", task.ID).Int64("lastImageID", lastID).Int64("completed", completed).Msg("GenImageIdChan completed")
	}()

	return out
}

// 取一个任务来执行
func (s *ImageSearchSrv) worker(ctx context.Context, task model.ExportTensorTask) error {
	if ex, ok := s.ExportingMap.Load(task.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
			logging.Get().Info().Int64("taskID", task.ID).Msg("task is running")
			return nil
		}
	}

	s.ExportingMap.Store(task.ID, consts.TaskExporting)

	filename := task.GenFilenamePrefix()

	imageIdChan := s.GenImageIdChan(ctx, task)
	excelDataChan := s.ExportImageInterface.GenExcelDataChan(ctx, task, imageIdChan)
	excelFileChan := s.ExportImageInterface.GenExcelFileChan(ctx, excelDataChan)

	if err := s.ExportImageInterface.ZipAndSave(ctx, filename, excelFileChan); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
		s.ExportingMap.Delete(task.ID)

		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.Get().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	s.ExportingMap.Delete(task.ID)
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, filename)); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}
	_ = s.UpdateTask.DeleteRedisData(ctx, task)
	return nil
}

func (s *ImageSearchSrv) Run(ctx context.Context) {
	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		ExecuteType: []string{consts.ExportImageSearch},
		TaskType:    model.ExportExcel,
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
