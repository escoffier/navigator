package service

import (
	"context"
	"fmt"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExportTaskInterface interface {
	CreateExportTask(ctx context.Context, data *model.ExportTensorTask) error
	SearchExportTask(ctx context.Context, executeType string, filter *model.Filter) ([]model.ExportTensorTask, int64, error)
	GetExportTask(ctx context.Context, id int64) (*model.ExportTensorTask, error)
	CheckScanTask(ctx context.Context, scanTaskID int64) (*ExportLimit, error)
	CreateSearchImage(ctx context.Context, taskID int64, param model.ImageListParam) error
	CreateScanTaskImage(ctx context.Context, taskID int64, scanGroupID int64) error

	ImageSrvInterface
}
type ExportTaskSrv struct {
	ExportDal               store.ExportTaskDal
	ImageSrv                ImageSrvInterface
	ScanTaskDal             store.ScanTaskDal
	MaxImageByOneExportTask int64
}
type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
}

func (s *ExportTaskSrv) ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error) {
	return s.ImageSrv.ListImageWithScanInfo(ctx, param, filter)
}

func (s *ExportTaskSrv) CreateSearchImage(ctx context.Context, taskID int64, param model.ImageListParam) error {
	if taskID <= 0 {
		return fmt.Errorf("no taskID:%d", taskID)
	}
	var startID int64
	for {
		filter := &model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
		param.JustReturnImage = true
		param.StartID = startID

		images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, param, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateSearchImage ListImageWithScanInfo")
			return err
		}
		if len(images) == 0 {
			break
		}
		startID = images[len(images)-1].ID
		data := make([]*model.ExportTaskImage, 0)
		for i := range images {
			data = append(data, &model.ExportTaskImage{
				TaskID:    taskID,
				ImageID:   images[i].ID,
				ImageName: images[i].GetImageName(),
			})
		}

		if err := s.ExportDal.CreateExportTaskImage(ctx, data); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Msg("CreateSearchImage CreateExportTaskImage")
			return err
		}
	}
	return nil
}

func (s *ExportTaskSrv) CreateScanTaskImage(ctx context.Context, taskID int64, scanGroupID int64) error {
	if taskID <= 0 {
		return fmt.Errorf("no taskID:%d", taskID)
	}
	var startID int64
	filter := &model.Filter{Limit: consts.DefaultLimit, SortBy: consts.SortByAsc, SortFiled: "id"}
	// 前端传过来的是groupID
	scanTasks, _, err := s.ScanTaskDal.GetTaskList(ctx, store.SearchTaskParam{GroupID: scanGroupID}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("groupID", scanGroupID).Msg("CreateScanTaskImage GetTaskList")
		return err
	}
	taskIds := make([]int64, 0)
	for i := range scanTasks {
		taskIds = append(taskIds, scanTasks[i].ID)
	}
	if len(taskIds) == 0 {
		logging.Get().Err(err).Int64("scanGroupID", scanGroupID).Msg("GenImageIdChan not fond task")
		return nil
	}

	for {
		param := store.SearchSubTaskParam{
			TaskIds:  taskIds,
			Statuses: []int{consts.ImageScanSuccess},
			LastID:   startID,
		}

		subtasks, _, err := s.ScanTaskDal.GetSubTasks(ctx, param, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).Msg("CreateScanTaskImage GetSubTasks")
			return err
		}
		if len(subtasks) == 0 {
			break
		}
		startID = subtasks[len(subtasks)-1].ID

		imageIds := make([]int64, 0)
		for i := range subtasks {
			imageIds = append(imageIds, subtasks[i].ImageID)
		}
		imageListParam := model.ImageListParam{ImageIds: imageIds, JustReturnImage: true}

		images, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, imageListParam, filter)
		if err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).Msg("CreateScanTaskImage ListImageWithScanInfo")
			return err
		}
		data := make([]*model.ExportTaskImage, 0)
		for i := range images {
			data = append(data, &model.ExportTaskImage{
				TaskID:    taskID,
				ImageID:   images[i].ID,
				ImageName: images[i].GetImageName(),
			})
		}

		if err := s.ExportDal.CreateExportTaskImage(ctx, data); err != nil {
			logging.Get().Err(err).Int64("taskID", taskID).Int64("scanGroupID", scanGroupID).Msg("CreateScanTaskImage CreateExportTaskImage")
		}
	}
	return nil

}

func (s *ExportTaskSrv) CreateExportTask(ctx context.Context, data *model.ExportTensorTask) error {
	if err := data.Check(); err != nil {
		return err
	}
	// 把文件名写进去，用于前端展示
	if err := s.ExportDal.CreateExportTensorTask(ctx, data); err != nil {
		logging.Get().Err(err).Msg("CreateExportTask")
		return err
	}
	return nil
}

func (s *ExportTaskSrv) SearchExportTask(ctx context.Context, executeType string, filter *model.Filter) ([]model.ExportTensorTask, int64, error) {
	ext := make([]string, 0)
	if executeType != "" {
		ext = append(ext, executeType)
	}
	tasks, cnt, err := s.ExportDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: ext}, filter)
	if err != nil {
		logging.Get().Err(err).Msg("SearchExportTask")
		return nil, 0, err
	}
	return tasks, cnt, nil
}

func (s *ExportTaskSrv) GetExportTask(ctx context.Context, id int64) (*model.ExportTensorTask, error) {
	if id <= 0 {
		return nil, fmt.Errorf("please input id :%d", id)
	}

	tasks, _, err := s.ExportDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ID: id}, nil)
	if err != nil {
		logging.Get().Err(err).Msg("GetExportTask")
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("not find the task taskId is :%d", id)
	}

	return &(tasks[0]), nil
}

type ExportLimit struct {
	ImageCount int64 `json:"imageCount"`
	ImageLimit int64 `json:"imageLimit"`
}

func (s *ExportTaskSrv) CheckScanTask(ctx context.Context, scanTaskId int64) (*ExportLimit, error) {
	if scanTaskId <= 0 {
		return nil, fmt.Errorf("no scanTaskId")
	}
	_, all, err := s.ScanTaskDal.GetSubTasks(ctx, store.SearchSubTaskParam{
		Statuses: []int{consts.ImageScanSuccess}, TaskIds: []int64{scanTaskId}},
		&model.Filter{Limit: 1, Offset: 0})
	if err != nil {
		logging.Get().Err(err).Int64("scanTaskId", scanTaskId).Msg("CheckScanTask")
		return nil, err
	}
	return &ExportLimit{ImageCount: all, ImageLimit: s.MaxImageByOneExportTask}, nil
}

func NewExportTaskSrv(exportDal store.ExportTaskDal, maxImageByOneExportTask int64, scanTaskDal store.ScanTaskDal, ImageSrv ImageSrvInterface) *ExportTaskSrv {
	return &ExportTaskSrv{
		ExportDal:               exportDal,
		ImageSrv:                ImageSrv,
		ScanTaskDal:             scanTaskDal,
		MaxImageByOneExportTask: maxImageByOneExportTask,
	}
}
