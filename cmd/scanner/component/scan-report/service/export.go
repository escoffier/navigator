package service

import (
	"context"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExportInterface interface {
	CreateExportTask(ctx context.Context, data model.ExportTensorTask) error
	SearchExportTask(ctx context.Context, executeType string, filter *model.Filter) ([]model.ExportTensorTask, int64, error)
	GetExportTask(ctx context.Context, id int64) (*model.ExportTensorTask, error)
}

type ExportSrv struct {
	exportDal store.ExportTaskDal
}

func (s *ExportSrv) CreateExportTask(ctx context.Context, data model.ExportTensorTask) error {
	if err := data.Check(); err != nil {
		return err
	}
	// 把文件名写进去，用于前端展示

	if err := s.exportDal.CreateExportTensorTask(ctx, data); err != nil {
		logging.GetLogger().Err(err).Msg("CreateExportTask")
		return err
	}
	return nil
}

func (s *ExportSrv) SearchExportTask(ctx context.Context, executeType string, filter *model.Filter) ([]model.ExportTensorTask, int64, error) {
	tasks, cnt, err := s.exportDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ExecuteType: executeType}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchExportTask")
		return nil, 0, err
	}
	return tasks, cnt, nil
}

func (s *ExportSrv) GetExportTask(ctx context.Context, id int64) (*model.ExportTensorTask, error) {
	if id <= 0 {
		return nil, fmt.Errorf("please input id :%d", id)
	}

	tasks, _, err := s.exportDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{ID: id}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("GetExportTask")
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, fmt.Errorf("not find the task taskId is :%d", id)
	}

	return &(tasks[0]), nil
}

func NewExportSrv(exportDal store.ExportTaskDal) *ExportSrv {
	return &ExportSrv{exportDal: exportDal}
}
