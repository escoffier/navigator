package export

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type UpdateTask interface {
	Start(ctx context.Context, id int64) error
	Success(ctx context.Context, id int64, filePath string) error
	Failure(ctx context.Context, id int64, msg string) error
}

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
}

type ImageScanDal interface {
	SearchScanImage(ctx context.Context, param store.SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error)
}

type UpdateTaskSrv struct {
	ExportTaskDal store.ExportTaskDal
}

func NewUpdateTaskSrv(exportTaskDal store.ExportTaskDal) *UpdateTaskSrv {
	return &UpdateTaskSrv{ExportTaskDal: exportTaskDal}
}

func (s *UpdateTaskSrv) Success(ctx context.Context, id int64, filePath string) error {
	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil

}

func (s *UpdateTaskSrv) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}
