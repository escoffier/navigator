package export

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type UpdateTask interface {
	Start(ctx context.Context, id int64) error
	Success(ctx context.Context, id int64, filePath string) error
	Failure(ctx context.Context, id int64, msg string) error
	IncrRedisFinished(ctx context.Context, task model.ExportTensorTask) error
	SetRedisAll(ctx context.Context, task model.ExportTensorTask, all int64) error
	DeleteRedisData(ctx context.Context, task model.ExportTensorTask) error
}

type ImageSrvInterface interface {
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageListResponse, int64, error)
}

type ImageScanDal interface {
	SearchScanImage(ctx context.Context, param store.SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error)
}

type UpdateTaskSrv struct {
	ExportTaskDal store.ExportTaskDal
	RedisCli      *redis.Client
}

func NewUpdateTaskSrv(exportTaskDal store.ExportTaskDal, redisCli *redis.Client) *UpdateTaskSrv {
	return &UpdateTaskSrv{ExportTaskDal: exportTaskDal, RedisCli: redisCli}
}

func (s *UpdateTaskSrv) Success(ctx context.Context, id int64, filePath string) error {
	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) IncrRedisFinished(ctx context.Context, task model.ExportTensorTask) error {

	err := s.RedisCli.Incr(ctx, task.GenRedisFinishedKey()).Err()
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv setAll")
	}
	return err
}

func (s *UpdateTaskSrv) SetRedisAll(ctx context.Context, task model.ExportTensorTask, all int64) error {
	err := s.RedisCli.Set(ctx, task.GenRedisAllKey(), all, 0).Err()
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv setAll")
	}
	return err
}

func (s *UpdateTaskSrv) DeleteRedisData(ctx context.Context, task model.ExportTensorTask) error {
	var err error
	err = s.RedisCli.Del(ctx, task.GenRedisAllKey()).Err()
	err = s.RedisCli.Del(ctx, task.GenRedisFinishedKey()).Err()

	if err != nil && err != redis.Nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv deleteRedisData")
	}
	return err
}

func (s *UpdateTaskSrv) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}
