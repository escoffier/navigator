package common

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type UpdateTaskSrv struct {
	ExportTaskDal imagesecStore.ExportTaskDal
	RedisCli      *redis.Client
	Log           *scannerUtils.LogEvent
}

func NewUpdateTaskSrv(exportTaskDal imagesecStore.ExportTaskDal, redisCli *redis.Client) *UpdateTaskSrv {
	return &UpdateTaskSrv{ExportTaskDal: exportTaskDal, RedisCli: redisCli,
		Log: scannerUtils.NewLogEvent(scannerUtils.WithModule("exportImage"), scannerUtils.WithSubModule("updateTask")),
	}
}

// func (s *UpdateTaskSrv) DeleteIdempotent(ctx context.Context) error {
//
// 	dataName := new(model.ExportTensorTask).TableName()
// 	err := s.ExportTaskDal.DeleteExportIdempotent(ctx, dataName, 0)
// 	if err != nil {
// 		s.Log.Err(err).Str("dataName", dataName).Msg("DeleteIdempotent")
// 		return err
// 	}
// 	return nil
// }

func (s *UpdateTaskSrv) Success(ctx context.Context, id int64, filePath string) error {
	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTask(ctx, where, updater, nil); err != nil {
		s.Log.Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) IncrRedisFinished(ctx context.Context, taskID int64) error {
	key := fmt.Sprintf("export-finished-%d", taskID)
	err := s.RedisCli.Incr(ctx, key).Err()
	if err != nil {
		s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateTaskSrv setAll")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) SetRedisAll(ctx context.Context, taskID int64, all int64) error {
	key := fmt.Sprintf("export-all-%d", taskID)
	err := s.RedisCli.Set(ctx, key, all, time.Hour*2).Err()
	if err != nil {
		s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateTaskSrv setAll")
		return err
	}
	return err
}

func (s *UpdateTaskSrv) DeleteRedisData(ctx context.Context, taskID int64) error {
	var err error
	err = s.RedisCli.Del(ctx, fmt.Sprintf("export-all-%d", taskID)).Err()
	err = s.RedisCli.Del(ctx, fmt.Sprintf("export-finished-%d", taskID)).Err()

	if err != nil && err != redis.Nil {
		s.Log.Err(err).Int64("taskID", taskID).Msg("UpdateTaskSrv deleteRedisData")
	}
	return err
}

func (s *UpdateTaskSrv) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTask(ctx, where, updater, nil); err != nil {
		s.Log.Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTask(ctx, where, updater, nil); err != nil {
		s.Log.Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}
