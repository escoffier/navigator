package main

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/taskmanager"
	"gitlab.com/piccolo_su/vegeta/cmd/data/ttlmanager"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func handleStorage(cleaners []def.Cleaner, taskType def.GCTaskType) (err error) {
	db, err := NewPostgresClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Msgf("new db client fail:%s", err.Error())
		return err
	}

	taskManager := taskmanager.NewManager(db,
		// 在最大清理时间的基础上加1个小时 预留足够间隙
		def.TaskMaxTime+time.Hour)
	ttlManager := ttlmanager.NewManager(db)

	ctx, cancel := context.WithTimeout(context.Background(), def.TaskMaxTime)
	defer cancel()

	cleanArg, err := getCleanArg(ctx, ttlManager, taskType)
	if err != nil {
		logging.GetLogger().Error().Msgf("getCleanArg fail, err:%s", err.Error())
		return err
	}

	taskID, err := getTaskID(ctx, taskManager, taskType)
	if err != nil {
		if err == def.ErrTaskConflict {
			logging.GetLogger().Info().Msgf("other task is in progress")
			return nil
		}
		logging.GetLogger().Error().Msgf("getTaskID fail, err:%s", err.Error())
		return err
	}

	defer func() {
		if err != nil {
			logging.GetLogger().Error().Msgf("handleStorage fail, err:%s", err.Error())
			if _err := taskManager.UpdateTaskStatus(ctx, taskID, model.GCFailed); _err != nil {
				logging.GetLogger().Error().Msgf("UpdateTaskStatus fail, err:%s", _err)
			}
			return
		}

		if _err := taskManager.UpdateTaskStatus(ctx, taskID, model.GCCompleted); _err != nil {
			logging.GetLogger().Error().Msgf("UpdateTaskStatus fail, err:%s", _err)
		}
	}()

	logging.GetLogger().Info().Msgf("start cleaners, taskType:%s, taskID:%s, cleanArg:%s",
		taskType.String(), taskID, cleanArg)
	var group errgroup.Group
	for _, cleaner := range cleaners {
		cleaner := cleaner
		group.Go(func() error {
			return cleaner.Clean(ctx, cleanArg)
		})
	}
	return group.Wait()
}
