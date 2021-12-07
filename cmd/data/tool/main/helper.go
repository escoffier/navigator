package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/cmd/data/env"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func NewPostgresClientFromEnv() (*rdbtools.GormWrapper, error) {
	return rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		db, err := databases.GetPostgresqlWithEnv(ctx)
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		return db, nil
	})
}

func getTaskID(ctx context.Context, manager def.TaskManager, taskType def.GCTaskType) (string, error) {
	if taskIDStr := os.Getenv(env.TaskID); taskIDStr != "" {
		// 手动触发任务时 已经提前生成了任务并通过环境变量传入任务id
		return taskIDStr, nil
	}
	// 定时任务需要通过任务管理器创建新任务
	task, err := manager.CreateGCTask(ctx, taskType)
	if err != nil {
		return "", err
	}

	return task.Hash, nil
}

func getCleanArg(ctx context.Context, manager def.TTLManager, taskType def.GCTaskType) (*def.CleanArg, error) {
	if ttlDayOffsetStr := os.Getenv(env.TTLDayOffset); ttlDayOffsetStr != "" {
		// 手动触发任务时 用户指定dayOffset并通过环境变量传入
		dayOffset, err := strconv.Atoi(ttlDayOffsetStr)
		if err != nil {
			return nil, err
		}
		return &def.CleanArg{
			DaysOffset: dayOffset,
			Cron:       false,
		}, nil
	}

	// 定时任务需要通过任务管理器从系统中获取dayOffset
	dayOffset, err := manager.GetTTLDayOffset(ctx, taskType)
	if err != nil {
		return nil, err
	}

	return &def.CleanArg{
		DaysOffset: dayOffset,
		Cron:       true,
	}, nil
}
