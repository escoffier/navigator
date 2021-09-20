package def

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	ErrUnknownTaskType  = fmt.Errorf("unknown gc task type")
	ErrTaskConflict     = fmt.Errorf("task conflict")
	ErrTaskNotFound     = fmt.Errorf("task not found")
	ErrInvalidDataType  = fmt.Errorf("invalid data type")
	ErrInvalidTTL       = fmt.Errorf("invalid ttl")
	ErrInvalidWaterline = fmt.Errorf("invalid waterline")
	ErrInvalidTaskID    = fmt.Errorf("invalid task id")
)

type GCTaskType int

func (t GCTaskType) String() string {
	switch t {
	case GCTaskTypeHotLogic:
		return model.DataTypeHotLogic
	case GCTaskTypeHotOffline:
		return model.DataTypeHotOffline
	case GCTaskTypeCold:
		return model.DataTypeCold
	default:
		return ""
	}
}

func (t *GCTaskType) ConvertFromStr(str string) error {
	switch str {
	case model.DataTypeHotLogic:
		*t = GCTaskTypeHotLogic
	case model.DataTypeHotOffline:
		*t = GCTaskTypeHotOffline
	case model.DataTypeCold:
		*t = GCTaskTypeCold
	default:
		return ErrUnknownTaskType
	}

	return nil
}

func (t GCTaskType) Check() bool {
	return t == GCTaskTypeHotLogic ||
		t == GCTaskTypeHotOffline ||
		t == GCTaskTypeCold
}

const (
	GCTaskTypeHotLogic GCTaskType = iota
	GCTaskTypeHotOffline
	GCTaskTypeCold
)

const (
	TaskMaxTime = time.Hour * 24
)

var (
	DefaultTTLDays = map[GCTaskType]int{
		GCTaskTypeHotLogic:   14,
		GCTaskTypeHotOffline: 14,
		GCTaskTypeCold:       180,
	}
)

const (
	DefaultWaterlinePercentage = 80
)

type CleanArg struct {
	Cron       bool
	DaysOffset int
}

func (c *CleanArg) String() string {
	return fmt.Sprintf("cron:%t, dayOffset:%d", c.Cron, c.DaysOffset)
}

type Cleaner interface {
	Clean(ctx context.Context, arg *CleanArg) error
}

type TaskManager interface {
	CreateGCTask(ctx context.Context, taskType GCTaskType) (*model.GCTask, error)
	GetGCTask(ctx context.Context, taskID string) (*model.GCTask, error)
	UpdateTaskStatus(ctx context.Context, taskID string, status string) error
	DealExpireTasks(ctx context.Context, nowTime time.Time) error
}

type TTLManager interface {
	GetTTLDayOffset(ctx context.Context, taskType GCTaskType) (int, error)
	SetTTLDayOffset(ctx context.Context, taskType GCTaskType, ttlDayOffset int) error
}

type WaterlineManager interface {
	GetWaterline(ctx context.Context) (int, error)
	SetWaterline(ctx context.Context, percentage int) error
}

type NotifyHandler interface {
	Notify(ctx context.Context, dataType string, storageView *model.StorageView) error
}
