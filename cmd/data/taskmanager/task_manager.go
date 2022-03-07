package taskmanager

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Manager struct {
	db           *databases.RDBInstance
	maxCleanTime time.Duration
}

func NewManager(db *databases.RDBInstance, maxCleanTime time.Duration) *Manager {
	return &Manager{
		db:           db,
		maxCleanTime: maxCleanTime,
	}
}

func (m *Manager) CreateGCTask(ctx context.Context, taskType def.GCTaskType) (*model.GCTask, error) {
	if !taskType.Check() {
		return nil, def.ErrUnknownTaskType
	}

	nowTime := time.Now()
	newGCTask := &model.GCTask{
		Hash:       util.GenerateUUIDHex(),
		Category:   taskType.String(),
		Status:     model.GCInProgress,
		CreatedAt:  nowTime,
		FinishedAt: nowTime,
	}

	var err = m.db.Get().Transaction(func(tx *gorm.DB) error {
		var task model.GCTask
		var _err = tx.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("category = ? and status = ?", taskType.String(), model.GCInProgress).Select("id").First(&task).Error
		if _err == nil {
			return def.ErrTaskConflict
		}
		if _err != gorm.ErrRecordNotFound {
			return _err
		}
		return tx.WithContext(ctx).Create(newGCTask).Error
	})

	return newGCTask, err
}

func (m *Manager) GetGCTask(ctx context.Context, taskID string) (*model.GCTask, error) {
	var task model.GCTask
	var err = m.db.GetReadDB().WithContext(ctx).Where("hash = ?", taskID).First(&task).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, def.ErrTaskNotFound
		}
		return nil, err
	}
	return &task, nil
}

func (m *Manager) UpdateTaskStatus(ctx context.Context, taskID, status string) error {
	nowTime := time.Now()
	sql := "update ivan_platform_gc_tasks set status = ?, finished_at = ? where hash = ?"
	retryFunc := func() error {
		return m.db.Get().WithContext(ctx).Exec(sql, status, nowTime, taskID).Error
	}

	return util.WithRetry(retryFunc, util.DefaultRetryConf)
}

func (m *Manager) DealExpireTasks(ctx context.Context, nowTime time.Time) error {
	sql := "update ivan_platform_gc_tasks set status = ?, finished_at = ? where created_at < ? and status = ?"
	return m.db.Get().WithContext(ctx).Exec(sql, model.GCFailed, nowTime, nowTime.Add(-m.maxCleanTime), model.GCInProgress).Error
}
