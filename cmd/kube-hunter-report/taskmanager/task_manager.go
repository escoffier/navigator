package taskmanager

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/kube-hunter-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Manager struct {
	db          *rdbtools.GormWrapper
	maxTaskTime time.Duration
}

func NewManager(db *rdbtools.GormWrapper, maxTaskTime time.Duration) *Manager {
	return &Manager{
		db:          db,
		maxTaskTime: maxTaskTime,
	}
}

func (m *Manager) CreateKubeHunterRecord(ctx context.Context, cluster, uuid, username string) (*model.KubeHunterRecord, error) {
	nowTime := time.Now()
	record := &model.KubeHunterRecord{
		UUID:      uuid,
		Cluster:   cluster,
		Username:  username,
		Status:    model.KubeHunterRecordStatusInit,
		CreatedAt: nowTime,
		UpdatedAt: nowTime,
	}

	var err = m.db.Get().Transaction(func(tx *gorm.DB) error {
		var r model.KubeHunterRecord
		var _err = tx.WithContext(ctx).Model(&model.KubeHunterRecord{}).Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("cluster = ? and status = ?", cluster, model.KubeHunterRecordStatusInit).First(&r).Error
		if _err == nil {
			return def.ErrTaskConflict
		}
		if _err != gorm.ErrRecordNotFound {
			return _err
		}
		return tx.WithContext(ctx).Create(record).Error
	})

	return record, err
}

func (m *Manager) GetLatestCompleteRecord(ctx context.Context, cluster string) (*model.KubeHunterRecord, error) {
	var record model.KubeHunterRecord
	var err = m.db.Get().WithContext(ctx).Where("cluster = ? and status = ?", cluster, model.KubeHunterRecordStatusComplete).
		Order("updated_at desc").
		Limit(1).
		First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, def.ErrNoRecord
		}
		return nil, err
	}
	return &record, nil
}

func (m *Manager) UpdateRecord(ctx context.Context, uuid string, status uint8, metaInfo []byte) error {
	nowTime := time.Now()
	sql := "update kube_hunter_records set status = ?, updated_at = ?, meta_info = ? where uuid = ?"
	retryFunc := func() error {
		return m.db.Get().WithContext(ctx).Exec(sql, status, nowTime, metaInfo, uuid).Error
	}

	return util.WithRetry(retryFunc, util.DefaultRetryConf)
}

func (m *Manager) DealExpireRecords(ctx context.Context, nowTime time.Time) error {
	sql := "update kube_hunter_records set status = ?, updated_at = ? where created_at < ? and status = ?"
	return m.db.Get().WithContext(ctx).Exec(sql,
		model.KubeHunterRecordStatusExpired,
		nowTime,
		nowTime.Add(-m.maxTaskTime),
		model.KubeHunterRecordStatusInit).Error
}

func (m *Manager) CheckInProgress(ctx context.Context, cluster string) (bool, error) {
	var count int64
	var err = m.db.Get().WithContext(ctx).Model(&model.KubeHunterRecord{}).
		Where("cluster = ? and status = ?", cluster, model.KubeHunterRecordStatusInit).Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
