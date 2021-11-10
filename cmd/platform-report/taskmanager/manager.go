package taskmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/cmd/platform-report/def"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type Manager struct {
	db          *rdbtools.GormWrapper
	maxTaskTime time.Duration
	reportPath  string
}

func NewManager(db *rdbtools.GormWrapper, maxTaskTime time.Duration, reportPath string) *Manager {
	return &Manager{
		db:          db,
		maxTaskTime: maxTaskTime,
		reportPath:  reportPath,
	}
}

func (m *Manager) GetTaskTemplate(ctx context.Context, id int32) (*model.ReportTaskTemplateMeta, error) {
	var record model.ReportTaskTemplateMeta
	var err = m.db.Get().WithContext(ctx).Where("id = ?", id).First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, def.ErrTaskTemplateNotExist
		}

		return nil, err
	}

	return &record, nil
}

func (m *Manager) CreateTaskTemplate(ctx context.Context, template *model.ReportTaskTemplateMeta) (int32, error) {
	var err = m.db.Get().WithContext(ctx).Create(template).Error
	if err != nil {
		if util.IsPostgresDuplicateError(err) {
			return 0, def.ErrTaskTemplateNameDuplicate
		}

		return 0, err
	}

	return template.ID, nil
}

func (m *Manager) UpdateTaskTemplate(ctx context.Context, template *model.ReportTaskTemplateMeta) error {
	var err = m.db.Get().WithContext(ctx).Select("*").
		Omit("created_at, latest_generate_timestamp, type").Updates(template).Error
	if err != nil {
		if util.IsPostgresDuplicateError(err) {
			return def.ErrTaskTemplateNameDuplicate
		}

		return err
	}

	return nil
}

func (m *Manager) DeleteTaskTemplate(ctx context.Context, id int32) error {
	return m.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var uuidList []string
		err := tx.WithContext(ctx).Model(&model.ReportRecord{}).
			Where("template_id = ? and status = ?", id, model.ReportRecordStatusComplete).
			Select("uuid").Scan(&uuidList).Error
		if err != nil {
			return err
		}

		err = tx.WithContext(ctx).Delete(&model.ReportTaskTemplateMeta{}, "id = ?", id).Error
		if err != nil {
			return err
		}

		for _, uuid := range uuidList {
			filename := path.Join(m.reportPath, uuid)
			if _err := os.Remove(filename); _err != nil && !errors.Is(err, os.ErrNotExist) {
				logging.GetLogger().Err(_err).Msgf("remove file fail, filename:%s", filename)
			}
		}

		return tx.WithContext(ctx).Delete(&model.ReportRecord{}, "template_id = ?", id).Error
	})
}

func (m *Manager) LoadAllTaskTemplates(ctx context.Context) ([]*model.ReportTaskTemplateMeta, error) {
	var records []*model.ReportTaskTemplateMeta
	var err = m.db.Get().WithContext(ctx).Find(&records).Error
	return records, err
}

func (m *Manager) GetReportTaskTemplates(ctx context.Context, types []string, query string, offset, limit int) ([]*model.ReportTaskTemplateMeta, int64, error) {
	var records []*model.ReportTaskTemplateMeta
	var count int64

	getBaseDB := func() *gorm.DB {
		db := m.db.Get().WithContext(ctx).Model(&model.ReportTaskTemplateMeta{})
		if query != "" {
			q := "%" + query + "%"
			db = db.Where("name like ? or emails like ?", q, q)
		}
		if len(types) > 0 {
			db = db.Where("type in (?)", types)
		}
		return db
	}

	var err = getBaseDB().Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = getBaseDB().Offset(offset).Limit(limit).Order("created_at desc").Find(&records).Error
	return records, count, err
}

func (m *Manager) CreateTask(ctx context.Context, templateID int32, startTimestamp, endTimestamp int64) (uuid string, err error) {
	uuid = util.GenerateUUIDHex()
	nowTime := time.Now()
	var record = &model.ReportRecord{
		UUID:           uuid,
		TemplateID:     templateID,
		StartTimestamp: startTimestamp,
		EndTimestamp:   endTimestamp,
		Status:         model.ReportRecordStatusInit,
		CreatedAt:      nowTime,
		UpdatedAt:      nowTime,
	}
	err = m.db.Get().Transaction(func(tx *gorm.DB) error {
		var r model.ReportRecord
		var _err = tx.WithContext(ctx).Model(&model.ReportRecord{}).Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("template_id = ? and start_timestamp = ? and end_timestamp = ? and (status = ? or status = ?)",
				templateID, startTimestamp, endTimestamp, model.ReportRecordStatusInit, model.ReportRecordStatusComplete).First(&r).Error
		if _err == nil {
			return def.ErrTaskConflict
		}
		if _err != gorm.ErrRecordNotFound {
			return _err
		}
		return tx.WithContext(ctx).Create(record).Error
	})

	return uuid, err
}

func (m *Manager) UpdateTaskFailed(ctx context.Context, uuid string) error {
	return m.db.Get().WithContext(ctx).Model(&model.ReportRecord{}).Where("uuid = ?", uuid).Updates(map[string]interface{}{
		"status":     model.ReportRecordStatusFailed,
		"updated_at": time.Now(),
	}).Error

}

func (m *Manager) FinishTask(ctx context.Context, id int32, uuid string, content []byte) error {
	var err = os.MkdirAll(m.reportPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("mkdir fail, err:%s", err)
	}

	err = os.WriteFile(path.Join(m.reportPath, uuid), content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("write file faile")
	}

	return m.db.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		nowTime := time.Now()
		err := tx.Model(&model.ReportRecord{}).Where("uuid = ?", uuid).Updates(map[string]interface{}{
			"status":     model.ReportRecordStatusComplete,
			"updated_at": nowTime,
		}).Error
		if err != nil {
			return err
		}

		return tx.Model(&model.ReportTaskTemplateMeta{}).Where("id = ?", id).
			UpdateColumn("latest_generate_timestamp", util.GetMillisecondTimestampByTime(nowTime)).Error
	})
}

func (m *Manager) DealExpireRecords(ctx context.Context, nowTime time.Time) error {
	return m.db.Get().WithContext(ctx).Model(&model.ReportRecord{}).
		Where("created_at < ? and status = ?", nowTime.Add(-m.maxTaskTime), model.ReportRecordStatusInit).
		UpdateColumn("status", model.ReportRecordStatusExpired).Error
}

func (m *Manager) GetTemplateReports(ctx context.Context, templateID int32, offset, limit int) ([]*model.ReportRecord, int64, error) {
	var records []*model.ReportRecord
	var count int64

	var err = m.db.Get().WithContext(ctx).Model(&model.ReportRecord{}).
		Where("template_id = ? and status = ?", templateID, model.ReportRecordStatusComplete).
		Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = m.db.Get().WithContext(ctx).
		Where("template_id = ? and status = ?", templateID, model.ReportRecordStatusComplete).
		Order("updated_at desc").
		Offset(offset).Limit(limit).
		Select("uuid, template_id, start_timestamp, end_timestamp").
		Find(&records).Error
	return records, count, err
}

func (m *Manager) GetReport(_ context.Context, uuid string) (*model.ReportDetail, error) {
	filename := path.Join(m.reportPath, uuid)
	content, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, def.ErrReportNotFound
		}
		return nil, err
	}

	var detail model.ReportDetail
	err = json.Unmarshal(content, &detail)
	if err != nil {
		return nil, fmt.Errorf("parse report fail, err:%s", err)
	}

	return &detail, nil
}
