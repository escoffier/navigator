package ttlmanager

import (
	"context"
	"encoding/json"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
)

type Manager struct {
	db *rdbtools.GormWrapper
}

func NewManager(db *rdbtools.GormWrapper) *Manager {
	return &Manager{
		db: db,
	}
}

const (
	ConfigKeyPrefix = "data-management-ttl-"
)

func (m *Manager) GetTTLDayOffset(ctx context.Context, taskType def.GCTaskType) (int, error) {
	if !taskType.Check() {
		return 0, def.ErrInvalidDataType
	}
	conf, err := dal.GetConfig(ctx, m.db, generateConfigKey(taskType))
	if err != nil {
		return 0, fmt.Errorf("GetConfig fail, err:%w", err)
	}

	if conf == nil {
		return def.DefaultTTLDays[taskType], nil
	}

	var record model.DataTTLConf
	err = json.Unmarshal(conf.Config, &record)
	if err != nil {
		return 0, fmt.Errorf("parse confi fail, err:%w", err)
	}

	return record.TTL, nil
}

func (m *Manager) SetTTLDayOffset(ctx context.Context, taskType def.GCTaskType, dayOffsetTTL int) error {
	if !taskType.Check() {
		return def.ErrInvalidDataType
	}

	conf := model.DataTTLConf{
		TTL: dayOffsetTTL,
	}
	jsonBytes, err := json.Marshal(conf)
	if err != nil {
		return err
	}

	return dal.SetConfig(ctx, m.db, generateConfigKey(taskType), jsonBytes)
}

func generateConfigKey(taskType def.GCTaskType) string {
	return fmt.Sprintf("%s%s", ConfigKeyPrefix, taskType.String())
}
