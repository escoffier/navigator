package waterlinemanager

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
	ConfigKey = "data-management-waterline"
)

func (m *Manager) GetWaterline(ctx context.Context) (int, error) {
	conf, err := dal.GetConfig(ctx, m.db, ConfigKey)
	if err != nil {
		return 0, err
	}

	if conf == nil {
		return def.DefaultWaterlinePercentage, nil
	}

	var record model.WaterlineConf
	err = json.Unmarshal(conf.Config, &record)
	if err != nil {
		return 0, fmt.Errorf("parse waterline conf fail:%w", err)
	}

	return record.Percentage, nil
}

func (m *Manager) SetWaterline(ctx context.Context, percentage int) error {
	conf := model.WaterlineConf{
		Percentage: percentage,
	}
	jsonBytes, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	return dal.SetConfig(ctx, m.db, ConfigKey, jsonBytes)
}
