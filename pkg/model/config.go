package model

import (
	"time"
)

const (
	ConfLicense = "conf-license"
)

type TensorConfig struct {
	Key       string    `gorm:"column:k;primaryKey"`
	Config    []byte    `gorm:"column:config;type:bytea"`
	Creator   string    `gorm:"column:creator"`
	Updater   string    `gorm:"column:updater"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Status    int32     `gorm:"column:status"`
}

func (TensorConfig) TableName() string {
	return "ivan_platform_configs"
}
