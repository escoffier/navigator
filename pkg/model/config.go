package model

import (
	"time"
)

type TensorConfig struct {
	Key       string    `gorm:"column:key;primaryKey"`
	Config    []byte    `gorm:"column:config;type:bytea"`
	Creator   string    `gorm:"column:creator"`
	Updater   string    `gorm:"column:updater"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Status    int32     `gorm:"column:status"`
}

func (TensorConfig) TableName() string {
	return "tensor_configs"
}
