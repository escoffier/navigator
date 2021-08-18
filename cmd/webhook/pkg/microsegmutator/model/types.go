package model

import (
	"gorm.io/gorm"
	"time"
)

type BaseInfo struct {
	Status    int `gorm:"type:smallint"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type TensorMicrosegResource struct {
	ID          uint32 `gorm:"type:bigint;primarykey"`
	SegmentID   uint32 `gorm:"type:bigint;index:idx_res_sid"`
	SegmentName string `gorm:"type:varchar(100);index:idx_res_sname"`
	Cluster     string `gorm:"type:varchar(100)"`
	Namespace   string `gorm:"type:varchar(100)"`
	Kind        string `gorm:"type:varchar(100)"`
	Name        string `gorm:"type:varchar(100)"`
	Policy      string `gorm:"type:varchar(100)"`
	BaseInfo
}

type mutationModel struct {
	db *gorm.DB
}

func NewMutationModel(db *gorm.DB) Model {
	return &mutationModel{
		db: db,
	}
}
