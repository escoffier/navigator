package model

import (
	"fmt"
	"time"
)

const (
	GCInProgress = "inprogress"
	GCCompleted  = "completed"
	GCFailed     = "failed"
)

const (
	DataTypeHotLogic   = "hotLogic"
	DataTypeHotOffline = "hotOffline"
	DataTypeCold       = "cold"
)

// TTLs ...
type TTLDays struct {
	ColdTTLDays       int         `json:"coldTTLDays"`
	HotOfflineTTLDays int         `json:"hotOfflineTTLDays"`
	HotLogicTTLDays   int         `json:"hotLogicTTLDays"`
	WaterlineData     int         `json:"waterlineData"`
	ColdView          StorageView `json:"coldView"`
	HotOfflineView    StorageView `json:"hotOfflineView"`
	HotLogicView      StorageView `json:"hotLogicView"`
}

// StorageView ...
type StorageView struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

func (s *StorageView) String() string {
	return fmt.Sprintf("total:%dMB, used:%dMB", s.Total/1024/1024, s.Used/1024/1024)
}

// GCTask ...
type GCTask struct {
	ID         int32     `gorm:"primaryKey; autoIncrement; column:id" json:"-"`
	Hash       string    `gorm:"column:hash; unique" json:"id"`
	Category   string    `gorm:"column:category; index" json:"category"`
	Status     string    `gorm:"column:status" json:"status"`
	CreatedAt  time.Time `gorm:"column:created_at" json:"startTime"`
	FinishedAt time.Time `gorm:"column:finished_at" json:"-"`
}

func (GCTask) TableName() string {
	return "ivan_platform_gc_tasks"
}

type DataTTLConf struct {
	TTL int `json:"ttl"`
}

type WaterlineConf struct {
	Percentage int `json:"percentage"`
}
