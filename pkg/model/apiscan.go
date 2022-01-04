package model

import "time"

type BaseInfo struct {
	Status    int `gorm:"type:smallint"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type TensorApi struct {
	ID          int64  `gorm:"primaryKey; autoIncrement; column:id"`
	Cluster     string `gorm:"column:cluster"`
	Resource    string `gorm:"column:resource"`
	Kind        string `gorm:"column:kind"`
	Namespace   string `gorm:"column:namespace"`
	PodName     string `gorm:"column:pod_name"`
	IP          string `gorm:"column:ip"`
	Port        string `gorm:"column:port"`
	Path        string
	Params      string `gorm:"column:params"`
	Scheme      string
	ContentType string `gorm:"column:content_type"`
	Method      string
	ScanResult  string `gorm:"column:scan_result"`
	BaseInfo
}

func (t *TensorApi) TableName() string {
	return "ivan_assets_apis"
}
