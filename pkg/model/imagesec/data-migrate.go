package imagesec

type DataMigrate struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	SoftVersion string `gorm:"soft_version" json:"softVersion"`
	Model       string `gorm:"model" json:"model"`                   // 标识的模块
	Last        string `gorm:"last" json:"last"`                     // 方便启动
	StartedAt   int64  `gorm:"column:started_at" json:"startedAt"`   // milliseconds
	FinishedAt  int64  `gorm:"column:finished_at" json:"finishedAt"` // milliseconds

	CreatedAt int64 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *DataMigrate) TableName() string { return "ivan_scan_data_migrate" }
